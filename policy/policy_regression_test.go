// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

// Statement.hash once omitted NotResources, so dropDuplicateStatements collapsed
// two Deny statements that differed only there -- silently discarding a Deny --
// but only past the 10-statement threshold where the hash path takes over.
func TestDropDuplicateStatementsKeepsNotResources(t *testing.T) {
	mk := func(n int) Policy {
		sts := []Statement{
			NewStatementWithNotResource("", Deny,
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("public/*")),
				condition.NewFunctions()),
			NewStatementWithNotResource("", Deny,
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("other/*")),
				condition.NewFunctions()),
		}
		// pad with distinct filler statements to cross the threshold
		for i := len(sts); i < n; i++ {
			sts = append(sts, NewStatement("", Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource(fmt.Sprintf("filler%d/*", i))),
				condition.NewFunctions()))
		}
		return Policy{Version: DefaultVersion, Statements: sts}
	}
	for _, n := range []int{4, 11, 20} {
		p := mk(n)
		before := len(p.Statements)
		p.dropDuplicateStatements()
		path := "original(<=10)"
		if n > 10 {
			path = "hashed(>10)"
		}
		t.Logf("n=%2d %-15s statements %d -> %d", n, path, before, len(p.Statements))
		if len(p.Statements) != before {
			t.Errorf("n=%d: LOST %d statement(s) that are not duplicates", n, before-len(p.Statements))
		}
	}
}

// Policy.hasDeny is only set by updateActionIndex, which a policy assembled as
// a struct literal outside this package never reaches, so HasDenyStatement must
// not trust the field alone.
func TestHasDenyStatementOnStructLiteralPolicy(t *testing.T) {
	// A literal built here has been through no parse path at all, so it pins
	// the behavior down regardless of what the canned policies contain.
	literal := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement("", Deny, NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("*")), condition.NewFunctions()),
		},
	}
	if !literal.HasDenyStatement() {
		t.Error("struct literal policy carries a Deny but HasDenyStatement() reports false")
	}

	checked := 0
	for _, name := range []string{"readonly", "consolereadonly", "diagnostics"} {
		for _, dp := range DefaultPolicies {
			if dp.Name != name {
				continue
			}
			p := dp.Definition
			hasDenyStmt := false
			for _, s := range p.Statements {
				if s.Effect == Deny {
					hasDenyStmt = true
				}
			}
			t.Logf("%-16s actual Deny statement=%v  HasDenyStatement()=%v", name, hasDenyStmt, p.HasDenyStatement())
			if hasDenyStmt {
				checked++
				if !p.HasDenyStatement() {
					t.Errorf("%s: carries a Deny but HasDenyStatement() reports false", name)
				}
			}
		}
	}
	if checked == 0 {
		t.Error("none of the named canned policies carries a Deny; this test checked nothing")
	}
}

// updateActionIndex appended to the action index and only ever set hasDeny to
// true, so a second pass accumulated onto the first instead of replacing it.
// Reindex is the exported way to re-derive that state, so repeating it has to
// land on the same answer as deriving it once.
func TestReindexIsIdempotent(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]},
		{"Effect":"Deny","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::b/*"]}]}`
	p, err := ParseConfig(bytes.NewReader([]byte(doc)))
	if err != nil {
		t.Fatal(err)
	}
	want := maps.Clone(p.actionStatementIndex)
	for i := range 3 {
		p.Reindex()
		if !maps.EqualFunc(p.actionStatementIndex, want, slices.Equal) {
			t.Fatalf("Reindex %d: index = %v, want %v", i+1, p.actionStatementIndex, want)
		}
		if !p.hasDeny {
			t.Fatalf("Reindex %d: hasDeny cleared on a policy that carries a Deny", i+1)
		}
	}

	// Dropping the Deny has to clear the flag, not leave it latched on.
	p.Statements = p.Statements[:1]
	p.Reindex()
	if p.hasDeny {
		t.Error("hasDeny still set after the only Deny statement was removed")
	}
	if p.HasDenyStatement() {
		t.Error("HasDenyStatement() true after the only Deny statement was removed")
	}
}

// Replacing Actions on a parsed policy leaves the cached statement class
// describing the old namespace, and that class decides whether Resources are
// matched at all -- an admin statement skips the check. So a statement switched
// from an admin action to an S3 one must stop being resource-exempt once
// Reindex has run. Without the Reindex call below, the first check fails.
func TestReindexRefreshesStatementClassAfterActionChange(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ServerInfo"],"Resource":[]}]}`
	p, err := ParseConfig(bytes.NewReader([]byte(doc)))
	if err != nil {
		t.Fatal(err)
	}

	// An S3 action confined to bucket "other" must not reach bucket "b".
	p.Statements[0].Actions = NewActionSet(GetObjectAction)
	p.Statements[0].Resources = NewResourceSet(NewResource("other/*"))
	p.Reindex()

	if p.IsAllowed(Args{Action: GetObjectAction, BucketName: "b", ObjectName: "o"}) {
		t.Error("GetObject on b/o allowed by a statement scoped to other/*: stale admin class skipped resource matching")
	}
	if !p.IsAllowed(Args{Action: GetObjectAction, BucketName: "other", ObjectName: "o"}) {
		t.Error("GetObject on other/o denied by a statement scoped to other/*")
	}
}

// Decide's DenyOnly and IsOwner fallthroughs sit below the Deny loop, so a
// policy with nothing to match must still reach them. Short-circuiting on an
// empty statement list turns every STS login for such a credential into
// ErrSTSAccessDenied. Any future work that narrows which statements Decide
// walks has to keep this passing.
func TestDecideReachesDenyOnlyAndIsOwnerWithNoStatements(t *testing.T) {
	p := Policy{Version: DefaultVersion}
	tests := []struct {
		name string
		args Args
		want Decision
	}{
		{"DenyOnly", Args{Action: Action(AssumeRoleWithWebIdentityAction), DenyOnly: true}, AllowDecision},
		{"IsOwner", Args{Action: GetObjectAction, BucketName: "b", ObjectName: "o", IsOwner: true}, AllowDecision},
		{"neither", Args{Action: GetObjectAction, BucketName: "b", ObjectName: "o"}, NoDecision},
	}
	for _, tt := range tests {
		if got := p.Decide(&tt.args); got != tt.want {
			t.Errorf("%s: Decide on a statement-less policy = %v, want %v", tt.name, got, tt.want)
		}
	}
}
