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
	"fmt"
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

// Policy.hasDeny is only set by updateActionIndex, which a policy built as a
// struct literal never reaches. The built-in readonly policies are built that
// way and do carry a Deny, so HasDenyStatement must not trust the field alone.
func TestHasDenyStatementOnStructLiteralPolicy(t *testing.T) {
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
			if hasDenyStmt && !p.HasDenyStatement() {
				t.Errorf("%s: carries a Deny but HasDenyStatement() reports false", name)
			}
		}
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
