// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import (
	"strings"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

// A policy admin can be limited to a set of policies by name.
func TestAdminPolicyNameCondition(t *testing.T) {
	doc := `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["admin:CreatePolicy", "admin:DeletePolicy", "admin:GetPolicy"],
    "Condition": {"StringLike": {"admin:PolicyName": ["app-*", "app-system"]}}
  }]
}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("a policy naming admin:PolicyName must parse: %v", err)
	}

	cases := []struct {
		action  AdminAction
		policy  []string
		allowed bool
	}{
		{CreatePolicyAdminAction, []string{"app-42"}, true},
		{DeletePolicyAdminAction, []string{"app-system"}, true},
		{GetPolicyAdminAction, []string{"app-7"}, true},
		{CreatePolicyAdminAction, []string{"consoleAdmin"}, false},
		{CreatePolicyAdminAction, []string{"app-"}, true},
		{CreatePolicyAdminAction, nil, false},
		{CreateUserAdminAction, []string{"app-42"}, false},
	}
	for _, tc := range cases {
		values := map[string][]string{}
		if tc.policy != nil {
			values["PolicyName"] = tc.policy
		}
		got := p.IsAllowed(Args{
			AccountName:     "orb",
			Action:          Action(tc.action),
			ConditionValues: values,
		})
		if got != tc.allowed {
			t.Errorf("%s on %v: allowed=%v, want %v", tc.action, tc.policy, got, tc.allowed)
		}
	}
}

// A Deny scoped by name overrides a wider Allow.
func TestAdminPolicyNameConditionDeny(t *testing.T) {
	doc := `{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["admin:CreatePolicy"]},
    {"Effect": "Deny", "Action": ["admin:CreatePolicy"],
     "Condition": {"StringEquals": {"admin:PolicyName": ["consoleAdmin"]}}}
  ]
}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	allowed := func(name string) bool {
		return p.IsAllowed(Args{
			AccountName:     "orb",
			Action:          Action(CreatePolicyAdminAction),
			ConditionValues: map[string][]string{"PolicyName": {name}},
		})
	}
	if allowed("consoleAdmin") {
		t.Error("the Deny must win for consoleAdmin")
	}
	if !allowed("app-1") {
		t.Error("the Allow must still hold for other names")
	}
}

// admin:PolicyName describes an admin API request, so no S3 statement may use it.
func TestAdminPolicyNameRefusedOnS3Actions(t *testing.T) {
	for _, action := range []string{"s3:*", "s3:GetObject", "s3:PutObject"} {
		doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["` + action + `"],
  "Resource": ["arn:aws:s3:::bucket/*"],
  "Condition": {"StringLike": {"admin:PolicyName": ["app-*"]}}}]}`
		if _, err := ParseConfig(strings.NewReader(doc)); err == nil {
			t.Errorf("%s with admin:PolicyName must be refused", action)
		}
	}
}

// scopedPolicyAdmin is an identity allowed to manage the app-* policies only.
const scopedPolicyAdmin = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["admin:CreatePolicy", "admin:DeletePolicy", "admin:GetPolicy"],
    "Condition": {"StringLike": {"admin:PolicyName": ["app-*"]}}
  }]
}`

func allowedPolicyAdmin(t *testing.T, doc string, action AdminAction, values map[string][]string) bool {
	t.Helper()
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p.IsAllowed(Args{AccountName: "orb", Action: Action(action), ConditionValues: values})
}

// Only the server sets admin:PolicyName. A request header reaches condition
// values under its canonical form, Policyname, which other keys fall back to;
// an admin key never does, so a header cannot name a policy.
func TestAdminPolicyNameIgnoresHeaderForm(t *testing.T) {
	for _, values := range []map[string][]string{
		{"Policyname": {"app-1"}},
		{"policyname": {"app-1"}},
		{"POLICYNAME": {"app-1"}},
		{"Policy-Name": {"app-1"}},
	} {
		if allowedPolicyAdmin(t, scopedPolicyAdmin, CreatePolicyAdminAction, values) {
			t.Errorf("%v must not satisfy admin:PolicyName", values)
		}
	}
	// The value the server set wins over a header form alongside it.
	values := map[string][]string{"PolicyName": {"consoleAdmin"}, "Policyname": {"app-1"}}
	if allowedPolicyAdmin(t, scopedPolicyAdmin, CreatePolicyAdminAction, values) {
		t.Error("a header form must not override the server's PolicyName")
	}
}

// Names that only resemble a granted one do not match it.
func TestAdminPolicyNameLookalikes(t *testing.T) {
	for _, name := range []string{
		"APP-1",        // case differs
		"App-1",        // case differs
		"xapp-1",       // prefix before the pattern
		" app-1",       // leading space
		"*",            // a wildcard is a name here, not a pattern
		"app",          // shorter than the pattern's literal part
		"consoleAdmin", // unrelated
		"",             // empty
		"ａｐｐ-1",        // full-width letters
	} {
		if allowedPolicyAdmin(t, scopedPolicyAdmin, CreatePolicyAdminAction, map[string][]string{"PolicyName": {name}}) {
			t.Errorf("PolicyName %q must not match app-*", name)
		}
	}
}

// A condition key spelled any other way is not admin:PolicyName: the policy
// is refused rather than parsed into a condition nothing satisfies or, worse,
// one something else satisfies.
func TestAdminPolicyNameMisspellingsRefused(t *testing.T) {
	for _, key := range []string{"Admin:PolicyName", "admin:policyname", "admin:Policyname", "ADMIN:POLICYNAME", "admin:PolicyName ", "aws:PolicyName", "s3:PolicyName"} {
		doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Action": ["admin:CreatePolicy"],
  "Condition": {"StringLike": {"` + key + `": ["app-*"]}}}]}`
		if _, err := ParseConfig(strings.NewReader(doc)); err == nil {
			t.Errorf("condition key %q must be refused", key)
		}
	}
}

// admin:PolicyName is refused on every non-admin action family, and a
// statement may not mix admin actions with others to carry it along.
func TestAdminPolicyNameRefusedOutsideAdmin(t *testing.T) {
	for _, actions := range []string{
		`"s3tables:*"`,
		`"s3tables:CreateTable"`,
		`"sts:AssumeRole"`,
		`"admin:CreatePolicy", "s3:GetObject"`,
	} {
		doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [` + actions + `],
  "Resource": ["*"],
  "Condition": {"StringLike": {"admin:PolicyName": ["app-*"]}}}]}`
		if _, err := ParseConfig(strings.NewReader(doc)); err == nil {
			t.Errorf("actions %s with admin:PolicyName must be refused", actions)
		}
	}
}

// NotAction cannot widen the scoped grant: a statement allowing every admin
// action but CreateUser, under the same condition, still leaves other policies
// out of reach.
func TestAdminPolicyNameNotAction(t *testing.T) {
	doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "NotAction": ["admin:CreateUser"],
  "Resource": ["arn:aws:s3:::*"],
  "Condition": {"StringLike": {"admin:PolicyName": ["app-*"]}}}]}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAllowed(Args{AccountName: "orb", Action: Action(CreatePolicyAdminAction), ConditionValues: map[string][]string{"PolicyName": {"app-1"}}}) {
		t.Error("NotAction must still allow the granted app-1")
	}
	for _, name := range []string{"consoleAdmin", "readwrite"} {
		if p.IsAllowed(Args{AccountName: "orb", Action: Action(CreatePolicyAdminAction), ConditionValues: map[string][]string{"PolicyName": {name}}}) {
			t.Errorf("NotAction must not allow creating %s", name)
		}
	}
}

// An admin key takes no /variable suffix: admin:PolicyName/x would read the
// value PolicyName/x, which the server never sets and a caller might. Such a
// policy loads but is refused before saving. Keys that do take a variable keep
// parsing and saving.
func TestAdminPolicyNameRefusesVariableSuffix(t *testing.T) {
	for _, key := range []string{"admin:PolicyName/target", "admin:PolicyName/", "admin:PolicyName/a/b"} {
		doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Action": ["admin:CreatePolicy"],
  "Condition": {"StringLike": {"` + key + `": ["app-*"]}}}]}`
		p, err := ParseConfig(strings.NewReader(doc))
		if err != nil {
			t.Errorf("condition key %q must load: %v", key, err)
			continue
		}
		if err := p.CheckVariables(); err == nil {
			t.Errorf("condition key %q must be refused before saving", key)
		}
	}

	doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"],
  "Condition": {"StringEquals": {"s3:ExistingObjectTag/team": ["a"]}}}]}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("a key that takes a variable must still parse: %v", err)
	}
	if err := p.CheckVariables(); err != nil {
		t.Errorf("a key that takes a variable must still be saved: %v", err)
	}
}

// admin:PolicyName names the policy a policy action works on, so it is valid on
// those actions only: creating, reading and deleting policies, and attaching or
// detaching them. On any other admin action no request carries it.
func TestAdminPolicyNameOnlyOnPolicyActions(t *testing.T) {
	doc := func(action string) string {
		return `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["` + action + `"],
  "Condition": {"StringLike": {"admin:PolicyName": ["app-*"]}}}]}`
	}
	for _, action := range []string{
		"admin:CreatePolicy", "admin:DeletePolicy", "admin:GetPolicy",
		"admin:AttachUserOrGroupPolicy", "admin:UpdatePolicyAssociation",
	} {
		if _, err := ParseConfig(strings.NewReader(doc(action))); err != nil {
			t.Errorf("%s must take admin:PolicyName: %v", action, err)
		}
	}
	for _, action := range []string{"admin:ServerInfo", "admin:CreateUser", "admin:ListUserPolicies", "admin:*"} {
		if _, err := ParseConfig(strings.NewReader(doc(action))); err == nil {
			t.Errorf("%s must refuse admin:PolicyName", action)
		}
	}
}

// Attaching and detaching are scoped per policy the same way.
func TestAdminPolicyNameScopesAttach(t *testing.T) {
	doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
  "Action": ["admin:AttachUserOrGroupPolicy", "admin:UpdatePolicyAssociation"],
  "Condition": {"StringLike": {"admin:PolicyName": ["app-*"]}}}]}`
	for _, action := range []AdminAction{AttachPolicyAdminAction, UpdatePolicyAssociationAction} {
		for name, want := range map[string]bool{"app-1": true, "consoleAdmin": false, "": false} {
			values := map[string][]string{}
			if name != "" {
				values["PolicyName"] = []string{name}
			}
			if got := allowedPolicyAdmin(t, doc, action, values); got != want {
				t.Errorf("%s on %q: allowed=%v, want %v", action, name, got, want)
			}
		}
	}
}

// The action-specific key table stays consistent with the key lists: every key
// it names is an action key that parses, every action it names exists, no key
// is both common and action-specific, and every action key is taken by at
// least one action, so a new key cannot be valid everywhere or nowhere by
// accident.
func TestAdminActionConditionKeysConsistent(t *testing.T) {
	common := map[condition.KeyName]bool{}
	for _, k := range condition.CommonAdminKeys {
		common[k] = true
	}
	actionKeys := map[condition.KeyName]bool{}
	for _, k := range condition.AdminActionKeys {
		if common[k] {
			t.Errorf("%s is both a common and an action-specific admin key", k)
		}
		if !k.ToKey().IsValid() {
			t.Errorf("action key %s does not parse", k)
		}
		actionKeys[k] = true
	}
	taken := map[condition.KeyName]bool{}
	for action, keys := range adminActionConditionKeys {
		if _, ok := SupportedAdminActions[action]; !ok {
			t.Errorf("%s is not a supported admin action", action)
		}
		for _, k := range keys {
			if !actionKeys[k] {
				t.Errorf("%s lists %s, which is not in condition.AdminActionKeys", action, k)
			}
			taken[k] = true
		}
	}
	for k := range actionKeys {
		if !taken[k] {
			t.Errorf("action key %s is taken by no admin action", k)
		}
	}
}
