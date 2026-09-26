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
