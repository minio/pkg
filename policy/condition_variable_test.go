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
	"encoding/json"
	"strings"
	"testing"
)

// conditionStatement is one Allow statement testing key with StringEquals.
func conditionStatement(actions, resources, key string) string {
	s := `{"Effect": "Allow", "Action": [` + actions + `],`
	if resources != "" {
		s += ` "Resource": [` + resources + `],`
	}
	return s + ` "Condition": {"StringEquals": {"` + key + `": ["v"]}}}`
}

var conditionVariableCases = []struct {
	actions, resources string
}{
	{`"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
	{`"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/*"`},
	{`"admin:CreatePolicy"`, ``},
	{`"sts:AssumeRoleWithWebIdentity"`, ``},
}

// Only the tag keys take a /<variable> suffix. A policy putting one on any
// other key loads, so a stored one keeps working, but is refused before it is
// saved rather than saved as a condition that reads a value no server sets.
func TestConditionVariableRefusedOnKeysThatTakeNone(t *testing.T) {
	for _, tc := range []struct {
		key, actions, resources string
	}{
		{"aws:SourceIp/x", `"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
		{"aws:username/x", `"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
		{"s3:prefix/x", `"s3:ListBucket"`, `"arn:aws:s3:::bucket"`},
		{"s3:versionid/x", `"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
		{"s3tables:namespace/x", `"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/*"`},
		{"admin:PolicyName/x", `"admin:CreatePolicy"`, ``},
		{"sts:DurationSeconds/x", `"sts:AssumeRoleWithWebIdentity"`, ``},
		{"jwt:groups/x", `"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
	} {
		doc := `{"Version": "2012-10-17", "Statement": [` + conditionStatement(tc.actions, tc.resources, tc.key) + `]}`
		p, err := ParseConfig(strings.NewReader(doc))
		if err != nil {
			t.Errorf("%s must load: %v", tc.key, err)
			continue
		}
		err = p.CheckVariables()
		if err == nil {
			t.Errorf("%s must be refused before saving", tc.key)
			continue
		}
		if !strings.Contains(err.Error(), "takes no variable") {
			t.Errorf("%s: refused for the wrong reason: %v", tc.key, err)
		}
	}
}

// The tag keys keep their suffix, on the actions they apply to.
func TestConditionVariableAllowedOnTagKeys(t *testing.T) {
	for _, tc := range []struct {
		key, actions, resources string
	}{
		{"s3:ExistingObjectTag/team", `"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
		{"s3:RequestObjectTag/team", `"s3:PutObject"`, `"arn:aws:s3:::bucket/*"`},
		{"s3tables:TableTag/team", `"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/*"`},
		{"s3tables:WarehouseTag/team", `"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/*"`},
	} {
		doc := `{"Version": "2012-10-17", "Statement": [` + conditionStatement(tc.actions, tc.resources, tc.key) + `]}`
		p, err := ParseConfig(strings.NewReader(doc))
		if err != nil {
			t.Errorf("%s must parse: %v", tc.key, err)
			continue
		}
		if err := p.CheckVariables(); err != nil {
			t.Errorf("%s must be saved: %v", tc.key, err)
		}
	}
}

// An empty suffix names no variable, so the key is malformed whatever it is:
// it is refused before saving. A stored one still loads and marshals back with
// its slash, so a re-save or replication does not rewrite it into a different
// condition.
func TestConditionVariableEmptyRefused(t *testing.T) {
	for _, key := range []string{"s3:ExistingObjectTag/", "aws:SourceIp/", "admin:PolicyName/"} {
		for _, c := range conditionVariableCases {
			doc := `{"Version": "2012-10-17", "Statement": [` + conditionStatement(c.actions, c.resources, key) + `]}`
			p, err := ParseConfig(strings.NewReader(doc))
			bare := `{"Version": "2012-10-17", "Statement": [` + conditionStatement(c.actions, c.resources, strings.TrimSuffix(key, "/")) + `]}`
			if _, bareErr := ParseConfig(strings.NewReader(bare)); bareErr != nil {
				// The key does not apply to these actions at all, so the
				// policy is refused whatever its suffix.
				if err == nil {
					t.Errorf("%s on %s must be refused, as %s is", key, c.actions, strings.TrimSuffix(key, "/"))
				}
				continue
			}
			if err != nil {
				t.Errorf("%s on %s must load: %v", key, c.actions, err)
				continue
			}
			if err := p.CheckVariables(); err == nil || !strings.Contains(err.Error(), "names no variable") {
				t.Errorf("%s on %s must be refused before saving, got %v", key, c.actions, err)
			}
			buf, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("%s on %s must marshal: %v", key, c.actions, err)
			}
			if !strings.Contains(string(buf), `"`+key+`"`) {
				t.Errorf("%s on %s lost its slash on marshal: %s", key, c.actions, buf)
			}
		}
	}
}

// Bucket policies follow the same rule.
func TestConditionVariableBucketPolicy(t *testing.T) {
	doc := func(key string) string {
		return `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]},
  "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"],
  "Condition": {"StringEquals": {"` + key + `": ["v"]}}}]}`
	}
	bp, err := ParseBucketPolicyConfig(strings.NewReader(doc("aws:SourceIp/x")), "bucket")
	if err != nil {
		t.Fatalf("a stored bucket policy with aws:SourceIp/x must load: %v", err)
	}
	if err := bp.CheckVariables(); err == nil || !strings.Contains(err.Error(), "takes no variable") {
		t.Errorf("aws:SourceIp/x must be refused before saving a bucket policy, got %v", err)
	}
	var decoded BucketPolicy
	if err := json.Unmarshal([]byte(doc("aws:SourceIp/")), &decoded); err != nil {
		t.Errorf("a stored bucket policy with aws:SourceIp/ must decode: %v", err)
	}
	bp, err = ParseBucketPolicyConfig(strings.NewReader(doc("s3:ExistingObjectTag/team")), "bucket")
	if err != nil {
		t.Fatalf("s3:ExistingObjectTag/team must parse in a bucket policy: %v", err)
	}
	if err := bp.CheckVariables(); err != nil {
		t.Errorf("s3:ExistingObjectTag/team must be saved in a bucket policy: %v", err)
	}
}

// A stored bucket policy's suffixed condition reads no value, so an anonymous
// caller who supplies SourceIp/x cannot satisfy it.
func TestConditionVariableStoredBucketPolicyFailsClosed(t *testing.T) {
	doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]},
  "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"],
  "Condition": {"StringEquals": {"aws:SourceIp/x": ["v"]}}}]}`
	bp, err := ParseBucketPolicyConfig(strings.NewReader(doc), "bucket")
	if err != nil {
		t.Fatalf("a stored bucket policy must load: %v", err)
	}
	if bp.IsAllowed(BucketPolicyArgs{
		Action:          GetObjectAction,
		BucketName:      "bucket",
		ObjectName:      "o",
		ConditionValues: map[string][]string{"SourceIp/x": {"v"}},
	}) {
		t.Error("a caller-supplied value must not satisfy a suffix the key does not take")
	}
}

// A policy stored before this rule still loads: loading decodes without
// validating, and refusing it there would break IAM on upgrade. Its suffixed
// condition reads no value, so a caller who supplies aws:username/x cannot
// satisfy it.
func TestConditionVariableStoredPolicyFailsClosed(t *testing.T) {
	for _, key := range []string{"aws:username/x", "aws:username/"} {
		doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::bucket/*"],
  "Condition": {"StringEquals": {"` + key + `": ["mallory"]}}}]}`
		var p Policy
		if err := json.Unmarshal([]byte(doc), &p); err != nil {
			t.Fatalf("a stored policy with %s must still load: %v", key, err)
		}
		if p.IsAllowed(Args{
			AccountName: "mallory",
			Action:      GetObjectAction,
			BucketName:  "bucket",
			ObjectName:  "o",
			ConditionValues: map[string][]string{
				"username/x": {"mallory"}, "username/": {"mallory"}, "username": {"mallory"},
			},
		}) {
			t.Errorf("%s: a caller-supplied value must not satisfy a suffix the key does not take", key)
		}
	}
}

// A condition on a suffix its key does not take can be neither checked nor
// satisfied, whatever the operator: an Allow carrying one never grants, and a
// Deny carrying one always applies. A negated operator reads an absent value as
// a match, so treating the key as merely absent would let such an Allow grant.
func TestConditionVariableStoredPolicyNegatedFailsClosed(t *testing.T) {
	for _, op := range []string{"StringNotEquals", "StringNotLike", "ForAllValues:StringEquals"} {
		for _, effect := range []string{"Allow", "Deny"} {
			doc := `{"Version": "2012-10-17", "Statement": [
  {"Effect": "` + effect + `", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"],
   "Condition": {"` + op + `": {"aws:username/x": ["alice"]}}}`
			if effect == "Deny" {
				doc += `,
  {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}`
			}
			doc += `]}`
			var p Policy
			if err := json.Unmarshal([]byte(doc), &p); err != nil {
				t.Fatalf("a stored policy must still load: %v", err)
			}
			if p.IsAllowed(Args{AccountName: "mallory", Action: GetObjectAction, BucketName: "bucket", ObjectName: "o"}) {
				t.Errorf("%s %s on aws:username/x must not let the request through", effect, op)
			}
		}
	}
}

// Strict validation refuses the same suffixes, admin statements included.
func TestConditionVariableRefusedStrict(t *testing.T) {
	for _, tc := range []struct{ key, actions, resources string }{
		{"admin:PolicyName/x", `"admin:CreatePolicy"`, ``},
		{"aws:SourceIp/x", `"s3:GetObject"`, `"arn:aws:s3:::bucket/*"`},
	} {
		doc := `{"Version": "2012-10-17", "Statement": [` + conditionStatement(tc.actions, tc.resources, tc.key) + `]}`
		if _, err := ParseConfigStrict(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "takes no variable") {
			t.Errorf("%s must be refused by strict validation, got %v", tc.key, err)
		}
	}
}
