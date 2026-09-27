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
// other key is refused with an error rather than parsed into a condition that
// reads a value no server sets.
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
		_, err := ParseConfig(strings.NewReader(doc))
		if err == nil {
			t.Errorf("%s must be refused", tc.key)
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
		if _, err := ParseConfig(strings.NewReader(doc)); err != nil {
			t.Errorf("%s must parse: %v", tc.key, err)
		}
	}
}

// An empty suffix names no variable, so the key is malformed whatever it is.
func TestConditionVariableEmptyRefused(t *testing.T) {
	for _, key := range []string{"s3:ExistingObjectTag/", "aws:SourceIp/", "admin:PolicyName/"} {
		for _, c := range conditionVariableCases {
			doc := `{"Version": "2012-10-17", "Statement": [` + conditionStatement(c.actions, c.resources, key) + `]}`
			if _, err := ParseConfig(strings.NewReader(doc)); err == nil {
				t.Errorf("%s on %s must be refused", key, c.actions)
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
	if _, err := ParseBucketPolicyConfig(strings.NewReader(doc("aws:SourceIp/x")), "bucket"); err == nil ||
		!strings.Contains(err.Error(), "takes no variable") {
		t.Errorf("aws:SourceIp/x must be refused in a bucket policy, got %v", err)
	}
	if _, err := ParseBucketPolicyConfig(strings.NewReader(doc("s3:ExistingObjectTag/team")), "bucket"); err != nil {
		t.Errorf("s3:ExistingObjectTag/team must parse in a bucket policy: %v", err)
	}
}

// A policy stored before this rule still loads: loading decodes without
// validating, and refusing it there would break IAM on upgrade. Its suffixed
// condition reads no value, so a caller who supplies aws:username/x cannot
// satisfy it.
func TestConditionVariableStoredPolicyFailsClosed(t *testing.T) {
	doc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::bucket/*"],
  "Condition": {"StringEquals": {"aws:username/x": ["mallory"]}}}]}`
	var p Policy
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatalf("a stored policy must still load: %v", err)
	}
	if p.IsAllowed(Args{
		AccountName:     "mallory",
		Action:          GetObjectAction,
		BucketName:      "bucket",
		ObjectName:      "o",
		ConditionValues: map[string][]string{"username/x": {"mallory"}},
	}) {
		t.Error("a caller-supplied value must not satisfy a suffix the key does not take")
	}
}
