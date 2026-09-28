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

func TestSourceIdentityConditions(t *testing.T) {
	doc := `{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::data/*"],
     "Condition": {"StringLike": {"aws:SourceIdentity": ["alice*"]}}},
    {"Effect": "Allow", "Action": ["admin:ServerInfo"],
     "Condition": {"StringEquals": {"aws:SourceIdentity": ["alice"]}}},
    {"Effect": "Allow", "Action": ["sts:AssumeRole"],
     "Condition": {"StringEquals": {"sts:SourceIdentity": ["alice"]}}}
  ]
}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("a policy naming the source identity keys must parse: %v", err)
	}

	cases := []struct {
		action         Action
		sourceIdentity []string
		allowed        bool
	}{
		{GetObjectAction, []string{"alice@example.com"}, true},
		{GetObjectAction, []string{"bob"}, false},
		{GetObjectAction, nil, false},
		{Action(ServerInfoAdminAction), []string{"alice"}, true},
		{Action(ServerInfoAdminAction), []string{"bob"}, false},
		{Action(AssumeRoleAction), []string{"alice"}, true},
		{Action(AssumeRoleAction), []string{"bob"}, false},
		{Action(AssumeRoleAction), nil, false},
	}
	for _, tc := range cases {
		values := map[string][]string{}
		if tc.sourceIdentity != nil {
			values["SourceIdentity"] = tc.sourceIdentity
		}
		got := p.IsAllowed(Args{
			AccountName:     "app",
			Action:          tc.action,
			BucketName:      "data",
			ObjectName:      "report.csv",
			ConditionValues: values,
		})
		if got != tc.allowed {
			t.Errorf("%s with source identity %v: allowed=%v, want %v", tc.action, tc.sourceIdentity, got, tc.allowed)
		}
	}
}
