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

// TestBucketTagConditions verifies that aws:ResourceTag/<key> and
// s3:BucketTag/<key> condition bucket and object actions on the tags of the
// bucket, and that aws:RequestTag/<key> and aws:TagKeys condition a bucket tag
// write on the tags it sets.
func TestBucketTagConditions(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
  {"Effect":"Deny","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::*"],
   "Condition":{"StringEquals":{"aws:ResourceTag/level":["restricted"]}}},
  {"Effect":"Deny","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::*"],
   "Condition":{"StringEquals":{"s3:BucketTag/state":["frozen"]}}},
  {"Effect":"Deny","Action":["s3:PutBucketTagging"],"Resource":["arn:aws:s3:::*"],
   "Condition":{"ForAnyValue:StringLike":{"aws:TagKeys":["fabric.governance.*"]}}},
  {"Effect":"Deny","Action":["s3:PutBucketTagging"],"Resource":["arn:aws:s3:::*"],
   "Condition":{"StringEquals":{"aws:RequestTag/tier":["gold"]}}}
]}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckVariables(); err != nil {
		t.Fatal(err)
	}

	args := func(action Action, object string, bucketTags, requestTags map[string]string) Args {
		values := map[string][]string{}
		for k, v := range bucketTags {
			values[condition.NewKey(condition.AWSResourceTag, k).Name()] = []string{v}
			values[condition.NewKey(condition.S3BucketTag, k).Name()] = []string{v}
		}
		var keys []string
		for k, v := range requestTags {
			keys = append(keys, k)
			values[condition.NewKey(condition.AWSRequestTag, k).Name()] = []string{v}
		}
		if requestTags != nil {
			values[condition.AWSTagKeys.Name()] = keys
		}
		return Args{AccountName: "user", Action: action, BucketName: "bucket", ObjectName: object, ConditionValues: values}
	}
	restricted := map[string]string{"level": "restricted"}

	for _, tc := range []struct {
		name string
		args Args
		want bool
	}{
		{"read in a restricted bucket", args(GetObjectAction, "obj", restricted, nil), false},
		{"list a restricted bucket", args(ListBucketAction, "", restricted, nil), false},
		{"read in a public bucket", args(GetObjectAction, "obj", map[string]string{"level": "public"}, nil), true},
		{"read in an untagged bucket", args(GetObjectAction, "obj", nil, nil), true},
		{"write in a restricted bucket", args(PutObjectAction, "obj", restricted, nil), true},
		{"write in a frozen bucket", args(PutObjectAction, "obj", map[string]string{"state": "frozen"}, nil), false},
		{"tag a bucket with a free key", args(PutBucketTaggingAction, "", nil, map[string]string{"team": "x"}), true},
		{"tag a bucket with a governed key", args(PutBucketTaggingAction, "", nil, map[string]string{"team": "x", "fabric.governance.level": "public"}), false},
		{"remove every bucket tag", args(PutBucketTaggingAction, "", nil, map[string]string{}), true},
		{"tag a bucket with a denied value", args(PutBucketTaggingAction, "", nil, map[string]string{"tier": "gold"}), false},
	} {
		if got := p.IsAllowed(tc.args); got != tc.want {
			t.Errorf("%s: IsAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}

	for _, accepted := range []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/*"],"Condition":{"StringEquals":{"aws:ResourceTag/level":["restricted"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteBucket"],"Resource":["arn:aws:s3:::bucket"],"Condition":{"StringEquals":{"s3:BucketTag/level":["restricted"]}}}]}`,
	} {
		if _, err := ParseConfig(strings.NewReader(accepted)); err != nil {
			t.Errorf("a bucket tag key on an S3 action must be accepted: %v: %s", err, accepted)
		}
		if _, err := ParseBucketPolicyConfig(strings.NewReader(strings.Replace(accepted, `"Action"`, `"Principal":"*","Action"`, 1)), "bucket"); err != nil {
			t.Errorf("a bucket tag key in a bucket policy must be accepted: %v: %s", err, accepted)
		}
	}

	for _, refused := range []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/*"],"Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["x"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/*"],"Condition":{"StringEquals":{"aws:RequestTag/x":["y"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3tables:GetTable"],"Resource":["arn:aws:s3tables:::bucket/*"],"Condition":{"StringEquals":{"aws:ResourceTag/x":["y"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListAllMyBuckets"],"Resource":["arn:aws:s3:::*"],"Condition":{"StringEquals":{"aws:ResourceTag/x":["y"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:CreateBucket"],"Resource":["arn:aws:s3:::bucket"],"Condition":{"StringEquals":{"s3:BucketTag/x":["y"]}}}]}`,
	} {
		if _, err := ParseConfig(strings.NewReader(refused)); err == nil {
			t.Errorf("must be refused: %s", refused)
		}
	}
}
