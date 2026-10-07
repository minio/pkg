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

// TestS3TablesRequestTagConditions verifies that aws:TagKeys and
// aws:RequestTag/<key> condition table and warehouse tag writes on the tags in
// the request, and that they are refused on actions that carry no request tags.
func TestS3TablesRequestTagConditions(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::bucket/*"]},
  {"Effect":"Deny","Action":["s3tables:TagTable","s3tables:UntagTable","s3tables:TagWarehouse","s3tables:UntagWarehouse","s3tables:CreateTable"],
   "Resource":["arn:aws:s3tables:::bucket/*"],
   "Condition":{"ForAnyValue:StringLike":{"aws:TagKeys":["orb.governance.*"]}}},
  {"Effect":"Deny","Action":["s3tables:TagTable"],"Resource":["arn:aws:s3tables:::bucket/*"],
   "Condition":{"StringEquals":{"aws:RequestTag/tier":["restricted"]}}}
]}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckVariables(); err != nil {
		t.Fatal(err)
	}

	args := func(action TableAction, tags map[string]string, keys ...string) Args {
		values := map[string][]string{}
		for k, v := range tags {
			keys = append(keys, k)
			values[condition.NewKey(condition.AWSRequestTag, k).Name()] = []string{v}
		}
		if len(keys) > 0 {
			values[condition.AWSTagKeys.Name()] = keys
		}
		return Args{AccountName: "user", Action: Action(action), BucketName: "bucket", ObjectName: "wh/table/id", ConditionValues: values}
	}

	for _, tc := range []struct {
		name string
		args Args
		want bool
	}{
		{"tag a free key", args(S3TablesTagTableAction, map[string]string{"team": "analytics"}), true},
		{"tag a governed key", args(S3TablesTagTableAction, map[string]string{"team": "analytics", "orb.governance.owner": "x"}), false},
		{"untag a free key", args(S3TablesUntagTableAction, nil, "team"), true},
		{"untag a governed key", args(S3TablesUntagTableAction, nil, "orb.governance.owner"), false},
		{"tag a warehouse with a governed key", args(S3TablesTagWarehouseAction, map[string]string{"orb.governance.owner": "x"}), false},
		{"untag a governed warehouse key", args(S3TablesUntagWarehouseAction, nil, "orb.governance.owner"), false},
		{"create a table with a governed key", args(S3TablesCreateTableAction, map[string]string{"orb.governance.owner": "x"}), false},
		{"create a table without tags", args(S3TablesCreateTableAction, nil), true},
		{"tag a denied value", args(S3TablesTagTableAction, map[string]string{"tier": "restricted"}), false},
		{"tag an allowed value", args(S3TablesTagTableAction, map[string]string{"tier": "public"}), true},
	} {
		if got := p.IsAllowed(tc.args); got != tc.want {
			t.Errorf("%s: IsAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}

	for _, refused := range []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3tables:GetTable"],"Resource":["arn:aws:s3tables:::bucket/*"],"Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["x"]}}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3tables:UntagTable"],"Resource":["arn:aws:s3tables:::bucket/*"],"Condition":{"StringEquals":{"aws:RequestTag/x":["y"]}}}]}`,
	} {
		if _, err := ParseConfig(strings.NewReader(refused)); err == nil {
			t.Errorf("a request tag key on an action that carries no request tags must be refused: %s", refused)
		}
	}
}
