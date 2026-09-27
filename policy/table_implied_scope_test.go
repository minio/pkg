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

// TestS3TablesImpliedActionsReachTableDataOnly verifies the S3 data actions a
// tables grant implies reach only the table resource the server presents for a
// warehouse object, never an object in an ordinary bucket, while a tables Deny
// still refuses the files of the tables it names.
func TestS3TablesImpliedActionsReachTableDataOnly(t *testing.T) {
	doc := func(statements ...string) string {
		return `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
	}
	plain := func(action Action, bucket, object string) Args {
		return Args{Action: action, BucketName: bucket, ObjectName: object}
	}
	table := func(action Action, warehouse, id string) Args {
		return Args{Action: action, BucketName: "bucket", ObjectName: warehouse + "/table/" + id}
	}

	everyWarehouse := doc(`{"Effect":"Allow","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::bucket/*"]}`)
	wildcard := doc(`{"Effect":"Allow","Action":["s3tables:GetTableData","s3tables:PutTableData"],"Resource":["arn:aws:s3tables:::*"]}`)
	oneWarehouse := doc(`{"Effect":"Allow","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`)
	deniedTable := doc(
		`{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::wh/*"]}`,
		`{"Effect":"Deny","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/wh/*"]}`,
	)

	for _, tc := range []struct {
		name   string
		policy string
		args   Args
		want   bool
	}{
		{"every warehouse: GetObject in an ordinary bucket", everyWarehouse, plain(GetObjectAction, "data", "x/y"), false},
		{"every warehouse: PutObject in an ordinary bucket", everyWarehouse, plain(PutObjectAction, "data", "x/y"), false},
		{"every warehouse: DeleteObject in an ordinary bucket", everyWarehouse, plain(DeleteObjectAction, "data", "x/y"), false},
		{"every warehouse: multipart in an ordinary bucket", everyWarehouse, plain(AbortMultipartUploadAction, "data", "x/y"), false},
		{"every warehouse: table data", everyWarehouse, table(PutObjectAction, "wh", "abc"), true},
		{"wildcard resource: GetObject in an ordinary bucket", wildcard, plain(GetObjectAction, "data", "x/y"), false},
		{"wildcard resource: PutObject in an ordinary bucket", wildcard, plain(PutObjectAction, "data", "x/y"), false},
		{"wildcard resource: table data", wildcard, table(GetObjectAction, "wh", "abc"), true},
		{"one warehouse: an object presented without its table", oneWarehouse, plain(GetObjectAction, "wh", "abc/data/f.parquet"), false},
		{"one warehouse: table data", oneWarehouse, table(GetObjectAction, "wh", "abc"), true},
		{"one warehouse: another warehouse's table", oneWarehouse, table(GetObjectAction, "other", "abc"), false},
		{"denied table: its file is refused over plain S3", deniedTable, plain(GetObjectAction, "wh", "abc/data/f.parquet"), false},
		{"denied table: its file is refused in tables form", deniedTable, table(GetObjectAction, "wh", "abc"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseConfig(strings.NewReader(tc.policy))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := p.IsAllowed(tc.args); got != tc.want {
				t.Fatalf("IsAllowed(%+v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}

	// A statement stored before mixing action types was refused keeps the S3
	// actions it names; only the ones it implies are confined to table data.
	t.Run("a legacy mixed statement keeps its named S3 actions", func(t *testing.T) {
		st := NewStatement("", Allow,
			NewActionSet(GetObjectAction, Action(S3TablesGetTableDataAction)),
			NewResourceSet(NewResource("data/*")),
			condition.NewFunctions())
		if !st.IsAllowed(plain(GetObjectAction, "data", "x")) {
			t.Fatal("a named s3:GetObject must still match its bucket")
		}
		if st.IsAllowed(plain(ListMultipartUploadPartsAction, "data", "x")) {
			t.Fatal("an action only GetTableData implies must not reach an ordinary bucket")
		}
	})
}
