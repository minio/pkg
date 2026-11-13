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

const (
	rpWarehouse = "wh"
	rpTable     = "0d6f5a9e-3c1b-4a8e-9f00-1b2c3d4e5f60"
)

var (
	rpWarehouseTarget = ResourcePolicyTarget{Warehouse: rpWarehouse}
	rpTableTarget     = ResourcePolicyTarget{Warehouse: rpWarehouse, Table: rpTable}
)

func rpDoc(statements ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
}

func TestTableActionScopeCoversEveryAction(t *testing.T) {
	for action := range SupportedTableActions {
		if action == AllS3TablesActions {
			if action.scope() != 0 {
				t.Errorf("%v: got scope %v, want none", action, action.scope())
			}
			continue
		}
		if action.scope() == 0 {
			t.Errorf("%v has no scope", action)
		}
	}
	for action := range tableActionScopes {
		if !action.IsValid() {
			t.Errorf("scope table names unsupported action %v", action)
		}
	}
}

func TestTableActionIsGlobal(t *testing.T) {
	for _, action := range []TableAction{
		S3TablesCreateWarehouseAction, S3TablesCreateTableBucketAction,
		S3TablesListWarehousesAction, S3TablesListTableBucketsAction, S3TablesTableMetricsAction,
	} {
		if !action.IsGlobal() {
			t.Errorf("%v must be global", action)
		}
	}
	for _, action := range []TableAction{
		S3TablesGetWarehouseAction, S3TablesCreateTableAction, S3TablesGetTableAction,
		AllS3TablesActions, TableAction(GetObjectAction),
	} {
		if action.IsGlobal() {
			t.Errorf("%v must not be global", action)
		}
	}
}

func TestTableActionScopeMatchesAliases(t *testing.T) {
	for warehouseAction, aliases := range implicitActions {
		w := TableAction(warehouseAction)
		if w.scope() == 0 {
			continue
		}
		for alias := range aliases {
			if !TableAction(alias).IsValid() {
				continue
			}
			if got := TableAction(alias).scope(); got != w.scope() {
				t.Errorf("%v has scope %v, its alias %v has %v", w, w.scope(), alias, got)
			}
		}
	}
}

func TestParseResourcePolicyForWrite(t *testing.T) {
	const (
		whARN    = `"arn:aws:s3tables:::bucket/wh"`
		tablesWh = `"arn:aws:s3tables:::bucket/wh/table/*"`
		tableARN = `"arn:aws:s3tables:::bucket/wh/table/` + rpTable + `"`
	)
	allow := func(principal, actions, resources string) string {
		return `{"Effect":"Allow","Principal":` + principal + `,"Action":[` + actions + `],"Resource":[` + resources + `]}`
	}

	for _, tc := range []struct {
		name    string
		doc     string
		target  ResourcePolicyTarget
		wantErr string
	}{
		{
			name:   "warehouse policy with warehouse and table actions",
			doc:    rpDoc(allow(`"*"`, `"s3tables:ListNamespaces","s3tables:GetTable"`, whARN+","+tablesWh)),
			target: rpWarehouseTarget,
		},
		{
			name:   "AWS wildcard principal",
			doc:    rpDoc(allow(`{"AWS":"*"}`, `"s3tables:GetTable"`, tablesWh)),
			target: rpWarehouseTarget,
		},
		{
			name:   "AWS wildcard principal list",
			doc:    rpDoc(allow(`{"AWS":["*"]}`, `"s3tables:GetTable"`, tablesWh)),
			target: rpWarehouseTarget,
		},
		{
			name:   "conditions narrow callers",
			doc:    rpDoc(`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable"],"Resource":[` + tablesWh + `],"Condition":{"StringEquals":{"aws:username":["alice"]}}}`),
			target: rpWarehouseTarget,
		},
		{
			name:   "view resource under the warehouse",
			doc:    rpDoc(allow(`"*"`, `"s3tables:GetView"`, `"arn:aws:s3tables:::bucket/wh/view/*"`)),
			target: rpWarehouseTarget,
		},
		{
			name:   "all tables actions",
			doc:    rpDoc(allow(`"*"`, `"s3tables:*"`, `"arn:aws:s3tables:::bucket/wh/*"`)),
			target: rpWarehouseTarget,
		},
		{
			name:   "table policy",
			doc:    rpDoc(allow(`"*"`, `"s3tables:GetTable","s3tables:GetTableData"`, tableARN)),
			target: rpTableTarget,
		},
		{
			name:   "table Deny",
			doc:    rpDoc(`{"Effect":"Deny","Principal":"*","Action":["s3tables:GetTableData"],"Resource":[` + tableARN + `]}`),
			target: rpTableTarget,
		},
		{
			name:    "named principal",
			doc:     rpDoc(allow(`{"AWS":["arn:aws:iam::123:user/alice"]}`, `"s3tables:GetTable"`, tablesWh)),
			target:  rpWarehouseTarget,
			wantErr: "unsupported Principal",
		},
		{
			name:    "missing principal",
			doc:     rpDoc(`{"Effect":"Allow","Action":["s3tables:GetTable"],"Resource":[` + tablesWh + `]}`),
			target:  rpWarehouseTarget,
			wantErr: "Principal must not be empty",
		},
		{
			name:    "NotPrincipal",
			doc:     rpDoc(`{"Effect":"Deny","NotPrincipal":"*","Action":["s3tables:GetTable"],"Resource":[` + tablesWh + `]}`),
			target:  rpWarehouseTarget,
			wantErr: "NotPrincipal",
		},
		{
			name:    "NotAction",
			doc:     rpDoc(`{"Effect":"Allow","Principal":"*","NotAction":["s3tables:GetTable"],"Resource":[` + tablesWh + `]}`),
			target:  rpWarehouseTarget,
			wantErr: "NotAction",
		},
		{
			name:    "NotResource",
			doc:     rpDoc(`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable"],"NotResource":[` + tablesWh + `]}`),
			target:  rpWarehouseTarget,
			wantErr: "NotResource",
		},
		{
			name:    "unknown field",
			doc:     rpDoc(`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable"],"Resource":[` + tablesWh + `],"Resources":["x"]}`),
			target:  rpWarehouseTarget,
			wantErr: "'Resources' is not supported",
		},
		{
			name:    "S3 action",
			doc:     rpDoc(allow(`"*"`, `"s3:GetObject"`, tablesWh)),
			target:  rpWarehouseTarget,
			wantErr: "s3tables actions only",
		},
		{
			name:    "global action",
			doc:     rpDoc(allow(`"*"`, `"s3tables:CreateWarehouse"`, whARN)),
			target:  rpWarehouseTarget,
			wantErr: "names no warehouse",
		},
		{
			name:    "warehouse action in a table policy",
			doc:     rpDoc(allow(`"*"`, `"s3tables:ListNamespaces"`, tableARN)),
			target:  rpTableTarget,
			wantErr: "cannot be granted by a table policy",
		},
		{
			name:    "another warehouse",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/other/table/*"`)),
			target:  rpWarehouseTarget,
			wantErr: "outside warehouse",
		},
		{
			name:    "warehouse name wildcard",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/wh*"`)),
			target:  rpWarehouseTarget,
			wantErr: "outside warehouse",
		},
		{
			name:    "warehouse name prefix",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, `"arn:aws:s3tables:::bucket/wh2/table/*"`)),
			target:  rpWarehouseTarget,
			wantErr: "outside warehouse",
		},
		{
			name:    "every resource",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, `"*"`)),
			target:  rpWarehouseTarget,
			wantErr: "not an S3 Tables ARN",
		},
		{
			name:    "S3 resource",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, `"arn:aws:s3:::wh/*"`)),
			target:  rpWarehouseTarget,
			wantErr: "not an S3 Tables ARN",
		},
		{
			name:    "table policy naming every table",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, tablesWh)),
			target:  rpTableTarget,
			wantErr: "must be this table's ARN",
		},
		{
			name:    "table policy naming its warehouse",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, whARN)),
			target:  rpTableTarget,
			wantErr: "must be this table's ARN",
		},
		{
			name:    "condition key the action does not take",
			doc:     rpDoc(`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable"],"Resource":[` + tablesWh + `],"Condition":{"StringEquals":{"s3tables:KMSKeyArn":["k"]}}}`),
			target:  rpWarehouseTarget,
			wantErr: "unsupported condition keys",
		},
		{
			name:    "no statements",
			doc:     rpDoc(),
			target:  rpWarehouseTarget,
			wantErr: "no statements",
		},
		{
			name:    "bad version",
			doc:     `{"Version":"2008-10-17","Statement":[` + allow(`"*"`, `"s3tables:GetTable"`, tablesWh) + `]}`,
			target:  rpWarehouseTarget,
			wantErr: "invalid version",
		},
		{
			name:    "no target",
			doc:     rpDoc(allow(`"*"`, `"s3tables:GetTable"`, tablesWh)),
			wantErr: "names no warehouse",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseResourcePolicyForWrite([]byte(tc.doc), tc.target)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got error %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseResourcePolicyLoadsWhatWriteRefuses(t *testing.T) {
	doc := rpDoc(`{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123:user/alice"]},"Action":["s3tables:GetTable"],"Resource":["arn:aws:s3tables:::bucket/other/table/*"]}`)
	if _, err := ParseResourcePolicyForWrite([]byte(doc), rpWarehouseTarget); err == nil {
		t.Fatal("write accepted a named principal")
	}
	if _, err := ParseResourcePolicy([]byte(doc)); err != nil {
		t.Fatalf("stored policy did not load: %v", err)
	}
	if _, err := ParseResourcePolicy([]byte(`{"Statement":[]} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func rpTableArgs(action Action, values map[string][]string) *Args {
	return &Args{Action: action, BucketName: "bucket", ObjectName: rpWarehouse + "/table/" + rpTable, ConditionValues: values}
}

func rpWarehouseArgs(action Action) *Args {
	return &Args{Action: action, BucketName: "bucket", ObjectName: rpWarehouse}
}

func mustParseResourcePolicy(t *testing.T, doc string) *ResourcePolicy {
	t.Helper()
	p, err := ParseResourcePolicy([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResourcePolicyDecide(t *testing.T) {
	alice := map[string][]string{"username": {"alice"}}
	bob := map[string][]string{"username": {"bob"}}

	grant := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:ListNamespaces"],"Resource":["arn:aws:s3tables:::bucket/wh"]}`,
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable","s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"],"Condition":{"StringEquals":{"aws:username":["alice"]}}}`,
	))
	denyData := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::bucket/wh/*"]}`,
		`{"Effect":"Deny","Principal":"*","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/wh/table/`+rpTable+`"]}`,
	))
	everything := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::bucket/wh","arn:aws:s3tables:::bucket/wh/*"]}`,
	))
	namedPrincipal := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":{"AWS":["alice"]},"Action":["s3tables:GetTable"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`,
		`{"Effect":"Deny","Principal":{"AWS":["bob"]},"Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`,
	))
	noAction := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`,
	))

	for _, tc := range []struct {
		name   string
		policy *ResourcePolicy
		args   *Args
		want   Decision
	}{
		{"warehouse action allowed", grant, rpWarehouseArgs(Action(S3TablesListNamespacesAction)), AllowDecision},
		{"condition matches", grant, rpTableArgs(Action(S3TablesGetTableAction), alice), AllowDecision},
		{"condition fails", grant, rpTableArgs(Action(S3TablesGetTableAction), bob), NoDecision},
		{"action not named", grant, rpTableArgs(Action(S3TablesDeleteTableAction), alice), NoDecision},
		{"Deny beats Allow", denyData, rpTableArgs(Action(S3TablesGetTableDataAction), nil), DenyDecision},
		{"Deny covers the table's files", denyData, rpTableArgs(GetObjectAction, nil), DenyDecision},
		{"other actions still allowed", denyData, rpTableArgs(Action(S3TablesGetTableAction), nil), AllowDecision},
		{"global action ignored", everything, rpWarehouseArgs(Action(S3TablesCreateWarehouseAction)), NoDecision},
		{"global alias ignored", everything, rpWarehouseArgs(Action(S3TablesCreateTableBucketAction)), NoDecision},
		{"warehouse action under s3tables:*", everything, rpWarehouseArgs(Action(S3TablesGetWarehouseAction)), AllowDecision},
		{
			"create table on a table without UUID", everything,
			&Args{Action: Action(S3TablesCreateTableAction), BucketName: "bucket", ObjectName: rpWarehouse + "/table/"},
			AllowDecision,
		},
		{
			"another warehouse", everything,
			&Args{Action: Action(S3TablesGetTableAction), BucketName: "bucket", ObjectName: "other/table/" + rpTable},
			NoDecision,
		},
		{"named principal Allow grants nothing", namedPrincipal, rpTableArgs(Action(S3TablesGetTableAction), alice), NoDecision},
		{"named principal Deny applies to everyone", namedPrincipal, rpTableArgs(Action(S3TablesGetTableDataAction), alice), DenyDecision},
		{"Allow without Action grants nothing", noAction, rpTableArgs(Action(S3TablesGetTableAction), nil), NoDecision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Decide(tc.args); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResourcePolicyDecideIgnoresOwnerAndDenyOnly(t *testing.T) {
	p := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`,
	))
	args := rpTableArgs(Action(S3TablesDeleteTableAction), nil)
	args.IsOwner = true
	if got := p.Decide(args); got != NoDecision {
		t.Fatalf("owner: got %v, want NoDecision", got)
	}
	args.IsOwner = false
	args.DenyOnly = true
	if got := p.Decide(args); got != NoDecision {
		t.Fatalf("DenyOnly: got %v, want NoDecision", got)
	}
}

func TestResourcePolicyHasCapability(t *testing.T) {
	p := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable","s3tables:GetTableData","s3tables:DeleteTable"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`,
		`{"Effect":"Deny","Principal":"*","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"],"Condition":{"Bool":{"aws:SecureTransport":["false"]}}}`,
		`{"Effect":"Deny","Principal":"*","Action":["s3tables:DeleteTable"],"Resource":["arn:aws:s3tables:::bucket/wh/table/*"]}`,
	))
	insecure := map[string][]string{"SecureTransport": {"false"}}
	if got := p.Decide(rpTableArgs(Action(S3TablesGetTableDataAction), insecure)); got != DenyDecision {
		t.Fatalf("Decide: got %v, want DenyDecision", got)
	}
	if got := p.HasCapability(rpTableArgs(Action(S3TablesGetTableDataAction), insecure)); got != AllowDecision {
		t.Fatalf("conditional Deny: got %v, want AllowDecision", got)
	}
	if got := p.HasCapability(rpTableArgs(Action(S3TablesDeleteTableAction), nil)); got != DenyDecision {
		t.Fatalf("unconditional Deny: got %v, want DenyDecision", got)
	}
	if got := p.HasCapability(rpTableArgs(Action(S3TablesUpdateTableAction), nil)); got != NoDecision {
		t.Fatalf("unnamed action: got %v, want NoDecision", got)
	}
}

func TestResourcePolicyAllowedActions(t *testing.T) {
	p := mustParseResourcePolicy(t, rpDoc(
		`{"Effect":"Allow","Principal":"*","Action":["s3tables:GetTable","s3tables:ListNamespaces"],"Resource":["arn:aws:s3tables:::bucket/wh/*"]}`,
		`{"Effect":"Deny","Principal":"*","Action":["s3tables:DeleteTable"],"Resource":["arn:aws:s3tables:::bucket/wh/*"]}`,
		`{"Effect":"Allow","Principal":{"AWS":["alice"]},"Action":["s3tables:UpdateTable"],"Resource":["arn:aws:s3tables:::bucket/wh/*"]}`,
	))
	got := p.AllowedActions()
	want := NewActionSet(Action(S3TablesGetTableAction), Action(S3TablesListNamespacesAction))
	if !got.Equals(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
