// Copyright (c) 2015-2024 MinIO, Inc.
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
	"slices"
	"strings"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

func TestConditionValues(t *testing.T) {
	const (
		resource = "bucket/wh1"
		action   = Action("s3tables:ListTables")
	)
	nsKey := condition.NewKey(condition.S3TablesNamespace, "")

	tests := []struct {
		name        string
		policy      string
		wantAllow   []string
		wantDeny    []string
		wantAllAll  bool
		wantDenyAll bool
	}{
		{
			name: "StringEquals values are permitted",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns1","ns2.ns3","n4"]}}}]}`,
			wantAllow: []string{"n4", "ns1", "ns2.ns3"},
		},
		{
			// Empty Resources matches every resource, the polarity IsAllowed uses.
			name: "a NotResource-only statement still contributes its values",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],
				 "NotResource":["arn:aws:s3tables:::bucket/private/*"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["sales"]}}}]}`,
			wantAllow: []string{"sales"},
		},
		{
			// ForAllValues holds when the request carries no value for the key, so
			// the listed values do not bound what the grant reaches.
			name: "a set qualifier is unconstrained",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"ForAllValues:StringEquals":{"s3tables:namespace":["ns1"]}}}]}`,
			wantAllAll: true,
		},
		{
			name: "an uninterpreted operator is unconstrained",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringEqualsIgnoreCase":{"s3tables:namespace":["ns1"]}}}]}`,
			wantAllAll: true,
		},
		{
			name: "no condition on the key is unconstrained",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"]}]}`,
			wantAllAll: true,
		},
		{
			name: "deny values are reported separately",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns1","ns2","ns3"]}}},
				{"Effect":"Deny","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns2"]}}}]}`,
			wantAllow: []string{"ns1", "ns2", "ns3"},
			wantDeny:  []string{"ns2"},
		},
		{
			name: "unconditional deny reports denyAll",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns1"]}}},
				{"Effect":"Deny","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"]}]}`,
			wantAllow:   []string{"ns1"},
			wantDenyAll: true,
		},
		{
			name: "another resource does not contribute",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh2"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns9"]}}}]}`,
		},
		{
			name: "another action does not contribute",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:DeleteTable"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns9"]}}}]}`,
		},
		{
			name: "StringLike values are permitted",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringLike":{"s3tables:namespace":["ns1.*"]}}}]}`,
			wantAllow: []string{"ns1.*"},
		},
		{
			// An uninterpretable condition form must not narrow the caller's view.
			name: "StringNotEquals is reported as allowAll",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"],
				 "Condition":{"StringNotEquals":{"s3tables:namespace":["ns9"]}}}]}`,
			wantAllAll: true,
		},
		{
			name: "wildcard resource contributes",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/*"],
				 "Condition":{"StringEquals":{"s3tables:namespace":["ns1"]}}}]}`,
			wantAllow: []string{"ns1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := ParseConfig(strings.NewReader(test.policy))
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}

			values := p.ConditionValues(resource, []Action{action}, nsKey)[action]
			var allow, deny []string
			var allowAll, denyAll bool
			if values != nil {
				allow, deny = values.Allow.ToSlice(), values.Deny.ToSlice()
				allowAll, denyAll = values.AllowAll, values.DenyAll
			}
			if allowAll != test.wantAllAll {
				t.Fatalf("allowAll = %v, want %v", allowAll, test.wantAllAll)
			}
			if denyAll != test.wantDenyAll {
				t.Fatalf("denyAll = %v, want %v", denyAll, test.wantDenyAll)
			}
			slices.Sort(allow)
			slices.Sort(deny)
			if !slices.Equal(allow, test.wantAllow) {
				t.Fatalf("allow = %v, want %v", allow, test.wantAllow)
			}
			if !slices.Equal(deny, test.wantDeny) {
				t.Fatalf("deny = %v, want %v", deny, test.wantDeny)
			}
		})
	}
}

func TestTableResourcePatterns(t *testing.T) {
	listTables := Action("s3tables:ListTables")
	deleteNamespace := Action("s3tables:DeleteNamespace")
	actions := []Action{listTables, deleteNamespace}

	tests := []struct {
		name       string
		policy     string
		wantAllow  map[Action][]string
		wantDeny   map[Action][]string
		wantNoData bool
	}{
		{
			name: "a literal warehouse is named for the granted action only",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/wh1"]}]}`,
			wantAllow: map[Action][]string{listTables: {"bucket/wh1"}},
		},
		{
			name: "a wildcard action credits every requested action",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::bucket/wh1"]}]}`,
			wantAllow: map[Action][]string{
				listTables:      {"bucket/wh1"},
				deleteNamespace: {"bucket/wh1"},
			},
		},
		{
			name: "a deny on one action leaves the other action's grant intact",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::bucket/wh1"]},
				{"Effect":"Deny","Action":["s3tables:DeleteNamespace"],"Resource":["arn:aws:s3tables:::bucket/wh1"]}]}`,
			wantAllow: map[Action][]string{
				listTables:      {"bucket/wh1"},
				deleteNamespace: {"bucket/wh1"},
			},
			wantDeny: map[Action][]string{deleteNamespace: {"bucket/wh1"}},
		},
		{
			name: "a wildcard warehouse is reported verbatim",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],"Resource":["arn:aws:s3tables:::bucket/*"]}]}`,
			wantAllow: map[Action][]string{listTables: {"bucket/*"}},
		},
		{
			// The statement reaches every warehouse but one, so it must name them
			// all rather than none; naming none would hide a permitted warehouse.
			name: "a NotResource-only statement names every resource",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:ListTables"],
				 "NotResource":["arn:aws:s3tables:::bucket/private/*"]}]}`,
			wantAllow: map[Action][]string{listTables: {"*"}},
		},
		{
			name: "a plain S3 resource names no table pattern",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::mybucket/*"]}]}`,
			wantNoData: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := ParseConfig(strings.NewReader(test.policy))
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			got := parsed.TableResourcePatterns(actions)
			if test.wantNoData {
				if len(got) != 0 {
					t.Fatalf("expected no patterns, got %v", got)
				}
				return
			}
			for action, want := range test.wantAllow {
				entry := got[action]
				if entry == nil {
					t.Fatalf("%s: no entry", action)
				}
				allow := entry.Allow.ToSlice()
				slices.Sort(allow)
				slices.Sort(want)
				if !slices.Equal(allow, want) {
					t.Errorf("%s allow = %v, want %v", action, allow, want)
				}
			}
			for action, entry := range got {
				deny := entry.Deny.ToSlice()
				slices.Sort(deny)
				want := test.wantDeny[action]
				slices.Sort(want)
				if len(deny) == 0 && len(want) == 0 {
					continue
				}
				if !slices.Equal(deny, want) {
					t.Errorf("%s deny = %v, want %v", action, deny, want)
				}
			}
		})
	}
}
