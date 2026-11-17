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

package catalog_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/minio/pkg/v3/policy"
	"github.com/minio/pkg/v3/policy/catalog"
)

func supportedActions() map[string]bool {
	all := map[string]bool{}
	add := func(name string) {
		if !strings.HasSuffix(name, ":*") {
			all[name] = true
		}
	}
	for a := range policy.SupportedActions {
		add(string(a))
	}
	for a := range policy.SupportedAdminActions {
		add(string(a))
	}
	for a := range policy.SupportedTableActions {
		add(string(a))
	}
	for a := range policy.SupportedVectorsActions {
		add(string(a))
	}
	for a := range policy.SupportedMemoryActions {
		add(string(a))
	}
	for a := range policy.SupportedFilesActions {
		add(string(a))
	}
	return all
}

// TestCatalogMatchesPolicy checks that the catalog names exactly the actions a
// policy may name. The policy package does not export the KMS and STS sets, so
// those actions are checked one way, through IsValid.
func TestCatalogMatchesPolicy(t *testing.T) {
	want := supportedActions()
	got := map[string]bool{}
	categories := map[catalog.Category]bool{}
	for _, c := range catalog.Get().Categories {
		if c.Title == "" {
			t.Errorf("category %s has no title", c.ID)
		}
		if categories[c.ID] {
			t.Errorf("category %s is listed twice", c.ID)
		}
		categories[c.ID] = true
	}
	for _, ns := range catalog.Get().Namespaces {
		if ns.Title == "" {
			t.Errorf("%s has no title", ns.Prefix)
		}
		for _, a := range ns.Actions {
			if !strings.HasPrefix(a.Name, ns.Prefix+":") {
				t.Errorf("%s is listed under %s", a.Name, ns.Prefix)
			}
			if !categories[a.Category] {
				t.Errorf("%s has category %q", a.Name, a.Category)
			}
			for _, n := range append([]string{a.Name}, a.Aliases...) {
				if got[n] {
					t.Errorf("%s is listed twice", n)
				}
				got[n] = true
			}
		}
	}
	for n := range want {
		if !got[n] {
			t.Errorf("%s is supported but missing from the catalog", n)
		}
	}
	for n := range got {
		if want[n] {
			continue
		}
		if p, _, _ := strings.Cut(n, ":"); p == "kms" || p == "sts" {
			if !policy.KMSAction(n).IsValid() && !policy.STSAction(n).IsValid() {
				t.Errorf("%s is in the catalog but not supported", n)
			}
			continue
		}
		t.Errorf("%s is in the catalog but not supported", n)
	}
}

func TestCatalogJSON(t *testing.T) {
	b, err := catalog.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var c catalog.Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.Version == "" || len(c.Namespaces) != len(catalog.Get().Namespaces) {
		t.Fatalf("decoded catalog differs: version %q, %d namespaces", c.Version, len(c.Namespaces))
	}
}

// TestCatalogConditionKeys checks that validation accepts every condition key
// the catalog lists for an action.
func TestCatalogConditionKeys(t *testing.T) {
	resources := map[string]string{
		"s3":        "arn:aws:s3:::bucket/*",
		"s3tables":  "arn:aws:s3tables:::bucket/warehouse/table/*",
		"s3vectors": "*",
		"memory":    "*",
		"s3express": "*",
	}
	for _, ns := range catalog.Get().Namespaces {
		for _, a := range ns.Actions {
			keys := append(append([]string{}, ns.ConditionKeys...), a.ConditionKeys...)
			for _, k := range keys {
				if strings.HasSuffix(k, "/") {
					k += "tag"
				}
				stmt := `{"Effect":"Allow","Action":["` + a.Name + `"]`
				if r, ok := resources[ns.Prefix]; ok {
					stmt += `,"Resource":["` + r + `"]`
				}
				stmt += `,"Condition":{"Null":{"` + k + `":["false"]}}}`
				doc := `{"Version":"2012-10-17","Statement":[` + stmt + `]}`
				p, err := policy.ParseConfig(strings.NewReader(doc))
				if err == nil {
					err = p.ValidateStrict()
				}
				if err != nil {
					t.Errorf("%s with %s: %v", a.Name, k, err)
				}
			}
		}
	}
}
