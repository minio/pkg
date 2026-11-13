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
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/actions.golden")

// goldenExtraProbes are action strings no supported set lists: declared but
// unsupported actions, patterns, and strings outside every namespace.
var goldenExtraProbes = []string{
	"",
	"*",
	"a*",
	"bogus:Action",
	"admin:KMSEnable",
	"admin:KMSBackup",
	"admin:KMSRestore",
	"admin:KMSKeyRotate",
	"admin:*",
	"admin:Get*",
	"admin:KMS*",
	"admin:?ealth",
	"s3:*",
	"s3:Get*",
	"s3:*Object*",
	"s3:Put?bject",
	"s3express:*",
	"s3tables:*",
	"s3tables:Get*",
	"s3tables:*Warehouse*",
	"s3tables:*TableBucket*",
	"sts:*",
	"sts:Assume*",
	"kms:*",
	"kms:Create*",
	"memory:*",
	"memory:List*",
	"s3files:*",
	"s3files:Get*",
	"s3vectors:*",
	"s3vectors:Get*",
}

func goldenSorted[T ~string](m map[T]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

func goldenActions() (supported, probes []string) {
	all := map[string]struct{}{}
	for _, names := range [][]string{
		goldenSorted(SupportedActions),
		goldenSorted(SupportedAdminActions),
		goldenSorted(supportedSTSActions),
		goldenSorted(supportedKMSActions),
		goldenSorted(SupportedTableActions),
		goldenSorted(SupportedVectorsActions),
		goldenSorted(SupportedMemoryActions),
		goldenSorted(SupportedFilesActions),
	} {
		for _, n := range names {
			all[n] = struct{}{}
		}
	}
	supported = goldenSorted(all)
	for _, p := range goldenExtraProbes {
		all[p] = struct{}{}
	}
	return supported, goldenSorted(all)
}

// goldenKeys prints a key set as the keys outside CommonKeys, with a marker for
// whether every common key is present, so each line stays short.
func goldenKeys(set condition.KeySet) string {
	if set == nil {
		return "<nil>"
	}
	common := 0
	var extra []string
	for k := range set {
		if condition.CommonKeysMap[condition.KeyName(k.String())] {
			common++
			continue
		}
		extra = append(extra, k.String())
	}
	sort.Strings(extra)
	marker := "common=none"
	switch {
	case common == len(condition.CommonKeys):
		marker = "common=all"
	case common > 0:
		marker = fmt.Sprintf("common=%d", common)
	}
	return marker + " " + strings.Join(extra, ",")
}

func goldenKeyMap(w *bytes.Buffer, name string, m map[Action]condition.KeySet) {
	fmt.Fprintf(w, "\n## %s\n", name)
	keys := make([]string, 0, len(m))
	for a := range m {
		keys = append(keys, string(a))
	}
	sort.Strings(keys)
	for _, a := range keys {
		fmt.Fprintf(w, "%s: %s\n", a, goldenKeys(m[Action(a)]))
	}
}

func goldenKeyNames(w *bytes.Buffer, name string, keys []condition.KeyName) {
	fmt.Fprintf(w, "%s:", name)
	for _, k := range keys {
		fmt.Fprintf(w, " %s", k)
	}
	fmt.Fprintln(w)
}

func goldenValidate(action, resource, cond string) string {
	stmt := `{"Effect":"Allow","Action":["` + action + `"]`
	if resource != "" {
		stmt += `,"Resource":["` + resource + `"]`
	}
	if cond != "" {
		stmt += `,"Condition":` + cond
	}
	doc := `{"Version":"2012-10-17","Statement":[` + stmt + `}]}`
	p, err := ParseConfig(strings.NewReader(doc))
	if err != nil {
		return "load: " + err.Error()
	}
	if err := p.ValidateStrict(); err != nil {
		return "strict: " + err.Error()
	}
	return "ok"
}

func renderActionsGolden() []byte {
	var w bytes.Buffer
	supported, probes := goldenActions()

	fmt.Fprintln(&w, "# Supported sets")
	for _, s := range []struct {
		name  string
		names []string
	}{
		{"SupportedActions", goldenSorted(SupportedActions)},
		{"SupportedObjectActions", goldenSorted(SupportedObjectActions)},
		{"SupportedAdminActions", goldenSorted(SupportedAdminActions)},
		{"AdminActionsWithResource", goldenSorted(AdminActionsWithResource)},
		{"supportedSTSActions", goldenSorted(supportedSTSActions)},
		{"supportedKMSActions", goldenSorted(supportedKMSActions)},
		{"SupportedTableActions", goldenSorted(SupportedTableActions)},
		{"SupportedVectorsActions", goldenSorted(SupportedVectorsActions)},
		{"SupportedMemoryActions", goldenSorted(SupportedMemoryActions)},
		{"SupportedFilesActions", goldenSorted(SupportedFilesActions)},
	} {
		fmt.Fprintf(&w, "\n## %s (%d)\n%s\n", s.name, len(s.names), strings.Join(s.names, "\n"))
	}

	fmt.Fprintln(&w, "\n# Condition keys")
	goldenKeyMap(&w, "adminActionConditionKeyMap", adminActionConditionKeyMap)
	goldenKeyMap(&w, "stsActionConditionKeyMap", stsActionConditionKeyMap)
	goldenKeyMap(&w, "tableActionConditionKeyMap", tableActionConditionKeyMap)
	goldenKeyMap(&w, "VectorsActionConditionKeyMap", VectorsActionConditionKeyMap)
	goldenKeyMap(&w, "MemoryActionConditionKeyMap", MemoryActionConditionKeyMap)
	goldenKeyMap(&w, "FilesActionConditionKeyMap", FilesActionConditionKeyMap)
	fmt.Fprintln(&w, "\n## IAMActionConditionKeyMap.Lookup")
	for _, p := range probes {
		fmt.Fprintf(&w, "%s: %s\n", p, goldenKeys(IAMActionConditionKeyMap.Lookup(Action(p))))
	}

	fmt.Fprintln(&w, "\n# Key names")
	goldenKeyNames(&w, "AllSupportedKeys", condition.AllSupportedKeys)
	goldenKeyNames(&w, "CommonKeys", condition.CommonKeys)
	goldenKeyNames(&w, "CommonAdminKeys", condition.CommonAdminKeys)
	goldenKeyNames(&w, "AdminActionKeys", condition.AdminActionKeys)
	goldenKeyNames(&w, "AllSupportedAdminKeys", condition.AllSupportedAdminKeys)
	goldenKeyNames(&w, "AllSupportedSTSKeys", condition.AllSupportedSTSKeys)
	goldenKeyNames(&w, "JWTKeys", condition.JWTKeys)
	seen := map[condition.KeyName]bool{}
	var allKeys []string
	for _, group := range [][]condition.KeyName{condition.AllSupportedKeys, condition.CommonKeys, condition.AllSupportedSTSKeys, condition.AllSupportedAdminKeys} {
		for _, k := range group {
			if !seen[k] {
				seen[k] = true
				allKeys = append(allKeys, string(k))
			}
		}
	}
	sort.Strings(allKeys)
	for _, k := range allKeys {
		kn := condition.KeyName(k)
		fmt.Fprintf(&w, "%s: name=%s variable=%v admin=%v\n", k, kn.Name(), kn.TakesVariable(), kn.IsAdmin())
	}

	fmt.Fprintln(&w, "\n# Classification")
	for _, p := range probes {
		fmt.Fprintf(&w, "%q: s3=%v obj=%v admin=%v adminres=%v sts=%v kms=%v table=%v vectors=%v memory=%v files=%v\n",
			p, Action(p).IsValid(), Action(p).IsObjectAction(),
			AdminAction(p).IsValid(), AdminAction(p).HasResource(),
			STSAction(p).IsValid(), KMSAction(p).IsValid(), TableAction(p).IsValid(),
			VectorsAction(p).IsValid(), MemoryAction(p).IsValid(), FilesAction(p).IsValid())
	}

	fmt.Fprintln(&w, "\n# ActionSet matches beyond the pattern itself")
	targets := append([]string{}, supported...)
	targets = append(targets, "admin:KMSEnable", "admin:KMSBackup", "admin:KMSRestore", "admin:KMSKeyRotate")
	for _, p := range probes {
		set := NewActionSet(Action(p))
		var matched, named []string
		for _, a := range targets {
			if a == p {
				continue
			}
			if set.Match(Action(a)) {
				matched = append(matched, a)
			}
			if set.matchesNamed(Action(a)) {
				named = append(named, a)
			}
		}
		if len(matched) > 0 || len(named) > 0 {
			fmt.Fprintf(&w, "%q: match=[%s] named=[%s]\n", p, strings.Join(matched, " "), strings.Join(named, " "))
		}
	}

	fmt.Fprintln(&w, "\n# Validation")
	ip := `{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}`
	for _, p := range probes {
		fmt.Fprintf(&w, "%q: none=%s | s3=%s | s3+ip=%s\n", p,
			goldenValidate(p, "", ""),
			goldenValidate(p, "arn:aws:s3:::bucket/*", ""),
			goldenValidate(p, "arn:aws:s3:::bucket/*", ip))
	}
	return w.Bytes()
}

// TestActionsGolden pins the observable behavior of every policy action: the
// supported sets, condition keys, classification, matching and validation.
// Rewrite the golden file with -update-golden and review the diff.
func TestActionsGolden(t *testing.T) {
	const path = "testdata/actions.golden"
	got := renderActionsGolden()
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update-golden to create it)", err)
	}
	if !bytes.Equal(got, want) {
		gotLines := strings.Split(string(got), "\n")
		wantLines := strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
			var g, wl string
			if i < len(gotLines) {
				g = gotLines[i]
			}
			if i < len(wantLines) {
				wl = wantLines[i]
			}
			if g != wl {
				t.Fatalf("golden mismatch at line %d:\n got: %s\nwant: %s\n(run with -update-golden and review the diff)", i+1, g, wl)
			}
		}
	}
}
