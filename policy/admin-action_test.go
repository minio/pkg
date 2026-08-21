// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
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

// isValidScan is the linear scan AdminAction.IsValid replaced. The fast path
// must agree with it on every input, so it stays here as the reference.
func isValidScan(action AdminAction) bool {
	for supAction := range SupportedAdminActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

func hasResourceScan(action AdminAction) bool {
	for a := range AdminActionsWithResource {
		if action.Match(a) {
			return true
		}
	}
	return false
}

// TestAdminActionNamespacePrefix pins the invariant AdminAction.IsValid's fast
// path rests on: an action that cannot start with "admin:" cannot be an admin
// action. SupportedActions has already lost the analogous s3: invariant to
// s3express:CreateSession, so this is not hypothetical.
func TestAdminActionNamespacePrefix(t *testing.T) {
	for action := range SupportedAdminActions {
		if !strings.HasPrefix(string(action), adminActionPrefix) {
			t.Errorf("SupportedAdminActions contains %q, which lacks the %q prefix that IsValid's fast path assumes", action, adminActionPrefix)
		}
	}
	for action := range AdminActionsWithResource {
		if !strings.HasPrefix(string(action), adminActionPrefix) {
			t.Errorf("AdminActionsWithResource contains %q, which lacks the %q prefix", action, adminActionPrefix)
		}
	}
}

func TestAdminActionIsValid(t *testing.T) {
	tests := []struct {
		action AdminAction
		want   bool
	}{
		{"admin:Heal", true},
		{"admin:*", true},
		{"*", true},
		{"**", true},
		{"*:*", true},
		{"adm*", true},
		{"ad?in:Heal", true},
		{"a*d*m*i*n*", true}, // a plain HasPrefix on the literal head gets this wrong
		{"admin:Hea*", true},
		{"?dmin:Heal", true},
		{"", false},
		{"?", false},
		{"admin", false},
		{"admin:", false},
		{"admin:NotAThing", false},
		{"admin:heal", false},
		{"Admin:*", false},
		{"adminx*", false},
		{"s3:*", false},
		{"s3:GetObject", false},
		{"s3tables:*", false},
		{"sts:*", false},
		{"kms:*", false},
		{"s3vectors:*", false},
		{"memory:*", false},
	}
	for _, tt := range tests {
		if got := tt.action.IsValid(); got != tt.want {
			t.Errorf("AdminAction(%q).IsValid() = %v, want %v", tt.action, got, tt.want)
		}
		if want := isValidScan(tt.action); tt.want != want {
			t.Errorf("test table disagrees with the reference scan for %q: table %v, scan %v", tt.action, tt.want, want)
		}
	}
}

func TestAdminActionHasResourceFastPath(t *testing.T) {
	tests := []struct {
		action AdminAction
		want   bool
	}{
		{"admin:SetBucketQuota", true},
		{"admin:Heal", true},
		{"admin:*", true}, // a key of SupportedAdminActions but not of AdminActionsWithResource
		{"*", true},
		{"admin:SetBucket*", true},
		{"admin:ServerInfo", false},
		{"admin:CreateUser", false},
		{"", false},
		{"s3:*", false},
	}
	for _, tt := range tests {
		if got := tt.action.HasResource(); got != tt.want {
			t.Errorf("AdminAction(%q).HasResource() = %v, want %v", tt.action, got, tt.want)
		}
		if want := hasResourceScan(tt.action); tt.want != want {
			t.Errorf("test table disagrees with the reference scan for %q: table %v, scan %v", tt.action, tt.want, want)
		}
	}
}

// TestAdminActionIsValidEquivalence checks the fast path against the reference
// scan over every action the package knows plus adversarial patterns.
func TestAdminActionIsValidEquivalence(t *testing.T) {
	var pats []string
	add := func(s string) { pats = append(pats, s) }
	for k := range SupportedAdminActions {
		add(string(k))
	}
	for k := range SupportedActions {
		add(string(k))
	}
	for k := range SupportedTableActions {
		add(string(k))
	}
	for k := range SupportedVectorsActions {
		add(string(k))
	}
	for k := range SupportedMemoryActions {
		add(string(k))
	}
	for k := range supportedKMSActions {
		add(string(k))
	}
	for k := range supportedSTSActions {
		add(string(k))
	}
	// Every prefix of "admin:Heal", with and without a trailing metacharacter.
	const sample = "admin:Heal"
	for i := range len(sample) + 1 {
		add(sample[:i])
		add(sample[:i] + "*")
		add(sample[:i] + "?")
		add("*" + sample[i:])
		add("?" + sample[i:])
	}
	for _, x := range []string{"", "*", "?", "a", "ad", "admin", "admin:", ":", "Heal", "s3"} {
		for _, y := range []string{"", "*", "?", "a", "ad", "admin", "admin:", ":", "Heal", "s3"} {
			add(x + y)
			for _, z := range []string{"", "*", "?", ":", "Heal"} {
				add(x + y + z)
			}
		}
	}
	for _, p := range pats {
		a := AdminAction(p)
		if got, want := a.IsValid(), isValidScan(a); got != want {
			t.Errorf("AdminAction(%q).IsValid() = %v, reference scan = %v", p, got, want)
		}
		if got, want := a.HasResource(), hasResourceScan(a); got != want {
			t.Errorf("AdminAction(%q).HasResource() = %v, reference scan = %v", p, got, want)
		}
	}
	t.Logf("checked %d patterns", len(pats))
}

func FuzzAdminActionIsValid(f *testing.F) {
	for _, s := range []string{"", "*", "admin:Heal", "adm*", "s3:GetObject", "?", "a*d", "admin:*"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// The reference scan is exponential in the star count; bound it so the
		// fuzzer compares answers rather than hanging on that separate bug.
		if strings.Count(s, "*") > 4 || len(s) > 32 {
			t.Skip()
		}
		a := AdminAction(s)
		if got, want := a.IsValid(), isValidScan(a); got != want {
			t.Fatalf("AdminAction(%q).IsValid() = %v, reference scan = %v", s, got, want)
		}
		if got, want := a.HasResource(), hasResourceScan(a); got != want {
			t.Fatalf("AdminAction(%q).HasResource() = %v, reference scan = %v", s, got, want)
		}
	})
}
