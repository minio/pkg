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

import "testing"

func findDefaultPolicy(name string) (Policy, bool) {
	for _, p := range DefaultPolicies {
		if p.Name == name {
			return p.Definition, true
		}
	}
	return Policy{}, false
}

func TestDefaultPolicyReadOnly(t *testing.T) {
	p, ok := findDefaultPolicy("readonly")
	if !ok {
		t.Fatal("readonly default policy not found")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("readonly policy invalid: %v", err)
	}

	allowed := NewActionSet(GetBucketLocationAction, GetObjectAction)
	denied := NewActionSet(CreateUserAdminAction)

	var sawAllow, sawDeny bool
	for _, s := range p.Statements {
		switch s.Effect {
		case Allow:
			sawAllow = true
			if !s.Actions.Equals(allowed) {
				t.Errorf("readonly Allow actions = %v, want %v", s.Actions, allowed)
			}
		case Deny:
			sawDeny = true
			if !s.Actions.Equals(denied) {
				t.Errorf("readonly Deny actions = %v, want %v", s.Actions, denied)
			}
		}
	}
	if !sawAllow || !sawDeny {
		t.Errorf("readonly missing Allow/Deny statement: allow=%v deny=%v", sawAllow, sawDeny)
	}
}

func TestDefaultPolicyConsoleReadOnly(t *testing.T) {
	p, ok := findDefaultPolicy("consolereadonly")
	if !ok {
		t.Fatal("consolereadonly default policy not found")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("consolereadonly policy invalid: %v", err)
	}

	allowed := NewActionSet(GetBucketLocationAction, GetObjectAction, ListBucketAction)
	denied := NewActionSet(CreateUserAdminAction)

	var sawAllow, sawDeny bool
	for _, s := range p.Statements {
		switch s.Effect {
		case Allow:
			sawAllow = true
			if !s.Actions.Equals(allowed) {
				t.Errorf("consolereadonly Allow actions = %v, want %v", s.Actions, allowed)
			}
		case Deny:
			sawDeny = true
			if !s.Actions.Equals(denied) {
				t.Errorf("consolereadonly Deny actions = %v, want %v", s.Actions, denied)
			}
		}
	}
	if !sawAllow || !sawDeny {
		t.Errorf("consolereadonly missing Allow/Deny statement: allow=%v deny=%v", sawAllow, sawDeny)
	}
}

func TestDefaultPolicyConsoleReadOnlyAllowsListBucket(t *testing.T) {
	p, ok := findDefaultPolicy("consolereadonly")
	if !ok {
		t.Fatal("consolereadonly default policy not found")
	}
	args := Args{
		AccountName: "testuser",
		Action:      ListBucketAction,
		BucketName:  "bucket1",
	}
	if !p.IsAllowed(args) {
		t.Error("consolereadonly should allow s3:ListBucket")
	}

	ro, ok := findDefaultPolicy("readonly")
	if !ok {
		t.Fatal("readonly default policy not found")
	}
	if ro.IsAllowed(args) {
		t.Error("readonly should NOT allow s3:ListBucket (sanity check)")
	}
}
