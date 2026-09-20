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

	var sawAllow bool
	for _, s := range p.Statements {
		switch s.Effect {
		case Allow:
			sawAllow = true
			if !s.Actions.Equals(allowed) {
				t.Errorf("readonly Allow actions = %v, want %v", s.Actions, allowed)
			}
		case Deny:
			t.Errorf("readonly carries an unexpected Deny statement: %v", s.Actions)
		}
	}
	if !sawAllow {
		t.Error("readonly missing Allow statement")
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

	var sawAllow bool
	for _, s := range p.Statements {
		switch s.Effect {
		case Allow:
			sawAllow = true
			if !s.Actions.Equals(allowed) {
				t.Errorf("consolereadonly Allow actions = %v, want %v", s.Actions, allowed)
			}
		case Deny:
			t.Errorf("consolereadonly carries an unexpected Deny statement: %v", s.Actions)
		}
	}
	if !sawAllow {
		t.Error("consolereadonly missing Allow statement")
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

func TestDefaultPolicyMemoryAdmin(t *testing.T) {
	p, ok := findDefaultPolicy("memoryAdmin")
	if !ok {
		t.Fatal("memoryAdmin default policy not found")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("memoryAdmin policy invalid: %v", err)
	}

	args := Args{
		AccountName: "operator",
		Action:      Action(MemoryCreateAgentAction),
		BucketName:  "research",
		ObjectName:  "agents/research-bot",
	}
	if !p.IsAllowed(args) {
		t.Error("memoryAdmin should allow memory:CreateAgent")
	}

	// It carries its own action family only, like tablesAdmin: an operator who
	// also browses a cortex's objects combines it with an S3 policy.
	if p.IsAllowed(Args{
		AccountName: "operator",
		Action:      GetObjectAction,
		BucketName:  "research",
		ObjectName:  "agents/research-bot",
	}) {
		t.Error("memoryAdmin should NOT carry s3 actions")
	}
}

func TestDefaultPolicyConsoleAdminAllowsMemory(t *testing.T) {
	args := Args{
		AccountName: "admin",
		Action:      Action(MemoryListCortexesAction),
		BucketName:  "research",
	}

	p, ok := findDefaultPolicy("consoleAdmin")
	if !ok {
		t.Fatal("consoleAdmin default policy not found")
	}
	// consoleAdmin drives the whole console, so it needs every action family
	// the console calls. Without this the Memory section is denied outright.
	if !p.IsAllowed(args) {
		t.Error("consoleAdmin should allow memory:ListCortexes")
	}

	// The grant belongs to the console admin, not to every default policy.
	rw, ok := findDefaultPolicy("readwrite")
	if !ok {
		t.Fatal("readwrite default policy not found")
	}
	if rw.IsAllowed(args) {
		t.Error("readwrite should NOT allow memory:ListCortexes (sanity check)")
	}
}
