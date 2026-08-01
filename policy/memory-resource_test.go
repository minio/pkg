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
	"encoding/json"
	"strings"
	"testing"
)

func TestParseMemoryResource(t *testing.T) {
	testCases := []struct {
		value       string
		wantPattern string
		wantType    ResourceARNType
	}{
		{"arn:minio:memory:::cortex", "cortex", ResourceARNMemory},
		{"arn:minio:memory:::cortex/agents/alpha", "cortex/agents/alpha", ResourceARNMemory},
		{"arn:minio:memory:::cortex/agents/alpha/*", "cortex/agents/alpha/*", ResourceARNMemory},
		{"arn:minio:memory:::cortex/secrets/*", "cortex/secrets/*", ResourceARNMemory},
		{"arn:minio:memory:::*", "*", ResourceARNMemory},
		{"*", "*", ResourceARNAll},
	}

	for _, tc := range testCases {
		got, err := ParseResource(tc.value)
		if err != nil {
			t.Errorf("ParseResource(%q): unexpected error %v", tc.value, err)
			continue
		}
		if got.Type != tc.wantType {
			t.Errorf("ParseResource(%q): type = %v, want %v", tc.value, got.Type, tc.wantType)
		}
		if got.Pattern != tc.wantPattern {
			t.Errorf("ParseResource(%q): pattern = %q, want %q", tc.value, got.Pattern, tc.wantPattern)
		}
		if !got.IsValid() {
			t.Errorf("ParseResource(%q): parsed but not valid", tc.value)
		}
	}
}

// TestMemoryResourceRejected covers the malformed ARNs a policy author or an
// attacker might write. Each must fail at parse or validation — never parse
// into something that quietly matches nothing, because a statement that grants
// less than its author believes is a silent security failure.
func TestMemoryResourceRejected(t *testing.T) {
	testCases := []struct {
		value  string
		reason string
	}{
		// Wrong ARN shape. Two colons puts the cortex in the region field.
		{"arn:minio:memory:cortex", "cortex in the region field"},
		{"arn:minio:memory::cortex", "cortex in the account field"},
		{"arn:minio:memory::::cortex", "extra ARN field"},
		{"arn:minio:memory", "truncated prefix"},
		{"arn:minio:memory:::", "prefix with no resource"},

		// Wrong partition or service.
		{"arn:aws:memory:::cortex", "aws partition"},
		{"arn:minio:memoryx:::cortex", "service is not memory"},
		{"arn:minio:mem:::cortex", "abbreviated service"},

		// ARNs are case sensitive.
		{"ARN:MINIO:MEMORY:::cortex", "upper case prefix"},
		{"Arn:Minio:Memory:::cortex", "mixed case prefix"},

		// Surrounding or embedded whitespace.
		{" arn:minio:memory:::cortex", "leading space"},
		{"arn:minio:memory:::cortex ", "trailing space in pattern"},
		{"arn:minio:memory:::cor tex", "space inside the cortex"},
		{"arn:minio:memory:::cortex\t/agents/*", "tab inside the pattern"},
		{"arn:minio:memory:::cortex\n/agents/*", "newline inside the pattern"},

		// Separator abuse.
		{"arn:minio:memory::://cortex", "leading separator"},
		{"arn:minio:memory:::/cortex", "leading separator"},
		{"arn:minio:memory:::cortex\\agents", "backslash separator"},

		// Traversal segments, which would let a pattern name a resource other
		// than the one it appears to name.
		{"arn:minio:memory:::cortex/agents/../secrets/*", "parent segment"},
		{"arn:minio:memory:::cortex/./agents/*", "current segment"},
		{"arn:minio:memory:::../cortex/*", "leading parent segment"},
		{"arn:minio:memory:::cortex/agents/..", "trailing parent segment"},

		// Not an ARN at all.
		{"", "empty"},
		{"cortex/agents/alpha", "bare path"},
		{"memory://cortex/agents/alpha", "url form"},
	}

	for _, tc := range testCases {
		r, err := ParseResource(tc.value)
		if err != nil {
			continue
		}
		if r.IsValid() {
			t.Errorf("ParseResource(%q) accepted a malformed resource (%s): %#v",
				tc.value, tc.reason, r)
			continue
		}
		// Parsed but invalid is acceptable only if a statement carrying it is
		// rejected. Prove that rather than assume it.
		if err := NewResourceSet(r).ValidateMemory(); err == nil {
			t.Errorf("ValidateMemory accepted a malformed resource %q (%s)", tc.value, tc.reason)
		}
	}
}

// TestBareARNPrefixIsNotWildcard pins a fix that applies to every ARN type. A
// bare prefix such as "arn:aws:s3:::" used to parse as ResourceARNAll with its
// own prefix as the pattern. It therefore validated cleanly and then matched
// nothing — an Allow that granted zero and, the direction that fails open, a
// Deny that never fired.
//
// It parses as its own type with an empty pattern and is marked bare. AWS
// documents no S3 resource type with an empty bucket name, and its
// wildcard-completion rule is scoped to ARNs with fewer than six fields, so
// this six-field form is not equivalent to "*". MinIO keeps it loadable so a
// policy already on disk keeps working, and refuses it on the create and
// update paths.
//
// Memory ARNs are excluded: see TestBareMemoryARNIsRejected.
func TestBareARNPrefixIsNotWildcard(t *testing.T) {
	prefixes := []string{
		ResourceARNPrefix,
		ResourceARNS3TablesPrefix,
		ResourceARNKMSPrefix,
	}

	for _, prefix := range prefixes {
		r, err := ParseResource(prefix)
		if err != nil {
			t.Errorf("ParseResource(%q): unexpected error %v; it must stay loadable", prefix, err)
			continue
		}
		if r.Type == ResourceARNAll {
			t.Errorf("ParseResource(%q) = wildcard; a bare prefix names no resource", prefix)
		}
		if !r.IsBareARN() {
			t.Errorf("ParseResource(%q) did not mark the resource bare", prefix)
		}
		if r.Pattern != "" {
			t.Errorf("ParseResource(%q): pattern = %q, want empty", prefix, r.Pattern)
		}

		// Inert: it matches nothing, which is the behavior already on disk.
		for _, probe := range []string{"bucket", "bucket/key", prefix, "*"} {
			if r.MatchResource(probe) {
				t.Errorf("bare %q matched %q; it must match nothing", prefix, probe)
			}
		}

		// Loadable, but not writable.
		if err := NewResourceSet(r).ValidateStrict(); err == nil {
			t.Errorf("ValidateStrict accepted a bare %q", prefix)
		}

		// It must still round-trip to the string it came from, so re-serializing
		// a loaded policy does not corrupt it.
		if got := r.String(); got != prefix {
			t.Errorf("bare %q round-tripped to %q", prefix, got)
		}
	}

	// "*" itself still means every resource.
	r, err := ParseResource("*")
	if err != nil || r.Type != ResourceARNAll || !r.IsValid() || r.IsBareARN() {
		t.Fatalf(`ParseResource("*") = (%#v, %v); want a valid wildcard`, r, err)
	}
	if !r.MatchResource("bucket/key") {
		t.Error(`"*" must match every resource`)
	}
	if err := NewResourceSet(r).ValidateStrict(); err != nil {
		t.Errorf(`ValidateStrict rejected "*": %v`, err)
	}
}

// TestBareMemoryARNIsRejected covers the Memory exception to the tolerance in
// TestBareARNPrefixIsNotWildcard: a bare Memory prefix fails at parse, on both
// the load and the create paths.
func TestBareMemoryARNIsRejected(t *testing.T) {
	if _, err := ParseResource(ResourceARNMemoryPrefix); err == nil {
		t.Fatalf("ParseResource(%q) accepted a prefix with no resource", ResourceARNMemoryPrefix)
	}

	const doc = `{"Version":"2012-10-17","Statement":[{
		"Effect":"Allow",
		"Action":["memory:GetAgent"],
		"Resource":["arn:minio:memory:::"]}]}`

	var p Policy
	if err := json.Unmarshal([]byte(doc), &p); err == nil {
		if err := p.Validate(); err == nil {
			t.Error("Validate accepted a bare Memory ARN")
		}
	}

	// The wildcard form is the way to name every Memory resource.
	r, err := ParseResource(ResourceARNMemoryPrefix + "*")
	if err != nil || !r.IsValid() {
		t.Fatalf("ParseResource(%q*) = (%#v, %v); want a valid resource", ResourceARNMemoryPrefix, r, err)
	}
	if !r.MatchResource("cortex/agents/alpha") {
		t.Error("the Memory wildcard must match every Memory resource")
	}
}

// TestBareARNPolicyLoadsButCannotBeWritten is the compatibility contract for
// the older ARN types: a stored policy carrying a bare prefix keeps loading,
// and the same document is refused when someone creates or updates it.
func TestBareARNPolicyLoadsButCannotBeWritten(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::*"]},
	  {"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::"]}]}`

	var p Policy
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("an existing policy must keep loading, got %v", err)
	}
	if err := p.ValidateStrict(); err == nil {
		t.Fatal("ValidateStrict accepted a policy carrying a bare ARN prefix")
	}

	// The inert Deny still does not fire — unchanged from before the fix, and
	// the reason writing a new one is now refused.
	if !p.IsAllowed(Args{
		AccountName: "u",
		Action:      "s3:GetObject",
		BucketName:  "secret",
		ObjectName:  "data",
	}) {
		t.Error("behavior of an already-stored policy changed")
	}
}

func TestMemoryResourceRoundTrip(t *testing.T) {
	const arn = "arn:minio:memory:::cortex/agents/alpha/*"

	r := NewMemoryResource("cortex/agents/alpha/*")
	if r.String() != arn {
		t.Fatalf("String() = %q, want %q", r.String(), arn)
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back Resource
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back != r {
		t.Fatalf("round trip changed the resource: got %#v, want %#v", back, r)
	}

	// A malformed ARN must not survive an unmarshal either.
	if err := json.Unmarshal([]byte(`"arn:minio:memory:::cortex/../x"`), &back); err == nil {
		if err := back.Validate(); err == nil {
			t.Fatal("unmarshal accepted a traversal pattern")
		}
	}
}

// TestParseResourceIsDeterministic guards against the map iteration in
// ParseResource. The ARN prefixes do not currently overlap, so the result must
// not depend on iteration order; if a future prefix does overlap, this fails
// loudly instead of producing a policy that means different things per process.
func TestParseResourceIsDeterministic(t *testing.T) {
	inputs := []string{
		"arn:aws:s3:::bucket/*",
		"arn:aws:s3tables:::bucket/wh/table/id",
		"arn:minio:kms:::key",
		"arn:minio:memory:::cortex/agents/alpha/*",
		"*",
	}
	for _, in := range inputs {
		first, err := ParseResource(in)
		if err != nil {
			t.Fatalf("ParseResource(%q): %v", in, err)
		}
		for range 200 {
			got, err := ParseResource(in)
			if err != nil || got != first {
				t.Fatalf("ParseResource(%q) is not deterministic: got (%#v, %v), want %#v",
					in, got, err, first)
			}
		}
	}
}

func TestMemoryResourceIsValid(t *testing.T) {
	testCases := []struct {
		pattern string
		want    bool
	}{
		{"cortex", true},
		{"cortex/agents/alpha", true},
		{"cortex/agents/alpha/*", true},
		{"cortex/*", true},
		{"*", true},
		{"cortex/agents/alpha..beta", true}, // dots inside a segment are fine
		{"", false},
		{"/cortex", false},
		{"cortex/../secrets", false},
		{"cortex/./agents", false},
		{"..", false},
		{"cortex:extra", false},
		{"cortex agents", false},
		{"cortex\\agents", false},
	}

	for _, tc := range testCases {
		if got := NewMemoryResource(tc.pattern).IsValid(); got != tc.want {
			t.Errorf("IsValid(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

// TestMemoryResourceMatch pins the subtree idiom. A pattern ending in "/*"
// does not match the parent itself, so granting an agent both its record and
// everything beneath it takes two resources — the same shape S3 already
// requires for a bucket and its objects.
func TestMemoryResourceMatch(t *testing.T) {
	testCases := []struct {
		pattern  string
		resource string
		want     bool
	}{
		// Subtree pattern covers descendants but not the record itself.
		{"cortex/agents/alpha/*", "cortex/agents/alpha/notes", true},
		{"cortex/agents/alpha/*", "cortex/agents/alpha", false},

		// Which is why the record needs its own exact resource.
		{"cortex/agents/alpha", "cortex/agents/alpha", true},
		{"cortex/agents/alpha", "cortex/agents/alpha/notes", false},

		// A prefix wildcard leaks across agents. Documented so nobody reaches
		// for it as a shorthand for the two-resource idiom.
		{"cortex/agents/alpha*", "cortex/agents/alpha2", true},
		{"cortex/agents/alpha*", "cortex/agents/alphabet/notes", true},

		// Collection and cortex wildcards.
		{"cortex/agents/*", "cortex/agents/alpha", true},
		{"cortex/secrets/*", "cortex/secrets/db/prod", true},
		{"cortex/secrets/*", "cortex/agents/alpha", false},
		{"cortex/*", "cortex/agents/alpha", true},
		{"cortex", "cortex", true},
		{"cortex", "other", false},

		// "*" crosses separators, matching S3 semantics. A pattern cannot
		// constrain a single path segment.
		{"cortex/agents/*/notes", "cortex/agents/alpha/beta/notes", true},

		// Cortex boundaries hold.
		{"cortex/agents/*", "other/agents/alpha", false},
		{"cortex/agents/alpha/*", "cortexevil/agents/alpha/notes", false},
		{"cortex", "cortex2", false},
		{"*", "cortex/agents/alpha", true},
	}

	for _, tc := range testCases {
		r := NewMemoryResource(tc.pattern)
		if got := r.MatchResource(tc.resource); got != tc.want {
			t.Errorf("Match(pattern=%q, resource=%q) = %v, want %v",
				tc.pattern, tc.resource, got, tc.want)
		}
	}
}

// TestMemoryMatchCleansResource covers traversal in the candidate. Match cleans
// a Memory resource before comparing, so a raw request path cannot escape the
// subtree its pattern names.
func TestMemoryMatchCleansResource(t *testing.T) {
	escaping := []string{
		"cortex/agents/alpha/../../secrets/db",
		"cortex/agents/alpha/../beta/notes",
		"cortex/agents/alpha/./../../secrets/db",
	}
	r := NewMemoryResource("cortex/agents/alpha/*")
	for _, resource := range escaping {
		if r.MatchResource(resource) {
			t.Errorf("Match(%q) escaped the alpha subtree", resource)
		}
	}

	// Cleaning must not break the resources that do belong to it.
	for _, resource := range []string{
		"cortex/agents/alpha/notes",
		"cortex/agents/alpha//notes",
		"cortex/agents/alpha/seen/workspace",
	} {
		if !r.MatchResource(resource) {
			t.Errorf("Match(%q) rejected a resource inside the subtree", resource)
		}
	}

	// Traversal that resolves into the subtree still matches it.
	if !r.MatchResource("cortex/agents/beta/../alpha/notes") {
		t.Error("a path resolving into the subtree must match")
	}

	// A pattern can never carry traversal in the first place.
	if NewMemoryResource("cortex/agents/alpha/../../secrets/*").IsValid() {
		t.Error("a pattern with traversal must be invalid")
	}
}

// TestBareARNLoadsInsideForeignStatement pins cross-type load compatibility. A
// bare prefix used to parse as ResourceARNAll, which satisfied every type
// predicate, so a KMS or Table statement carrying one loaded. It now carries a
// concrete type, and the type validators tolerate it so those keep loading.
func TestBareARNLoadsInsideForeignStatement(t *testing.T) {
	testCases := []struct {
		name    string
		policy  string
		wantErr bool
	}{
		{
			name: "bare S3 prefix in a KMS statement",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow","Action":["kms:ListKeys"],
				"Resource":["arn:aws:s3:::"]}]}`,
		},
		{
			name: "bare S3 prefix in a Tables statement",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow","Action":["s3tables:GetTableData"],
				"Resource":["arn:aws:s3:::"]}]}`,
		},
		{
			name: "bare KMS prefix in an S3 statement",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow","Action":["s3:GetObject"],
				"Resource":["arn:minio:kms:::"]}]}`,
		},
		{
			// Memory statements carry no such tolerance.
			name: "bare S3 prefix in a Memory statement",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow","Action":["memory:GetAgent"],
				"Resource":["arn:aws:s3:::"]}]}`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var p Policy
			err := json.Unmarshal([]byte(tc.policy), &p)
			if err == nil {
				err = p.Validate()
			}
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("a statement already on disk must keep loading, got %v", err)
			}
			// Either way it can never be written.
			if err == nil {
				if err := p.ValidateStrict(); err == nil {
					t.Error("ValidateStrict accepted a bare ARN prefix")
				}
			}
		})
	}
}

// TestMemoryResourceTypeIsolation proves a Memory grant cannot be written as,
// or satisfied by, any other resource type. Each validator must reject the
// others, so no policy can express Memory access through an S3 ARN or the
// reverse.
func TestMemoryResourceTypeIsolation(t *testing.T) {
	memory := NewResourceSet(NewMemoryResource("cortex/agents/alpha/*"))
	s3 := NewResourceSet(NewResource("cortex/*"))
	kms := NewResourceSet(NewKMSResource("key"))
	tables := NewResourceSet(NewS3TablesResource("bucket/wh/table/id"))

	if err := memory.ValidateS3(); err == nil {
		t.Error("ValidateS3 accepted a Memory ARN")
	}
	if err := memory.ValidateKMS(); err == nil {
		t.Error("ValidateKMS accepted a Memory ARN")
	}
	if err := memory.ValidateTable(); err == nil {
		t.Error("ValidateTable accepted a Memory ARN")
	}
	if err := s3.ValidateMemory(); err == nil {
		t.Error("ValidateMemory accepted an S3 ARN")
	}
	if err := kms.ValidateMemory(); err == nil {
		t.Error("ValidateMemory accepted a KMS ARN")
	}
	if err := tables.ValidateMemory(); err == nil {
		t.Error("ValidateMemory accepted an S3 Tables ARN")
	}
	if err := memory.ValidateMemory(); err != nil {
		t.Errorf("ValidateMemory rejected a Memory ARN: %v", err)
	}
}

// TestMemoryPolicyValidation exercises whole policy documents, which is the
// path a real deployment takes.
func TestMemoryPolicyValidation(t *testing.T) {
	testCases := []struct {
		name    string
		policy  string
		wantErr bool
	}{
		{
			name: "agent record and its subtree",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent","memory:PutAgent"],
				"Resource":["arn:minio:memory:::cortex/agents/alpha",
				            "arn:minio:memory:::cortex/agents/alpha/*"]}]}`,
		},
		{
			name: "cortex-wide list",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:ListAgents"],
				"Resource":["arn:minio:memory:::cortex/*"]}]}`,
		},
		{
			name: "deny statement",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Deny",
				"Action":["memory:DeleteAgent"],
				"Resource":["arn:minio:memory:::cortex/agents/*"]}]}`,
		},
		{
			name: "valid Memory NotResource",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent"],
				"NotResource":["arn:minio:memory:::cortex/secrets/*"]}]}`,
		},
		{
			name: "NotResource is validated too",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent"],
				"NotResource":["arn:aws:s3:::cortex/*"]}]}`,
			wantErr: true,
		},
		{
			name: "S3 ARN cannot carry a Memory action",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent"],
				"Resource":["arn:aws:s3:::cortex/*"]}]}`,
			wantErr: true,
		},
		{
			name: "Memory ARN cannot carry an S3 action",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["s3:GetObject"],
				"Resource":["arn:minio:memory:::cortex/agents/alpha"]}]}`,
			wantErr: true,
		},
		{
			name: "action types cannot be mixed",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent","s3:GetObject"],
				"Resource":["arn:minio:memory:::cortex/agents/alpha"]}]}`,
			wantErr: true,
		},
		{
			name: "resource is required",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent"]}]}`,
			wantErr: true,
		},
		{
			name: "traversal in a resource is rejected",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent"],
				"Resource":["arn:minio:memory:::cortex/agents/../secrets/*"]}]}`,
			wantErr: true,
		},
		{
			name: "bare prefix is rejected",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:GetAgent"],
				"Resource":["arn:minio:memory:::"]}]}`,
			wantErr: true,
		},
		{
			name: "unknown memory action is rejected",
			policy: `{"Version":"2012-10-17","Statement":[{
				"Effect":"Allow",
				"Action":["memory:StealAgent"],
				"Resource":["arn:minio:memory:::cortex/agents/alpha"]}]}`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var p Policy
			err := json.Unmarshal([]byte(tc.policy), &p)
			if err == nil {
				err = p.Validate()
			}
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error %v", err)
			}
		})
	}
}

// TestMemoryPolicyIsAllowed drives the evaluation path end to end: a policy
// scoped to one agent must allow that agent's resources and deny every
// neighbor, including one whose id shares a prefix.
func TestMemoryPolicyIsAllowed(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[{
		"Effect":"Allow",
		"Action":["memory:GetAgent"],
		"Resource":["arn:minio:memory:::cortex/agents/alpha",
		            "arn:minio:memory:::cortex/agents/alpha/*"]}]}`

	var p Policy
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	testCases := []struct {
		object string
		want   bool
	}{
		{"agents/alpha", true},
		{"agents/alpha/notes", true},
		{"agents/alpha/seen/workspace", true},
		{"agents/alpha2", false},
		{"agents/alphabet", false},
		{"agents/beta", false},
		{"secrets/db", false},
		{"", false},
	}

	for _, tc := range testCases {
		got := p.IsAllowed(Args{
			AccountName: "tester",
			Action:      Action(MemoryGetAgentAction),
			BucketName:  "cortex",
			ObjectName:  tc.object,
		})
		if got != tc.want {
			t.Errorf("IsAllowed(cortex/%s) = %v, want %v", tc.object, got, tc.want)
		}
	}

	// A different cortex is never reachable, whatever the object.
	if p.IsAllowed(Args{
		AccountName: "tester",
		Action:      Action(MemoryGetAgentAction),
		BucketName:  "other",
		ObjectName:  "agents/alpha",
	}) {
		t.Error("a policy scoped to one cortex allowed another")
	}

	// A different action is never reachable, whatever the resource.
	if p.IsAllowed(Args{
		AccountName: "tester",
		Action:      Action(MemoryDeleteAgentAction),
		BucketName:  "cortex",
		ObjectName:  "agents/alpha",
	}) {
		t.Error("a policy granting GetAgent allowed DeleteAgent")
	}
}

// TestMemoryResourceStringNeverLeaksStorage is a guard on the whole point of
// the Memory ARN: it names a logical resource, so no storage detail may appear
// in a policy document. If the storage layout ever leaks into an ARN, every
// policy becomes coupled to it.
func TestMemoryResourceStringNeverLeaksStorage(t *testing.T) {
	for _, pattern := range []string{
		"cortex",
		"cortex/agents/alpha",
		"cortex/agents/alpha/*",
		"cortex/secrets/db/prod",
	} {
		got := NewMemoryResource(pattern).String()
		for _, leak := range []string{".mem", ".secrets", ".cortex", "profile.json", "/L0/", "/L1/"} {
			if strings.Contains(got, leak) {
				t.Errorf("Memory ARN %q leaks storage detail %q", got, leak)
			}
		}
		if !strings.HasPrefix(got, ResourceARNMemoryPrefix) {
			t.Errorf("Memory ARN %q lost its prefix", got)
		}
	}
}
