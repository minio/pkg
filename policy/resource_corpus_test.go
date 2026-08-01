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
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

// acceptedResourceCorpus is every resource form the policy language accepts.
//
// ParseResource is shared by every ARN type, so a change made for one narrows
// what the others accept. Adding a form here is a deliberate widening; removing
// one is a breaking change for stored policies and has to be argued rather than
// discovered downstream.
var acceptedResourceCorpus = []string{
	// Wildcards. Anything longer than "*" keeps what follows as its pattern.
	//
	// "**" is not exotic: String() renders the wildcard type as its prefix plus
	// its pattern, so a policy written as "*" is re-serialized as "**". Any
	// stored policy MinIO has read and written back carries that form.
	"*",
	"**",
	"*foo",

	// S3.
	"arn:aws:s3:::bucket",
	"arn:aws:s3:::bucket/*",
	"arn:aws:s3:::bucket/key",
	"arn:aws:s3:::bucket/a/b/c",
	"arn:aws:s3:::*",
	"arn:aws:s3:::bucket*",
	"arn:aws:s3:::${aws:username}",
	"arn:aws:s3:::bucket/${aws:username}/*",

	// S3 Tables.
	"arn:aws:s3tables:::bucket/wh/table/id",
	"arn:aws:s3tables:::*",

	// KMS.
	"arn:minio:kms:::key",
	"arn:minio:kms:::*",

	// Memory.
	"arn:minio:memory:::cortex",
	"arn:minio:memory:::cortex/*",
	"arn:minio:memory:::cortex/agents/alpha",
	"arn:minio:memory:::cortex/agents/alpha/*",
	"arn:minio:memory:::cortex/secrets/db/prod",
	"arn:minio:memory:::*",

	// Bare ARN prefixes. Inert and refused on write, but they must keep
	// loading so a stored policy carrying one does not break on upgrade.
	"arn:aws:s3:::",
	"arn:aws:s3tables:::",
	"arn:minio:kms:::",
}

// TestAcceptedResourceCorpusStillParses guards the shared parser against a
// change made for one ARN type quietly rejecting another's inputs. Every entry
// must parse, validate, and round-trip through its string form.
func TestAcceptedResourceCorpusStillParses(t *testing.T) {
	for _, value := range acceptedResourceCorpus {
		t.Run(value, func(t *testing.T) {
			r, err := ParseResource(value)
			if err != nil {
				t.Fatalf("no longer parses: %v", err)
			}
			if !r.IsValid() {
				t.Fatalf("parsed but no longer valid: %#v", r)
			}
			// Assert the round trip is stable rather than byte-identical: "*"
			// serializes to "**" and settles there, which is how the doubled
			// form reaches stored policies in the first place.
			again, err := ParseResource(r.String())
			if err != nil {
				t.Fatalf("re-parsing %q failed: %v", r.String(), err)
			}
			if again != r {
				t.Errorf("round trip changed the resource: %#v -> %q -> %#v", r, r.String(), again)
			}
		})
	}
}

// TestAcceptedResourceCorpusLoadsInAPolicy runs the same corpus through a whole
// policy document, which is the path a deployment actually takes. A form that
// parses in isolation but fails statement validation is just as broken.
func TestAcceptedResourceCorpusLoadsInAPolicy(t *testing.T) {
	for _, value := range acceptedResourceCorpus {
		t.Run(value, func(t *testing.T) {
			r, err := ParseResource(value)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			// Pair each resource with an action of its own type; the two must
			// agree or statement validation rejects the pair for that reason
			// rather than for the resource itself.
			action := "s3:GetObject"
			switch r.Type {
			case ResourceARNKMS:
				action = "kms:ListKeys"
			case ResourceARNS3Tables:
				action = "s3tables:GetTableData"
			case ResourceARNMemory:
				action = "memory:GetAgent"
			}

			set := NewResourceSet(r)
			statement := NewStatement("", Allow, NewActionSet(Action(action)), set, condition.NewFunctions())
			if err := statement.Validate(); err != nil {
				t.Fatalf("statement carrying %q no longer validates: %v", value, err)
			}
		})
	}
}
