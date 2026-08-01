// Copyright (c) 2015-2021 MinIO, Inc.
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
	"encoding/json"
	"path"
	"strings"

	"github.com/minio/pkg/v3/policy/condition"
	"github.com/minio/pkg/v3/wildcard"
)

const (
	// ResourceARNPrefix - resource S3 ARN prefix as per S3 specification.
	ResourceARNPrefix = "arn:aws:s3:::"

	// ResourceARNS3TablesPrefix - resource prefix for Amazon S3 Tables resources.
	ResourceARNS3TablesPrefix = "arn:aws:s3tables:::"

	// ResourceARNKMSPrefix is for KMS key resources. MinIO specific API.
	ResourceARNKMSPrefix = "arn:minio:kms:::"

	// ResourceARNMemoryPrefix is for AIStor Memory API resources. MinIO
	// specific API; AWS has no equivalent service to borrow an ARN from.
	//
	// The pattern is the logical Memory path — <cortex>, <cortex>/secrets/<name>,
	// <cortex>/agents/<id> — never a storage key, so the Memory API's on-disk
	// layout can change without invalidating a policy.
	//
	// Granting an agent both its record and everything beneath it takes two
	// resources, because a "/*" pattern does not match its own parent:
	//
	//	arn:minio:memory:::cortex/agents/alpha
	//	arn:minio:memory:::cortex/agents/alpha/*
	//
	// This is the shape S3 already requires for a bucket and its objects.
	// Collapsing it to "alpha*" would also match an unrelated agent "alpha2".
	ResourceARNMemoryPrefix = "arn:minio:memory:::"
)

// ResourceARNType - ARN prefix type
type ResourceARNType uint32

const (
	// Zero value for detecting errors
	unknownARN ResourceARNType = iota

	// ResourceARNS3 is the ARN prefix type for S3 resources.
	ResourceARNS3

	// ResourceARNS3Tables is the ARN prefix type for Amazon S3 Tables resources.
	ResourceARNS3Tables

	// ResourceARNKMS is the ARN prefix type for MinIO KMS resources.
	ResourceARNKMS

	// ResourceARNMemory is the ARN prefix type for AIStor Memory resources.
	ResourceARNMemory

	// ResourceARNAll is the ARN '*'
	ResourceARNAll
)

// ARNTypeToPrefix maps the type to prefix string
var ARNTypeToPrefix = map[ResourceARNType]string{
	ResourceARNS3:       ResourceARNPrefix,
	ResourceARNS3Tables: ResourceARNS3TablesPrefix,
	ResourceARNKMS:      ResourceARNKMSPrefix,
	ResourceARNMemory:   ResourceARNMemoryPrefix,
	ResourceARNAll:      "*",
}

// ARNPrefixToType maps prefix to types.
var ARNPrefixToType map[string]ResourceARNType

func init() {
	ARNPrefixToType = make(map[string]ResourceARNType)
	for k, v := range ARNTypeToPrefix {
		ARNPrefixToType[v] = k
	}
}

func (a ResourceARNType) String() string {
	return ARNTypeToPrefix[a]
}

// Resource - resource in policy statement.
type Resource struct {
	Pattern string
	Type    ResourceARNType

	// bareARN marks a resource that named an ARN prefix with nothing after it,
	// such as "arn:aws:s3:::". It names no resource, so it matches nothing: an
	// Allow grants nothing and a Deny never fires, which is the direction that
	// fails open.
	//
	// Such a resource loads but cannot be written: isValid accepts it so a
	// policy already on disk keeps working, and ValidateStrict refuses it on
	// the create and update paths.
	//
	// Only the S3, S3 Tables and KMS ARNs carry this tolerance. A bare Memory
	// ARN is an error at parse.
	bareARN bool
}

// IsBareARN reports whether the resource named an ARN prefix with no resource
// after it. Such a resource is inert: it matches nothing.
func (r Resource) IsBareARN() bool { return r.bareARN }

func (r Resource) isKMS() bool {
	return r.Type == ResourceARNKMS || r.Type == ResourceARNAll
}

func (r Resource) isS3() bool {
	return r.Type == ResourceARNS3 || r.Type == ResourceARNAll
}

func (r Resource) isTable() bool {
	return r.Type == ResourceARNS3Tables || r.Type == ResourceARNAll
}

func (r Resource) isMemory() bool {
	return r.Type == ResourceARNMemory || r.Type == ResourceARNAll
}

func (r Resource) isBucketPattern() bool {
	return !strings.Contains(r.Pattern, "/") || r.Pattern == "*"
}

func (r Resource) isObjectPattern() bool {
	return strings.Contains(r.Pattern, "/") || strings.Contains(r.Pattern, "*")
}

// IsValid - checks whether Resource is valid or not.
func (r Resource) IsValid() bool {
	if r.Type == unknownARN {
		return false
	}
	// A bare ARN prefix is tolerated here so existing policies keep loading.
	// It is inert, and ValidateStrict refuses to let a new one be written.
	if r.bareARN {
		return true
	}
	if r.isS3() {
		if strings.HasPrefix(r.Pattern, "/") {
			return false
		}
	}
	if r.isTable() {
		if strings.HasPrefix(r.Pattern, "/") {
			return false
		}
	}
	if r.Type == ResourceARNMemory {
		if !isValidMemoryPattern(r.Pattern) {
			return false
		}
	}
	if r.isKMS() {
		if strings.IndexFunc(r.Pattern, func(c rune) bool {
			return c == '/' || c == '\\' || c == '.'
		}) >= 0 {
			return false
		}
	}

	return r.Pattern != ""
}

// isValidMemoryPattern reports whether pattern can name a Memory resource.
//
// A Memory pattern is <cortex>[/<collection>[/<name>]], where <cortex> is a
// bucket name. Anything a bucket name cannot contain is rejected here rather
// than accepted as a pattern that silently matches nothing — a policy that
// grants less than its author believes is worse than one that fails to load.
//
// Rejected: a leading separator (the cortex would be empty), a colon (an extra
// ARN field leaked into the resource), whitespace, a backslash, and any "."
// or ".." path segment (which would let a pattern name a resource other than
// the one it appears to name).
func isValidMemoryPattern(pattern string) bool {
	if pattern == "" || strings.HasPrefix(pattern, "/") {
		return false
	}
	if strings.ContainsAny(pattern, ":\\ \t\r\n") {
		return false
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// MatchResource matches object name with resource pattern only.
func (r Resource) MatchResource(resource string) bool {
	return r.Match(resource, nil)
}

// Match - matches object name with resource pattern, including specific conditionals.
func (r Resource) Match(resource string, conditionValues map[string][]string) bool {
	// Happy path, with no replacements
	idx := strings.IndexByte(r.Pattern, '$')
	if idx < 0 {
		if cp := path.Clean(resource); cp != "." && cp == r.Pattern {
			return true
		}
		return wildcard.Match(r.Pattern, resource)
	}

	// Use a small buffer
	pat := smallBufPool.Get().(*bytes.Buffer)
	defer smallBufPool.Put(pat)
	pat.Reset()

	// Do replacement of known keys.
	pat.WriteString(r.Pattern[:idx])
	remain := r.Pattern[idx:]
	for len(remain) > 0 {
		val := remain[0]
		if val != '$' || len(remain) < 3 {
			pat.WriteByte(val)
			remain = remain[1:]
			continue
		}
		keyEnds := strings.IndexByte(remain, '}')

		// If no curly brackets, emit as-is.
		if remain[1] != '{' || keyEnds < 0 {
			pat.WriteByte('$')
			remain = remain[1:]
			continue
		}

		ckey := condition.KeyName(remain[2:keyEnds])

		// Only replace keys we know
		if rvalues, ok := conditionValues[ckey.Name()]; condition.CommonKeysMap[ckey] && ok && rvalues[0] != "" {
			pat.WriteString(rvalues[0])
		} else {
			// Write without replacing...
			pat.WriteString("${")
			pat.WriteString(string(ckey))
			pat.WriteString("}")
		}
		remain = remain[keyEnds+1:]
	}
	pattern := pat.String()
	if cp := path.Clean(resource); cp != "." && cp == pattern {
		return true
	}
	return wildcard.Match(pattern, resource)
}

// MarshalJSON - encodes Resource to JSON data.
func (r Resource) MarshalJSON() ([]byte, error) {
	if !r.IsValid() {
		return nil, Errorf("invalid resource %v", r)
	}

	return json.Marshal(r.String())
}

func (r Resource) String() string {
	return r.Type.String() + r.Pattern
}

// UnmarshalJSON - decodes JSON data to Resource.
func (r *Resource) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsedResource, err := ParseResource(s)
	if err != nil {
		return err
	}

	*r = parsedResource

	return nil
}

// Validate - validates Resource.
func (r Resource) Validate() error {
	if !r.IsValid() {
		return Errorf("invalid resource")
	}
	return nil
}

// ValidateBucket - validates that given bucketName is matched by Resource.
func (r Resource) ValidateBucket(bucketName string) error {
	if !r.IsValid() {
		return Errorf("invalid resource")
	}

	// For the resource to match the bucket, there are two cases:
	//
	//   1. the whole resource pattern must match the bucket name (e.g.
	//   `example*a` matches bucket 'example-east-a'), or
	//
	//   2. bucket name followed by '/' must match as a prefix of the resource
	//   pattern (e.g. `example*a` includes resources in a bucket 'example22'
	//   for example the object `example22/2023/a` is matched by this resource).
	if !wildcard.Match(r.Pattern, bucketName) &&
		!wildcard.MatchAsPatternPrefix(r.Pattern, bucketName+"/") {

		return Errorf("bucket name does not match")
	}

	return nil
}

// ParseResource - parses string to Resource.
func ParseResource(s string) (Resource, error) {
	// "*" is the only string that denotes every resource. A bare ARN prefix
	// such as "arn:aws:s3:::" names no resource and is not a wildcard; it
	// parses as its own type with an empty pattern and is marked bareARN.
	if s == ResourceARNAll.String() {
		return Resource{Type: ResourceARNAll, Pattern: s}, nil
	}

	r := Resource{}
	for k, v := range ARNPrefixToType {
		if k == ResourceARNAll.String() {
			continue
		}
		if rem, ok := strings.CutPrefix(s, k); ok {
			r.Type = v
			r.Pattern = rem
			break
		}
	}
	if r.Type == unknownARN {
		return r, Errorf("invalid resource '%v'", s)
	}

	if r.Pattern == "" {
		// Memory ARNs carry no compatibility tolerance.
		if r.Type == ResourceARNMemory {
			return r, Errorf("invalid resource '%v' - an ARN prefix with no resource after it matches nothing; use '%v*' to mean every Memory resource",
				s, ResourceARNMemoryPrefix)
		}
		r.bareARN = true
		return r, nil
	}

	if strings.HasPrefix(r.Pattern, "/") {
		return r, Errorf("invalid resource '%v' - starts with '/' will not match a bucket", s)
	}

	return r, nil
}

// NewResource - creates new resource with the default ARN type of S3.
func NewResource(pattern string) Resource {
	return Resource{
		Pattern: pattern,
		Type:    ResourceARNS3,
	}
}

// NewKMSResource - creates new resource with type KMS
func NewKMSResource(pattern string) Resource {
	return Resource{
		Pattern: pattern,
		Type:    ResourceARNKMS,
	}
}

// NewMemoryResource - creates new resource with type Memory. The pattern is
// the logical Memory path, <cortex>[/<collection>[/<name>]] — never a storage
// key, so the Memory API's on-disk layout stays out of policy documents.
func NewMemoryResource(pattern string) Resource {
	return Resource{
		Pattern: pattern,
		Type:    ResourceARNMemory,
	}
}

// isTableResourceString reports whether s has the form
// bucket/<bucket-name>/(table|view)[/<id>].
func isTableResourceString(s string) bool {
	if !strings.HasPrefix(s, "bucket/") {
		return false
	}
	rest := strings.TrimPrefix(s, "bucket/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	if parts[0] == "" {
		return false
	}
	if parts[1] != "table" && parts[1] != "view" {
		return false
	}
	return true
}

// NewS3TablesResource - creates new resource with type S3 Tables
func NewS3TablesResource(pattern string) Resource {
	return Resource{
		Pattern: pattern,
		Type:    ResourceARNS3Tables,
	}
}
