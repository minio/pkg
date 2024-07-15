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
	"encoding/json"
	"path"
	"strings"

	"github.com/minio/pkg/v3/policy/condition"
	"github.com/minio/pkg/v3/wildcard"
)

const (
	// ResourceARNPrefix - resource S3 ARN prefix as per S3 specification.
	ResourceARNPrefix = "arn:aws:s3:::"

	// ResourceARNKMSPrefix is for KMS key resources. MinIO specific API.
	ResourceARNKMSPrefix = "arn:minio:kms:::"
)

// ResourceARNType - ARN prefix type
type ResourceARNType uint32

const (
	// Zero value for detecting errors
	unknownARN ResourceARNType = iota

	// ResourceARNS3 is the ARN prefix type for S3 resources.
	ResourceARNS3

	// ResourceARNKMS is the ARN prefix type for MinIO KMS resources.
	ResourceARNKMS
)

// ARNTypeToPrefix maps the type to prefix string
var ARNTypeToPrefix = map[ResourceARNType]string{
	ResourceARNS3:  ResourceARNPrefix,
	ResourceARNKMS: ResourceARNKMSPrefix,
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
}

func (r Resource) isKMS() bool {
	return r.Type == ResourceARNKMS
}

func (r Resource) isS3() bool {
	return r.Type == ResourceARNS3
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
	if r.isS3() {
		if strings.HasPrefix(r.Pattern, "/") {
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

// MatchResource matches object name with resource pattern only.
func (r Resource) MatchResource(resource string) bool {
	return r.Match(resource, nil)
}

// Match - matches object name with resource pattern, including specific conditionals.
func (r Resource) Match(resource string, conditionValues map[string][]string) bool {
	pattern := r.Pattern
	if len(conditionValues) != 0 {
		for _, key := range condition.CommonKeys {
			// Empty values are not supported for policy variables.
			if rvalues, ok := conditionValues[key.Name()]; ok && rvalues[0] != "" {
				pattern = strings.Replace(pattern, key.VarName(), rvalues[0], -1)
			}
		}
	}
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

	parsedResource, err := parseResource(s)
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

// parseResource - parses string to Resource.
func parseResource(s string) (Resource, error) {
	r := Resource{}
	for k, v := range ARNPrefixToType {
		if rem, ok := strings.CutPrefix(s, k); ok {
			r.Type = v
			r.Pattern = rem
			break
		}
	}
	if r.Type == unknownARN {
		return r, Errorf("invalid resource '%v'", s)
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
