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
	// ResourceARNPrefix - resource S3 ARN prefix as per AWS S3 specification.
	ResourceARNPrefix = "arn:aws:s3:::"

	// ResourceARNKMSPrefix is for KMS key resources. MinIO specific API.
	ResourceARNKMSPrefix = "arn:minio:kms:::"
)

// ARNPrefixType - ARN prefix type
type ARNPrefixType uint8

const (
	// ARNPrefixTypeAWSS3 is the ARN prefix type for AWS S3 resources.
	ARNPrefixTypeAWSS3 ARNPrefixType = iota + 1

	// ARNPrefixTypeMinIOKMS is the ARN prefix type for MinIO KMS resources.
	ARNPrefixTypeMinIOKMS
)

// ARNTypeToPrefix maps the type to prefix string
var ARNTypeToPrefix = map[ARNPrefixType]string{
	ARNPrefixTypeAWSS3:    ResourceARNPrefix,
	ARNPrefixTypeMinIOKMS: ResourceARNKMSPrefix,
}

// ARNPrefixToType maps prefix to types.
var ARNPrefixToType map[string]ARNPrefixType

func init() {
	ARNPrefixToType = make(map[string]ARNPrefixType)
	for k, v := range ARNTypeToPrefix {
		ARNPrefixToType[v] = k
	}
}

func (a ARNPrefixType) String() string {
	return ARNTypeToPrefix[a]
}

// Resource - resource in policy statement.
type Resource struct {
	Pattern string
	Type    ARNPrefixType
}

func (r Resource) isKMS() bool {
	return r.Type == ARNPrefixTypeMinIOKMS
}

func (r Resource) isAWSS3() bool {
	return r.Type == ARNPrefixTypeAWSS3
}

func (r Resource) isBucketPattern() bool {
	return !strings.Contains(r.Pattern, "/") || r.Pattern == "*"
}

func (r Resource) isObjectPattern() bool {
	return strings.Contains(r.Pattern, "/") || strings.Contains(r.Pattern, "*")
}

// IsValid - checks whether Resource is valid or not.
func (r Resource) IsValid() bool {
	if r.isAWSS3() {
		if strings.HasPrefix(r.Pattern, "/") {
			return false
		}
	}
	if r.isKMS() {
		// TODO: Copied from KES repo, confirm that it is generally applicable.
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
	switch {
	case strings.HasPrefix(s, ResourceARNPrefix):
		r.Pattern = strings.TrimPrefix(s, ResourceARNPrefix)
		r.Type = ARNPrefixTypeAWSS3

	case strings.HasPrefix(s, ResourceARNKMSPrefix):
		r.Pattern = strings.TrimPrefix(s, ResourceARNKMSPrefix)
		r.Type = ARNPrefixTypeMinIOKMS
	default:
		return Resource{}, Errorf("invalid resource '%v'", s)
	}

	if strings.HasPrefix(r.Pattern, "/") {
		return Resource{}, Errorf("invalid resource '%v' - starts with '/' will not match a bucket", s)
	}

	return r, nil
}

// NewResourceAWSS3 - creates new resource with the default ARN type of AWS S3.
func NewResourceAWSS3(pattern string) Resource {
	return Resource{
		Pattern: pattern,
		Type:    ARNPrefixTypeAWSS3,
	}
}

// NewResourceKMS - creates new resource with type KMS
func NewResourceKMS(pattern string) Resource {
	return Resource{
		Pattern: pattern,
		Type:    ARNPrefixTypeMinIOKMS,
	}
}
