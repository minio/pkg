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
	"io"

	iamp "github.com/minio/pkg/iam/policy"
)

// DefaultVersion - default policy version as per AWS S3 specification.
const DefaultVersion = "2012-10-17"

// Args - arguments to policy to check whether it is allowed
type Args struct {
	AccountName     string              `json:"account"`
	Groups          []string            `json:"groups"`
	Action          iamp.Action         `json:"action"`
	BucketName      string              `json:"bucket"`
	ConditionValues map[string][]string `json:"conditions"`
	IsOwner         bool                `json:"owner"`
	ObjectName      string              `json:"object"`
}

// Policy - bucket policy.
type Policy struct {
	ID         iamp.ID `json:"ID,omitempty"`
	Version    string
	Statements []Statement `json:"Statement"`
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (policy Policy) IsAllowed(args Args) bool {
	// Check all deny statements. If any one statement denies, return false.
	for _, statement := range policy.Statements {
		if statement.Effect == iamp.Deny {
			if !statement.IsAllowed(args) {
				return false
			}
		}
	}

	// For owner, its allowed by default.
	if args.IsOwner {
		return true
	}

	// Check all allow statements. If any one statement allows, return true.
	for _, statement := range policy.Statements {
		if statement.Effect == iamp.Allow {
			if statement.IsAllowed(args) {
				return true
			}
		}
	}

	return false
}

// IsEmpty - returns whether policy is empty or not.
func (policy Policy) IsEmpty() bool {
	return len(policy.Statements) == 0
}

// isValid - checks if Policy is valid or not.
func (policy Policy) isValid() error {
	if policy.Version != DefaultVersion && policy.Version != "" {
		return Errorf("invalid version '%v'", policy.Version)
	}

	for _, statement := range policy.Statements {
		if err := statement.isValid(); err != nil {
			return err
		}
	}

	return nil
}

// MarshalJSON - encodes Policy to JSON data.
func (policy Policy) MarshalJSON() ([]byte, error) {
	if err := policy.isValid(); err != nil {
		return nil, err
	}

	// subtype to avoid recursive call to MarshalJSON()
	type subPolicy Policy
	return json.Marshal(subPolicy(policy))
}

// MergePolicies merges all the given policies into a single policy dropping any
// duplicate statements.
func MergePolicies(inputs ...Policy) Policy {
	var merged Policy
	for _, p := range inputs {
		if merged.Version == "" {
			merged.Version = p.Version
		}
		for _, st := range p.Statements {
			merged.Statements = append(merged.Statements, st.Clone())
		}
	}
	merged.dropDuplicateStatements()
	return merged
}

func (policy *Policy) dropDuplicateStatements() {
	dups := make(map[int]struct{})
	for i := range policy.Statements {
		if _, ok := dups[i]; ok {
			// i is already a duplicate of some statement, so we do not need to
			// compare with it.
			continue
		}
		for j := i + 1; j < len(policy.Statements); j++ {
			if !policy.Statements[i].Equals(policy.Statements[j]) {
				continue
			}

			// save duplicate statement index for removal.
			dups[j] = struct{}{}
		}
	}

	// remove duplicate items from the slice.
	var c int
	for i := range policy.Statements {
		if _, ok := dups[i]; ok {
			continue
		}
		policy.Statements[c] = policy.Statements[i]
		c++
	}
	policy.Statements = policy.Statements[:c]
}

// UnmarshalJSON - decodes JSON data to Policy.
func (policy *Policy) UnmarshalJSON(data []byte) error {
	// subtype to avoid recursive call to UnmarshalJSON()
	type subPolicy Policy
	var sp subPolicy
	if err := json.Unmarshal(data, &sp); err != nil {
		return err
	}

	p := Policy(sp)
	if err := p.isValid(); err != nil {
		return err
	}

	p.dropDuplicateStatements()

	*policy = p

	return nil
}

// Validate - validates all statements are for given bucket or not.
func (policy Policy) Validate(bucketName string) error {
	if err := policy.isValid(); err != nil {
		return err
	}

	for _, statement := range policy.Statements {
		if err := statement.Validate(bucketName); err != nil {
			return err
		}
	}

	return nil
}

// ParseConfig - parses data in given reader to Policy.
func ParseConfig(reader io.Reader, bucketName string) (*Policy, error) {
	var policy Policy

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, Errorf("%w", err)
	}

	err := policy.Validate(bucketName)
	return &policy, err
}

// Equals returns true if the two policies are identical
func (policy *Policy) Equals(p Policy) bool {
	if policy.ID != p.ID || policy.Version != p.Version {
		return false
	}
	if len(policy.Statements) != len(p.Statements) {
		return false
	}
	for i, st := range policy.Statements {
		if !p.Statements[i].Equals(st) {
			return false
		}
	}
	return true
}
