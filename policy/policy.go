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
	"strings"

	"github.com/minio/minio-go/v7/pkg/set"
)

// DefaultVersion - default policy version as per AWS S3 specification.
const DefaultVersion = "2012-10-17"

// Args - arguments to policy to check whether it is allowed
type Args struct {
	AccountName     string                 `json:"account"`
	Groups          []string               `json:"groups"`
	Action          Action                 `json:"action"`
	BucketName      string                 `json:"bucket"`
	ConditionValues map[string][]string    `json:"conditions"`
	IsOwner         bool                   `json:"owner"`
	ObjectName      string                 `json:"object"`
	Claims          map[string]interface{} `json:"claims"`
	DenyOnly        bool                   `json:"denyOnly"` // only applies deny
}

// GetValuesFromClaims returns the list of values for the input claimName.
// Supports values in following formats
// - string
// - comma separated values
// - string array
func GetValuesFromClaims(claims map[string]interface{}, claimName string) (set.StringSet, bool) {
	s := set.NewStringSet()
	pname, ok := claims[claimName]
	if !ok {
		return s, false
	}
	pnames, ok := pname.([]interface{})
	if !ok {
		pnameStr, ok := pname.(string)
		if ok {
			for _, pname := range strings.Split(pnameStr, ",") {
				pname = strings.TrimSpace(pname)
				if pname == "" {
					// ignore any empty strings, considerate
					// towards some user errors.
					continue
				}
				s.Add(pname)
			}
			return s, true
		}
		return s, false
	}
	for _, pname := range pnames {
		pnameStr, ok := pname.(string)
		if ok {
			for _, pnameStr := range strings.Split(pnameStr, ",") {
				pnameStr = strings.TrimSpace(pnameStr)
				if pnameStr == "" {
					// ignore any empty strings, considerate
					// towards some user errors.
					continue
				}
				s.Add(pnameStr)
			}
		}
	}
	return s, true
}

// GetPoliciesFromClaims returns the list of policies to be applied for this
// incoming request, extracting the information from input JWT claims.
func GetPoliciesFromClaims(claims map[string]interface{}, policyClaimName string) (set.StringSet, bool) {
	return GetValuesFromClaims(claims, policyClaimName)
}

// GetPolicies returns the list of policies to be applied for this
// incoming request, extracting the information from JWT claims.
func (a Args) GetPolicies(policyClaimName string) (set.StringSet, bool) {
	return GetPoliciesFromClaims(a.Claims, policyClaimName)
}

// GetRoleArn returns the role ARN from JWT claims if present. Otherwise returns
// empty string.
func (a Args) GetRoleArn() string {
	s, ok := a.Claims["roleArn"]
	roleArn, ok2 := s.(string)
	if ok && ok2 {
		return roleArn
	}
	return ""
}

// Policy - iam bucket iamp.
type Policy struct {
	ID         ID `json:"ID,omitempty"`
	Version    string
	Statements []Statement `json:"Statement"`
}

// MatchResource matches resource with match resource patterns
func (iamp Policy) MatchResource(resource string) bool {
	for _, statement := range iamp.Statements {
		if statement.Resources.MatchResource(resource) {
			return true
		}
	}
	return false
}

// IsAllowedActions returns all supported actions for this policy.
func (iamp Policy) IsAllowedActions(bucketName, objectName string, conditionValues map[string][]string) ActionSet {
	actionSet := make(ActionSet)
	for action := range supportedActions {
		if iamp.IsAllowed(Args{
			BucketName:      bucketName,
			ObjectName:      objectName,
			Action:          action,
			ConditionValues: conditionValues,
		}) {
			actionSet.Add(action)
		}
	}
	for action := range supportedAdminActions {
		admAction := Action(action)
		if iamp.IsAllowed(Args{
			BucketName:      bucketName,
			ObjectName:      objectName,
			Action:          admAction,
			ConditionValues: conditionValues,
			// checks mainly for actions that can have explicit
			// deny, while without it are implicitly enabled.
			DenyOnly: action == CreateServiceAccountAdminAction || action == CreateUserAdminAction,
		}) {
			actionSet.Add(admAction)
		}
	}
	for action := range supportedKMSActions {
		kmsAction := Action(action)
		if iamp.IsAllowed(Args{
			BucketName:      bucketName,
			ObjectName:      objectName,
			Action:          kmsAction,
			ConditionValues: conditionValues,
		}) {
			actionSet.Add(kmsAction)
		}
	}

	return actionSet
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (iamp Policy) IsAllowed(args Args) bool {
	// Check all deny statements. If any one statement denies, return false.
	for _, statement := range iamp.Statements {
		if statement.Effect == Deny {
			if !statement.IsAllowed(args) {
				return false
			}
		}
	}

	// Applied any 'Deny' only policies, if we have
	// reached here it means that there were no 'Deny'
	// policies - this function mainly used for
	// specific scenarios where we only want to validate
	// 'Deny' only policies.
	if args.DenyOnly {
		return true
	}

	// For owner, its allowed by default.
	if args.IsOwner {
		return true
	}

	// Check all allow statements. If any one statement allows, return true.
	for _, statement := range iamp.Statements {
		if statement.Effect == Allow {
			if statement.IsAllowed(args) {
				return true
			}
		}
	}

	return false
}

// IsEmpty - returns whether policy is empty or not.
func (iamp Policy) IsEmpty() bool {
	return len(iamp.Statements) == 0
}

// isValid - checks if Policy is valid or not.
func (iamp Policy) isValid() error {
	if iamp.Version != DefaultVersion && iamp.Version != "" {
		return Errorf("invalid version '%v'", iamp.Version)
	}

	for _, statement := range iamp.Statements {
		if err := statement.isValid(); err != nil {
			return err
		}
	}
	return nil
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

func (iamp *Policy) dropDuplicateStatements() {
	dups := make(map[int]struct{})
	for i := range iamp.Statements {
		if _, ok := dups[i]; ok {
			// i is already a duplicate of some statement, so we do not need to
			// compare with it.
			continue
		}
		for j := i + 1; j < len(iamp.Statements); j++ {
			if !iamp.Statements[i].Equals(iamp.Statements[j]) {
				continue
			}

			// save duplicate statement index for removal.
			dups[j] = struct{}{}
		}
	}

	// remove duplicate items from the slice.
	var c int
	for i := range iamp.Statements {
		if _, ok := dups[i]; ok {
			continue
		}
		iamp.Statements[c] = iamp.Statements[i]
		c++
	}
	iamp.Statements = iamp.Statements[:c]
}

// UnmarshalJSON - decodes JSON data to Iamp.
func (iamp *Policy) UnmarshalJSON(data []byte) error {
	// subtype to avoid recursive call to UnmarshalJSON()
	type subPolicy Policy
	var sp subPolicy
	if err := json.Unmarshal(data, &sp); err != nil {
		return err
	}

	p := Policy(sp)
	p.dropDuplicateStatements()
	*iamp = p
	return nil
}

// Validate - validates all statements are for given bucket or not.
func (iamp Policy) Validate() error {
	return iamp.isValid()
}

// ParseConfig - parses data in given reader to Iamp.
func ParseConfig(reader io.Reader) (*Policy, error) {
	var iamp Policy

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&iamp); err != nil {
		return nil, Errorf("%w", err)
	}

	return &iamp, iamp.Validate()
}

// Equals returns true if the two policies are identical
func (iamp *Policy) Equals(p Policy) bool {
	if iamp.ID != p.ID || iamp.Version != p.Version {
		return false
	}
	if len(iamp.Statements) != len(p.Statements) {
		return false
	}
	for i, st := range iamp.Statements {
		if !p.Statements[i].Equals(st) {
			return false
		}
	}
	return true
}
