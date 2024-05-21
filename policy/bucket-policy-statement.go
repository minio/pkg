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
	"strings"

	"github.com/minio/pkg/v3/policy/condition"
)

// BPStatement - policy statement.
type BPStatement struct {
	SID        ID                  `json:"Sid,omitempty"`
	Effect     Effect              `json:"Effect"`
	Principal  Principal           `json:"Principal"`
	Actions    ActionSet           `json:"Action"`
	NotActions ActionSet           `json:"NotAction,omitempty"`
	Resources  ResourceSet         `json:"Resource"`
	Conditions condition.Functions `json:"Condition,omitempty"`
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (statement BPStatement) IsAllowed(args BucketPolicyArgs) bool {
	check := func() bool {
		if !statement.Principal.Match(args.AccountName) {
			return false
		}

		if (!statement.Actions.Match(args.Action) && !statement.Actions.IsEmpty()) ||
			statement.NotActions.Match(args.Action) {
			return false
		}

		resource := args.BucketName
		if args.ObjectName != "" {
			if !strings.HasPrefix(args.ObjectName, "/") {
				resource += "/"
			}

			resource += args.ObjectName
		}

		if !statement.Resources.Match(resource, args.ConditionValues) {
			return false
		}

		return statement.Conditions.Evaluate(args.ConditionValues)
	}

	return statement.Effect.IsAllowed(check())
}

// isValid - checks whether statement is valid or not.
func (statement BPStatement) isValid() error {
	if !statement.Effect.IsValid() {
		return Errorf("invalid Effect %v", statement.Effect)
	}

	if !statement.Principal.IsValid() {
		return Errorf("invalid Principal %v", statement.Principal)
	}

	if len(statement.Actions) == 0 && len(statement.NotActions) == 0 {
		return Errorf("Action must not be empty")
	}

	if len(statement.Resources) == 0 {
		return Errorf("Resource must not be empty")
	}

	for action := range statement.Actions {
		if action.IsObjectAction() {
			if !statement.Resources.ObjectResourceExists() {
				return Errorf("unsupported Resource found %v for action %v", statement.Resources, action)
			}
		} else {
			if !statement.Resources.BucketResourceExists() {
				return Errorf("unsupported Resource found %v for action %v", statement.Resources, action)
			}
		}

		keys := statement.Conditions.Keys()
		keyDiff := keys.Difference(IAMActionConditionKeyMap.Lookup(action))
		if !keyDiff.IsEmpty() {
			return Errorf("unsupported condition keys '%v' used for action '%v'", keyDiff, action)
		}
	}

	return nil
}

// Validate - validates Statement is for given bucket or not.
func (statement BPStatement) Validate(bucketName string) error {
	if err := statement.isValid(); err != nil {
		return err
	}

	return statement.Resources.ValidateBucket(bucketName)
}

// Equals checks if two statements are equal
func (statement BPStatement) Equals(st BPStatement) bool {
	if statement.Effect != st.Effect {
		return false
	}
	if !statement.Principal.Equals(st.Principal) {
		return false
	}
	if !statement.Actions.Equals(st.Actions) {
		return false
	}
	if !statement.NotActions.Equals(st.NotActions) {
		return false
	}
	if !statement.Resources.Equals(st.Resources) {
		return false
	}
	if !statement.Conditions.Equals(st.Conditions) {
		return false
	}
	return true
}

// Clone clones Statement structure
func (statement BPStatement) Clone() BPStatement {
	return BPStatement{
		SID:        statement.SID,
		Effect:     statement.Effect,
		Principal:  statement.Principal.Clone(),
		Actions:    statement.Actions.Clone(),
		NotActions: statement.NotActions.Clone(),
		Resources:  statement.Resources.Clone(),
		Conditions: statement.Conditions.Clone(),
	}
}

// NewBPStatement - creates new statement.
func NewBPStatement(sid ID, effect Effect, principal Principal, actionSet ActionSet, resourceSet ResourceSet, conditions condition.Functions) BPStatement {
	return BPStatement{
		SID:        sid,
		Effect:     effect,
		Principal:  principal,
		Actions:    actionSet,
		Resources:  resourceSet,
		Conditions: conditions,
	}
}

// NewBPStatementWithNotAction - creates new statement with NotAction.
func NewBPStatementWithNotAction(sid ID, effect Effect, principal Principal, notActions ActionSet, resources ResourceSet, conditions condition.Functions) BPStatement {
	return BPStatement{
		SID:        sid,
		Effect:     effect,
		Principal:  principal,
		NotActions: notActions,
		Resources:  resources,
		Conditions: conditions,
	}
}
