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
	"strings"
	"sync"

	"github.com/minio/pkg/v3/policy/condition"
)

// Statement - iam policy statement.
type Statement struct {
	SID          ID                  `json:"Sid,omitempty"`
	Effect       Effect              `json:"Effect"`
	Actions      ActionSet           `json:"Action"`
	NotActions   ActionSet           `json:"NotAction,omitempty"`
	Resources    ResourceSet         `json:"Resource,omitempty"`
	NotResources ResourceSet         `json:"NotResource,omitempty"`
	Conditions   condition.Functions `json:"Condition,omitempty"`
}

// smallBufPool should always return a non-nil *bytes.Buffer
var smallBufPool = sync.Pool{
	New: func() interface{} { return &bytes.Buffer{} },
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (statement Statement) IsAllowed(args Args) bool {
	check := func() bool {
		if (!statement.Actions.Match(args.Action) && !statement.Actions.IsEmpty()) ||
			statement.NotActions.Match(args.Action) {
			return false
		}
		resource := smallBufPool.Get().(*bytes.Buffer)
		defer smallBufPool.Put(resource)
		resource.Reset()

		resource.WriteString(args.BucketName)
		if args.ObjectName != "" {
			if !strings.HasPrefix(args.ObjectName, "/") {
				resource.WriteByte('/')
			}

			resource.WriteString(args.ObjectName)
		} else {
			resource.WriteByte('/')
		}

		if statement.isKMS() {
			if resource.Len() == 1 && resource.String() == "/" || len(statement.Resources) == 0 {
				// In previous MinIO versions, KMS statements ignored Resources, so if len(statement.Resources) == 0,
				// allow backward compatibility by not trying to Match.

				// When resource is "/", this allows evaluating KMS statements while explicitly excluding Resource,
				// by passing Args with empty BucketName and ObjectName. This is useful when doing a
				// two-phase authorization of a request.
				return statement.Conditions.Evaluate(args.ConditionValues)
			}
		}

		// For some admin statements, resource match can be ignored.
		ignoreResourceMatch := statement.isAdmin() || statement.isSTS()

		if !ignoreResourceMatch && len(statement.Resources) > 0 && !statement.Resources.Match(resource.String(), args.ConditionValues) {
			return false
		}

		if !ignoreResourceMatch && len(statement.NotResources) > 0 && statement.NotResources.Match(resource.String(), args.ConditionValues) {
			return false
		}

		return statement.Conditions.Evaluate(args.ConditionValues)
	}

	return statement.Effect.IsAllowed(check())
}

func (statement Statement) isAdmin() bool {
	for action := range statement.Actions {
		if AdminAction(action).IsValid() {
			return true
		}
	}
	return false
}

func (statement Statement) isSTS() bool {
	for action := range statement.Actions {
		if STSAction(action).IsValid() {
			return true
		}
	}
	return false
}

func (statement Statement) isKMS() bool {
	for action := range statement.Actions {
		if KMSAction(action).IsValid() {
			return true
		}
	}
	return false
}

// isValid - checks whether statement is valid or not.
func (statement Statement) isValid() error {
	if !statement.Effect.IsValid() {
		return Errorf("invalid Effect %v", statement.Effect)
	}

	if len(statement.Actions) == 0 && len(statement.NotActions) == 0 {
		return Errorf("Action must not be empty")
	}

	if len(statement.Actions) > 0 && len(statement.NotActions) > 0 {
		return Errorf("Action and NotAction cannot be specified in the same statement")
	}

	if statement.isAdmin() {
		if err := statement.Actions.ValidateAdmin(); err != nil {
			return err
		}
		for action := range statement.Actions {
			keys := statement.Conditions.Keys()
			keyDiff := keys.Difference(adminActionConditionKeyMap[action])
			if !keyDiff.IsEmpty() {
				return Errorf("unsupported condition keys '%v' used for action '%v'", keyDiff, action)
			}
		}
		return nil
	}

	if statement.isSTS() {
		if err := statement.Actions.ValidateSTS(); err != nil {
			return err
		}
		for action := range statement.Actions {
			keys := statement.Conditions.Keys()
			keyDiff := keys.Difference(stsActionConditionKeyMap[action])
			if !keyDiff.IsEmpty() {
				return Errorf("unsupported condition keys '%v' used for action '%v'", keyDiff, action)
			}
		}
		return nil
	}

	if statement.isKMS() {
		if err := statement.Actions.ValidateKMS(); err != nil {
			return err
		}
		if err := statement.Resources.ValidateKMS(); err != nil {
			return err
		}
		if err := statement.NotResources.ValidateKMS(); err != nil {
			return err
		}
		return nil
	}

	if !statement.SID.IsValid() {
		return Errorf("invalid SID %v", statement.SID)
	}

	if len(statement.Resources) == 0 && len(statement.NotResources) == 0 {
		return Errorf("Resource must not be empty")
	}

	if len(statement.Resources) > 0 && len(statement.NotResources) > 0 {
		return Errorf("Resource and NotResource cannot be specified in the same statement")
	}

	if err := statement.Resources.ValidateS3(); err != nil {
		return err
	}

	if err := statement.NotResources.ValidateS3(); err != nil {
		return err
	}

	if err := statement.Actions.Validate(); err != nil {
		return err
	}

	for action := range statement.Actions {
		if len(statement.Resources) > 0 && !statement.Resources.ObjectResourceExists() && !statement.Resources.BucketResourceExists() {
			return Errorf("unsupported Resource found %v for action %v", statement.Resources, action)
		}
		if len(statement.NotResources) > 0 && !statement.NotResources.ObjectResourceExists() && !statement.NotResources.BucketResourceExists() {
			return Errorf("unsupported NotResource found %v for action %v", statement.NotResources, action)
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
func (statement Statement) Validate() error {
	return statement.isValid()
}

// Equals checks if two statements are equal
func (statement Statement) Equals(st Statement) bool {
	if statement.Effect != st.Effect {
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
	if !statement.NotResources.Equals(st.NotResources) {
		return false
	}
	if !statement.Conditions.Equals(st.Conditions) {
		return false
	}
	return true
}

// Clone clones Statement structure
func (statement Statement) Clone() Statement {
	return Statement{
		SID:          statement.SID,
		Effect:       statement.Effect,
		Actions:      statement.Actions.Clone(),
		NotActions:   statement.NotActions.Clone(),
		Resources:    statement.Resources.Clone(),
		NotResources: statement.NotResources.Clone(),
		Conditions:   statement.Conditions.Clone(),
	}
}

// NewStatement - creates new statement.
func NewStatement(sid ID, effect Effect, actionSet ActionSet, resourceSet ResourceSet, conditions condition.Functions) Statement {
	return Statement{
		SID:        sid,
		Effect:     effect,
		Actions:    actionSet,
		Resources:  resourceSet,
		Conditions: conditions,
	}
}

// NewStatementWithNotResource - creates new statement with NotAction.
func NewStatementWithNotResource(sid ID, effect Effect, actions ActionSet, notResources ResourceSet, conditions condition.Functions) Statement {
	return Statement{
		SID:          sid,
		Effect:       effect,
		Actions:      actions,
		NotResources: notResources,
		Conditions:   conditions,
	}
}

// NewStatementWithNotAction - creates new statement with NotAction.
func NewStatementWithNotAction(sid ID, effect Effect, notActions ActionSet, resources ResourceSet, conditions condition.Functions) Statement {
	return Statement{
		SID:        sid,
		Effect:     effect,
		NotActions: notActions,
		Resources:  resources,
		Conditions: conditions,
	}
}
