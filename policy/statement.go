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
	"encoding/binary"
	"strings"
	"sync"

	"github.com/minio/pkg/v3/policy/condition"
	"github.com/zeebo/xxh3"
)

// Statement - iam policy statement.
type Statement struct {
	SID          ID                  `json:"Sid,omitempty"`
	Effect       Effect              `json:"Effect"`
	Actions      ActionSet           `json:"Action,omitempty"`
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
	return statement.IsAllowedPtr(&args)
}

// IsAllowedPtr - checks given policy args is allowed to continue the Rest API.
func (statement Statement) IsAllowedPtr(args *Args) bool {
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

		if statement.isTable() && !TableAction(args.Action).IsValid() {
			// When a tables policy statement (for example
			//   "Action":   ["s3tables:GetTableData"],
			//   "Resource": ["arn:aws:s3tables:::bucket/wh/table/uuid"]
			// ) is evaluated for a plain S3 data-path action such as
			// GetObject on (BucketName "wh", ObjectName "uuid[/...]"), the
			// action match succeeds via implicitActions. However, the
			// resource string built from Args ("wh/uuid[/...]") does not
			// look like a tables ARN suffix ("bucket/wh/table/uuid"), so a
			// direct string match against the S3 Tables resource
			// would fail. In this specific case we know:
			//   - the statement is a tables statement,
			//   - the incoming action is covered implicitly (not a table API),
			//   - and the stored policy resource is S3 Tables style.
			// To allow GetObject/ListMultipartUploadParts/etc. when
			// s3tables:GetTableData (or similar) is granted, normalize the
			// S3 data-path resource into the canonical tables form before
			// running the usual resource match.
			if !isTableResourceString(resource.String()) {
				if args.BucketName == "" || args.ObjectName == "" {
					return false
				}
				objectName := args.ObjectName
				if idx := strings.IndexByte(objectName, '/'); idx >= 0 {
					objectName = objectName[:idx]
				}
				resource.Reset()
				resource.WriteString("bucket/")
				resource.WriteString(args.BucketName)
				resource.WriteString("/table/")
				resource.WriteString(objectName)
				if !isTableResourceString(resource.String()) {
					return false
				}
			}
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

func (statement Statement) isTable() bool {
	for action := range statement.Actions {
		if TableAction(action).IsValid() {
			return true
		}
	}
	return false
}

func (statement Statement) isVectors() bool {
	for action := range statement.Actions {
		if VectorsAction(action).IsValid() {
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

	if statement.isTable() {
		if err := statement.Actions.ValidateTable(); err != nil {
			return err
		}
		for action := range statement.Actions {
			keys := statement.Conditions.Keys()
			keyDiff := keys.Difference(tableActionConditionKeyMap[action])
			if !keyDiff.IsEmpty() {
				return Errorf("unsupported condition keys '%v' used for action '%v'", keyDiff, action)
			}
		}

		if len(statement.Resources) == 0 && len(statement.NotResources) == 0 {
			return Errorf("Resource must not be empty")
		}

		if len(statement.Resources) > 0 && len(statement.NotResources) > 0 {
			return Errorf("Resource and NotResource cannot be specified in the same statement")
		}

		if err := statement.Resources.ValidateTable(); err != nil {
			return err
		}

		if err := statement.NotResources.ValidateTable(); err != nil {
			return err
		}

		for action := range statement.Actions {
			if len(statement.Resources) > 0 && !statement.Resources.ObjectResourceExists() && !statement.Resources.BucketResourceExists() {
				return Errorf("unsupported Resource found %v for action %v", statement.Resources, action)
			}
			if len(statement.NotResources) > 0 && !statement.NotResources.ObjectResourceExists() && !statement.NotResources.BucketResourceExists() {
				return Errorf("unsupported NotResource found %v for action %v", statement.NotResources, action)
			}
		}

		return nil
	}

	if statement.isVectors() {
		if err := statement.Actions.ValidateVectors(); err != nil {
			return err
		}
		for action := range statement.Actions {
			keys := statement.Conditions.Keys()
			keyDiff := keys.Difference(VectorsActionConditionKeyMap[action])
			if !keyDiff.IsEmpty() {
				return Errorf("unsupported condition keys '%v' used for action '%v'", keyDiff, action)
			}
		}

		if len(statement.Resources) == 0 && len(statement.NotResources) == 0 {
			return Errorf("Resource must not be empty")
		}

		if len(statement.Resources) > 0 && len(statement.NotResources) > 0 {
			return Errorf("Resource and NotResource cannot be specified in the same statement")
		}

		if err := statement.Resources.ValidateVectors(); err != nil {
			return err
		}

		if err := statement.NotResources.ValidateVectors(); err != nil {
			return err
		}

		for action := range statement.Actions {
			if len(statement.Resources) > 0 && !statement.Resources.ObjectResourceExists() && !statement.Resources.BucketResourceExists() {
				return Errorf("unsupported Resource found %v for action %v", statement.Resources, action)
			}
			if len(statement.NotResources) > 0 && !statement.NotResources.ObjectResourceExists() && !statement.NotResources.BucketResourceExists() {
				return Errorf("unsupported NotResource found %v for action %v", statement.NotResources, action)
			}
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

// Equals checks if two statements are equal
func (statement Statement) hash(seed uint64) [16]byte {
	// Order independent xor.
	xorTo := func(dst *xxh3.Uint128, v xxh3.Uint128) {
		dst.Lo ^= v.Lo
		dst.Hi ^= v.Hi
	}
	// Add value with seed.
	xorInt := func(dst *xxh3.Uint128, n int, seed uint64) {
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], uint64(n))
		xorTo(dst, xxh3.Hash128Seed(tmp[:], seed))
	}

	h := xxh3.HashString128Seed(string(statement.Effect), seed)

	xorInt(&h, len(statement.Actions), seed+1)
	for action := range statement.Actions {
		xorTo(&h, xxh3.HashString128Seed(string(action), seed+2))
	}

	xorInt(&h, len(statement.NotActions), seed+3)
	for action := range statement.NotActions {
		xorTo(&h, xxh3.HashString128Seed(string(action), seed+4))
	}

	xorInt(&h, len(statement.Resources), seed+5)
	for res := range statement.Resources {
		xorTo(&h, xxh3.HashString128Seed(res.Pattern+res.Type.String(), seed+6))
	}

	xorInt(&h, len(statement.Conditions), seed+7)
	for _, cond := range statement.Conditions {
		xorTo(&h, xxh3.HashString128Seed(cond.String(), seed+8))
	}
	return h.Bytes()
}
