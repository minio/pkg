// Copyright (c) 2015-2023 MinIO, Inc.
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

	"github.com/minio/pkg/v2/wildcard"
)

// ActionType - type of action.
type ActionType string

// Typed string constants for ActionType.
const (
	S3ActionType    ActionType = "s3"
	STSActionType   ActionType = "sts"
	KMSActionType   ActionType = "kms"
	AdminActionType ActionType = "admin"
)

// Action - policy action.
type Action string

const (
	s3ActionTypePrefix    = "s3:"
	stsActionTypePrefix   = "sts:"
	kmsActionTypePrefix   = "kms:"
	adminActionTypePrefix = "admin:"
)

// Type - returns type of action. If the action does not have a valid prefix,
// returns empty string.
func (action Action) Type() ActionType {
	s := string(action)
	switch {
	case strings.HasPrefix(s, s3ActionTypePrefix):
		return S3ActionType
	case strings.HasPrefix(s, stsActionTypePrefix):
		return STSActionType
	case strings.HasPrefix(s, kmsActionTypePrefix):
		return KMSActionType
	case strings.HasPrefix(s, adminActionTypePrefix):
		return AdminActionType
	default:
		return ""
	}
}

// IsObjectAction - returns whether action is for an object.
func (action Action) IsObjectAction() bool {
	if action.Type() != S3ActionType {
		return false
	}
	return S3Action(action).IsObjectAction()
}

// Match - matches action name with action pattern.
func (action Action) Match(a Action) bool {
	return wildcard.Match(string(action), string(a))
}

// IsValid - checks if action is valid or not.
//
// Deprecated: IsValid is deprecated, use Type() and specific action type's
// IsValid instead.
func (action Action) IsValid() bool {
	switch action.Type() {
	case S3ActionType:
		return S3Action(action).IsValid()
	case STSActionType:
		return STSAction(action).IsValid()
	case KMSActionType:
		return KMSAction(action).IsValid()
	case AdminActionType:
		return AdminAction(action).IsValid()
	default:
		return false
	}
}
