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
	"github.com/minio/pkg/v3/policy/condition"
	"github.com/minio/pkg/v3/wildcard"
)

// Action - policy action.
// Refer https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html
// for more information about available actions.
type Action string

// IsObjectAction - returns whether action is object type or not.
func (action Action) IsObjectAction() bool {
	for supAction := range SupportedObjectActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

// Match - matches action name with action patter.
func (action Action) Match(a Action) bool {
	return wildcard.Match(string(action), string(a))
}

// IsValid - checks if action is valid or not.
func (action Action) IsValid() bool {
	for supAction := range SupportedActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

// ActionConditionKeyMap is alias for the map type used here.
type ActionConditionKeyMap map[Action]condition.KeySet

func newActionKeySet(base []condition.KeyName, extra ...condition.KeyName) condition.KeySet {
	keys := make([]condition.Key, 0, len(base)+len(extra))
	for _, name := range base {
		keys = append(keys, name.ToKey())
	}
	for _, name := range extra {
		keys = append(keys, name.ToKey())
	}
	return condition.NewKeySet(keys...)
}

// Lookup - looks up the action in the condition key map.
func (a ActionConditionKeyMap) Lookup(action Action) condition.KeySet {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	ckeysMerged := condition.NewKeySet(commonKeys...)
	if !bucketlessActions[action] {
		ckeysMerged.Merge(bucketTagKeys)
	}
	for act, ckey := range a {
		if action.Match(act) {
			ckeysMerged.Merge(ckey)
		}
	}
	return ckeysMerged
}

// bucketTagKeys are the keys every S3 action that acts on an existing bucket
// takes, read from that bucket's tags.
var bucketTagKeys = condition.NewKeySet(
	condition.AWSResourceTag.ToKey(),
	condition.S3BucketTag.ToKey(),
)

// bucketlessActions act on no existing bucket, so no bucket tags reach them.
var bucketlessActions = map[Action]bool{
	ListAllMyBucketsAction: true,
	CreateBucketAction:     true,
}
