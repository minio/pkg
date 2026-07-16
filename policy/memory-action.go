// Copyright (c) 2015-2025 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import (
	"github.com/minio/pkg/v3/policy/condition"
)

// MemoryAction - AIStor Memory API policy action. The Memory API is a MinIO
// AIStor extension serving agent memory on a Cortex (Memory Bucket).
type MemoryAction string

const (
	// MemoryCreateCortexAction - create a Memory cortex (Memory Bucket).
	MemoryCreateCortexAction MemoryAction = "memory:CreateCortex"

	// MemoryDeleteCortexAction - delete a Memory cortex.
	MemoryDeleteCortexAction MemoryAction = "memory:DeleteCortex"

	// MemoryGetCortexAction - read a Memory cortex's metadata.
	MemoryGetCortexAction MemoryAction = "memory:GetCortex"

	// MemoryListCortexesAction - list Memory cortexes.
	MemoryListCortexesAction MemoryAction = "memory:ListCortexes"

	// MemoryPutSecretAction - write a secret in a cortex.
	MemoryPutSecretAction MemoryAction = "memory:PutSecret"

	// MemoryGetSecretAction - read a secret's decrypted value from a cortex.
	MemoryGetSecretAction MemoryAction = "memory:GetSecret"

	// MemoryDeleteSecretAction - delete a secret from a cortex.
	MemoryDeleteSecretAction MemoryAction = "memory:DeleteSecret"

	// MemoryListSecretsAction - list the secrets in a cortex.
	MemoryListSecretsAction MemoryAction = "memory:ListSecrets"

	// MemorySearchAction - search (corpus-grep) the objects in a cortex.
	MemorySearchAction MemoryAction = "memory:Search"

	// AllMemoryActions - all AIStor Memory API actions.
	AllMemoryActions MemoryAction = "memory:*"
)

// SupportedMemoryActions - list of all supported AIStor Memory API actions.
var SupportedMemoryActions = map[MemoryAction]struct{}{
	MemoryCreateCortexAction: {},
	MemoryDeleteCortexAction: {},
	MemoryGetCortexAction:    {},
	MemoryListCortexesAction: {},
	MemoryPutSecretAction:    {},
	MemoryGetSecretAction:    {},
	MemoryDeleteSecretAction: {},
	MemoryListSecretsAction:  {},
	MemorySearchAction:       {},
	AllMemoryActions:         {},
}

// IsValid - checks if action is valid or not.
func (action MemoryAction) IsValid() bool {
	_, ok := SupportedMemoryActions[action]
	return ok
}

func createMemoryActionConditionKeyMap() map[Action]condition.KeySet {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	memoryActionConditionKeyMap := map[Action]condition.KeySet{}
	for act := range SupportedMemoryActions {
		memoryActionConditionKeyMap[Action(act)] = condition.NewKeySet(commonKeys...)
	}

	return memoryActionConditionKeyMap
}

// MemoryActionConditionKeyMap - holds mapping of Memory actions to condition keys.
var MemoryActionConditionKeyMap = createMemoryActionConditionKeyMap()
