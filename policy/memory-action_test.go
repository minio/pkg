// Copyright (c) 2015-2026 MinIO, Inc.
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
	"testing"
)

func TestMemoryActionIsValid(t *testing.T) {
	testCases := []struct {
		action         MemoryAction
		expectedResult bool
	}{
		{MemoryCreateCortexAction, true},
		{MemoryDeleteCortexAction, true},
		{MemoryGetCortexAction, true},
		{MemoryListCortexesAction, true},
		{MemoryPutSecretAction, true},
		{MemoryGetSecretAction, true},
		{MemoryDeleteSecretAction, true},
		{MemoryListSecretsAction, true},
		{MemorySearchAction, true},
		{AllMemoryActions, true},
		{MemoryAction("memory:FooBar"), false},
		{MemoryAction("s3tables:CreateTable"), false},
	}

	for i, testCase := range testCases {
		if result := testCase.action.IsValid(); result != testCase.expectedResult {
			t.Fatalf("case %v: action %v: expected: %v, got: %v", i+1, testCase.action, testCase.expectedResult, result)
		}
	}
}

func TestMemoryActionConditionKeys(t *testing.T) {
	for action := range SupportedMemoryActions {
		if _, ok := MemoryActionConditionKeyMap[Action(action)]; !ok {
			t.Fatalf("action %v: no condition key set registered", action)
		}
	}
}
