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

	"github.com/minio/pkg/v3/policy/condition"
)

func TestTableActionIsValid(t *testing.T) {
	testCases := []struct {
		action         TableAction
		expectedResult bool
	}{
		{S3TablesCreateFunctionAction, true},
		{S3TablesDeleteFunctionAction, true},
		{S3TablesGetFunctionAction, true},
		{S3TablesRenameFunctionAction, true},
		{S3TablesUpdateFunctionAction, true},
		{S3TablesListFunctionsAction, true},
		{S3TablesRegisterFunctionAction, true},
		{S3TablesGetViewAction, true},
		{AllS3TablesActions, true},
		{TableAction("s3tables:FooFunction"), false},
	}

	for i, testCase := range testCases {
		if result := testCase.action.IsValid(); result != testCase.expectedResult {
			t.Fatalf("case %v: action %v: expected: %v, got: %v", i+1, testCase.action, testCase.expectedResult, result)
		}
	}
}

func TestTableActionConditionKeys(t *testing.T) {
	functionNameKey := condition.S3TablesFunctionName.ToKey()
	namespaceKey := condition.S3TablesNamespace.ToKey()
	registerLocationKey := condition.S3TablesRegisterLocation.ToKey()

	testCases := []struct {
		action              TableAction
		expectedKeys        []condition.Key
		unexpectedKeys      []condition.Key
		expectedDescription string
	}{
		{S3TablesCreateFunctionAction, []condition.Key{namespaceKey, functionNameKey}, nil, "create carries namespace and function name"},
		{S3TablesDeleteFunctionAction, []condition.Key{namespaceKey, functionNameKey}, nil, "delete carries namespace and function name"},
		{S3TablesGetFunctionAction, []condition.Key{namespaceKey, functionNameKey}, nil, "get carries namespace and function name"},
		{S3TablesRenameFunctionAction, []condition.Key{namespaceKey, functionNameKey}, nil, "rename carries namespace and function name"},
		{S3TablesUpdateFunctionAction, []condition.Key{namespaceKey, functionNameKey}, nil, "update carries namespace and function name"},
		{S3TablesRegisterFunctionAction, []condition.Key{namespaceKey, functionNameKey, registerLocationKey}, nil, "register also carries the register location"},
		{S3TablesListFunctionsAction, []condition.Key{namespaceKey}, []condition.Key{functionNameKey}, "list is namespace-scoped, not function-scoped"},
		{AllS3TablesActions, []condition.Key{functionNameKey}, nil, "the wildcard action supports the function name key"},
	}

	for i, testCase := range testCases {
		keySet, ok := tableActionConditionKeyMap[Action(testCase.action)]
		if !ok {
			t.Fatalf("case %v: action %v: no condition key set registered", i+1, testCase.action)
		}
		for _, key := range testCase.expectedKeys {
			if !keySet.Match(key) {
				t.Fatalf("case %v (%v): action %v: expected key %v in condition key set",
					i+1, testCase.expectedDescription, testCase.action, key)
			}
		}
		for _, key := range testCase.unexpectedKeys {
			if keySet.Match(key) {
				t.Fatalf("case %v (%v): action %v: unexpected key %v in condition key set",
					i+1, testCase.expectedDescription, testCase.action, key)
			}
		}
	}
}
