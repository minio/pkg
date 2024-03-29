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

package condition

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestFunctionsEvaluate(t *testing.T) {
	func1, err := newNullFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewBoolValue(true)), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2, err := newIPAddressFunc(AWSSourceIP.ToKey(), NewValueSet(NewStringValue("192.168.1.0/24")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func3, err := newStringEqualsFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func4, err := newStringLikeFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject*")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case1Function := NewFunctions(func1, func2, func3, func4)

	testCases := []struct {
		functions      Functions
		values         map[string][]string
		expectedResult bool
	}{
		{case1Function, map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		}, false},
		{case1Function, map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
			"Refer":             {"http://example.org/"},
		}, false},
		{case1Function, map[string][]string{"x-amz-copy-source": {"mybucket/myobject"}}, false},
		{case1Function, map[string][]string{"SourceIp": {"192.168.1.10"}}, false},
		{case1Function, map[string][]string{
			"x-amz-copy-source": {"mybucket/yourobject"},
			"SourceIp":          {"192.168.1.10"},
		}, false},
		{case1Function, map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.2.10"},
		}, false},
		{case1Function, map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"Refer":             {"http://example.org/"},
		}, false},
	}

	for i, testCase := range testCases {
		result := testCase.functions.Evaluate(testCase.values)

		if result != testCase.expectedResult {
			t.Errorf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestFunctionsKeys(t *testing.T) {
	func1, err := newNullFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewBoolValue(true)), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2, err := newIPAddressFunc(AWSSourceIP.ToKey(), NewValueSet(NewStringValue("192.168.1.0/24")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func3, err := newStringEqualsFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func4, err := newStringLikeFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject*")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	testCases := []struct {
		functions      Functions
		expectedResult KeySet
	}{
		{NewFunctions(func1, func2, func3, func4), NewKeySet(S3XAmzCopySource.ToKey(), AWSSourceIP.ToKey())},
	}

	for i, testCase := range testCases {
		result := testCase.functions.Keys()

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestFunctionsMarshalJSON(t *testing.T) {
	func1, err := newStringLikeFunc(S3XAmzMetadataDirective.ToKey(), NewValueSet(NewStringValue("REPL*")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2, err := newStringEqualsFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func3, err := newStringNotEqualsFunc(S3XAmzServerSideEncryption.ToKey(), NewValueSet(NewStringValue("AES256")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func3SSEKMS, err := newStringNotEqualsFunc(S3XAmzServerSideEncryption.ToKey(), NewValueSet(NewStringValue("aws:kms")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func4, err := newNotIPAddressFunc(AWSSourceIP.ToKey(),
		NewValueSet(NewStringValue("10.1.10.0/24")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func5, err := newStringNotLikeFunc(S3XAmzStorageClass.ToKey(), NewValueSet(NewStringValue("STANDARD")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func6, err := newNullFunc(S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(), NewValueSet(NewBoolValue(true)), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func7, err := newIPAddressFunc(AWSSourceIP.ToKey(),
		NewValueSet(NewStringValue("192.168.1.0/24")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case1Result := []byte(`{"IpAddress":{"aws:SourceIp":["192.168.1.0/24"]},"NotIpAddress":{"aws:SourceIp":["10.1.10.0/24"]},"Null":{"s3:x-amz-server-side-encryption-customer-algorithm":[true]},"StringEquals":{"s3:x-amz-copy-source":["mybucket/myobject"]},"StringLike":{"s3:x-amz-metadata-directive":["REPL*"]},"StringNotEquals":{"s3:x-amz-server-side-encryption":["AES256"]},"StringNotLike":{"s3:x-amz-storage-class":["STANDARD"]}}`)
	case1ResultKMS := []byte(`{"IpAddress":{"aws:SourceIp":["192.168.1.0/24"]},"NotIpAddress":{"aws:SourceIp":["10.1.10.0/24"]},"Null":{"s3:x-amz-server-side-encryption-customer-algorithm":[true]},"StringEquals":{"s3:x-amz-copy-source":["mybucket/myobject"]},"StringLike":{"s3:x-amz-metadata-directive":["REPL*"]},"StringNotEquals":{"s3:x-amz-server-side-encryption":["aws:kms"]},"StringNotLike":{"s3:x-amz-storage-class":["STANDARD"]}}`)

	case2Result := []byte(`{"Null":{"s3:x-amz-server-side-encryption-customer-algorithm":[true]}}`)

	testCases := []struct {
		functions      Functions
		expectedResult []byte
		expectErr      bool
	}{
		{NewFunctions(func1, func2, func3, func4, func5, func6, func7), case1Result, false},
		{NewFunctions(func1, func2, func3SSEKMS, func4, func5, func6, func7), case1ResultKMS, false},
		{NewFunctions(func6), case2Result, false},
		{NewFunctions(), []byte(`{}`), false},
		{nil, []byte(`{}`), false},
	}

	for i, testCase := range testCases {
		result, err := json.Marshal(testCase.functions)
		expectErr := (err != nil)

		if testCase.expectErr != expectErr {
			fmt.Println(err)
			t.Fatalf("case %v: error: expected: %v, got: %v %v", i+1, testCase.expectErr, expectErr, string(case1Result))
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("case %v: result: expected: %v, got: %v", i+1, string(testCase.expectedResult), string(result))
			}
		}
	}
}

func TestFunctionsUnmarshalJSON(t *testing.T) {
	case1Data := []byte(`{
    "StringLike": {
        "s3:x-amz-metadata-directive": "REPL*"
    },
    "StringEquals": {
        "s3:x-amz-copy-source": "mybucket/myobject"
    },
    "StringNotEquals": {
        "s3:x-amz-server-side-encryption": "AES256"
    },
    "NotIpAddress": {
        "aws:SourceIp": [
            "10.1.10.0/24",
            "10.10.1.0/24"
        ]
    },
    "StringNotLike": {
        "s3:x-amz-storage-class": "STANDARD"
    },
    "Null": {
        "s3:x-amz-server-side-encryption-customer-algorithm": true
    },
    "IpAddress": {
        "aws:SourceIp": [
            "192.168.1.0/24",
            "192.168.2.0/24"
        ]
    }
}`)
	func1, err := newStringLikeFunc(S3XAmzMetadataDirective.ToKey(), NewValueSet(NewStringValue("REPL*")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2, err := newStringEqualsFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func3, err := newStringNotEqualsFunc(S3XAmzServerSideEncryption.ToKey(), NewValueSet(NewStringValue("AES256")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func4, err := newNotIPAddressFunc(AWSSourceIP.ToKey(),
		NewValueSet(NewStringValue("10.1.10.0/24"), NewStringValue("10.10.1.0/24")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func5, err := newStringNotLikeFunc(S3XAmzStorageClass.ToKey(), NewValueSet(NewStringValue("STANDARD")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func6, err := newNullFunc(S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(), NewValueSet(NewBoolValue(true)), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func7, err := newIPAddressFunc(AWSSourceIP.ToKey(),
		NewValueSet(NewStringValue("192.168.1.0/24"), NewStringValue("192.168.2.0/24")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case2Data := []byte(`{
    "Null": {
        "s3:x-amz-server-side-encryption-customer-algorithm": true
    },
    "Null": {
        "s3:x-amz-server-side-encryption-customer-algorithm": "true"
    }
}`)

	case3Data := []byte(`{}`)

	case4Data := []byte(`{
    "StringLike": {
        "s3:x-amz-metadata-directive": "REPL*"
    },
    "StringEquals": {
        "s3:x-amz-copy-source": "mybucket/myobject",
        "s3:prefix": [
           "",
           "home/"
        ],
        "s3:delimiter": [
           "/"
        ]
    },
    "StringNotEquals": {
        "s3:x-amz-server-side-encryption": "AES256"
    },
    "NotIpAddress": {
        "aws:SourceIp": [
            "10.1.10.0/24",
            "10.10.1.0/24"
        ]
    },
    "StringNotLike": {
        "s3:x-amz-storage-class": "STANDARD"
    },
    "Null": {
        "s3:x-amz-server-side-encryption-customer-algorithm": true
    },
    "IpAddress": {
        "aws:SourceIp": [
            "192.168.1.0/24",
            "192.168.2.0/24"
        ]
    }
}`)

	func2_1, err := newStringEqualsFunc(S3XAmzCopySource.ToKey(), NewValueSet(NewStringValue("mybucket/myobject")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2_2, err := newStringEqualsFunc(S3Prefix.ToKey(), NewValueSet(NewStringValue(""), NewStringValue("home/")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2_3, err := newStringEqualsFunc(S3Delimiter.ToKey(), NewValueSet(NewStringValue("/")), "")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	testCases := []struct {
		data           []byte
		expectedResult Functions
		expectErr      bool
	}{
		// Success case, basic conditions.
		{case1Data, NewFunctions(func1, func2, func3, func4, func5, func6, func7), false},
		// Duplicate conditions, success case only one value is preserved.
		{case2Data, NewFunctions(func6), false},
		// empty condition error.
		{case3Data, nil, true},
		// Success case multiple keys, same condition.
		{case4Data, NewFunctions(func1, func2_1, func2_2, func2_3, func3, func4, func5, func6, func7), false},
	}

	for i, testCase := range testCases {
		result := new(Functions)
		err := json.Unmarshal(testCase.data, result)
		expectErr := (err != nil)

		if testCase.expectErr != expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if (*result).String() != testCase.expectedResult.String() {
				t.Fatalf("case %v: result: expected: %v, got: %v", i+1, testCase.expectedResult, *result)
			}
		}
	}
}
