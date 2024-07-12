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
	"reflect"
	"testing"
)

func TestResourceIsBucketPattern(t *testing.T) {
	testCases := []struct {
		resource       Resource
		expectedResult bool
	}{
		{NewResourceS3("*"), true},
		{NewResourceS3("mybucket"), true},
		{NewResourceS3("mybucket*"), true},
		{NewResourceS3("mybucket?0"), true},
		{NewResourceS3("*/*"), false},
		{NewResourceS3("mybucket/*"), false},
		{NewResourceS3("mybucket*/myobject"), false},
		{NewResourceS3("mybucket?0/2010/photos/*"), false},

		{NewResourceKMS("*"), true},
		{NewResourceKMS("mykey"), true},
		{NewResourceKMS("mykey*"), true},
		{NewResourceKMS("mykey?0"), true},
	}

	for i, testCase := range testCases {
		result := testCase.resource.isBucketPattern()

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceIsObjectPattern(t *testing.T) {
	testCases := []struct {
		resource       Resource
		expectedResult bool
	}{
		{NewResourceS3("*"), true},
		{NewResourceS3("mybucket*"), true},
		{NewResourceS3("*/*"), true},
		{NewResourceS3("mybucket/*"), true},
		{NewResourceS3("mybucket*/myobject"), true},
		{NewResourceS3("mybucket?0/2010/photos/*"), true},
		{NewResourceS3("mybucket"), false},
		{NewResourceS3("mybucket?0"), false},
	}

	for i, testCase := range testCases {
		result := testCase.resource.isObjectPattern()

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceIsValid(t *testing.T) {
	testCases := []struct {
		resource       Resource
		expectedResult bool
	}{
		{NewResourceS3("*"), true},
		{NewResourceS3("mybucket*"), true},
		{NewResourceS3("*/*"), true},
		{NewResourceS3("mybucket/*"), true},
		{NewResourceS3("mybucket*/myobject"), true},
		{NewResourceS3("mybucket?0/2010/photos/*"), true},
		{NewResourceS3("mybucket"), true},
		{NewResourceS3("mybucket?0"), true},
		{NewResourceS3("/*"), false},
		{NewResourceS3(""), false},

		{NewResourceKMS("*"), true},
		{NewResourceKMS("mykey*"), true},
		{NewResourceKMS("*/*"), false},
		{NewResourceKMS("mykey/*"), false},
		{NewResourceKMS("mykey/"), false},
		{NewResourceKMS("./mykey"), false},
		{NewResourceKMS("../../mykey"), false},
		{NewResourceKMS(""), false},
	}

	for i, testCase := range testCases {
		result := testCase.resource.IsValid()

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceMatch(t *testing.T) {
	// Only test with valid resources (specifically, resources must not start
	// with '/')
	testCases := []struct {
		resource       Resource
		objectName     string
		expectedResult bool
	}{
		{NewResourceS3("*"), "mybucket", true},
		{NewResourceS3("*"), "mybucket/myobject", true},
		{NewResourceS3("mybucket*"), "mybucket", true},
		{NewResourceS3("mybucket*"), "mybucket/myobject", true},
		{NewResourceS3("*/*"), "mybucket/myobject", true},
		{NewResourceS3("mybucket/*"), "mybucket/myobject", true},
		{NewResourceS3("mybucket*/myobject"), "mybucket/myobject", true},
		{NewResourceS3("mybucket*/myobject"), "mybucket100/myobject", true},
		{NewResourceS3("mybucket?0/2010/photos/*"), "mybucket20/2010/photos/1.jpg", true},
		{NewResourceS3("mybucket"), "mybucket", true},
		{NewResourceS3("mybucket?0"), "mybucket30", true},
		{NewResourceS3("*/*"), "mybucket", false},
		{NewResourceS3("mybucket/*"), "mybucket10/myobject", false},
		{NewResourceS3("mybucket?0/2010/photos/*"), "mybucket0/2010/photos/1.jpg", false},
		{NewResourceS3("mybucket"), "mybucket/myobject", false},
	}

	for i, testCase := range testCases {
		result := testCase.resource.Match(testCase.objectName, nil)

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceMarshalJSON(t *testing.T) {
	// Only test with valid resources (specifically, resources must not start
	// with '/')
	testCases := []struct {
		resource       Resource
		expectedResult []byte
		expectErr      bool
	}{
		{NewResourceS3("*"), []byte(`"arn:aws:s3:::*"`), false},
		{NewResourceS3("mybucket*"), []byte(`"arn:aws:s3:::mybucket*"`), false},
		{NewResourceS3("mybucket"), []byte(`"arn:aws:s3:::mybucket"`), false},
		{NewResourceS3("*/*"), []byte(`"arn:aws:s3:::*/*"`), false},
		{NewResourceS3("mybucket/*"), []byte(`"arn:aws:s3:::mybucket/*"`), false},
		{NewResourceS3("mybucket*/myobject"), []byte(`"arn:aws:s3:::mybucket*/myobject"`), false},
		{NewResourceS3("mybucket?0/2010/photos/*"), []byte(`"arn:aws:s3:::mybucket?0/2010/photos/*"`), false},
		{Resource{}, nil, true},
	}

	for i, testCase := range testCases {
		result, err := json.Marshal(testCase.resource)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("case %v: result: expected: %v, got: %v", i+1, string(testCase.expectedResult), string(result))
			}
		}
	}
}

func TestResourceUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		data           []byte
		expectedResult Resource
		expectErr      bool
	}{
		{[]byte(`"arn:aws:s3:::*"`), NewResourceS3("*"), false},
		{[]byte(`"arn:aws:s3:::mybucket*"`), NewResourceS3("mybucket*"), false},
		{[]byte(`"arn:aws:s3:::mybucket"`), NewResourceS3("mybucket"), false},
		{[]byte(`"arn:aws:s3:::*/*"`), NewResourceS3("*/*"), false},
		{[]byte(`"arn:aws:s3:::mybucket/*"`), NewResourceS3("mybucket/*"), false},
		{[]byte(`"arn:aws:s3:::mybucket*/myobject"`), NewResourceS3("mybucket*/myobject"), false},
		{[]byte(`"arn:aws:s3:::mybucket?0/2010/photos/*"`), NewResourceS3("mybucket?0/2010/photos/*"), false},
		{[]byte(`"mybucket/myobject*"`), Resource{}, true},
		{[]byte(`"arn:aws:s3:::/*"`), Resource{}, true},
	}

	for i, testCase := range testCases {
		var result Resource
		err := json.Unmarshal(testCase.data, &result)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("case %v: result: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestResourceValidate(t *testing.T) {
	testCases := []struct {
		resource  Resource
		expectErr bool
	}{
		{NewResourceS3("mybucket/myobject*"), false},
		{NewResourceS3("/myobject*"), true},
		{NewResourceS3("/"), true},
	}

	for i, testCase := range testCases {
		err := testCase.resource.Validate()
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestResourceValidateBucket(t *testing.T) {
	testCases := []struct {
		resource   Resource
		bucketName string
		expectErr  bool
	}{
		{NewResourceS3("mybucket/myobject*"), "mybucket", false},
		{NewResourceS3("/myobject*"), "yourbucket", true},
		{NewResourceS3("mybucket/myobject*"), "yourbucket", true},
		{NewResourceS3("mybucket*a/myobject*"), "mybucket-east-a", false},

		// Following test cases **should validate** successfully - they are
		// corner cases for the given patterns and buckets.
		{NewResourceS3("mybucket*a/myobject*"), "mybucket", false},
		{NewResourceS3("mybucket*a/myobject*"), "mybucket22", false},
	}

	for i, testCase := range testCases {
		err := testCase.resource.ValidateBucket(testCase.bucketName)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Errorf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}
