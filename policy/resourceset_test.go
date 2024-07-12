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

func TestResourceSetBucketResourceExists(t *testing.T) {
	testCases := []struct {
		resourceSet    ResourceSet
		expectedResult bool
	}{
		{NewResourceSet(NewResourceS3("*")), true},
		{NewResourceSet(NewResourceS3("mybucket")), true},
		{NewResourceSet(NewResourceS3("mybucket*")), true},
		{NewResourceSet(NewResourceS3("mybucket?0")), true},
		{NewResourceSet(NewResourceS3("mybucket/2010/photos/*"),
			NewResourceS3("mybucket")), true},
		{NewResourceSet(NewResourceS3("*/*")), false},
		{NewResourceSet(NewResourceS3("mybucket/*")), false},
		{NewResourceSet(NewResourceS3("mybucket*/myobject")), false},
		{NewResourceSet(NewResourceS3("mybucket?0/2010/photos/*")), false},
	}

	for i, testCase := range testCases {
		result := testCase.resourceSet.BucketResourceExists()

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceSetObjectResourceExists(t *testing.T) {
	testCases := []struct {
		resourceSet    ResourceSet
		expectedResult bool
	}{
		{NewResourceSet(NewResourceS3("*")), true},
		{NewResourceSet(NewResourceS3("mybucket*")), true},
		{NewResourceSet(NewResourceS3("*/*")), true},
		{NewResourceSet(NewResourceS3("mybucket/*")), true},
		{NewResourceSet(NewResourceS3("mybucket*/myobject")), true},
		{NewResourceSet(NewResourceS3("mybucket?0/2010/photos/*")), true},
		{NewResourceSet(NewResourceS3("mybucket"), NewResourceS3("mybucket/2910/photos/*")), true},
		{NewResourceSet(NewResourceS3("mybucket")), false},
		{NewResourceSet(NewResourceS3("mybucket?0")), false},
	}

	for i, testCase := range testCases {
		result := testCase.resourceSet.ObjectResourceExists()

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceSetAdd(t *testing.T) {
	testCases := []struct {
		resourceSet    ResourceSet
		resource       Resource
		expectedResult ResourceSet
	}{
		{
			NewResourceSet(), NewResourceS3("mybucket/myobject*"),
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
		},
		{
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
			NewResourceS3("mybucket/yourobject*"),
			NewResourceSet(NewResourceS3("mybucket/myobject*"),
				NewResourceS3("mybucket/yourobject*")),
		},
		{
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
			NewResourceS3("mybucket/myobject*"),
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
		},
	}

	for i, testCase := range testCases {
		testCase.resourceSet.Add(testCase.resource)

		if !reflect.DeepEqual(testCase.resourceSet, testCase.expectedResult) {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, testCase.resourceSet)
		}
	}
}

func TestResourceSetIntersection(t *testing.T) {
	testCases := []struct {
		set            ResourceSet
		setToIntersect ResourceSet
		expectedResult ResourceSet
	}{
		{NewResourceSet(), NewResourceSet(NewResourceS3("mybucket/myobject*")), NewResourceSet()},
		{NewResourceSet(NewResourceS3("mybucket/myobject*")), NewResourceSet(), NewResourceSet()},
		{
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
			NewResourceSet(NewResourceS3("mybucket/myobject*"), NewResourceS3("mybucket/yourobject*")),
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
		},
	}

	for i, testCase := range testCases {
		result := testCase.set.Intersection(testCase.setToIntersect)

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, testCase.set)
		}
	}
}

func TestResourceSetMarshalJSON(t *testing.T) {
	testCases := []struct {
		resoruceSet    ResourceSet
		expectedResult []byte
		expectErr      bool
	}{
		{
			NewResourceSet(NewResourceS3("mybucket/myobject*")),
			[]byte(`["arn:aws:s3:::mybucket/myobject*"]`), false,
		},
		{
			NewResourceSet(NewResourceS3("mybucket/photos/myobject*")),
			[]byte(`["arn:aws:s3:::mybucket/photos/myobject*"]`), false,
		},
		{NewResourceSet(), []byte(`[]`), false}, // Empty resources don't return error, only empty actions do.
	}

	for i, testCase := range testCases {
		result, err := json.Marshal(testCase.resoruceSet)
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

func TestResourceSetMatch(t *testing.T) {
	testCases := []struct {
		resourceSet    ResourceSet
		resource       string
		expectedResult bool
	}{
		{NewResourceSet(NewResourceS3("*")), "mybucket", true},
		{NewResourceSet(NewResourceS3("*")), "mybucket/myobject", true},
		{NewResourceSet(NewResourceS3("mybucket*")), "mybucket", true},
		{NewResourceSet(NewResourceS3("mybucket*")), "mybucket/myobject", true},
		{NewResourceSet(NewResourceS3("*/*")), "mybucket/myobject", true},
		{NewResourceSet(NewResourceS3("mybucket/*")), "mybucket/myobject", true},
		{NewResourceSet(NewResourceS3("mybucket*/myobject")), "mybucket/myobject", true},
		{NewResourceSet(NewResourceS3("mybucket*/myobject")), "mybucket100/myobject", true},
		{NewResourceSet(NewResourceS3("mybucket?0/2010/photos/*")), "mybucket20/2010/photos/1.jpg", true},
		{NewResourceSet(NewResourceS3("mybucket")), "mybucket", true},
		{NewResourceSet(NewResourceS3("mybucket?0")), "mybucket30", true},
		{NewResourceSet(NewResourceS3("mybucket?0/2010/photos/*"),
			NewResourceS3("mybucket/2010/photos/*")), "mybucket/2010/photos/1.jpg", true},
		{NewResourceSet(NewResourceS3("*/*")), "mybucket", false},
		{NewResourceSet(NewResourceS3("mybucket/*")), "mybucket10/myobject", false},
		{NewResourceSet(NewResourceS3("mybucket")), "mybucket/myobject", false},
		{NewResourceSet(), "mybucket/myobject", false},
	}

	for i, testCase := range testCases {
		result := testCase.resourceSet.Match(testCase.resource, nil)

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestResourceSetUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		data           []byte
		expectedResult ResourceSet
		expectErr      bool
	}{
		{
			[]byte(`"arn:aws:s3:::mybucket/myobject*"`),
			NewResourceSet(NewResourceS3("mybucket/myobject*")), false,
		},
		{
			[]byte(`"arn:aws:s3:::mybucket/photos/myobject*"`),
			NewResourceSet(NewResourceS3("mybucket/photos/myobject*")), false,
		},
		{[]byte(`"arn:aws:s3:::mybucket"`), NewResourceSet(NewResourceS3("mybucket")), false},
		{[]byte(`"mybucket/myobject*"`), nil, true},
	}

	for i, testCase := range testCases {
		var result ResourceSet
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

func TestResourceSetAWSS3Validate(t *testing.T) {
	testCases := []struct {
		resourceSet ResourceSet
		expectErr   bool
	}{
		{NewResourceSet(NewResourceS3("mybucket/myobject*")), false},
		{NewResourceSet(NewResourceS3("/")), true},
		{NewResourceSet(NewResourceS3("mybucket"), NewResourceKMS("mykey")), true}, // mismatching types
	}

	for i, testCase := range testCases {
		err := testCase.resourceSet.ValidateAWSS3()
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestResourceSetKMSValidate(t *testing.T) {
	testCases := []struct {
		resourceSet ResourceSet
		expectErr   bool
	}{
		{NewResourceSet(NewResourceKMS("mykey/invalid")), true},
		{NewResourceSet(NewResourceKMS("/")), true},
		{NewResourceSet(NewResourceKMS("mykey")), false},
		{NewResourceSet(NewResourceKMS("mykey"), NewResourceS3("mybucket")), true}, // mismatching types
	}

	for i, testCase := range testCases {
		err := testCase.resourceSet.ValidateKMS()
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestResourceSetValidateBucket(t *testing.T) {
	testCases := []struct {
		resourceSet ResourceSet
		bucketName  string
		expectErr   bool
	}{
		{NewResourceSet(NewResourceS3("mybucket/myobject*")), "mybucket", false},
		{NewResourceSet(NewResourceS3("/myobject*")), "yourbucket", true},
		{NewResourceSet(NewResourceS3("mybucket/myobject*")), "yourbucket", true},
	}

	for i, testCase := range testCases {
		err := testCase.resourceSet.ValidateBucket(testCase.bucketName)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}
