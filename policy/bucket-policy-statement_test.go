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
	"net"
	"reflect"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

func TestBPStatementIsAllowed(t *testing.T) {
	case1Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(GetBucketLocationAction, PutObjectAction),
		NewResourceSet(NewResource("*")),
		condition.NewFunctions(),
	)

	case2Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(GetObjectAction, PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(),
	)

	_, IPNet1, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	func1, err := condition.NewIPAddressFunc(
		condition.AWSSourceIP.ToKey(),
		IPNet1,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case3Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(GetObjectAction, PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	case4Statement := NewBPStatement("",
		Deny,
		NewPrincipal("*"),
		NewActionSet(GetObjectAction, PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	case5Statement := NewBPStatementWithNotAction(
		"",
		Allow,
		NewPrincipal("*"),
		NewActionSet(GetObjectAction, CreateBucketAction),
		NewResourceSet(NewResource("mybucket/myobject*"), NewResource("mybucket")),
		condition.NewFunctions(),
	)

	case6Statement := NewBPStatementWithNotAction(
		"",
		Deny,
		NewPrincipal("*"),
		NewActionSet(GetObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	anonGetBucketLocationArgs := BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
	}

	anonPutObjectActionArgs := BucketPolicyArgs{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		ObjectName: "myobject",
	}

	anonGetObjectActionArgs := BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		ObjectName:      "myobject",
	}

	getBucketLocationArgs := BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
	}

	putObjectActionArgs := BucketPolicyArgs{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		IsOwner:    true,
		ObjectName: "myobject",
	}

	getObjectActionArgs := BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
		ObjectName:      "myobject",
	}

	testCases := []struct {
		statement      BPStatement
		args           BucketPolicyArgs
		expectedResult bool
	}{
		{case1Statement, anonGetBucketLocationArgs, true},
		{case1Statement, anonPutObjectActionArgs, true},
		{case1Statement, anonGetObjectActionArgs, false},
		{case1Statement, getBucketLocationArgs, true},
		{case1Statement, putObjectActionArgs, true},
		{case1Statement, getObjectActionArgs, false},

		{case2Statement, anonGetBucketLocationArgs, false},
		{case2Statement, anonPutObjectActionArgs, true},
		{case2Statement, anonGetObjectActionArgs, true},
		{case2Statement, getBucketLocationArgs, false},
		{case2Statement, putObjectActionArgs, true},
		{case2Statement, getObjectActionArgs, true},

		{case3Statement, anonGetBucketLocationArgs, false},
		{case3Statement, anonPutObjectActionArgs, true},
		{case3Statement, anonGetObjectActionArgs, false},
		{case3Statement, getBucketLocationArgs, false},
		{case3Statement, putObjectActionArgs, true},
		{case3Statement, getObjectActionArgs, false},

		{case4Statement, anonGetBucketLocationArgs, true},
		{case4Statement, anonPutObjectActionArgs, false},
		{case4Statement, anonGetObjectActionArgs, true},
		{case4Statement, getBucketLocationArgs, true},
		{case4Statement, putObjectActionArgs, false},
		{case4Statement, getObjectActionArgs, true},

		{case5Statement, anonGetBucketLocationArgs, true},
		{case5Statement, anonPutObjectActionArgs, true},
		{case5Statement, anonGetObjectActionArgs, false},
		{case5Statement, getBucketLocationArgs, true},
		{case5Statement, getObjectActionArgs, false},
		{case5Statement, putObjectActionArgs, true},

		{case6Statement, anonGetBucketLocationArgs, true},
		{case6Statement, anonPutObjectActionArgs, false},
		{case6Statement, anonGetObjectActionArgs, true},
		{case6Statement, getBucketLocationArgs, true},
		{case6Statement, putObjectActionArgs, false},
		{case6Statement, getObjectActionArgs, true},
	}

	for i, testCase := range testCases {
		result := testCase.statement.IsAllowed(testCase.args)

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestBPStatementIsValid(t *testing.T) {
	_, IPNet1, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	func1, err := condition.NewIPAddressFunc(
		condition.AWSSourceIP.ToKey(),
		IPNet1,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	func2, err := condition.NewStringEqualsFunc(
		"",
		condition.S3XAmzCopySource.ToKey(),
		"mybucket/myobject",
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	testCases := []struct {
		statement BPStatement
		expectErr bool
	}{
		// Invalid effect error.
		{NewBPStatement("",
			Effect("foo"),
			NewPrincipal("*"),
			NewActionSet(GetBucketLocationAction, PutObjectAction),
			NewResourceSet(NewResource("*")),
			condition.NewFunctions(),
		), true},
		// Invalid principal error.
		{NewBPStatement("",
			Allow,
			NewPrincipal(),
			NewActionSet(GetBucketLocationAction, PutObjectAction),
			NewResourceSet(NewResource("*")),
			condition.NewFunctions(),
		), true},
		// Empty actions error.
		{NewBPStatement("",
			Allow,
			NewPrincipal("*"),
			NewActionSet(),
			NewResourceSet(NewResource("*")),
			condition.NewFunctions(),
		), true},
		// Empty resources error.
		{NewBPStatement("",
			Allow,
			NewPrincipal("*"),
			NewActionSet(GetBucketLocationAction, PutObjectAction),
			NewResourceSet(),
			condition.NewFunctions(),
		), true},
		// Unsupported resource found for object action.
		{NewBPStatement("",
			Allow,
			NewPrincipal("*"),
			NewActionSet(GetBucketLocationAction, PutObjectAction),
			NewResourceSet(NewResource("mybucket")),
			condition.NewFunctions(),
		), true},
		// Unsupported resource found for bucket action.
		{NewBPStatement("",
			Allow,
			NewPrincipal("*"),
			NewActionSet(GetBucketLocationAction, PutObjectAction),
			NewResourceSet(NewResource("mybucket/myobject*")),
			condition.NewFunctions(),
		), true},
		// Unsupported condition key for action.
		{NewBPStatement("",
			Allow,
			NewPrincipal("*"),
			NewActionSet(GetObjectAction, PutObjectAction),
			NewResourceSet(NewResource("mybucket/myobject*")),
			condition.NewFunctions(func1, func2),
		), true},
		{NewBPStatement("",
			Deny,
			NewPrincipal("*"),
			NewActionSet(GetObjectAction, PutObjectAction),
			NewResourceSet(NewResource("mybucket/myobject*")),
			condition.NewFunctions(func1),
		), false},
		{BPStatement{
			SID:        "",
			Effect:     Allow,
			Principal:  NewPrincipal("*"),
			NotActions: NewActionSet(GetObjectAction),
			Resources:  NewResourceSet(NewResource("mybucket/myobject*")),
			Conditions: condition.NewFunctions(),
		}, false},
	}

	for i, testCase := range testCases {
		err := testCase.statement.isValid()
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestBPStatementUnmarshalJSONAndValidate(t *testing.T) {
	case1Data := []byte(`{
    "Sid": "SomeId1",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)
	case1Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(),
	)
	case1Statement.SID = "SomeId1"

	case2Data := []byte(`{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*",
    "Condition": {
        "Null": {
            "s3:x-amz-copy-source": true
        }
    }
}`)
	func1, err := condition.NewNullFunc(
		condition.S3XAmzCopySource.ToKey(),
		true,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	case2Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	case3Data := []byte(`{
    "Effect": "Deny",
    "Principal": {
        "AWS": "*"
    },
    "Action": [
        "s3:PutObject",
        "s3:GetObject"
    ],
    "Resource": "arn:aws:s3:::mybucket/myobject*",
    "Condition": {
        "Null": {
            "s3:x-amz-server-side-encryption": "false"
        }
    }
}`)
	func2, err := condition.NewNullFunc(
		condition.S3XAmzServerSideEncryption.ToKey(),
		false,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	case3Statement := NewBPStatement("",
		Deny,
		NewPrincipal("*"),
		NewActionSet(PutObjectAction, GetObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(func2),
	)

	case4Data := []byte(`{
    "Effect": "Allow",
    "Principal": "Q3AM3UQ867SPQQA43P2F",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)

	case5Data := []byte(`{
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)

	case6Data := []byte(`{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)

	case7Data := []byte(`{
    "Effect": "Allow",
    "Principal": "*",
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)

	case8Data := []byte(`{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject"
}`)

	case9Data := []byte(`{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*",
    "Condition": {
    }
}`)

	case10Data := []byte(`{
    "Effect": "Deny",
    "Principal": {
        "AWS": "*"
    },
    "Action": [
        "s3:PutObject",
        "s3:GetObject"
    ],
    "Resource": "arn:aws:s3:::mybucket/myobject*",
    "Condition": {
        "StringEquals": {
            "s3:x-amz-copy-source": "yourbucket/myobject*"
        }
    }
}`)

	case11Data := []byte(`{
    "Effect": "Deny",
    "Principal": "*",
    "NotAction": [
        "s3:PutObject",
        "s3:GetObject"
    ],
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)
	case11Statement := BPStatement{
		Effect:     Deny,
		Principal:  NewPrincipal("*"),
		NotActions: NewActionSet(GetObjectAction, PutObjectAction),
		Resources:  NewResourceSet(NewResource("mybucket/myobject*")),
		Conditions: condition.NewFunctions(),
	}

	testCases := []struct {
		data                []byte
		expectedResult      BPStatement
		expectUnmarshalErr  bool
		bucket              string
		expectValidationErr bool
	}{
		{case1Data, case1Statement, false, "mybucket", false},
		{case2Data, case2Statement, false, "mybucket", false},
		{case3Data, case3Statement, false, "mybucket", false},
		// JSON unmarshaling error.
		{case4Data, BPStatement{}, true, "mybucket", true},
		// Invalid effect error.
		{case5Data, BPStatement{}, false, "mybucket", true},
		// empty principal error.
		{case6Data, BPStatement{}, false, "mybucket", true},
		// Empty action error.
		{case7Data, BPStatement{}, false, "mybucket", true},
		// Empty resource error.
		{case8Data, BPStatement{}, false, "mybucket", true},
		// Empty condition error.
		{case9Data, BPStatement{}, true, "mybucket", false},
		// Unsupported condition key error.
		{case10Data, BPStatement{}, false, "mybucket", true},
		{case11Data, case11Statement, false, "mybucket", false},
	}

	for i, testCase := range testCases {
		var result BPStatement
		expectErr := (json.Unmarshal(testCase.data, &result) != nil)

		if expectErr != testCase.expectUnmarshalErr {
			t.Errorf("case %v: error during unmarshal: expected: %v, got: %v", i+1, testCase.expectUnmarshalErr, expectErr)
		}

		expectErr = (result.Validate(testCase.bucket) != nil)
		if expectErr != testCase.expectValidationErr {
			t.Errorf("case %v: error during validation: expected: %v, got: %v", i+1, testCase.expectValidationErr, expectErr)
		}

		if !testCase.expectUnmarshalErr && !testCase.expectValidationErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("case %v: result: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestBPStatementValidate(t *testing.T) {
	case1Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(),
	)

	func1, err := condition.NewNullFunc(
		condition.S3XAmzCopySource.ToKey(),
		true,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	func2, err := condition.NewNullFunc(
		condition.S3XAmzServerSideEncryption.ToKey(),
		false,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	case2Statement := NewBPStatement("",
		Allow,
		NewPrincipal("*"),
		NewActionSet(GetObjectAction, PutObjectAction),
		NewResourceSet(NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1, func2),
	)

	testCases := []struct {
		statement  BPStatement
		bucketName string
		expectErr  bool
	}{
		{case1Statement, "mybucket", false},
		{case2Statement, "mybucket", true},
		{case1Statement, "yourbucket", true},
	}

	for i, testCase := range testCases {
		err := testCase.statement.Validate(testCase.bucketName)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}
