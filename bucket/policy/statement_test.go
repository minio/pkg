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

	iamp "github.com/minio/pkg/iam/policy"
	"github.com/minio/pkg/iam/policy/condition"
)

func TestStatementIsAllowed(t *testing.T) {
	case1Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetBucketLocationAction, iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("*")),
		condition.NewFunctions(),
	)

	case2Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
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

	case3Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	case4Statement := NewStatement("",
		iamp.Deny,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	case5Statement := NewStatementWithNotAction(
		"",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetObjectAction, iamp.CreateBucketAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*"), iamp.NewResource("mybucket")),
		condition.NewFunctions(),
	)

	case6Statement := NewStatementWithNotAction(
		"",
		iamp.Deny,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1),
	)

	anonGetBucketLocationArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          iamp.GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
	}

	anonPutObjectActionArgs := Args{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      iamp.PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		ObjectName: "myobject",
	}

	anonGetObjectActionArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          iamp.GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		ObjectName:      "myobject",
	}

	getBucketLocationArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          iamp.GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
	}

	putObjectActionArgs := Args{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      iamp.PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		IsOwner:    true,
		ObjectName: "myobject",
	}

	getObjectActionArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          iamp.GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
		ObjectName:      "myobject",
	}

	testCases := []struct {
		statement      Statement
		args           Args
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

func TestStatementIsValid(t *testing.T) {
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
		statement Statement
		expectErr bool
	}{
		// Invalid effect error.
		{NewStatement("",
			iamp.Effect("foo"),
			NewPrincipal("*"),
			iamp.NewActionSet(iamp.GetBucketLocationAction, iamp.PutObjectAction),
			iamp.NewResourceSet(iamp.NewResource("*")),
			condition.NewFunctions(),
		), true},
		// Invalid principal error.
		{NewStatement("",
			iamp.Allow,
			NewPrincipal(),
			iamp.NewActionSet(iamp.GetBucketLocationAction, iamp.PutObjectAction),
			iamp.NewResourceSet(iamp.NewResource("*")),
			condition.NewFunctions(),
		), true},
		// Empty actions error.
		{NewStatement("",
			iamp.Allow,
			NewPrincipal("*"),
			iamp.NewActionSet(),
			iamp.NewResourceSet(iamp.NewResource("*")),
			condition.NewFunctions(),
		), true},
		// Empty resources error.
		{NewStatement("",
			iamp.Allow,
			NewPrincipal("*"),
			iamp.NewActionSet(iamp.GetBucketLocationAction, iamp.PutObjectAction),
			iamp.NewResourceSet(),
			condition.NewFunctions(),
		), true},
		// Unsupported resource found for object action.
		{NewStatement("",
			iamp.Allow,
			NewPrincipal("*"),
			iamp.NewActionSet(iamp.GetBucketLocationAction, iamp.PutObjectAction),
			iamp.NewResourceSet(iamp.NewResource("mybucket")),
			condition.NewFunctions(),
		), true},
		// Unsupported resource found for bucket action.
		{NewStatement("",
			iamp.Allow,
			NewPrincipal("*"),
			iamp.NewActionSet(iamp.GetBucketLocationAction, iamp.PutObjectAction),
			iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
			condition.NewFunctions(),
		), true},
		// Unsupported condition key for action.
		{NewStatement("",
			iamp.Allow,
			NewPrincipal("*"),
			iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
			iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
			condition.NewFunctions(func1, func2),
		), true},
		{NewStatement("",
			iamp.Deny,
			NewPrincipal("*"),
			iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
			iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
			condition.NewFunctions(func1),
		), false},
		{Statement{
			SID:        "",
			Effect:     iamp.Allow,
			Principal:  NewPrincipal("*"),
			NotActions: iamp.NewActionSet(iamp.GetObjectAction),
			Resources:  iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
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

func TestStatementUnmarshalJSONAndValidate(t *testing.T) {
	case1Data := []byte(`{
    "Sid": "SomeId1",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::mybucket/myobject*"
}`)
	case1Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
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
	case2Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
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
	case3Statement := NewStatement("",
		iamp.Deny,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.PutObjectAction, iamp.GetObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
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
	case11Statement := Statement{
		Effect:     iamp.Deny,
		Principal:  NewPrincipal("*"),
		NotActions: iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
		Resources:  iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
		Conditions: condition.NewFunctions(),
	}

	testCases := []struct {
		data                []byte
		expectedResult      Statement
		expectUnmarshalErr  bool
		bucket              string
		expectValidationErr bool
	}{
		{case1Data, case1Statement, false, "mybucket", false},
		{case2Data, case2Statement, false, "mybucket", false},
		{case3Data, case3Statement, false, "mybucket", false},
		// JSON unmarshaling error.
		{case4Data, Statement{}, true, "mybucket", true},
		// Invalid effect error.
		{case5Data, Statement{}, false, "mybucket", true},
		// empty principal error.
		{case6Data, Statement{}, false, "mybucket", true},
		// Empty action error.
		{case7Data, Statement{}, false, "mybucket", true},
		// Empty resource error.
		{case8Data, Statement{}, false, "mybucket", true},
		// Empty condition error.
		{case9Data, Statement{}, true, "mybucket", false},
		// Unsupported condition key error.
		{case10Data, Statement{}, false, "mybucket", true},
		{case11Data, case11Statement, false, "mybucket", false},
	}

	for i, testCase := range testCases {
		var result Statement
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

func TestStatementValidate(t *testing.T) {
	case1Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
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
	case2Statement := NewStatement("",
		iamp.Allow,
		NewPrincipal("*"),
		iamp.NewActionSet(iamp.GetObjectAction, iamp.PutObjectAction),
		iamp.NewResourceSet(iamp.NewResource("mybucket/myobject*")),
		condition.NewFunctions(func1, func2),
	)

	testCases := []struct {
		statement  Statement
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
