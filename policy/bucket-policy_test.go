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

func TestBucketPolicyIsAllowed(t *testing.T) {
	case1Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetBucketLocationAction, PutObjectAction),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
		},
	}

	case2Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	_, IPNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	func1, err := condition.NewIPAddressFunc(
		condition.AWSSourceIP.ToKey(),
		IPNet,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case3Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
		},
	}

	case4Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
		},
	}

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
		policy         BucketPolicy
		args           BucketPolicyArgs
		expectedResult bool
	}{
		{case1Policy, anonGetBucketLocationArgs, true},
		{case1Policy, anonPutObjectActionArgs, true},
		{case1Policy, anonGetObjectActionArgs, false},
		{case1Policy, getBucketLocationArgs, true},
		{case1Policy, putObjectActionArgs, true},
		{case1Policy, getObjectActionArgs, true},

		{case2Policy, anonGetBucketLocationArgs, false},
		{case2Policy, anonPutObjectActionArgs, true},
		{case2Policy, anonGetObjectActionArgs, true},
		{case2Policy, getBucketLocationArgs, true},
		{case2Policy, putObjectActionArgs, true},
		{case2Policy, getObjectActionArgs, true},

		{case3Policy, anonGetBucketLocationArgs, false},
		{case3Policy, anonPutObjectActionArgs, true},
		{case3Policy, anonGetObjectActionArgs, false},
		{case3Policy, getBucketLocationArgs, true},
		{case3Policy, putObjectActionArgs, true},
		{case3Policy, getObjectActionArgs, true},

		{case4Policy, anonGetBucketLocationArgs, false},
		{case4Policy, anonPutObjectActionArgs, false},
		{case4Policy, anonGetObjectActionArgs, false},
		{case4Policy, getBucketLocationArgs, true},
		{case4Policy, putObjectActionArgs, false},
		{case4Policy, getObjectActionArgs, true},
	}

	for i, testCase := range testCases {
		result := testCase.policy.IsAllowed(testCase.args)

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestBucketPolicyIsEmpty(t *testing.T) {
	case1Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case2Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket",
		Version: DefaultVersion,
	}

	testCases := []struct {
		policy         BucketPolicy
		expectedResult bool
	}{
		{case1Policy, false},
		{case2Policy, true},
	}

	for i, testCase := range testCases {
		result := testCase.policy.IsEmpty()

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestBucketPolicyIsValid(t *testing.T) {
	case1Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case2Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case3Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/yourobject*")),
				condition.NewFunctions(),
			),
		},
	}

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

	case4Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func2),
			),
		},
	}

	case5Policy := BucketPolicy{
		Version: "17-10-2012",
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case6Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1, func2),
			),
		},
	}

	case7Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case8Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		policy    BucketPolicy
		expectErr bool
	}{
		{case1Policy, false},
		// allowed duplicate principal.
		{case2Policy, false},
		// allowed duplicate principal and action.
		{case3Policy, false},
		// allowed duplicate principal, action and resource.
		{case4Policy, false},
		// Invalid version error.
		{case5Policy, true},
		// Invalid statement error.
		{case6Policy, true},
		// Duplicate statement success different effects.
		{case7Policy, false},
		// Duplicate statement success, duplicate statement dropped.
		{case8Policy, false},
	}

	for i, testCase := range testCases {
		err := testCase.policy.isValid()
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestBucketPolicyMarshalJSON(t *testing.T) {
	case1Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}
	case1Policy.Statements[0].SID = "SomeId1"
	case1Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Sid":"SomeId1","Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]}]}`)

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

	case2Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/yourobject*")),
				condition.NewFunctions(func1),
			),
		},
	}
	case2Data := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]},{"Effect":"Deny","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::mybucket/yourobject*"],"Condition":{"IpAddress":{"aws:SourceIp":["192.168.1.0/24"]}}}]}`)

	case3Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("Q3AM3UQ867SPQQA43P2F"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}
	case3Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["Q3AM3UQ867SPQQA43P2F"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]},{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]}]}`)

	case4Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}
	case4Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]},{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]}]}`)

	case5Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/yourobject*")),
				condition.NewFunctions(),
			),
		},
	}
	case5Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"]},{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/yourobject*"]}]}`)

	_, IPNet2, err := net.ParseCIDR("192.168.2.0/24")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	func2, err := condition.NewIPAddressFunc(
		condition.AWSSourceIP.ToKey(),
		IPNet2,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case6Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func2),
			),
		},
	}
	case6Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"],"Condition":{"IpAddress":{"aws:SourceIp":["192.168.1.0/24"]}}},{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/myobject*"],"Condition":{"IpAddress":{"aws:SourceIp":["192.168.2.0/24"]}}}]}`)

	case7Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetBucketLocationAction),
				NewResourceSet(NewResource("mybucket")),
				condition.NewFunctions(),
			),
		},
	}
	case7Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetBucketLocation"],"Resource":["arn:aws:s3:::mybucket"]}]}`)

	case8Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetBucketLocationAction),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
		},
	}
	case8Data := []byte(`{"ID":"MyPolicyForMyBucket1","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetBucketLocation"],"Resource":["arn:aws:s3:::*"]}]}`)

	func3, err := condition.NewNullFunc(
		condition.S3XAmzCopySource.ToKey(),
		true,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	case9Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1, func2, func3),
			),
		},
	}

	testCases := []struct {
		policy         BucketPolicy
		expectedResult []byte
		expectErr      bool
	}{
		{case1Policy, case1Data, false},
		{case2Policy, case2Data, false},
		{case3Policy, case3Data, false},
		{case4Policy, case4Data, false},
		{case5Policy, case5Data, false},
		{case6Policy, case6Data, false},
		{case7Policy, case7Data, false},
		{case8Policy, case8Data, false},
		{case9Policy, nil, true},
	}

	for i, testCase := range testCases {
		result, err := json.Marshal(testCase.policy)
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

func TestBucketPolicyUnmarshalJSON(t *testing.T) {
	case1Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SomeId1",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case1Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}
	case1Policy.Statements[0].SID = "SomeId1"

	case2Data := []byte(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::mybucket/yourobject*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "192.168.1.0/24"
                }
            }
        }
    ]
}`)
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

	case2Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/yourobject*")),
				condition.NewFunctions(func1),
			),
		},
	}

	case3Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "Q3AM3UQ867SPQQA43P2F"
                ]
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case3Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("Q3AM3UQ867SPQQA43P2F"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case4Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case4Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case5Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/yourobject*"
        }
    ]
}`)
	case5Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/yourobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case6Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "192.168.1.0/24"
                }
            }
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "192.168.2.0/24"
                }
            }
        }
    ]
}`)
	_, IPNet2, err := net.ParseCIDR("192.168.2.0/24")
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}
	func2, err := condition.NewIPAddressFunc(
		condition.AWSSourceIP.ToKey(),
		IPNet2,
	)
	if err != nil {
		t.Fatalf("unexpected error. %v\n", err)
	}

	case6Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func2),
			),
		},
	}

	case7Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetBucketLocation",
            "Resource": "arn:aws:s3:::mybucket"
        }
    ]
}`)

	case7Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetBucketLocationAction),
				NewResourceSet(NewResource("mybucket")),
				condition.NewFunctions(),
			),
		},
	}

	case8Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetBucketLocation",
            "Resource": "arn:aws:s3:::*"
        }
    ]
}`)

	case8Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetBucketLocationAction),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
		},
	}

	case9Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "17-10-2012",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)

	case10Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)

	case10Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case11Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)

	case11Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewBPStatement("",
				Deny,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		data           []byte
		expectedResult BucketPolicy
		expectErr      bool
	}{
		{case1Data, case1Policy, false},
		{case2Data, case2Policy, false},
		{case3Data, case3Policy, false},
		{case4Data, case4Policy, false},
		{case5Data, case5Policy, false},
		{case6Data, case6Policy, false},
		{case7Data, case7Policy, false},
		{case8Data, case8Policy, false},
		// Invalid version error.
		{case9Data, BucketPolicy{}, true},
		// Duplicate statement success, duplicate statement removed.
		{case10Data, case10Policy, false},
		// Duplicate statement success (Effect differs).
		{case11Data, case11Policy, false},
	}

	for i, testCase := range testCases {
		var result BucketPolicy
		err := json.Unmarshal(testCase.data, &result)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Errorf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Errorf("case %v: result: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestBucketPolicyValidate(t *testing.T) {
	case1Policy := BucketPolicy{
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

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
	case2Policy := BucketPolicy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []BPStatement{
			NewBPStatement("",
				Allow,
				NewPrincipal("*"),
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1, func2),
			),
		},
	}

	testCases := []struct {
		policy     BucketPolicy
		bucketName string
		expectErr  bool
	}{
		{case1Policy, "mybucket", false},
		{case2Policy, "yourbucket", true},
		{case1Policy, "yourbucket", true},
	}

	for i, testCase := range testCases {
		err := testCase.policy.Validate(testCase.bucketName)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}
