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
	"bytes"
	"encoding/json"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/minio/pkg/v3/policy/condition"
)

func TestGetPoliciesFromClaims(t *testing.T) {
	attributesArray := `{
  "exp": 1594690452,
  "iat": 1594689552,
  "auth_time": 1594689552,
  "jti": "18ed05c9-2c69-45d5-a33f-8c94aca99ad5",
  "iss": "http://localhost:8080/auth/realms/minio",
  "aud": "account",
  "sub": "7e5e2f30-1c97-4616-8623-2eae14dee9b1",
  "typ": "ID",
  "azp": "account",
  "nonce": "66ZoLzwJbjdkiedI",
  "session_state": "3df7b526-5310-4038-9f35-50ecd295a31d",
  "acr": "1",
  "upn": "harsha",
  "address": {},
  "email_verified": false,
  "groups": [
    "offline_access"
  ],
  "preferred_username": "harsha",
  "policy": [
    "readwrite",
    "readwrite,readonly",
    "  readonly",
    ""
  ]}`
	m := make(map[string]interface{})
	if err := json.Unmarshal([]byte(attributesArray), &m); err != nil {
		t.Fatal(err)
	}
	expectedSet := set.CreateStringSet("readwrite", "readonly")
	gotSet, ok := GetPoliciesFromClaims(m, "policy")
	if !ok {
		t.Fatal("no policy claim was found")
	}
	if gotSet.IsEmpty() {
		t.Fatal("no policies were found in policy claim")
	}
	if !gotSet.Equals(expectedSet) {
		t.Fatalf("Expected %v got %v", expectedSet, gotSet)
	}
}

func TestAdminPolicyResource(t *testing.T) {
	test := `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:*"
   ],
   "Resource": [
    "*"
   ]
  },
  {
   "Effect": "Allow",
   "Action": [
    "admin:ListServiceAccounts",
    "admin:GetBucketQuota"
   ]
  }
 ]
}`
	p, err := ParseConfig(strings.NewReader(test))
	if err != nil {
		t.Fatal(err)
	}

	allowedActions := p.IsAllowedActions("", "", map[string][]string{})
	if !allowedActions.Match(ListServiceAccountsAdminAction) {
		t.Fatal("expected success for ListServiceAccounts, but failed to match")
	}

	if !allowedActions.Match(GetBucketQuotaAdminAction) {
		t.Fatal("expected success for GetBucketQuota, but failed to match")
	}
}

func TestPolicyIsAllowedActions(t *testing.T) {
	policy1 := `{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Sid":"statement1",
         "Effect":"Allow",
         "Action": "s3:CreateBucket",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
             "StringLike": {
                 "s3:LocationConstraint": "us-east-1"
             }
         }
       },
      {
         "Sid":"statement2",
         "Effect":"Deny",
         "Action": "s3:CreateBucket",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
             "StringNotLike": {
                 "s3:LocationConstraint": "us-east-1"
             }
         }
       }
    ]
}`
	p, err := ParseConfig(strings.NewReader(policy1))
	if err != nil {
		t.Fatal(err)
	}

	allowedActions := p.IsAllowedActions("testbucket", "", map[string][]string{
		"LocationConstraint": {"us-east-1"},
	})

	if !allowedActions.Match(CreateBucketAction) {
		t.Fatal("expected success for CreateBucket, but failed to match")
	}

	allowedActions = p.IsAllowedActions("testbucket", "", map[string][]string{
		"LocationConstraint": {"us-east-2"},
	})

	if allowedActions.Match(CreateBucketAction) {
		t.Fatal("expected no CreateBucket in allowed actions, but found instead")
	}
}

func TestPolicyIsAllowedCornerCase1(t *testing.T) {
	policy1Str := `{
   "Version":"2012-10-17",
   "Statement":[
       {
           "Sid":"1",
           "Effect":"Allow",
           "Action": "s3:PutObject",
           "Resource": "arn:aws:s3:::mybucket2/*"
       },
       {
           "Sid":"2",
           "Effect":"Allow",
           "Action": "s3:*",
           "Resource": "arn:aws:s3:::mybucket1/*"
       }
    ]
}`
	policy1, err := ParseConfig(strings.NewReader(policy1Str))
	if err != nil {
		t.Fatal(err)
	}

	args1 := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          PutObjectAction,
		BucketName:      "mybucket1",
		ConditionValues: nil,
		ObjectName:      "myobject",
	}

	testCases := []struct {
		policy         *Policy
		args           Args
		expectedResult bool
	}{
		{policy1, args1, true},
	}

	for i, testCase := range testCases {
		result := testCase.policy.IsAllowed(testCase.args)

		if result != testCase.expectedResult {
			t.Errorf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestPolicyIsAllowed(t *testing.T) {
	case1Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetBucketLocationAction, PutObjectAction),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
		},
	}

	case2Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
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

	case3Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
		},
	}

	case4Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Deny,
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
		},
	}

	case5Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/*")),
				condition.NewFunctions(),
			),
			NewStatementWithNotResource(
				"",
				Deny,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/notmyobject*")),
				condition.NewFunctions(),
			),
		},
	}

	anonGetBucketLocationArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
	}

	anonPutObjectActionArgs := Args{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		ObjectName: "myobject",
	}

	anonGetObjectActionArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		ObjectName:      "myobject",
	}

	getBucketLocationArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
	}

	putObjectActionArgs := Args{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		ObjectName: "myobject",
	}

	getObjectActionArgs := Args{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		ObjectName:      "myobject",
	}

	testCases := []struct {
		policy         Policy
		args           Args
		expectedResult bool
	}{
		{case1Policy, anonGetBucketLocationArgs, true},
		{case1Policy, anonPutObjectActionArgs, true},
		{case1Policy, anonGetObjectActionArgs, false},
		{case1Policy, getBucketLocationArgs, true},
		{case1Policy, putObjectActionArgs, true},
		{case1Policy, getObjectActionArgs, false},

		{case2Policy, anonGetBucketLocationArgs, false},
		{case2Policy, anonPutObjectActionArgs, true},
		{case2Policy, anonGetObjectActionArgs, true},
		{case2Policy, getBucketLocationArgs, false},
		{case2Policy, putObjectActionArgs, true},
		{case2Policy, getObjectActionArgs, true},

		{case3Policy, anonGetBucketLocationArgs, false},
		{case3Policy, anonPutObjectActionArgs, true},
		{case3Policy, anonGetObjectActionArgs, false},
		{case3Policy, getBucketLocationArgs, false},
		{case3Policy, putObjectActionArgs, true},
		{case3Policy, getObjectActionArgs, false},

		{case4Policy, anonGetBucketLocationArgs, false},
		{case4Policy, anonPutObjectActionArgs, false},
		{case4Policy, anonGetObjectActionArgs, false},
		{case4Policy, getBucketLocationArgs, false},
		{case4Policy, putObjectActionArgs, false},
		{case4Policy, getObjectActionArgs, false},

		{case5Policy, anonGetBucketLocationArgs, false},
		{case5Policy, anonPutObjectActionArgs, false},
		{case5Policy, anonGetObjectActionArgs, true},
		{case5Policy, getBucketLocationArgs, false},
		{case5Policy, putObjectActionArgs, false},
		{case5Policy, getObjectActionArgs, true},
	}

	for i, testCase := range testCases {
		result := testCase.policy.IsAllowed(testCase.args)

		if result != testCase.expectedResult {
			t.Errorf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func TestPolicyIsEmpty(t *testing.T) {
	case1Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case2Policy := Policy{
		ID:      "MyPolicyForMyBucket",
		Version: DefaultVersion,
	}

	testCases := []struct {
		policy         Policy
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

func TestPolicyIsValid(t *testing.T) {
	case1Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case2Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case3Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
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

	case4Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
			NewStatement(
				"",
				Deny,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func2),
			),
		},
	}

	case5Policy := Policy{
		Version: "17-10-2012",
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case6Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1, func2),
			),
		},
	}

	case7Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case8Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		policy    Policy
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
		// Duplicate statement different Effects.
		{case7Policy, false},
		// Duplicate statement same Effects, duplicate effect will be removed.
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

// Parse config with location constraints
func TestPolicyParseConfig(t *testing.T) {
	policy1LocationConstraint := `{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Sid":"statement1",
         "Effect":"Allow",
         "Action": "s3:CreateBucket",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
             "StringLike": {
                 "s3:LocationConstraint": "us-east-1"
             }
         }
       },
      {
         "Sid":"statement2",
         "Effect":"Deny",
         "Action": "s3:CreateBucket",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
             "StringNotLike": {
                 "s3:LocationConstraint": "us-east-1"
             }
         }
       }
    ]
}`
	policy2Condition := `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "statement1",
            "Effect": "Allow",
            "Action": "s3:GetObjectVersion",
            "Resource": "arn:aws:s3:::test/HappyFace.jpg"
        },
        {
            "Sid": "statement2",
            "Effect": "Deny",
            "Action": "s3:GetObjectVersion",
            "Resource": "arn:aws:s3:::test/HappyFace.jpg",
            "Condition": {
                "StringNotEquals": {
                    "s3:versionid": "AaaHbAQitwiL_h47_44lRO2DDfLlBO5e"
                }
            }
        }
    ]
}`

	policy3ConditionActionRegex := `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "statement2",
            "Effect": "Allow",
            "Action": "s3:Get*",
            "Resource": "arn:aws:s3:::test/HappyFace.jpg",
            "Condition": {
                "StringEquals": {
                    "s3:versionid": "AaaHbAQitwiL_h47_44lRO2DDfLlBO5e"
                }
            }
        }
    ]
}`

	policy4ConditionAction := `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "statement2",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::test/HappyFace.jpg",
            "Condition": {
                "StringEquals": {
                    "s3:versionid": "AaaHbAQitwiL_h47_44lRO2DDfLlBO5e"
                }
            }
        }
    ]
}`

	policy5ConditionCurrenTime := `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:Get*",
    "s3:Put*"
   ],
   "Resource": [
    "arn:aws:s3:::test/*"
   ],
   "Condition": {
    "DateGreaterThan": {
     "aws:CurrentTime": [
      "2017-02-28T00:00:00Z"
     ]
    }
   }
  }
 ]
}`

	policy5ConditionCurrenTimeLesser := `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:Get*",
    "s3:Put*"
   ],
   "Resource": [
    "arn:aws:s3:::test/*"
   ],
   "Condition": {
    "DateLessThan": {
     "aws:CurrentTime": [
      "2017-02-28T00:00:00Z"
     ]
    }
   }
  }
 ]
}`

	tests := []struct {
		p       string
		args    Args
		allowed bool
	}{
		{
			p:       policy1LocationConstraint,
			allowed: true,
			args: Args{
				AccountName:     "allowed",
				Action:          CreateBucketAction,
				BucketName:      "test",
				ConditionValues: map[string][]string{"LocationConstraint": {"us-east-1"}},
			},
		},
		{
			p:       policy1LocationConstraint,
			allowed: false,
			args: Args{
				AccountName:     "disallowed",
				Action:          CreateBucketAction,
				BucketName:      "test",
				ConditionValues: map[string][]string{"LocationConstraint": {"us-east-2"}},
			},
		},
		{
			p:       policy2Condition,
			allowed: true,
			args: Args{
				AccountName:     "allowed",
				Action:          GetObjectAction,
				BucketName:      "test",
				ObjectName:      "HappyFace.jpg",
				ConditionValues: map[string][]string{"versionid": {"AaaHbAQitwiL_h47_44lRO2DDfLlBO5e"}},
			},
		},
		{
			p:       policy2Condition,
			allowed: false,
			args: Args{
				AccountName:     "disallowed",
				Action:          GetObjectAction,
				BucketName:      "test",
				ObjectName:      "HappyFace.jpg",
				ConditionValues: map[string][]string{"versionid": {"AaaHbAQitwiL_h47_44lRO2DDfLlBO5f"}},
			},
		},
		{
			p:       policy3ConditionActionRegex,
			allowed: true,
			args: Args{
				AccountName:     "allowed",
				Action:          GetObjectAction,
				BucketName:      "test",
				ObjectName:      "HappyFace.jpg",
				ConditionValues: map[string][]string{"versionid": {"AaaHbAQitwiL_h47_44lRO2DDfLlBO5e"}},
			},
		},
		{
			p:       policy3ConditionActionRegex,
			allowed: false,
			args: Args{
				AccountName:     "disallowed",
				Action:          GetObjectAction,
				BucketName:      "test",
				ObjectName:      "HappyFace.jpg",
				ConditionValues: map[string][]string{"versionid": {"AaaHbAQitwiL_h47_44lRO2DDfLlBO5f"}},
			},
		},
		{
			p:       policy4ConditionAction,
			allowed: true,
			args: Args{
				AccountName:     "allowed",
				Action:          GetObjectAction,
				BucketName:      "test",
				ObjectName:      "HappyFace.jpg",
				ConditionValues: map[string][]string{"versionid": {"AaaHbAQitwiL_h47_44lRO2DDfLlBO5e"}},
			},
		},
		{
			p:       policy5ConditionCurrenTime,
			allowed: true,
			args: Args{
				AccountName: "allowed",
				Action:      GetObjectAction,
				BucketName:  "test",
				ObjectName:  "HappyFace.jpg",
				ConditionValues: map[string][]string{
					"CurrentTime": {time.Now().Format(time.RFC3339)},
				},
			},
		},
		{
			p:       policy5ConditionCurrenTimeLesser,
			allowed: false,
			args: Args{
				AccountName: "disallowed",
				Action:      GetObjectAction,
				BucketName:  "test",
				ObjectName:  "HappyFace.jpg",
				ConditionValues: map[string][]string{
					"CurrentTime": {time.Now().Format(time.RFC3339)},
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.args.AccountName, func(t *testing.T) {
			ip, err := ParseConfig(strings.NewReader(test.p))
			if err != nil {
				t.Error(err)
			}
			if got := ip.IsAllowed(test.args); got != test.allowed {
				t.Errorf("Expected %t, got %t", test.allowed, got)
			}
		})
	}
}

func TestPolicyUnmarshalJSONAndValidate(t *testing.T) {
	case1Data := []byte(`{
    "ID": "MyPolicyForMyBucket1",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SomeId1",
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case1Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Deny",
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

	case2Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
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
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case3Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case4Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/yourobject*"
        }
    ]
}`)
	case5Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
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

	case6Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1),
			),
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:GetBucketLocation",
            "Resource": "arn:aws:s3:::mybucket"
        }
    ]
}`)

	case7Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:GetBucketLocation",
            "Resource": "arn:aws:s3:::*"
        }
    ]
}`)

	case8Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)
	case10Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
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
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        },
        {
            "Effect": "Deny",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mybucket/myobject*"
        }
    ]
}`)

	case11Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case12Data := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "admin:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    }
  ]
}`)

	case12Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(AllActions),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
				NewActionSet(AllAdminActions),
				ResourceSet{},
				condition.NewFunctions(),
			),
		},
	}

	case13Data := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    },
    {
      "Effect": "Deny",
      "Action": [
        "admin:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "admin:*"
      ]
    }
  ]
}`)

	case13Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(AllActions),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
				NewActionSet(AllAdminActions),
				ResourceSet{},
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
				NewActionSet(AllAdminActions),
				ResourceSet{},
				condition.NewFunctions(),
			),
		},
	}

	case14Data := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    },
    {
      "Effect": "Deny",
      "Action": [
        "admin:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    }
  ]
}`)

	case14Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(AllActions),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Deny,
				NewActionSet(AllAdminActions),
				ResourceSet{},
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		data                []byte
		expectedResult      Policy
		expectUnmarshalErr  bool
		expectValidationErr bool
	}{
		{case1Data, case1Policy, false, false},
		{case2Data, case2Policy, false, false},
		{case3Data, case3Policy, false, false},
		{case4Data, case4Policy, false, false},
		{case5Data, case5Policy, false, false},
		{case6Data, case6Policy, false, false},
		{case7Data, case7Policy, false, false},
		{case8Data, case8Policy, false, false},
		// Invalid version error.
		{case9Data, Policy{}, false, true},
		// Duplicate statement success, duplicate statement is removed.
		{case10Data, case10Policy, false, false},
		// Duplicate statement success (Effect differs).
		{case11Data, case11Policy, false, false},
		// Duplicate statement success, must be removed.
		{case12Data, case12Policy, false, false},
		// Duplicate statement success, must be removed.
		{case13Data, case13Policy, false, false},
		// Duplicate statement success, must be removed.
		{case14Data, case14Policy, false, false},
	}

	for i, testCase := range testCases {
		var result Policy
		err := json.Unmarshal(testCase.data, &result)
		expectErr := (err != nil)

		if expectErr != testCase.expectUnmarshalErr {
			t.Errorf("case %v: error during unmarshal: expected: %v, got: %v", i+1, testCase.expectUnmarshalErr, expectErr)
		}

		err = result.Validate()
		expectErr = (err != nil)

		if expectErr != testCase.expectValidationErr {
			t.Errorf("case %v: error during validation: expected: %v, got: %v", i+1, testCase.expectValidationErr, expectErr)
		}

		if !testCase.expectUnmarshalErr && !testCase.expectValidationErr {
			exp1, _ := json.Marshal(result)
			exp2, _ := json.Marshal(testCase.expectedResult)
			if !bytes.Equal(exp1, exp2) {
				t.Errorf("case %v: result: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	case1Policy := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(PutObjectAction),
				NewResourceSet(NewResource("")),
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
	case2Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(func1, func2),
			),
		},
	}

	case3Policy := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetObjectAction, PutObjectAction),
				NewResourceSet(NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		policy    Policy
		expectErr bool
	}{
		{case1Policy, true},
		{case2Policy, true},
		{case3Policy, false},
	}

	for i, testCase := range testCases {
		err := testCase.policy.Validate()
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestMergePolicies(t *testing.T) {
	p1 := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Deny,
				NewActionSet(AllAdminActions),
				ResourceSet{},
				condition.NewFunctions(),
			),
			NewStatement(
				"",
				Allow,
				NewActionSet(AllActions),
				NewResourceSet(NewResource("*")),
				condition.NewFunctions(),
			),
		},
	}

	// p2 is a subset of p1
	p2 := Policy{
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Deny,
				NewActionSet(AllAdminActions),
				ResourceSet{},
				condition.NewFunctions(),
			),
		},
	}

	p3 := Policy{
		ID:      "MyPolicyForMyBucket1",
		Version: DefaultVersion,
		Statements: []Statement{
			NewStatement(
				"",
				Allow,
				NewActionSet(GetBucketLocationAction),
				NewResourceSet(NewResource("mybucket")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		inputs   []Policy
		expected Policy
	}{
		{
			inputs:   nil,
			expected: Policy{},
		},
		{
			inputs:   []Policy{},
			expected: Policy{},
		},
		{
			inputs:   []Policy{p1},
			expected: p1,
		},
		{
			inputs:   []Policy{p1, p1},
			expected: p1,
		},
		{
			inputs:   []Policy{p1, p1, p1},
			expected: p1,
		},
		{ // case 6
			inputs:   []Policy{p1, p2},
			expected: p1,
		},
		{
			inputs:   []Policy{p1, p2, p1},
			expected: p1,
		},
		{
			inputs: []Policy{p1, p2, p3},
			expected: Policy{
				Version: DefaultVersion,
				Statements: []Statement{
					NewStatement(
						"",
						Deny,
						NewActionSet(AllAdminActions),
						ResourceSet{},
						condition.NewFunctions(),
					),
					NewStatement(
						"",
						Allow,
						NewActionSet(AllActions),
						NewResourceSet(NewResource("*")),
						condition.NewFunctions(),
					),
					NewStatement(
						"",
						Allow,
						NewActionSet(GetBucketLocationAction),
						NewResourceSet(NewResource("mybucket")),
						condition.NewFunctions(),
					),
				},
			},
		},
		{
			inputs: []Policy{p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3, p1, p2, p3},
			expected: Policy{
				Version: DefaultVersion,
				Statements: []Statement{
					NewStatement(
						"",
						Deny,
						NewActionSet(AllAdminActions),
						ResourceSet{},
						condition.NewFunctions(),
					),
					NewStatement(
						"",
						Allow,
						NewActionSet(AllActions),
						NewResourceSet(NewResource("*")),
						condition.NewFunctions(),
					),
					NewStatement(
						"",
						Allow,
						NewActionSet(GetBucketLocationAction),
						NewResourceSet(NewResource("mybucket")),
						condition.NewFunctions(),
					),
				},
			},
		},
	}
	for i, testCase := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got := MergePolicies(testCase.inputs...)
			if !got.Equals(testCase.expected) {
				t.Errorf("Case %d: expected: %v, got %v", i, testCase.expected, got)
			}
		})
	}
}

func TestJWTScopePolicyIntegration(t *testing.T) {
	tests := []struct {
		name           string
		policyJSON     string
		args           Args
		expectedAllow  bool
		expectParseErr bool
	}{
		// Positive case: Matching single scope with ForAnyValue:StringEquals
		{
			name: "Matching scope for ListBucket",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:ListBucket"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          ListBucketAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"readonly"}},
			},
			expectedAllow: true,
		},
		{
			name: "Matching scope for GetObject",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:ListBucket"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"readonly"}},
			},
			expectedAllow: true,
		},
		// Negative case: Mismatched scope
		{
			name: "Mismatched scope for GetObject",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"writeonly"}},
			},
			expectedAllow: false,
		},
		// Negative case: Missing scope claim
		{
			name: "Missing scope for GetObject",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{},
			},
			expectedAllow: false,
		},
		// Deny effect with matching scope
		{
			name: "Deny effect with matching scope",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Deny",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"readonly"}},
			},
			expectedAllow: false,
		},
		// Multi-value scopes: Partial match with ForAnyValue
		{
			name: "Multi-value partial match",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly", "admin"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"readonly", "writeonly"}},
			},
			expectedAllow: true,
		},
		// Multi-value scopes: No match
		{
			name: "Multi-value no match",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly", "admin"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"guest"}},
			},
			expectedAllow: false,
		},
		// Different operator: StringNotEquals
		{
			name: "StringNotEquals mismatch allows",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"StringNotEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"writeonly"}},
			},
			expectedAllow: true,
		},
		{
			name: "StringNotEquals match denies",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"StringNotEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          GetObjectAction,
				BucketName:      "bucket1",
				ObjectName:      "test.txt",
				ConditionValues: map[string][]string{"scope": {"readonly"}},
			},
			expectedAllow: false,
		},
		// Invalid operator: Expect parse error (assuming ParseConfig validates operators for JWTScope)
		{
			name: "Invalid operator NumericEquals",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::bucket1/*"],
						"Condition": {
							"NumericEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args:           Args{}, // Not used if parse fails
			expectParseErr: true,
		},
		// Bucket-level resource for ListBucket (add bucket ARN if needed)
		{
			name: "Bucket-level ListBucket with matching scope",
			policyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:ListBucket"],
						"Resource": ["arn:aws:s3:::bucket1"],
						"Condition": {
							"ForAnyValue:StringEquals": {
								"jwt:scope": ["readonly"]
							}
						}
					}
				]
			}`,
			args: Args{
				Action:          ListBucketAction,
				BucketName:      "bucket1",
				ObjectName:      "", // No object for bucket action
				ConditionValues: map[string][]string{"scope": {"readonly"}},
			},
			expectedAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseConfig(strings.NewReader(tt.policyJSON))
			if tt.expectParseErr {
				if err == nil {
					t.Errorf("Expected ParseConfig error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected ParseConfig error: %v", err)
			}

			got := p.IsAllowed(tt.args)
			if got != tt.expectedAllow {
				t.Errorf("Expected IsAllowed to return %v, got %v", tt.expectedAllow, got)
			}
		})
	}
}

func TestDropDuplicateStatements(t *testing.T) {
	tests := []struct {
		name     string
		input    []Statement
		expected []Statement
	}{
		{
			name: "NoDuplicates",
			input: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:PutObject"}, []string{"arn:aws:s3:::bucket2/*"}, "Deny", nil),
			},
			expected: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:PutObject"}, []string{"arn:aws:s3:::bucket2/*"}, "Deny", nil),
			},
		},
		{
			name: "AllDuplicates",
			input: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
			},
			expected: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
			},
		},
		{
			name: "MixedDuplicates",
			input: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:PutObject"}, []string{"arn:aws:s3:::bucket2/*"}, "Deny", nil),
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket3/*"}, "Allow", nil),
			},
			expected: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
				setupStatement([]string{"s3:PutObject"}, []string{"arn:aws:s3:::bucket2/*"}, "Deny", nil),
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket3/*"}, "Allow", nil),
			},
		},
		{
			name:     "EmptySlice",
			input:    []Statement{},
			expected: []Statement{},
		},
		{
			name: "SingleStatement",
			input: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
			},
			expected: []Statement{
				setupStatement([]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket1/*"}, "Allow", nil),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				Version:    "2012-10-17",
				Statements: tt.input,
			}
			policy.dropDuplicateStatements()
			if !reflect.DeepEqual(policy.Statements, tt.expected) {
				t.Errorf("got %v, want %v", policy.Statements, tt.expected)
			}
		})
	}
}

func TestPolicyParseS3TablesExamples(t *testing.T) {
	tests := []struct {
		name              string
		policyJSON        string
		expectedActions   []Action
		expectedResources []string
		expectedCondKeys  []condition.KeyName
	}{
		{
			name: "TableBucketMaintenance",
			policyJSON: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3tables:PutTableBucketMaintenanceConfiguration"
      ],
      "Resource": "arn:aws:s3tables:::bucket/*"
    }
  ]
}`,
			expectedActions:   []Action{S3TablesPutTableBucketMaintenanceConfigurationAction},
			expectedResources: []string{"arn:aws:s3tables:::bucket/*"},
		},
		{
			name: "NamespaceSelectAccess",
			policyJSON: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3tables:GetTableData",
        "s3tables:GetTableMetadataLocation"
      ],
      "Resource": "arn:aws:s3tables:::bucket/amzn-s3-demo-table-bucket/table/*",
      "Condition": {
        "StringLike": {
          "s3tables:namespace": "hr"
        }
      }
    }
  ]
}`,
			expectedActions:   []Action{S3TablesGetTableDataAction, S3TablesGetTableMetadataLocationAction},
			expectedResources: []string{"arn:aws:s3tables:::bucket/amzn-s3-demo-table-bucket/table/*"},
			expectedCondKeys:  []condition.KeyName{condition.S3TablesNamespace},
		},
		{
			name: "TableDeleteFlow",
			policyJSON: `{
  "Version": "2012-10-17",
  "Id": "DeleteTable",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3tables:DeleteTable",
        "s3tables:UpdateTableMetadataLocation",
        "s3tables:PutTableData",
        "s3tables:GetTableMetadataLocation"
      ],
      "Resource": "arn:aws:s3tables:::bucket/amzn-s3-demo-bucket/table/tableUUID"
    }
  ]
}`,
			expectedActions: []Action{
				S3TablesDeleteTableAction,
				S3TablesUpdateTableMetadataLocationAction,
				S3TablesPutTableDataAction,
				S3TablesGetTableMetadataLocationAction,
			},
			expectedResources: []string{"arn:aws:s3tables:::bucket/amzn-s3-demo-bucket/table/tableUUID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseConfig(strings.NewReader(tt.policyJSON))
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if len(p.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(p.Statements))
			}
			st := p.Statements[0]

			actions := st.Actions.ToSlice()
			if len(actions) != len(tt.expectedActions) {
				t.Fatalf("expected %d actions, got %d", len(tt.expectedActions), len(actions))
			}
			actionSet := make(map[Action]struct{}, len(actions))
			for _, a := range actions {
				actionSet[a] = struct{}{}
			}
			for _, want := range tt.expectedActions {
				if _, ok := actionSet[want]; !ok {
					t.Fatalf("expected action %v missing", want)
				}
			}

			resources := st.Resources.ToSlice()
			if len(resources) != len(tt.expectedResources) {
				t.Fatalf("expected %d resources, got %d", len(tt.expectedResources), len(resources))
			}
			resourceSet := make(map[string]struct{}, len(resources))
			for _, r := range resources {
				resourceSet[r.String()] = struct{}{}
			}
			for _, want := range tt.expectedResources {
				if _, ok := resourceSet[want]; !ok {
					t.Fatalf("expected resource %q missing", want)
				}
			}

			if len(tt.expectedCondKeys) > 0 {
				keys := st.Conditions.Keys()
				if len(keys) != len(tt.expectedCondKeys) {
					t.Fatalf("expected %d condition keys, got %d", len(tt.expectedCondKeys), len(keys))
				}
				for _, keyName := range tt.expectedCondKeys {
					if !keys.Match(keyName.ToKey()) {
						t.Fatalf("expected condition key %v", keyName)
					}
				}
			} else if len(st.Conditions) != 0 {
				t.Fatalf("expected no conditions, got %v", st.Conditions)
			}
		})
	}
}

func TestS3TablesActionsWithImplicitMatching(t *testing.T) {
	policy1JSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3tables:GetTableData"],
				"Resource": ["arn:aws:s3tables:::bucket/my-warehouse/table/table-uuid-123"]
			}
		]
	}`

	policy2JSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3tables:PutTableData"],
				"Resource": ["arn:aws:s3tables:::bucket/test-warehouse/table/uuid-456"]
			}
		]
	}`

	policy3JSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3tables:GetTableData", "s3tables:PutTableData"],
				"Resource": ["arn:aws:s3tables:::bucket/wh/table/id"]
			}
		]
	}`

	policy4JSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3tables:*"],
				"Resource": ["arn:aws:s3tables:::bucket/all-warehouse/table/all-uuid"]
			}
		]
	}`

	testCases := []struct {
		name           string
		policyJSON     string
		args           Args
		expectedResult bool
		description    string
	}{
		{
			name:       "GetTableData direct match",
			policyJSON: policy1JSON,
			args: Args{
				Action:     S3TablesGetTableDataAction,
				BucketName: "bucket/my-warehouse/table/table-uuid-123",
			},
			expectedResult: true,
			description:    "S3 Tables action should match S3 Tables resource directly",
		},
		{
			name:       "GetTableData implicit GetObject match with resource conversion",
			policyJSON: policy1JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "my-warehouse",
				ObjectName: "table-uuid-123--table-aistor",
			},
			expectedResult: true,
			description:    "GetObject (implicit from GetTableData) should match when resource is converted from S3 to S3Tables format",
		},
		{
			name:       "GetTableData implicit GetObject with extra path",
			policyJSON: policy1JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "my-warehouse",
				ObjectName: "table-uuid-123--table-aistor/data/file.parquet",
			},
			expectedResult: true,
			description:    "GetObject should match even with extra path segments (should be discarded in conversion)",
		},
		{
			name:       "GetTableData implicit ListMultipartUploadParts match",
			policyJSON: policy1JSON,
			args: Args{
				Action:     ListMultipartUploadPartsAction,
				BucketName: "my-warehouse",
				ObjectName: "table-uuid-123--table-aistor",
			},
			expectedResult: true,
			description:    "ListMultipartUploadParts (implicit from GetTableData) should match with resource conversion",
		},
		{
			name:       "GetTableData wrong warehouse - should not match",
			policyJSON: policy1JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "wrong-warehouse",
				ObjectName: "table-uuid-123--table-aistor",
			},
			expectedResult: false,
			description:    "Should not match when warehouse name doesn't match",
		},
		{
			name:       "GetTableData wrong table uuid - should not match",
			policyJSON: policy1JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "my-warehouse",
				ObjectName: "wrong-uuid--table-aistor",
			},
			expectedResult: false,
			description:    "Should not match when table UUID doesn't match",
		},
		{
			name:       "PutTableData direct match",
			policyJSON: policy2JSON,
			args: Args{
				Action:     S3TablesPutTableDataAction,
				BucketName: "bucket/test-warehouse/table/uuid-456",
			},
			expectedResult: true,
			description:    "PutTableData action should match S3 Tables resource directly",
		},
		{
			name:       "PutTableData implicit PutObject match",
			policyJSON: policy2JSON,
			args: Args{
				Action:     PutObjectAction,
				BucketName: "test-warehouse",
				ObjectName: "uuid-456--table-aistor",
			},
			expectedResult: true,
			description:    "PutObject (implicit from PutTableData) should match with resource conversion",
		},
		{
			name:       "PutTableData implicit AbortMultipartUpload match",
			policyJSON: policy2JSON,
			args: Args{
				Action:     AbortMultipartUploadAction,
				BucketName: "test-warehouse",
				ObjectName: "uuid-456--table-aistor/upload",
			},
			expectedResult: true,
			description:    "AbortMultipartUpload (implicit from PutTableData) should match",
		},
		{
			name:       "Multiple actions - GetObject implicit match",
			policyJSON: policy3JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "wh",
				ObjectName: "id--table-aistor",
			},
			expectedResult: true,
			description:    "Should match with multiple S3 Tables actions in statement",
		},
		{
			name:       "Multiple actions - PutObject implicit match",
			policyJSON: policy3JSON,
			args: Args{
				Action:     PutObjectAction,
				BucketName: "wh",
				ObjectName: "id--table-aistor",
			},
			expectedResult: true,
			description:    "Should match PutObject when both GetTableData and PutTableData are allowed",
		},
		{
			name:       "Non-implicit action should not match",
			policyJSON: policy1JSON,
			args: Args{
				Action:     DeleteObjectAction,
				BucketName: "my-warehouse",
				ObjectName: "table-uuid-123--table-aistor",
			},
			expectedResult: false,
			description:    "DeleteObject is not implicit from GetTableData, should not match",
		},
		{
			name:       "s3tables:* allows GetObject implicitly",
			policyJSON: policy4JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "all-warehouse",
				ObjectName: "all-uuid--table-aistor",
			},
			expectedResult: true,
			description:    "s3tables:* should allow GetObject through implicit matching with resource conversion",
		},
		{
			name:       "s3tables:* allows PutObject implicitly",
			policyJSON: policy4JSON,
			args: Args{
				Action:     PutObjectAction,
				BucketName: "all-warehouse",
				ObjectName: "all-uuid--table-aistor",
			},
			expectedResult: true,
			description:    "s3tables:* should allow PutObject through implicit matching",
		},
		{
			name:       "s3tables:* allows ListMultipartUploadParts implicitly",
			policyJSON: policy4JSON,
			args: Args{
				Action:     ListMultipartUploadPartsAction,
				BucketName: "all-warehouse",
				ObjectName: "all-uuid--table-aistor",
			},
			expectedResult: true,
			description:    "s3tables:* should allow ListMultipartUploadParts through implicit matching",
		},
		{
			name:       "s3tables:* allows AbortMultipartUpload implicitly",
			policyJSON: policy4JSON,
			args: Args{
				Action:     AbortMultipartUploadAction,
				BucketName: "all-warehouse",
				ObjectName: "all-uuid--table-aistor",
			},
			expectedResult: true,
			description:    "s3tables:* should allow AbortMultipartUpload through implicit matching",
		},
		{
			name:       "s3tables:* with extra path segments",
			policyJSON: policy4JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "all-warehouse",
				ObjectName: "all-uuid--table-aistor/extra/path/data.parquet",
			},
			expectedResult: true,
			description:    "s3tables:* should match with extra path segments discarded",
		},
		{
			name:       "s3tables:* wrong warehouse should not match",
			policyJSON: policy4JSON,
			args: Args{
				Action:     GetObjectAction,
				BucketName: "wrong-warehouse",
				ObjectName: "all-uuid--table-aistor",
			},
			expectedResult: false,
			description:    "s3tables:* should not match when warehouse name is wrong",
		},
		{
			name:       "s3tables:* wrong uuid should not match",
			policyJSON: policy4JSON,
			args: Args{
				Action:     PutObjectAction,
				BucketName: "all-warehouse",
				ObjectName: "wrong-uuid--table-aistor",
			},
			expectedResult: false,
			description:    "s3tables:* should not match when table UUID is wrong",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseConfig(strings.NewReader(tc.policyJSON))
			if err != nil {
				t.Fatalf("failed to parse policy: %v", err)
			}

			result := p.IsAllowed(tc.args)
			if result != tc.expectedResult {
				t.Errorf("%s: expected %v, got %v", tc.description, tc.expectedResult, result)
			}
		})
	}
}
