// Copyright (c) 2015-2022 MinIO, Inc.
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

package iampolicy

// KMSAction - KMS policy action.
type KMSAction string

const (
	// KMSCreateKeyAction - allow creating a new KMS master key
	KMSCreateKeyAction = "kms:KMSCreateKey"
	// KMSDeleteKeyAction - allow deleting a KMS master key
	KMSDeleteKeyAction = "kms:KMSDeleteKey"
	// KMSListKeysAction - allow getting list of KMS keys
	KMSListKeysAction = "kms:KMSListKeys"
	// KMSImportKeyAction - allow importing KMS key
	KMSImportKeyAction = "kms:KMSImportKey"
	// KMSDescribePolicyAction - allow getting KMS policy
	KMSDescribePolicyAction = "kms:KMSDescribePolicy"
	// KMSAssignPolicyAction - allow assigning an identity to a KMS policy
	KMSAssignPolicyAction = "kms:KMSAssignPolicy"
	// KMSDeletePolicyAction - allow deleting a policy
	KMSDeletePolicyAction = "kms:KMSDeletePolicy"
	// KMSSetPolicyAction - allow creating or updating a policy
	KMSSetPolicyAction = "kms:KMSSetPolicy"
	// KMSGetPolicyAction - allow getting a policy
	KMSGetPolicyAction = "kms:KMSGetPolicy"
	// KMSListPoliciesAction - allow getting list of KMS policies
	KMSListPoliciesAction = "kms:KMSListPolicies"
	// KMSDescribeIdentityAction - allow getting KMS identity
	KMSDescribeIdentityAction = "kms:KMSDescribeIdentity"
	// KMSDescribeSelfIdentityAction - allow getting self KMS identity
	KMSDescribeSelfIdentityAction = "kms:KMSDescribeSelfIdentity"
	// KMSDeleteIdentityAction - allow deleting a policy
	KMSDeleteIdentityAction = "kms:KMSDeleteIdentity"
	// KMSListIdentitiesAction - allow getting list of KMS identities
	KMSListIdentitiesAction = "kms:KMSListIdentities"
	// KMSKeyStatusAction - allow getting KMS key status
	KMSKeyStatusAction = "kms:KMSKeyStatus"
	// KMSStatusAction - allow getting KMS status
	KMSStatusAction = "kms:KMSStatus"
	// AllKMSActions - provides all admin permissions
	AllKMSActions = "kms:*"
)

// List of all supported admin actions.
var supportedKMSActions = map[KMSAction]struct{}{
	KMSCreateKeyAction:            {},
	KMSDeleteKeyAction:            {},
	KMSListKeysAction:             {},
	KMSImportKeyAction:            {},
	KMSDescribePolicyAction:       {},
	KMSAssignPolicyAction:         {},
	KMSDeletePolicyAction:         {},
	KMSSetPolicyAction:            {},
	KMSGetPolicyAction:            {},
	KMSListPoliciesAction:         {},
	KMSDescribeIdentityAction:     {},
	KMSDescribeSelfIdentityAction: {},
	KMSDeleteIdentityAction:       {},
	KMSListIdentitiesAction:       {},
	KMSKeyStatusAction:            {},
	AllKMSActions:                 {},
}

// IsValid - checks if action is valid or not.
func (action KMSAction) IsValid() bool {
	_, ok := supportedKMSActions[action]
	return ok
}
