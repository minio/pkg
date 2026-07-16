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

package policy

// KMSAction - KMS policy action.
type KMSAction string

const (
	// KMSCreateKeyAction - allow creating a new KMS master key
	KMSCreateKeyAction KMSAction = "kms:CreateKey"
	// KMSDeleteKeyAction - allow deleting a KMS master key
	KMSDeleteKeyAction KMSAction = "kms:DeleteKey"
	// KMSListKeysAction - allow getting list of KMS keys
	KMSListKeysAction KMSAction = "kms:ListKeys"
	// KMSImportKeyAction - allow importing KMS key
	KMSImportKeyAction KMSAction = "kms:ImportKey"
	// KMSDescribePolicyAction - allow getting KMS policy
	KMSDescribePolicyAction KMSAction = "kms:DescribePolicy"
	// KMSAssignPolicyAction - allow assigning an identity to a KMS policy
	KMSAssignPolicyAction KMSAction = "kms:AssignPolicy"
	// KMSDeletePolicyAction - allow deleting a policy
	KMSDeletePolicyAction KMSAction = "kms:DeletePolicy"
	// KMSSetPolicyAction - allow creating or updating a policy
	KMSSetPolicyAction KMSAction = "kms:SetPolicy"
	// KMSGetPolicyAction - allow getting a policy
	KMSGetPolicyAction KMSAction = "kms:GetPolicy"
	// KMSListPoliciesAction - allow getting list of KMS policies
	KMSListPoliciesAction KMSAction = "kms:ListPolicies"
	// KMSDescribeIdentityAction - allow getting KMS identity
	KMSDescribeIdentityAction KMSAction = "kms:DescribeIdentity"
	// KMSDescribeSelfIdentityAction - allow getting self KMS identity
	KMSDescribeSelfIdentityAction KMSAction = "kms:DescribeSelfIdentity"
	// KMSDeleteIdentityAction - allow deleting a policy
	KMSDeleteIdentityAction KMSAction = "kms:DeleteIdentity"
	// KMSListIdentitiesAction - allow getting list of KMS identities
	KMSListIdentitiesAction KMSAction = "kms:ListIdentities"
	// KMSKeyStatusAction - allow getting KMS key status
	KMSKeyStatusAction KMSAction = "kms:KeyStatus"
	// KMSStatusAction - allow getting KMS status
	KMSStatusAction KMSAction = "kms:Status"
	// KMSAPIAction - allow getting a list of supported API endpoints
	KMSAPIAction KMSAction = "kms:API"
	// KMSMetricsAction - allow getting server metrics in the Prometheus exposition format
	KMSMetricsAction KMSAction = "kms:Metrics"
	// KMSVersionAction - allow getting version information
	KMSVersionAction KMSAction = "kms:Version"
	// KMSAuditLogAction - subscribes to the audit log
	KMSAuditLogAction KMSAction = "kms:AuditLog"
	// KMSErrorLogAction - subscribes to the error log
	KMSErrorLogAction KMSAction = "kms:ErrorLog"
	// AllKMSActions - provides all admin permissions
	AllKMSActions KMSAction = "kms:*"
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
	KMSStatusAction:               {},
	KMSAPIAction:                  {},
	KMSMetricsAction:              {},
	KMSVersionAction:              {},
	KMSAuditLogAction:             {},
	KMSErrorLogAction:             {},
	AllKMSActions:                 {},
}

// IsValid - checks if action is valid or not.
func (action KMSAction) IsValid() bool {
	_, ok := supportedKMSActions[action]
	return ok
}
