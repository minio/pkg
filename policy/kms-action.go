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
	KMSCreateKeyAction = "kms:CreateKey"
	// KMSDeleteKeyAction - allow deleting a KMS master key
	KMSDeleteKeyAction = "kms:DeleteKey"
	// KMSListKeysAction - allow getting list of KMS keys
	KMSListKeysAction = "kms:ListKeys"
	// KMSImportKeyAction - allow importing KMS key
	KMSImportKeyAction = "kms:ImportKey"
	// KMSDescribePolicyAction - allow getting KMS policy
	KMSDescribePolicyAction = "kms:DescribePolicy"
	// KMSAssignPolicyAction - allow assigning an identity to a KMS policy
	KMSAssignPolicyAction = "kms:AssignPolicy"
	// KMSDeletePolicyAction - allow deleting a policy
	KMSDeletePolicyAction = "kms:DeletePolicy"
	// KMSSetPolicyAction - allow creating or updating a policy
	KMSSetPolicyAction = "kms:SetPolicy"
	// KMSGetPolicyAction - allow getting a policy
	KMSGetPolicyAction = "kms:GetPolicy"
	// KMSListPoliciesAction - allow getting list of KMS policies
	KMSListPoliciesAction = "kms:ListPolicies"
	// KMSDescribeIdentityAction - allow getting KMS identity
	KMSDescribeIdentityAction = "kms:DescribeIdentity"
	// KMSDescribeSelfIdentityAction - allow getting self KMS identity
	KMSDescribeSelfIdentityAction = "kms:DescribeSelfIdentity"
	// KMSDeleteIdentityAction - allow deleting a policy
	KMSDeleteIdentityAction = "kms:DeleteIdentity"
	// KMSListIdentitiesAction - allow getting list of KMS identities
	KMSListIdentitiesAction = "kms:ListIdentities"
	// KMSKeyStatusAction - allow getting KMS key status
	KMSKeyStatusAction = "kms:KeyStatus"
	// KMSStatusAction - allow getting KMS status
	KMSStatusAction = "kms:Status"
	// KMSAPIAction - allow getting a list of supported API endpoints
	KMSAPIAction = "kms:API"
	// KMSMetricsAction - allow getting server metrics in the Prometheus exposition format
	KMSMetricsAction = "kms:Metrics"
	// KMSVersionAction - allow getting version information
	KMSVersionAction = "kms:Version"
	// KMSAuditLogAction - subscribes to the audit log
	KMSAuditLogAction = "kms:AuditLog"
	// KMSErrorLogAction - subscribes to the error log
	KMSErrorLogAction = "kms:ErrorLog"
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
