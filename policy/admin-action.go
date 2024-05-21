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
	"github.com/minio/pkg/v3/policy/condition"
)

// AdminAction - admin policy action.
type AdminAction string

const (
	// HealAdminAction - allows heal command
	HealAdminAction = "admin:Heal"

	// DecommissionAdminAction - allows decomissioning of pools
	DecommissionAdminAction = "admin:Decommission"

	// RebalanceAdminAction - allows rebalancing of pools
	RebalanceAdminAction = "admin:Rebalance"
	// Service Actions

	// StorageInfoAdminAction - allow listing server info
	StorageInfoAdminAction = "admin:StorageInfo"
	// PrometheusAdminAction - prometheus info action
	PrometheusAdminAction = "admin:Prometheus"
	// DataUsageInfoAdminAction - allow listing data usage info
	DataUsageInfoAdminAction = "admin:DataUsageInfo"
	// ForceUnlockAdminAction - allow force unlocking locks
	ForceUnlockAdminAction = "admin:ForceUnlock"
	// TopLocksAdminAction - allow listing top locks
	TopLocksAdminAction = "admin:TopLocksInfo"
	// ProfilingAdminAction - allow profiling
	ProfilingAdminAction = "admin:Profiling"
	// TraceAdminAction - allow listing server trace
	TraceAdminAction = "admin:ServerTrace"
	// ConsoleLogAdminAction - allow listing console logs on terminal
	ConsoleLogAdminAction = "admin:ConsoleLog"
	// KMSCreateKeyAdminAction - allow creating a new KMS master key
	KMSCreateKeyAdminAction = "admin:KMSCreateKey"
	// KMSKeyStatusAdminAction - allow getting KMS key status
	KMSKeyStatusAdminAction = "admin:KMSKeyStatus"
	// ServerInfoAdminAction - allow listing server info
	ServerInfoAdminAction = "admin:ServerInfo"
	// HealthInfoAdminAction - allow obtaining cluster health information
	HealthInfoAdminAction = "admin:OBDInfo"
	// BandwidthMonitorAction - allow monitoring bandwidth usage
	BandwidthMonitorAction = "admin:BandwidthMonitor"
	// InspectDataAction - allows downloading raw files from backend
	InspectDataAction = "admin:InspectData"

	// ServerUpdateAdminAction - allow MinIO binary update
	ServerUpdateAdminAction = "admin:ServerUpdate"
	// ServiceRestartAdminAction - allow restart of MinIO service.
	ServiceRestartAdminAction = "admin:ServiceRestart"
	// ServiceStopAdminAction - allow stopping MinIO service.
	ServiceStopAdminAction = "admin:ServiceStop"
	// ServiceFreezeAdminAction - allow freeze/unfreeze MinIO service.
	ServiceFreezeAdminAction = "admin:ServiceFreeze"

	// ConfigUpdateAdminAction - allow MinIO config management
	ConfigUpdateAdminAction = "admin:ConfigUpdate"

	// CreateUserAdminAction - allow creating MinIO user
	CreateUserAdminAction = "admin:CreateUser"
	// DeleteUserAdminAction - allow deleting MinIO user
	DeleteUserAdminAction = "admin:DeleteUser"
	// ListUsersAdminAction - allow list users permission
	ListUsersAdminAction = "admin:ListUsers"
	// EnableUserAdminAction - allow enable user permission
	EnableUserAdminAction = "admin:EnableUser"
	// DisableUserAdminAction - allow disable user permission
	DisableUserAdminAction = "admin:DisableUser"
	// GetUserAdminAction - allows GET permission on user info
	GetUserAdminAction = "admin:GetUser"

	// Cluster Replicate Actions

	// SiteReplicationAddAction - allow adding clusters for site-level replication
	SiteReplicationAddAction = "admin:SiteReplicationAdd"
	// SiteReplicationDisableAction - allow disabling a cluster from replication
	SiteReplicationDisableAction = "admin:SiteReplicationDisable"
	// SiteReplicationRemoveAction - allow removing a cluster from replication
	SiteReplicationRemoveAction = "admin:SiteReplicationRemove"
	// SiteReplicationResyncAction - allow resyncing cluster data to another site
	SiteReplicationResyncAction = "admin:SiteReplicationResync"
	// SiteReplicationInfoAction - allow getting site replication info
	SiteReplicationInfoAction = "admin:SiteReplicationInfo"
	// SiteReplicationOperationAction - allow performing site replication
	// create/update/delete operations to peers
	SiteReplicationOperationAction = "admin:SiteReplicationOperation"

	// Service account Actions

	// CreateServiceAccountAdminAction - allow create a service account for a user
	CreateServiceAccountAdminAction = "admin:CreateServiceAccount"
	// UpdateServiceAccountAdminAction - allow updating a service account
	UpdateServiceAccountAdminAction = "admin:UpdateServiceAccount"
	// RemoveServiceAccountAdminAction - allow removing a service account
	RemoveServiceAccountAdminAction = "admin:RemoveServiceAccount"
	// ListServiceAccountsAdminAction - allow listing service accounts
	ListServiceAccountsAdminAction = "admin:ListServiceAccounts"

	// ListTemporaryAccountsAdminAction - allow listing of temporary accounts
	ListTemporaryAccountsAdminAction = "admin:ListTemporaryAccounts"

	// Group Actions

	// AddUserToGroupAdminAction - allow adding user to group permission
	AddUserToGroupAdminAction = "admin:AddUserToGroup"
	// RemoveUserFromGroupAdminAction - allow removing user to group permission
	RemoveUserFromGroupAdminAction = "admin:RemoveUserFromGroup"
	// GetGroupAdminAction - allow getting group info
	GetGroupAdminAction = "admin:GetGroup"
	// ListGroupsAdminAction - allow list groups permission
	ListGroupsAdminAction = "admin:ListGroups"
	// EnableGroupAdminAction - allow enable group permission
	EnableGroupAdminAction = "admin:EnableGroup"
	// DisableGroupAdminAction - allow disable group permission
	DisableGroupAdminAction = "admin:DisableGroup"

	// Policy Actions

	// CreatePolicyAdminAction - allow create policy permission
	CreatePolicyAdminAction = "admin:CreatePolicy"
	// DeletePolicyAdminAction - allow delete policy permission
	DeletePolicyAdminAction = "admin:DeletePolicy"
	// GetPolicyAdminAction - allow get policy permission
	GetPolicyAdminAction = "admin:GetPolicy"
	// AttachPolicyAdminAction - allows attaching a policy to a user/group
	AttachPolicyAdminAction = "admin:AttachUserOrGroupPolicy"
	// UpdatePolicyAssociationAction - allows to add/remove policy association
	// on a user or group.
	UpdatePolicyAssociationAction = "admin:UpdatePolicyAssociation"
	// ListUserPoliciesAdminAction - allows listing user policies
	ListUserPoliciesAdminAction = "admin:ListUserPolicies"

	// Bucket quota Actions

	// SetBucketQuotaAdminAction - allow setting bucket quota
	SetBucketQuotaAdminAction = "admin:SetBucketQuota"
	// GetBucketQuotaAdminAction - allow getting bucket quota
	GetBucketQuotaAdminAction = "admin:GetBucketQuota"

	// Bucket Target admin Actions

	// SetBucketTargetAction - allow setting bucket target
	SetBucketTargetAction = "admin:SetBucketTarget"
	// GetBucketTargetAction - allow getting bucket targets
	GetBucketTargetAction = "admin:GetBucketTarget"

	// ReplicationDiff - allow computing the unreplicated objects in a bucket
	ReplicationDiff = "admin:ReplicationDiff"

	// Bucket import/export admin Actions

	// ImportBucketMetadataAction - allow importing bucket metadata
	ImportBucketMetadataAction = "admin:ImportBucketMetadata"
	// ExportBucketMetadataAction - allow exporting bucket metadata
	ExportBucketMetadataAction = "admin:ExportBucketMetadata"

	// Remote Tier admin Actions

	// SetTierAction - allow adding/editing a remote tier
	SetTierAction = "admin:SetTier"
	// ListTierAction - allow listing remote tiers
	ListTierAction = "admin:ListTier"

	// Migrate IAM admin Actions

	// ExportIAMAction - allow exporting of all IAM info
	ExportIAMAction = "admin:ExportIAM"
	// ImportIAMAction - allow importing IAM info to MinIO
	ImportIAMAction = "admin:ImportIAM"

	// Batch Job APIs

	// ListBatchJobsAction allow listing current active jobs
	ListBatchJobsAction = "admin:ListBatchJobs"

	// DescribeBatchJobAction allow getting batch job YAML
	DescribeBatchJobAction = "admin:DescribeBatchJob"

	// StartBatchJobAction allow submitting a batch job
	StartBatchJobAction = "admin:StartBatchJob"

	// CancelBatchJobAction allow canceling a batch job
	CancelBatchJobAction = "admin:CancelBatchJob"

	// AllAdminActions - provides all admin permissions
	AllAdminActions = "admin:*"
)

// List of all supported admin actions.
var supportedAdminActions = map[AdminAction]struct{}{
	HealAdminAction:                  {},
	StorageInfoAdminAction:           {},
	DataUsageInfoAdminAction:         {},
	TopLocksAdminAction:              {},
	ProfilingAdminAction:             {},
	PrometheusAdminAction:            {},
	TraceAdminAction:                 {},
	ConsoleLogAdminAction:            {},
	KMSCreateKeyAdminAction:          {},
	KMSKeyStatusAdminAction:          {},
	ServerInfoAdminAction:            {},
	HealthInfoAdminAction:            {},
	BandwidthMonitorAction:           {},
	ServerUpdateAdminAction:          {},
	ServiceRestartAdminAction:        {},
	ServiceStopAdminAction:           {},
	ServiceFreezeAdminAction:         {},
	ConfigUpdateAdminAction:          {},
	CreateUserAdminAction:            {},
	DeleteUserAdminAction:            {},
	ListUsersAdminAction:             {},
	EnableUserAdminAction:            {},
	DisableUserAdminAction:           {},
	GetUserAdminAction:               {},
	AddUserToGroupAdminAction:        {},
	RemoveUserFromGroupAdminAction:   {},
	GetGroupAdminAction:              {},
	ListGroupsAdminAction:            {},
	EnableGroupAdminAction:           {},
	DisableGroupAdminAction:          {},
	CreateServiceAccountAdminAction:  {},
	UpdateServiceAccountAdminAction:  {},
	RemoveServiceAccountAdminAction:  {},
	ListServiceAccountsAdminAction:   {},
	ListTemporaryAccountsAdminAction: {},
	CreatePolicyAdminAction:          {},
	DeletePolicyAdminAction:          {},
	GetPolicyAdminAction:             {},
	AttachPolicyAdminAction:          {},
	UpdatePolicyAssociationAction:    {},
	ListUserPoliciesAdminAction:      {},
	SetBucketQuotaAdminAction:        {},
	GetBucketQuotaAdminAction:        {},
	SetBucketTargetAction:            {},
	GetBucketTargetAction:            {},
	ReplicationDiff:                  {},
	SetTierAction:                    {},
	ListTierAction:                   {},
	DecommissionAdminAction:          {},
	RebalanceAdminAction:             {},
	SiteReplicationAddAction:         {},
	SiteReplicationDisableAction:     {},
	SiteReplicationInfoAction:        {},
	SiteReplicationOperationAction:   {},
	SiteReplicationRemoveAction:      {},
	SiteReplicationResyncAction:      {},

	ImportBucketMetadataAction: {},
	ExportBucketMetadataAction: {},
	ExportIAMAction:            {},
	ImportIAMAction:            {},

	ListBatchJobsAction:    {},
	DescribeBatchJobAction: {},
	StartBatchJobAction:    {},
	CancelBatchJobAction:   {},

	AllAdminActions: {},
}

// IsValid - checks if action is valid or not.
func (action AdminAction) IsValid() bool {
	_, ok := supportedAdminActions[action]
	return ok
}

func createAdminActionConditionKeyMap() map[Action]condition.KeySet {
	allSupportedAdminKeys := []condition.Key{}
	for _, keyName := range condition.AllSupportedAdminKeys {
		allSupportedAdminKeys = append(allSupportedAdminKeys, keyName.ToKey())
	}

	adminActionConditionKeyMap := map[Action]condition.KeySet{}
	for act := range supportedAdminActions {
		adminActionConditionKeyMap[Action(act)] = condition.NewKeySet(allSupportedAdminKeys...)
	}
	return adminActionConditionKeyMap
}

// adminActionConditionKeyMap - holds mapping of supported condition key for an action.
var adminActionConditionKeyMap = createAdminActionConditionKeyMap()
