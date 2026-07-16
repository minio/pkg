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
	"github.com/minio/pkg/v3/wildcard"
)

// AdminAction - admin policy action.
type AdminAction string

const (
	// HealAdminAction - allows heal command
	HealAdminAction AdminAction = "admin:Heal"

	// DecommissionAdminAction - allows decomissioning of pools
	DecommissionAdminAction AdminAction = "admin:Decommission"

	// RebalanceAdminAction - allows rebalancing of pools
	RebalanceAdminAction AdminAction = "admin:Rebalance"
	// Service Actions

	// StorageInfoAdminAction - allow listing server info
	StorageInfoAdminAction AdminAction = "admin:StorageInfo"
	// PrometheusAdminAction - prometheus info action
	PrometheusAdminAction AdminAction = "admin:Prometheus"
	// DataUsageInfoAdminAction - allow listing data usage info
	DataUsageInfoAdminAction AdminAction = "admin:DataUsageInfo"
	// ForceUnlockAdminAction - allow force unlocking locks
	ForceUnlockAdminAction AdminAction = "admin:ForceUnlock"
	// TopLocksAdminAction - allow listing top locks
	TopLocksAdminAction AdminAction = "admin:TopLocksInfo"
	// ProfilingAdminAction - allow profiling
	ProfilingAdminAction AdminAction = "admin:Profiling"
	// TraceAdminAction - allow listing server trace
	TraceAdminAction AdminAction = "admin:ServerTrace"
	// ConsoleLogAdminAction - allow listing console logs on terminal
	ConsoleLogAdminAction AdminAction = "admin:ConsoleLog"
	// KMSEnableAdminAction - allow enabling the builtin KMS
	KMSEnableAdminAction AdminAction = "admin:KMSEnable"
	// KMSBackupAdminAction - allow backing up builtin KMS keys
	KMSBackupAdminAction AdminAction = "admin:KMSBackup"
	// KMSRestoreAdminAction - allow restoring builtin KMS keys
	KMSRestoreAdminAction AdminAction = "admin:KMSRestore"
	// KMSCreateKeyAdminAction - allow creating a new KMS master key
	KMSCreateKeyAdminAction AdminAction = "admin:KMSCreateKey"
	// KMSKeyStatusAdminAction - allow getting KMS key status
	KMSKeyStatusAdminAction AdminAction = "admin:KMSKeyStatus"
	// KMSKeyRotateAdminAction - allow rotating KMS keys
	KMSKeyRotateAdminAction AdminAction = "admin:KMSKeyRotate"
	// ServerInfoAdminAction - allow listing server info
	ServerInfoAdminAction AdminAction = "admin:ServerInfo"
	// HealthInfoAdminAction - allow obtaining cluster health information
	HealthInfoAdminAction AdminAction = "admin:OBDInfo"
	// LicenseInfoAdminAction - allow obtaining license information
	LicenseInfoAdminAction AdminAction = "admin:LicenseInfo"
	// BandwidthMonitorAction - allow monitoring bandwidth usage
	BandwidthMonitorAction AdminAction = "admin:BandwidthMonitor"
	// InspectDataAction - allows downloading raw files from backend
	InspectDataAction AdminAction = "admin:InspectData"

	// ServerUpdateAdminAction - allow MinIO binary update
	ServerUpdateAdminAction AdminAction = "admin:ServerUpdate"
	// ServiceRestartAdminAction - allow restart of MinIO service.
	ServiceRestartAdminAction AdminAction = "admin:ServiceRestart"
	// ServiceStopAdminAction - allow stopping MinIO service.
	ServiceStopAdminAction AdminAction = "admin:ServiceStop"
	// ServiceFreezeAdminAction - allow freeze/unfreeze MinIO service.
	ServiceFreezeAdminAction AdminAction = "admin:ServiceFreeze"
	// ServiceCordonAdminAction - allow cordon/uncordon MinIO service.
	ServiceCordonAdminAction AdminAction = "admin:ServiceCordon"

	// ConfigUpdateAdminAction - allow MinIO config management
	ConfigUpdateAdminAction AdminAction = "admin:ConfigUpdate"

	// CreateUserAdminAction - allow creating MinIO user
	CreateUserAdminAction AdminAction = "admin:CreateUser"
	// DeleteUserAdminAction - allow deleting MinIO user
	DeleteUserAdminAction AdminAction = "admin:DeleteUser"
	// ListUsersAdminAction - allow list users permission
	ListUsersAdminAction AdminAction = "admin:ListUsers"
	// EnableUserAdminAction - allow enable user permission
	EnableUserAdminAction AdminAction = "admin:EnableUser"
	// DisableUserAdminAction - allow disable user permission
	DisableUserAdminAction AdminAction = "admin:DisableUser"
	// GetUserAdminAction - allows GET permission on user info
	GetUserAdminAction AdminAction = "admin:GetUser"
	// ChangeMyPasswordAdminAction - allow changing own password
	ChangeMyPasswordAdminAction AdminAction = "admin:ChangeMyPassword"

	// Cluster Replicate Actions

	// SiteReplicationAddAction - allow adding clusters for site-level replication
	SiteReplicationAddAction AdminAction = "admin:SiteReplicationAdd"
	// SiteReplicationDisableAction - allow disabling a cluster from replication
	SiteReplicationDisableAction AdminAction = "admin:SiteReplicationDisable"
	// SiteReplicationRemoveAction - allow removing a cluster from replication
	SiteReplicationRemoveAction AdminAction = "admin:SiteReplicationRemove"
	// SiteReplicationResyncAction - allow resyncing cluster data to another site
	SiteReplicationResyncAction AdminAction = "admin:SiteReplicationResync"
	// SiteReplicationInfoAction - allow getting site replication info
	SiteReplicationInfoAction AdminAction = "admin:SiteReplicationInfo"
	// SiteReplicationOperationAction - allow performing site replication
	// create/update/delete operations to peers
	SiteReplicationOperationAction AdminAction = "admin:SiteReplicationOperation"

	// Tables Replication Actions

	// TablesReplicationAddAction - allow adding tables replication targets
	TablesReplicationAddAction AdminAction = "admin:TablesReplicationAdd"
	// TablesReplicationRemoveAction - allow removing tables replication targets
	TablesReplicationRemoveAction AdminAction = "admin:TablesReplicationRemove"
	// TablesReplicationInfoAction - allow getting tables replication info/status
	TablesReplicationInfoAction AdminAction = "admin:TablesReplicationInfo"
	// TablesReplicationStartFailoverAction - allow starting tables replication failover
	TablesReplicationStartFailoverAction AdminAction = "admin:TablesReplicationStartFailover"
	// TablesReplicationCatalogAdminAction - allow catalog debugging operations (reset, dump contents)
	TablesReplicationCatalogAdminAction AdminAction = "admin:TablesReplicationCatalogAdmin"

	// Service account Actions

	// CreateServiceAccountAdminAction - allow create a service account for a user
	CreateServiceAccountAdminAction AdminAction = "admin:CreateServiceAccount"
	// UpdateServiceAccountAdminAction - allow updating a service account
	UpdateServiceAccountAdminAction AdminAction = "admin:UpdateServiceAccount"
	// RemoveServiceAccountAdminAction - allow removing a service account
	RemoveServiceAccountAdminAction AdminAction = "admin:RemoveServiceAccount"
	// ListServiceAccountsAdminAction - allow listing service accounts
	ListServiceAccountsAdminAction AdminAction = "admin:ListServiceAccounts"

	// ListTemporaryAccountsAdminAction - allow listing of temporary accounts
	ListTemporaryAccountsAdminAction AdminAction = "admin:ListTemporaryAccounts"

	// Group Actions

	// AddUserToGroupAdminAction - allow adding user to group permission
	AddUserToGroupAdminAction AdminAction = "admin:AddUserToGroup"
	// RemoveUserFromGroupAdminAction - allow removing user to group permission
	RemoveUserFromGroupAdminAction AdminAction = "admin:RemoveUserFromGroup"
	// GetGroupAdminAction - allow getting group info
	GetGroupAdminAction AdminAction = "admin:GetGroup"
	// ListGroupsAdminAction - allow list groups permission
	ListGroupsAdminAction AdminAction = "admin:ListGroups"
	// EnableGroupAdminAction - allow enable group permission
	EnableGroupAdminAction AdminAction = "admin:EnableGroup"
	// DisableGroupAdminAction - allow disable group permission
	DisableGroupAdminAction AdminAction = "admin:DisableGroup"

	// Policy Actions

	// CreatePolicyAdminAction - allow create policy permission
	CreatePolicyAdminAction AdminAction = "admin:CreatePolicy"
	// DeletePolicyAdminAction - allow delete policy permission
	DeletePolicyAdminAction AdminAction = "admin:DeletePolicy"
	// GetPolicyAdminAction - allow get policy permission
	GetPolicyAdminAction AdminAction = "admin:GetPolicy"
	// AttachPolicyAdminAction - allows attaching a policy to a user/group
	AttachPolicyAdminAction AdminAction = "admin:AttachUserOrGroupPolicy"
	// UpdatePolicyAssociationAction - allows to add/remove policy association
	// on a user or group.
	UpdatePolicyAssociationAction AdminAction = "admin:UpdatePolicyAssociation"
	// ListUserPoliciesAdminAction - allows listing user policies
	ListUserPoliciesAdminAction AdminAction = "admin:ListUserPolicies"

	// Bucket quota Actions

	// SetBucketQuotaAdminAction - allow setting bucket quota
	SetBucketQuotaAdminAction AdminAction = "admin:SetBucketQuota"
	// GetBucketQuotaAdminAction - allow getting bucket quota
	GetBucketQuotaAdminAction AdminAction = "admin:GetBucketQuota"

	// Bucket compression Actions

	// SetBucketCompressionAdminAction - allow setting per-bucket compression config
	SetBucketCompressionAdminAction AdminAction = "admin:SetBucketCompression"
	// GetBucketCompressionAdminAction - allow getting per-bucket compression config
	GetBucketCompressionAdminAction AdminAction = "admin:GetBucketCompression"

	// Bucket Target admin Actions

	// SetBucketTargetAction - allow setting bucket target
	SetBucketTargetAction AdminAction = "admin:SetBucketTarget"
	// GetBucketTargetAction - allow getting bucket targets
	GetBucketTargetAction AdminAction = "admin:GetBucketTarget"

	// ReplicationDiff - allow computing the unreplicated objects in a bucket
	ReplicationDiff AdminAction = "admin:ReplicationDiff"

	// Bucket import/export admin Actions

	// ImportBucketMetadataAction - allow importing bucket metadata
	ImportBucketMetadataAction AdminAction = "admin:ImportBucketMetadata"
	// ExportBucketMetadataAction - allow exporting bucket metadata
	ExportBucketMetadataAction AdminAction = "admin:ExportBucketMetadata"

	// Remote Tier admin Actions

	// SetTierAction - allow adding/editing a remote tier
	SetTierAction AdminAction = "admin:SetTier"
	// ListTierAction - allow listing remote tiers
	ListTierAction AdminAction = "admin:ListTier"

	// Migrate IAM admin Actions

	// ExportIAMAction - allow exporting of all IAM info
	ExportIAMAction AdminAction = "admin:ExportIAM"
	// ImportIAMAction - allow importing IAM info to MinIO
	ImportIAMAction AdminAction = "admin:ImportIAM"

	// Batch Job APIs

	// ListBatchJobsAction allow listing current active jobs
	ListBatchJobsAction AdminAction = "admin:ListBatchJobs"

	// DescribeBatchJobAction allow getting batch job YAML
	DescribeBatchJobAction AdminAction = "admin:DescribeBatchJob"

	// StartBatchJobAction allow submitting a batch job
	StartBatchJobAction AdminAction = "admin:StartBatchJob"

	// CancelBatchJobAction allow canceling a batch job
	CancelBatchJobAction AdminAction = "admin:CancelBatchJob"

	// GenerateBatchJobAction allow requesting batch job templates
	GenerateBatchJobAction AdminAction = "admin:GenerateBatchJob"

	// Distributed Job APIs

	// DistJobStatusAction allow viewing status of distributed jobs
	// (decommission and any future job type built on the same framework),
	// regardless of which job type is being queried.
	DistJobStatusAction AdminAction = "admin:DistJobStatus"

	// Inventory Control Actions

	// InventoryControlAction - allows control of inventory jobs
	InventoryControlAction AdminAction = "admin:InventoryControl"

	// All new v4 APIs

	// ClusterInfoAction - allow cluster summary
	ClusterInfoAction AdminAction = "admin:ClusterInfo"

	// PoolListAction - allow list how many pools and summary per pool
	PoolListAction AdminAction = "admin:PoolList"

	// PoolInfoAction - allow pool specific summary and detail information
	PoolInfoAction AdminAction = "admin:PoolInfo"

	// NodeListAction - allow listing of nodes
	NodeListAction AdminAction = "admin:NodeList"

	// NodeInfoAction - allow node specific summary and detailed information
	NodeInfoAction AdminAction = "admin:NodeInfo"

	// SetInfoAction - allow set specific summary and detail
	SetInfoAction AdminAction = "admin:SetInfo"

	// DriveListAction - allow listing of drives
	DriveListAction AdminAction = "admin:DriveList"

	// DriveInfoAction - allow drive specific summary and detail
	DriveInfoAction AdminAction = "admin:DriveInfo"

	// Delta Sharing Actions

	// DeltaSharingAdminAction - allow managing Delta Sharing shares and tokens
	DeltaSharingAdminAction AdminAction = "admin:DeltaSharing"
	// DeltaSharingCreateShareAction - allow creating Delta Sharing shares
	DeltaSharingCreateShareAction AdminAction = "admin:DeltaSharingCreateShare"
	// DeltaSharingDeleteShareAction - allow deleting Delta Sharing shares
	DeltaSharingDeleteShareAction AdminAction = "admin:DeltaSharingDeleteShare"
	// DeltaSharingListSharesAction - allow listing Delta Sharing shares
	DeltaSharingListSharesAction AdminAction = "admin:DeltaSharingListShares"
	// DeltaSharingGetShareAction - allow getting Delta Sharing share details
	DeltaSharingGetShareAction AdminAction = "admin:DeltaSharingGetShare"
	// DeltaSharingUpdateShareAction - allow updating Delta Sharing shares
	DeltaSharingUpdateShareAction AdminAction = "admin:DeltaSharingUpdateShare"
	// DeltaSharingCreateTokenAction - allow creating Delta Sharing tokens
	DeltaSharingCreateTokenAction AdminAction = "admin:DeltaSharingCreateToken"
	// DeltaSharingDeleteTokenAction - allow deleting Delta Sharing tokens
	DeltaSharingDeleteTokenAction AdminAction = "admin:DeltaSharingDeleteToken"
	// DeltaSharingListTokensAction - allow listing Delta Sharing tokens
	DeltaSharingListTokensAction AdminAction = "admin:DeltaSharingListTokens"
	// ReadAlertsAction - allow reading stored alerts
	ReadAlertsAction AdminAction = "admin:ReadAlerts"

	// Log Actions

	// ReadAPILogsAction - allow reading stored API logs
	ReadAPILogsAction AdminAction = "admin:ReadAPILogs"
	// ReadErrorLogsAction - allow reading stored error logs
	ReadErrorLogsAction AdminAction = "admin:ReadErrorLogs"
	// ReadAuditLogsAction - allow reading stored audit logs
	ReadAuditLogsAction AdminAction = "admin:ReadAuditLogs"

	// AllAdminActions - provides all admin permissions
	AllAdminActions AdminAction = "admin:*"
)

// SupportedAdminActions - list of all supported admin actions.
var SupportedAdminActions = map[AdminAction]struct{}{
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
	LicenseInfoAdminAction:           {},
	BandwidthMonitorAction:           {},
	InspectDataAction:                {},
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
	ChangeMyPasswordAdminAction:      {},
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
	SetBucketCompressionAdminAction:  {},
	GetBucketCompressionAdminAction:  {},
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

	TablesReplicationAddAction:           {},
	TablesReplicationRemoveAction:        {},
	TablesReplicationInfoAction:          {},
	TablesReplicationStartFailoverAction: {},
	TablesReplicationCatalogAdminAction:  {},

	ImportBucketMetadataAction: {},
	ExportBucketMetadataAction: {},
	ExportIAMAction:            {},
	ImportIAMAction:            {},

	ForceUnlockAdminAction: {},

	ListBatchJobsAction:    {},
	DescribeBatchJobAction: {},
	StartBatchJobAction:    {},
	CancelBatchJobAction:   {},
	GenerateBatchJobAction: {},

	DistJobStatusAction: {},

	InventoryControlAction: {},

	ClusterInfoAction: {},
	PoolListAction:    {},
	PoolInfoAction:    {},
	NodeListAction:    {},
	NodeInfoAction:    {},
	SetInfoAction:     {},
	DriveListAction:   {},
	DriveInfoAction:   {},

	ServiceCordonAdminAction: {},

	DeltaSharingAdminAction:       {},
	DeltaSharingCreateShareAction: {},
	DeltaSharingDeleteShareAction: {},
	DeltaSharingListSharesAction:  {},
	DeltaSharingGetShareAction:    {},
	DeltaSharingUpdateShareAction: {},
	DeltaSharingCreateTokenAction: {},
	DeltaSharingDeleteTokenAction: {},
	DeltaSharingListTokensAction:  {},

	ReadAPILogsAction:   {},
	ReadErrorLogsAction: {},
	ReadAuditLogsAction: {},
	ReadAlertsAction:    {},

	AllAdminActions: {},
}

// AdminActionsWithResource enumerates admin actions that operate on
// a specific bucket resource. When a policy statement contains one of
// these actions *and* specifies a Resource, the resource is enforced
// against the target bucket. All other admin actions are resource-less;
// any Resource specified in the statement is ignored for them.
var AdminActionsWithResource = map[AdminAction]struct{}{
	SetBucketQuotaAdminAction:       {},
	GetBucketQuotaAdminAction:       {},
	SetBucketCompressionAdminAction: {},
	GetBucketCompressionAdminAction: {},
	SetBucketTargetAction:           {},
	GetBucketTargetAction:           {},
	ReplicationDiff:                 {},
	ImportBucketMetadataAction:      {},
	ExportBucketMetadataAction:      {},
	HealAdminAction:                 {},
	InventoryControlAction:          {},
}

// HasResource reports whether this admin action operates on a bucket resource.
func (action AdminAction) HasResource() bool {
	for a := range AdminActionsWithResource {
		if action.Match(a) {
			return true
		}
	}
	return false
}

// Match - matches action name with action pattern.
func (action AdminAction) Match(a AdminAction) bool {
	return wildcard.Match(string(action), string(a))
}

// IsValid - checks if action is valid or not.
func (action AdminAction) IsValid() bool {
	for supAction := range SupportedAdminActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

func createAdminActionConditionKeyMap() map[Action]condition.KeySet {
	allSupportedAdminKeys := []condition.Key{}
	for _, keyName := range condition.AllSupportedAdminKeys {
		allSupportedAdminKeys = append(allSupportedAdminKeys, keyName.ToKey())
	}

	adminActionConditionKeyMap := map[Action]condition.KeySet{}
	for act := range SupportedAdminActions {
		adminActionConditionKeyMap[Action(act)] = condition.NewKeySet(allSupportedAdminKeys...)
	}
	return adminActionConditionKeyMap
}

// adminActionConditionKeyMap - holds mapping of supported condition key for an action.
var adminActionConditionKeyMap = createAdminActionConditionKeyMap()
