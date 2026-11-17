// Copyright (c) 2015-2026 MinIO, Inc.
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

package actionspec

// Admin is the admin action namespace.
var Admin = &Namespace{
	Prefix:       "admin",
	Title:        "AIStor Admin",
	Desc:         "Cluster administration: identities, policies, configuration, replication and operations.",
	GoNameFormat: "%sAdminAction",
	BaseKeys:     CommonAdminKeys,
	Resource:     ResourceNone,
	Actions: []Action{
		{
			Name:     "Heal",
			Category: CategoryOperate,
			Desc:     "Allows heal command",
			Resource: ResourceBucket,
		},
		{
			Name:     "Decommission",
			Category: CategoryOperate,
			Desc:     "Allows decomissioning of pools",
		},
		{
			Name:     "Rebalance",
			Category: CategoryOperate,
			Desc:     "Allows rebalancing of pools",
		},
		// Service Actions
		{
			Name:     "StorageInfo",
			Category: CategoryMonitor,
			Desc:     "Allow listing server info",
		},
		{
			Name:     "Prometheus",
			Category: CategoryMonitor,
			Desc:     "Prometheus info action",
		},
		{
			Name:     "DataUsageInfo",
			Category: CategoryMonitor,
			Desc:     "Allow listing data usage info",
		},
		{
			Name:     "ForceUnlock",
			Category: CategoryOperate,
			Desc:     "Allow force unlocking locks",
		},
		{
			Name:     "TopLocksInfo",
			Category: CategoryMonitor,
			GoName:   "TopLocksAdminAction",
			Desc:     "Allow listing top locks",
		},
		{
			Name:     "Profiling",
			Category: CategoryDiagnostics,
			Desc:     "Allow profiling",
		},
		{
			Name:     "ServerTrace",
			Category: CategoryDiagnostics,
			GoName:   "TraceAdminAction",
			Desc:     "Allow listing server trace",
		},
		{
			Name:     "ConsoleLog",
			Category: CategoryDiagnostics,
			Desc:     "Allow listing console logs on terminal",
		},
		{
			Name:        "KMSEnable",
			Category:    CategoryOperate,
			Desc:        "Allow enabling the builtin KMS",
			Unsupported: true,
		},
		{
			Name:        "KMSBackup",
			Category:    CategoryOperate,
			Desc:        "Allow backing up builtin KMS keys",
			Unsupported: true,
		},
		{
			Name:        "KMSRestore",
			Category:    CategoryOperate,
			Desc:        "Allow restoring builtin KMS keys",
			Unsupported: true,
		},
		{
			Name:     "KMSCreateKey",
			Category: CategoryOperate,
			Desc:     "Allow creating a new KMS master key",
		},
		{
			Name:     "KMSKeyStatus",
			Category: CategoryMonitor,
			Desc:     "Allow getting KMS key status",
		},
		{
			Name:        "KMSKeyRotate",
			Category:    CategoryOperate,
			Desc:        "Allow rotating KMS keys",
			Unsupported: true,
		},
		{
			Name:     "ServerInfo",
			Category: CategoryMonitor,
			Desc:     "Allow listing server info",
		},
		{
			Name:     "OBDInfo",
			Category: CategoryDiagnostics,
			GoName:   "HealthInfoAdminAction",
			Desc:     "Allow obtaining cluster health information",
		},
		{
			Name:     "LicenseInfo",
			Category: CategoryMonitor,
			Desc:     "Allow obtaining license information",
		},
		{
			Name:     "BandwidthMonitor",
			Category: CategoryMonitor,
			GoName:   "BandwidthMonitorAction",
			Desc:     "Allow monitoring bandwidth usage",
		},
		{
			Name:     "InspectData",
			Category: CategoryDiagnostics,
			GoName:   "InspectDataAction",
			Desc:     "Allows downloading raw files from backend",
		},
		{
			Name:     "ServerUpdate",
			Category: CategoryOperate,
			Desc:     "Allow MinIO binary update",
		},
		{
			Name:     "ServiceRestart",
			Category: CategoryOperate,
			Desc:     "Allow restart of MinIO service.",
		},
		{
			Name:     "ServiceStop",
			Category: CategoryOperate,
			Desc:     "Allow stopping MinIO service.",
		},
		{
			Name:     "ServiceFreeze",
			Category: CategoryOperate,
			Desc:     "Allow freeze/unfreeze MinIO service.",
		},
		{
			Name:     "ServiceCordon",
			Category: CategoryOperate,
			Desc:     "Allow cordon/uncordon MinIO service.",
		},
		{
			Name:     "ConfigUpdate",
			Category: CategoryOperate,
			Desc:     "Allow MinIO config management",
		},
		{
			Name:     "CreateUser",
			Category: CategoryIdentity,
			Desc:     "Allow creating MinIO user",
		},
		{
			Name:     "DeleteUser",
			Category: CategoryIdentity,
			Desc:     "Allow deleting MinIO user",
		},
		{
			Name:     "ListUsers",
			Category: CategoryIdentity,
			Desc:     "Allow list users permission",
		},
		{
			Name:     "EnableUser",
			Category: CategoryIdentity,
			Desc:     "Allow enable user permission",
		},
		{
			Name:     "DisableUser",
			Category: CategoryIdentity,
			Desc:     "Allow disable user permission",
		},
		{
			Name:     "GetUser",
			Category: CategoryIdentity,
			Desc:     "Allows GET permission on user info",
		},
		{
			Name:     "ChangeMyPassword",
			Category: CategoryIdentity,
			Desc:     "Allow changing own password",
		},
		{
			Name:     "SetRootAccess",
			Category: CategoryPermissions,
			Desc:     "Allow enabling or disabling the root credential",
		},
		// Cluster Replicate Actions
		{
			Name:     "SiteReplicationAdd",
			Category: CategoryOperate,
			GoName:   "SiteReplicationAddAction",
			Desc:     "Allow adding clusters for site-level replication",
		},
		{
			Name:     "SiteReplicationDisable",
			Category: CategoryOperate,
			GoName:   "SiteReplicationDisableAction",
			Desc:     "Allow disabling a cluster from replication",
		},
		{
			Name:     "SiteReplicationRemove",
			Category: CategoryOperate,
			GoName:   "SiteReplicationRemoveAction",
			Desc:     "Allow removing a cluster from replication",
		},
		{
			Name:     "SiteReplicationResync",
			Category: CategoryOperate,
			GoName:   "SiteReplicationResyncAction",
			Desc:     "Allow resyncing cluster data to another site",
		},
		{
			Name:     "SiteReplicationInfo",
			Category: CategoryMonitor,
			GoName:   "SiteReplicationInfoAction",
			Desc:     "Allow getting site replication info",
		},
		{
			Name:     "SiteReplicationOperation",
			Category: CategoryOperate,
			GoName:   "SiteReplicationOperationAction",
			Desc:     "Allow performing site replication\ncreate/update/delete operations to peers",
		},
		// Tables Replication Actions
		{
			Name:     "TablesReplicationAdd",
			Category: CategoryOperate,
			GoName:   "TablesReplicationAddAction",
			Desc:     "Allow adding tables replication targets",
		},
		{
			Name:     "TablesReplicationRemove",
			Category: CategoryOperate,
			GoName:   "TablesReplicationRemoveAction",
			Desc:     "Allow removing tables replication targets",
		},
		{
			Name:     "TablesReplicationInfo",
			Category: CategoryMonitor,
			GoName:   "TablesReplicationInfoAction",
			Desc:     "Allow getting tables replication info/status",
		},
		{
			Name:     "TablesReplicationStartFailover",
			Category: CategoryOperate,
			GoName:   "TablesReplicationStartFailoverAction",
			Desc:     "Allow starting tables replication failover",
		},
		{
			Name:     "TablesReplicationCatalogAdmin",
			Category: CategoryOperate,
			GoName:   "TablesReplicationCatalogAdminAction",
			Desc:     "Allow catalog debugging operations (reset, dump contents)",
		},
		// Service account Actions
		{
			Name:     "CreateServiceAccount",
			Category: CategoryIdentity,
			Desc:     "Allow create a service account for a user",
		},
		{
			Name:     "UpdateServiceAccount",
			Category: CategoryIdentity,
			Desc:     "Allow updating a service account",
		},
		{
			Name:     "RemoveServiceAccount",
			Category: CategoryIdentity,
			Desc:     "Allow removing a service account",
		},
		{
			Name:     "ListServiceAccounts",
			Category: CategoryIdentity,
			Desc:     "Allow listing service accounts",
		},
		{
			Name:     "ListTemporaryAccounts",
			Category: CategoryIdentity,
			Desc:     "Allow listing of temporary accounts",
		},
		// Group Actions
		{
			Name:     "AddUserToGroup",
			Category: CategoryIdentity,
			Desc:     "Allow adding user to group permission",
		},
		{
			Name:     "RemoveUserFromGroup",
			Category: CategoryIdentity,
			Desc:     "Allow removing user to group permission",
		},
		{
			Name:     "GetGroup",
			Category: CategoryIdentity,
			Desc:     "Allow getting group info",
		},
		{
			Name:     "ListGroups",
			Category: CategoryIdentity,
			Desc:     "Allow list groups permission",
		},
		{
			Name:     "EnableGroup",
			Category: CategoryIdentity,
			Desc:     "Allow enable group permission",
		},
		{
			Name:     "DisableGroup",
			Category: CategoryIdentity,
			Desc:     "Allow disable group permission",
		},
		// Policy Actions
		{
			Name:     "CreatePolicy",
			Category: CategoryPermissions,
			Desc:     "Allow create policy permission",
			Keys:     []*Key{AdminPolicyName},
		},
		{
			Name:     "DeletePolicy",
			Category: CategoryPermissions,
			Desc:     "Allow delete policy permission",
			Keys:     []*Key{AdminPolicyName},
		},
		{
			Name:     "GetPolicy",
			Category: CategoryPermissions,
			Desc:     "Allow get policy permission",
			Keys:     []*Key{AdminPolicyName},
		},
		{
			Name:     "AttachUserOrGroupPolicy",
			Category: CategoryPermissions,
			GoName:   "AttachPolicyAdminAction",
			Desc:     "Allows attaching a policy to a user/group",
			Keys:     []*Key{AdminPolicyName},
		},
		{
			Name:     "UpdatePolicyAssociation",
			Category: CategoryPermissions,
			GoName:   "UpdatePolicyAssociationAction",
			Desc:     "Allows to add/remove policy association\non a user or group.",
			Keys:     []*Key{AdminPolicyName},
		},
		{
			Name:     "ListUserPolicies",
			Category: CategoryPermissions,
			Desc:     "Allows listing user policies",
		},
		// Bucket quota Actions
		{
			Name:     "SetBucketQuota",
			Category: CategoryOperate,
			Desc:     "Allow setting bucket quota",
			Resource: ResourceBucket,
		},
		{
			Name:     "GetBucketQuota",
			Category: CategoryMonitor,
			Desc:     "Allow getting bucket quota",
			Resource: ResourceBucket,
		},
		// Bucket compression Actions
		{
			Name:     "SetBucketCompression",
			Category: CategoryOperate,
			Desc:     "Allow setting per-bucket compression config",
			Resource: ResourceBucket,
		},
		{
			Name:     "GetBucketCompression",
			Category: CategoryMonitor,
			Desc:     "Allow getting per-bucket compression config",
			Resource: ResourceBucket,
		},
		// Bucket Target admin Actions
		{
			Name:     "SetBucketTarget",
			Category: CategoryOperate,
			GoName:   "SetBucketTargetAction",
			Desc:     "Allow setting bucket target",
			Resource: ResourceBucket,
		},
		{
			Name:     "GetBucketTarget",
			Category: CategoryMonitor,
			GoName:   "GetBucketTargetAction",
			Desc:     "Allow getting bucket targets",
			Resource: ResourceBucket,
		},
		{
			Name:     "ReplicationDiff",
			Category: CategoryMonitor,
			GoName:   "ReplicationDiff",
			Desc:     "Allow computing the unreplicated objects in a bucket",
			Resource: ResourceBucket,
		},
		// Bucket import/export admin Actions
		{
			Name:     "ImportBucketMetadata",
			Category: CategoryOperate,
			GoName:   "ImportBucketMetadataAction",
			Desc:     "Allow importing bucket metadata",
			Resource: ResourceBucket,
		},
		{
			Name:     "ExportBucketMetadata",
			Category: CategoryOperate,
			GoName:   "ExportBucketMetadataAction",
			Desc:     "Allow exporting bucket metadata",
			Resource: ResourceBucket,
		},
		// Remote Tier admin Actions
		{
			Name:     "SetTier",
			Category: CategoryOperate,
			GoName:   "SetTierAction",
			Desc:     "Allow adding/editing a remote tier",
		},
		{
			Name:     "ListTier",
			Category: CategoryMonitor,
			GoName:   "ListTierAction",
			Desc:     "Allow listing remote tiers",
		},
		// Migrate IAM admin Actions
		{
			Name:     "ExportIAM",
			Category: CategoryPermissions,
			GoName:   "ExportIAMAction",
			Desc:     "Allow exporting of all IAM info",
		},
		{
			Name:     "ImportIAM",
			Category: CategoryPermissions,
			GoName:   "ImportIAMAction",
			Desc:     "Allow importing IAM info to MinIO",
		},
		// Batch Job APIs
		{
			Name:     "ListBatchJobs",
			Category: CategoryMonitor,
			GoName:   "ListBatchJobsAction",
			Desc:     "allow listing current active jobs",
		},
		{
			Name:     "DescribeBatchJob",
			Category: CategoryMonitor,
			GoName:   "DescribeBatchJobAction",
			Desc:     "allow getting batch job YAML",
		},
		{
			Name:     "StartBatchJob",
			Category: CategoryOperate,
			GoName:   "StartBatchJobAction",
			Desc:     "allow submitting a batch job",
		},
		{
			Name:     "CancelBatchJob",
			Category: CategoryOperate,
			GoName:   "CancelBatchJobAction",
			Desc:     "allow canceling a batch job",
		},
		{
			Name:     "GenerateBatchJob",
			Category: CategoryOperate,
			GoName:   "GenerateBatchJobAction",
			Desc:     "allow requesting batch job templates",
		},
		// Distributed Job APIs
		{
			Name:     "DistJobStatus",
			Category: CategoryMonitor,
			GoName:   "DistJobStatusAction",
			Desc:     "allow viewing status of distributed jobs\n(decommission and any future job type built on the same framework),\nregardless of which job type is being queried.",
		},
		// Inventory Control Actions
		{
			Name:     "InventoryControl",
			Category: CategoryOperate,
			GoName:   "InventoryControlAction",
			Desc:     "Allows control of inventory jobs",
			Resource: ResourceBucket,
		},
		// All new v4 APIs
		{
			Name:     "ClusterInfo",
			Category: CategoryMonitor,
			GoName:   "ClusterInfoAction",
			Desc:     "Allow cluster summary",
		},
		{
			Name:     "PoolList",
			Category: CategoryMonitor,
			GoName:   "PoolListAction",
			Desc:     "Allow list how many pools and summary per pool",
		},
		{
			Name:     "PoolInfo",
			Category: CategoryMonitor,
			GoName:   "PoolInfoAction",
			Desc:     "Allow pool specific summary and detail information",
		},
		{
			Name:     "NodeList",
			Category: CategoryMonitor,
			GoName:   "NodeListAction",
			Desc:     "Allow listing of nodes",
		},
		{
			Name:     "NodeInfo",
			Category: CategoryMonitor,
			GoName:   "NodeInfoAction",
			Desc:     "Allow node specific summary and detailed information",
		},
		{
			Name:     "SetInfo",
			Category: CategoryMonitor,
			GoName:   "SetInfoAction",
			Desc:     "Allow set specific summary and detail",
		},
		{
			Name:     "DriveList",
			Category: CategoryMonitor,
			GoName:   "DriveListAction",
			Desc:     "Allow listing of drives",
		},
		{
			Name:     "DriveInfo",
			Category: CategoryMonitor,
			GoName:   "DriveInfoAction",
			Desc:     "Allow drive specific summary and detail",
		},
		// Delta Sharing Actions
		{
			Name:     "DeltaSharing",
			Category: CategoryPermissions,
			Desc:     "Allow managing Delta Sharing shares and tokens",
		},
		{
			Name:     "DeltaSharingCreateShare",
			Category: CategoryPermissions,
			GoName:   "DeltaSharingCreateShareAction",
			Desc:     "Allow creating Delta Sharing shares",
		},
		{
			Name:     "DeltaSharingDeleteShare",
			Category: CategoryPermissions,
			GoName:   "DeltaSharingDeleteShareAction",
			Desc:     "Allow deleting Delta Sharing shares",
		},
		{
			Name:     "DeltaSharingListShares",
			Category: CategoryViewSettings,
			GoName:   "DeltaSharingListSharesAction",
			Desc:     "Allow listing Delta Sharing shares",
		},
		{
			Name:     "DeltaSharingGetShare",
			Category: CategoryViewSettings,
			GoName:   "DeltaSharingGetShareAction",
			Desc:     "Allow getting Delta Sharing share details",
		},
		{
			Name:     "DeltaSharingUpdateShare",
			Category: CategoryPermissions,
			GoName:   "DeltaSharingUpdateShareAction",
			Desc:     "Allow updating Delta Sharing shares",
		},
		{
			Name:     "DeltaSharingCreateToken",
			Category: CategoryPermissions,
			GoName:   "DeltaSharingCreateTokenAction",
			Desc:     "Allow creating Delta Sharing tokens",
		},
		{
			Name:     "DeltaSharingDeleteToken",
			Category: CategoryPermissions,
			GoName:   "DeltaSharingDeleteTokenAction",
			Desc:     "Allow deleting Delta Sharing tokens",
		},
		{
			Name:     "DeltaSharingListTokens",
			Category: CategoryViewSettings,
			GoName:   "DeltaSharingListTokensAction",
			Desc:     "Allow listing Delta Sharing tokens",
		},
		{
			Name:     "DeltaSharingUseShare",
			Category: CategoryRead,
			GoName:   "DeltaSharingUseShareAction",
			Desc:     "Allow reading Delta Sharing shares owned by other users",
		},
		{
			Name:     "DeltaSharingUseRecipient",
			Category: CategoryRead,
			GoName:   "DeltaSharingUseRecipientAction",
			Desc:     "Allow reading Delta Sharing recipients owned by other users",
		},
		{
			Name:     "ReadAlerts",
			Category: CategoryMonitor,
			GoName:   "ReadAlertsAction",
			Desc:     "Allow reading stored alerts",
		},
		// Log Actions
		{
			Name:     "ReadAPILogs",
			Category: CategoryMonitor,
			GoName:   "ReadAPILogsAction",
			Desc:     "Allow reading stored API logs",
		},
		{
			Name:     "ReadErrorLogs",
			Category: CategoryMonitor,
			GoName:   "ReadErrorLogsAction",
			Desc:     "Allow reading stored error logs",
		},
		{
			Name:     "ReadAuditLogs",
			Category: CategoryDiagnostics,
			GoName:   "ReadAuditLogsAction",
			Desc:     "Allow reading stored audit logs",
		},
		{
			Name:   "*",
			GoName: "AllAdminActions",
			Desc:   "Provides all admin permissions",
		},
	},
}
