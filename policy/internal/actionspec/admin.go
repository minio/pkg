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
	GoNameFormat: "%sAdminAction",
	BaseKeys:     CommonAdminKeys,
	Resource:     ResourceNone,
	Actions: []Action{
		{
			Name:     "Heal",
			Desc:     "Allows heal command",
			Resource: ResourceBucket,
		},
		{
			Name: "Decommission",
			Desc: "Allows decomissioning of pools",
		},
		{
			Name: "Rebalance",
			Desc: "Allows rebalancing of pools",
		},
		// Service Actions
		{
			Name: "StorageInfo",
			Desc: "Allow listing server info",
		},
		{
			Name: "Prometheus",
			Desc: "Prometheus info action",
		},
		{
			Name: "DataUsageInfo",
			Desc: "Allow listing data usage info",
		},
		{
			Name: "ForceUnlock",
			Desc: "Allow force unlocking locks",
		},
		{
			Name:   "TopLocksInfo",
			GoName: "TopLocksAdminAction",
			Desc:   "Allow listing top locks",
		},
		{
			Name: "Profiling",
			Desc: "Allow profiling",
		},
		{
			Name:   "ServerTrace",
			GoName: "TraceAdminAction",
			Desc:   "Allow listing server trace",
		},
		{
			Name: "ConsoleLog",
			Desc: "Allow listing console logs on terminal",
		},
		{
			Name:        "KMSEnable",
			Desc:        "Allow enabling the builtin KMS",
			Unsupported: true,
		},
		{
			Name:        "KMSBackup",
			Desc:        "Allow backing up builtin KMS keys",
			Unsupported: true,
		},
		{
			Name:        "KMSRestore",
			Desc:        "Allow restoring builtin KMS keys",
			Unsupported: true,
		},
		{
			Name: "KMSCreateKey",
			Desc: "Allow creating a new KMS master key",
		},
		{
			Name: "KMSKeyStatus",
			Desc: "Allow getting KMS key status",
		},
		{
			Name:        "KMSKeyRotate",
			Desc:        "Allow rotating KMS keys",
			Unsupported: true,
		},
		{
			Name: "ServerInfo",
			Desc: "Allow listing server info",
		},
		{
			Name:   "OBDInfo",
			GoName: "HealthInfoAdminAction",
			Desc:   "Allow obtaining cluster health information",
		},
		{
			Name: "LicenseInfo",
			Desc: "Allow obtaining license information",
		},
		{
			Name:   "BandwidthMonitor",
			GoName: "BandwidthMonitorAction",
			Desc:   "Allow monitoring bandwidth usage",
		},
		{
			Name:   "InspectData",
			GoName: "InspectDataAction",
			Desc:   "Allows downloading raw files from backend",
		},
		{
			Name: "ServerUpdate",
			Desc: "Allow MinIO binary update",
		},
		{
			Name: "ServiceRestart",
			Desc: "Allow restart of MinIO service.",
		},
		{
			Name: "ServiceStop",
			Desc: "Allow stopping MinIO service.",
		},
		{
			Name: "ServiceFreeze",
			Desc: "Allow freeze/unfreeze MinIO service.",
		},
		{
			Name: "ServiceCordon",
			Desc: "Allow cordon/uncordon MinIO service.",
		},
		{
			Name: "ConfigUpdate",
			Desc: "Allow MinIO config management",
		},
		{
			Name: "CreateUser",
			Desc: "Allow creating MinIO user",
		},
		{
			Name: "DeleteUser",
			Desc: "Allow deleting MinIO user",
		},
		{
			Name: "ListUsers",
			Desc: "Allow list users permission",
		},
		{
			Name: "EnableUser",
			Desc: "Allow enable user permission",
		},
		{
			Name: "DisableUser",
			Desc: "Allow disable user permission",
		},
		{
			Name: "GetUser",
			Desc: "Allows GET permission on user info",
		},
		{
			Name: "ChangeMyPassword",
			Desc: "Allow changing own password",
		},
		{
			Name: "SetRootAccess",
			Desc: "Allow enabling or disabling the root credential",
		},
		// Cluster Replicate Actions
		{
			Name:   "SiteReplicationAdd",
			GoName: "SiteReplicationAddAction",
			Desc:   "Allow adding clusters for site-level replication",
		},
		{
			Name:   "SiteReplicationDisable",
			GoName: "SiteReplicationDisableAction",
			Desc:   "Allow disabling a cluster from replication",
		},
		{
			Name:   "SiteReplicationRemove",
			GoName: "SiteReplicationRemoveAction",
			Desc:   "Allow removing a cluster from replication",
		},
		{
			Name:   "SiteReplicationResync",
			GoName: "SiteReplicationResyncAction",
			Desc:   "Allow resyncing cluster data to another site",
		},
		{
			Name:   "SiteReplicationInfo",
			GoName: "SiteReplicationInfoAction",
			Desc:   "Allow getting site replication info",
		},
		{
			Name:   "SiteReplicationOperation",
			GoName: "SiteReplicationOperationAction",
			Desc:   "Allow performing site replication\ncreate/update/delete operations to peers",
		},
		// Tables Replication Actions
		{
			Name:   "TablesReplicationAdd",
			GoName: "TablesReplicationAddAction",
			Desc:   "Allow adding tables replication targets",
		},
		{
			Name:   "TablesReplicationRemove",
			GoName: "TablesReplicationRemoveAction",
			Desc:   "Allow removing tables replication targets",
		},
		{
			Name:   "TablesReplicationInfo",
			GoName: "TablesReplicationInfoAction",
			Desc:   "Allow getting tables replication info/status",
		},
		{
			Name:   "TablesReplicationStartFailover",
			GoName: "TablesReplicationStartFailoverAction",
			Desc:   "Allow starting tables replication failover",
		},
		{
			Name:   "TablesReplicationCatalogAdmin",
			GoName: "TablesReplicationCatalogAdminAction",
			Desc:   "Allow catalog debugging operations (reset, dump contents)",
		},
		// Service account Actions
		{
			Name: "CreateServiceAccount",
			Desc: "Allow create a service account for a user",
		},
		{
			Name: "UpdateServiceAccount",
			Desc: "Allow updating a service account",
		},
		{
			Name: "RemoveServiceAccount",
			Desc: "Allow removing a service account",
		},
		{
			Name: "ListServiceAccounts",
			Desc: "Allow listing service accounts",
		},
		{
			Name: "ListTemporaryAccounts",
			Desc: "Allow listing of temporary accounts",
		},
		// Group Actions
		{
			Name: "AddUserToGroup",
			Desc: "Allow adding user to group permission",
		},
		{
			Name: "RemoveUserFromGroup",
			Desc: "Allow removing user to group permission",
		},
		{
			Name: "GetGroup",
			Desc: "Allow getting group info",
		},
		{
			Name: "ListGroups",
			Desc: "Allow list groups permission",
		},
		{
			Name: "EnableGroup",
			Desc: "Allow enable group permission",
		},
		{
			Name: "DisableGroup",
			Desc: "Allow disable group permission",
		},
		// Policy Actions
		{
			Name: "CreatePolicy",
			Desc: "Allow create policy permission",
			Keys: []*Key{AdminPolicyName},
		},
		{
			Name: "DeletePolicy",
			Desc: "Allow delete policy permission",
			Keys: []*Key{AdminPolicyName},
		},
		{
			Name: "GetPolicy",
			Desc: "Allow get policy permission",
			Keys: []*Key{AdminPolicyName},
		},
		{
			Name:   "AttachUserOrGroupPolicy",
			GoName: "AttachPolicyAdminAction",
			Desc:   "Allows attaching a policy to a user/group",
			Keys:   []*Key{AdminPolicyName},
		},
		{
			Name:   "UpdatePolicyAssociation",
			GoName: "UpdatePolicyAssociationAction",
			Desc:   "Allows to add/remove policy association\non a user or group.",
			Keys:   []*Key{AdminPolicyName},
		},
		{
			Name: "ListUserPolicies",
			Desc: "Allows listing user policies",
		},
		// Bucket quota Actions
		{
			Name:     "SetBucketQuota",
			Desc:     "Allow setting bucket quota",
			Resource: ResourceBucket,
		},
		{
			Name:     "GetBucketQuota",
			Desc:     "Allow getting bucket quota",
			Resource: ResourceBucket,
		},
		// Bucket compression Actions
		{
			Name:     "SetBucketCompression",
			Desc:     "Allow setting per-bucket compression config",
			Resource: ResourceBucket,
		},
		{
			Name:     "GetBucketCompression",
			Desc:     "Allow getting per-bucket compression config",
			Resource: ResourceBucket,
		},
		// Bucket Target admin Actions
		{
			Name:     "SetBucketTarget",
			GoName:   "SetBucketTargetAction",
			Desc:     "Allow setting bucket target",
			Resource: ResourceBucket,
		},
		{
			Name:     "GetBucketTarget",
			GoName:   "GetBucketTargetAction",
			Desc:     "Allow getting bucket targets",
			Resource: ResourceBucket,
		},
		{
			Name:     "ReplicationDiff",
			GoName:   "ReplicationDiff",
			Desc:     "Allow computing the unreplicated objects in a bucket",
			Resource: ResourceBucket,
		},
		// Bucket import/export admin Actions
		{
			Name:     "ImportBucketMetadata",
			GoName:   "ImportBucketMetadataAction",
			Desc:     "Allow importing bucket metadata",
			Resource: ResourceBucket,
		},
		{
			Name:     "ExportBucketMetadata",
			GoName:   "ExportBucketMetadataAction",
			Desc:     "Allow exporting bucket metadata",
			Resource: ResourceBucket,
		},
		// Remote Tier admin Actions
		{
			Name:   "SetTier",
			GoName: "SetTierAction",
			Desc:   "Allow adding/editing a remote tier",
		},
		{
			Name:   "ListTier",
			GoName: "ListTierAction",
			Desc:   "Allow listing remote tiers",
		},
		// Migrate IAM admin Actions
		{
			Name:   "ExportIAM",
			GoName: "ExportIAMAction",
			Desc:   "Allow exporting of all IAM info",
		},
		{
			Name:   "ImportIAM",
			GoName: "ImportIAMAction",
			Desc:   "Allow importing IAM info to MinIO",
		},
		// Batch Job APIs
		{
			Name:   "ListBatchJobs",
			GoName: "ListBatchJobsAction",
			Desc:   "allow listing current active jobs",
		},
		{
			Name:   "DescribeBatchJob",
			GoName: "DescribeBatchJobAction",
			Desc:   "allow getting batch job YAML",
		},
		{
			Name:   "StartBatchJob",
			GoName: "StartBatchJobAction",
			Desc:   "allow submitting a batch job",
		},
		{
			Name:   "CancelBatchJob",
			GoName: "CancelBatchJobAction",
			Desc:   "allow canceling a batch job",
		},
		{
			Name:   "GenerateBatchJob",
			GoName: "GenerateBatchJobAction",
			Desc:   "allow requesting batch job templates",
		},
		// Distributed Job APIs
		{
			Name:   "DistJobStatus",
			GoName: "DistJobStatusAction",
			Desc:   "allow viewing status of distributed jobs\n(decommission and any future job type built on the same framework),\nregardless of which job type is being queried.",
		},
		// Inventory Control Actions
		{
			Name:     "InventoryControl",
			GoName:   "InventoryControlAction",
			Desc:     "Allows control of inventory jobs",
			Resource: ResourceBucket,
		},
		// All new v4 APIs
		{
			Name:   "ClusterInfo",
			GoName: "ClusterInfoAction",
			Desc:   "Allow cluster summary",
		},
		{
			Name:   "PoolList",
			GoName: "PoolListAction",
			Desc:   "Allow list how many pools and summary per pool",
		},
		{
			Name:   "PoolInfo",
			GoName: "PoolInfoAction",
			Desc:   "Allow pool specific summary and detail information",
		},
		{
			Name:   "NodeList",
			GoName: "NodeListAction",
			Desc:   "Allow listing of nodes",
		},
		{
			Name:   "NodeInfo",
			GoName: "NodeInfoAction",
			Desc:   "Allow node specific summary and detailed information",
		},
		{
			Name:   "SetInfo",
			GoName: "SetInfoAction",
			Desc:   "Allow set specific summary and detail",
		},
		{
			Name:   "DriveList",
			GoName: "DriveListAction",
			Desc:   "Allow listing of drives",
		},
		{
			Name:   "DriveInfo",
			GoName: "DriveInfoAction",
			Desc:   "Allow drive specific summary and detail",
		},
		// Delta Sharing Actions
		{
			Name: "DeltaSharing",
			Desc: "Allow managing Delta Sharing shares and tokens",
		},
		{
			Name:   "DeltaSharingCreateShare",
			GoName: "DeltaSharingCreateShareAction",
			Desc:   "Allow creating Delta Sharing shares",
		},
		{
			Name:   "DeltaSharingDeleteShare",
			GoName: "DeltaSharingDeleteShareAction",
			Desc:   "Allow deleting Delta Sharing shares",
		},
		{
			Name:   "DeltaSharingListShares",
			GoName: "DeltaSharingListSharesAction",
			Desc:   "Allow listing Delta Sharing shares",
		},
		{
			Name:   "DeltaSharingGetShare",
			GoName: "DeltaSharingGetShareAction",
			Desc:   "Allow getting Delta Sharing share details",
		},
		{
			Name:   "DeltaSharingUpdateShare",
			GoName: "DeltaSharingUpdateShareAction",
			Desc:   "Allow updating Delta Sharing shares",
		},
		{
			Name:   "DeltaSharingCreateToken",
			GoName: "DeltaSharingCreateTokenAction",
			Desc:   "Allow creating Delta Sharing tokens",
		},
		{
			Name:   "DeltaSharingDeleteToken",
			GoName: "DeltaSharingDeleteTokenAction",
			Desc:   "Allow deleting Delta Sharing tokens",
		},
		{
			Name:   "DeltaSharingListTokens",
			GoName: "DeltaSharingListTokensAction",
			Desc:   "Allow listing Delta Sharing tokens",
		},
		{
			Name:   "DeltaSharingUseShare",
			GoName: "DeltaSharingUseShareAction",
			Desc:   "Allow reading Delta Sharing shares owned by other users",
		},
		{
			Name:   "DeltaSharingUseRecipient",
			GoName: "DeltaSharingUseRecipientAction",
			Desc:   "Allow reading Delta Sharing recipients owned by other users",
		},
		{
			Name:   "ReadAlerts",
			GoName: "ReadAlertsAction",
			Desc:   "Allow reading stored alerts",
		},
		// Log Actions
		{
			Name:   "ReadAPILogs",
			GoName: "ReadAPILogsAction",
			Desc:   "Allow reading stored API logs",
		},
		{
			Name:   "ReadErrorLogs",
			GoName: "ReadErrorLogsAction",
			Desc:   "Allow reading stored error logs",
		},
		{
			Name:   "ReadAuditLogs",
			GoName: "ReadAuditLogsAction",
			Desc:   "Allow reading stored audit logs",
		},
		{
			Name:   "*",
			GoName: "AllAdminActions",
			Desc:   "Provides all admin permissions",
		},
	},
}
