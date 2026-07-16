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

// Policy claim constants
const (
	PolicyName        = "policy"
	SessionPolicyName = "sessionPolicy"
)

// DefaultPolicies - list of canned policies available in MinIO.
var DefaultPolicies = []struct {
	Name       string
	Definition Policy
}{
	// ReadWrite - provides full access to all buckets and all objects.
	{
		Name: "readwrite",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(AllActions),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// ReadOnly - read only.
	{
		Name: "readonly",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(GetBucketLocationAction, GetObjectAction),
					Resources: NewResourceSet(NewResource("*")),
				},
				{
					SID:       ID(""),
					Effect:    Deny,
					Actions:   NewActionSet(Action(CreateUserAdminAction)),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// ConsoleReadOnly - read only with ListBucket for console browsing.
	{
		Name: "consolereadonly",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(GetBucketLocationAction, GetObjectAction, ListBucketAction),
					Resources: NewResourceSet(NewResource("*")),
				},
				{
					SID:       ID(""),
					Effect:    Deny,
					Actions:   NewActionSet(Action(CreateUserAdminAction)),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// WriteOnly - provides write access.
	{
		Name: "writeonly",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:       ID(""),
					Effect:    Allow,
					Actions:   NewActionSet(PutObjectAction),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// AdminDiagnostics - provides admin diagnostics access.
	{
		Name: "diagnostics",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(Action(ProfilingAdminAction),
						Action(TraceAdminAction), Action(ConsoleLogAdminAction),
						Action(ServerInfoAdminAction), Action(TopLocksAdminAction),
						Action(HealthInfoAdminAction), Action(BandwidthMonitorAction),
						Action(PrometheusAdminAction),
					),
					Resources: NewResourceSet(NewResource("*")),
				},
			},
		},
	},

	// TablesAdmin - provides admin access to S3 Tables
	{
		Name: "tablesAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(Action(AllS3TablesActions)),
					Resources:  NewResourceSet(NewS3TablesResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// IAMAdmin - provides IAM management access (users, groups, policies,
	// service accounts) but no infrastructure, diagnostics, or S3 data access.
	{
		Name: "iamAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// User management
						Action(CreateUserAdminAction),
						Action(DeleteUserAdminAction),
						Action(ListUsersAdminAction),
						Action(EnableUserAdminAction),
						Action(DisableUserAdminAction),
						Action(GetUserAdminAction),
						// Group management
						Action(AddUserToGroupAdminAction),
						Action(RemoveUserFromGroupAdminAction),
						Action(GetGroupAdminAction),
						Action(ListGroupsAdminAction),
						Action(EnableGroupAdminAction),
						Action(DisableGroupAdminAction),
						// Policy management
						Action(CreatePolicyAdminAction),
						Action(DeletePolicyAdminAction),
						Action(GetPolicyAdminAction),
						Action(AttachPolicyAdminAction),
						Action(UpdatePolicyAssociationAction),
						Action(ListUserPoliciesAdminAction),
						// Service account management
						Action(CreateServiceAccountAdminAction),
						Action(UpdateServiceAccountAdminAction),
						Action(RemoveServiceAccountAdminAction),
						Action(ListServiceAccountsAdminAction),
						// Temporary accounts
						Action(ListTemporaryAccountsAdminAction),
						// IAM import/export
						Action(ExportIAMAction),
						Action(ImportIAMAction),
					),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// InfraAdmin - provides infrastructure and server management access
	// (config, pools, healing, tiers, batch jobs) but no
	// IAM or S3 data access.
	{
		Name: "infraAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// Server lifecycle
						Action(ServerUpdateAdminAction),
						Action(ServiceRestartAdminAction),
						Action(ServiceStopAdminAction),
						Action(ServiceFreezeAdminAction),
						Action(ServiceCordonAdminAction),
						// Server info
						Action(ServerInfoAdminAction),
						Action(StorageInfoAdminAction),
						// Configuration
						Action(ConfigUpdateAdminAction),
						// Healing & recovery
						Action(HealAdminAction),
						Action(ForceUnlockAdminAction),
						// Pool management
						Action(DecommissionAdminAction),
						Action(RebalanceAdminAction),
						// Bucket admin
						Action(SetBucketQuotaAdminAction),
						Action(GetBucketQuotaAdminAction),
						Action(SetBucketCompressionAdminAction),
						Action(GetBucketCompressionAdminAction),
						// Tiers
						Action(SetTierAction),
						Action(ListTierAction),
						// Data & license info
						Action(LicenseInfoAdminAction),
						Action(DataUsageInfoAdminAction),
						// Bucket metadata import/export
						Action(ImportBucketMetadataAction),
						Action(ExportBucketMetadataAction),
						// Batch jobs
						Action(StartBatchJobAction),
						Action(ListBatchJobsAction),
						Action(DescribeBatchJobAction),
						Action(CancelBatchJobAction),
						Action(GenerateBatchJobAction),
						// Inventory
						Action(InventoryControlAction),
						// Cluster topology (v4 APIs)
						Action(ClusterInfoAction),
						Action(PoolListAction),
						Action(PoolInfoAction),
						Action(NodeListAction),
						Action(NodeInfoAction),
						Action(SetInfoAction),
						Action(DriveListAction),
						Action(DriveInfoAction),
					),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// TablesReadWrite - provides read and write access to S3 Tables data and views
	// but no DDL (cannot create/delete namespaces or tables). Mirrors the data
	// access tier of AWS AmazonS3TablesFullAccess minus administrative operations.
	{
		Name: "tablesReadWrite",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// Warehouse read
						Action(S3TablesGetWarehouseAction),
						Action(S3TablesGetWarehouseEncryptionAction),
						Action(S3TablesGetWarehouseMaintenanceConfigurationAction),
						Action(S3TablesGetWarehousePolicyAction),
						Action(S3TablesListWarehousesAction),
						// Namespace read + property updates
						Action(S3TablesGetNamespaceAction),
						Action(S3TablesListNamespacesAction),
						Action(S3TablesUpdateNamespacePropertiesAction),
						// Table read + data write
						Action(S3TablesGetTableAction),
						Action(S3TablesListTablesAction),
						Action(S3TablesGetTableDataAction),
						Action(S3TablesPutTableDataAction),
						Action(S3TablesGetTableEncryptionAction),
						Action(S3TablesGetTableMaintenanceConfigurationAction),
						Action(S3TablesGetTableMaintenanceJobStatusAction),
						Action(S3TablesGetTableMetadataLocationAction),
						Action(S3TablesGetTablePolicyAction),
						// Table mutations (non-destructive)
						Action(S3TablesCreateTableAction),
						Action(S3TablesUpdateTableAction),
						Action(S3TablesUpdateTableMetadataLocationAction),
						Action(S3TablesRenameTableAction),
						Action(S3TablesRegisterTableAction),
						// Views full CRUD
						Action(S3TablesGetViewAction),
						Action(S3TablesListViewsAction),
						Action(S3TablesCreateViewAction),
						Action(S3TablesUpdateViewAction),
						Action(S3TablesRenameViewAction),
						Action(S3TablesDeleteViewAction),
						Action(S3TablesRegisterViewAction),
						// Functions (SQL UDFs) full CRUD
						Action(S3TablesGetFunctionAction),
						Action(S3TablesListFunctionsAction),
						Action(S3TablesCreateFunctionAction),
						Action(S3TablesUpdateFunctionAction),
						Action(S3TablesRenameFunctionAction),
						Action(S3TablesDeleteFunctionAction),
						Action(S3TablesRegisterFunctionAction),
						// Catalog config + metrics
						Action(S3TablesGetConfigAction),
						Action(S3TablesTableMetricsAction),
					),
					Resources:  NewResourceSet(NewS3TablesResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// TablesReadOnly - provides read-only access to S3 Tables. Mirrors
	// AWS AmazonS3TablesReadOnlyAccess (s3tables:Get* + s3tables:List*).
	{
		Name: "tablesReadOnly",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// Warehouse read
						Action(S3TablesGetWarehouseAction),
						Action(S3TablesGetWarehouseEncryptionAction),
						Action(S3TablesGetWarehouseMaintenanceConfigurationAction),
						Action(S3TablesGetWarehousePolicyAction),
						Action(S3TablesListWarehousesAction),
						// Namespace read
						Action(S3TablesGetNamespaceAction),
						Action(S3TablesListNamespacesAction),
						// Table read
						Action(S3TablesGetTableAction),
						Action(S3TablesListTablesAction),
						Action(S3TablesGetTableDataAction),
						Action(S3TablesGetTableEncryptionAction),
						Action(S3TablesGetTableMaintenanceConfigurationAction),
						Action(S3TablesGetTableMaintenanceJobStatusAction),
						Action(S3TablesGetTableMetadataLocationAction),
						Action(S3TablesGetTablePolicyAction),
						// View read
						Action(S3TablesGetViewAction),
						Action(S3TablesListViewsAction),
						// Function read
						Action(S3TablesGetFunctionAction),
						Action(S3TablesListFunctionsAction),
						// Catalog config + metrics
						Action(S3TablesGetConfigAction),
						Action(S3TablesTableMetricsAction),
					),
					Resources:  NewResourceSet(NewS3TablesResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// ReplicationAdmin - provides site replication and bucket replication
	// management access, but no IAM, general infrastructure, or S3 data access.
	{
		Name: "replicationAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// Site replication management
						Action(SiteReplicationAddAction),
						Action(SiteReplicationDisableAction),
						Action(SiteReplicationRemoveAction),
						Action(SiteReplicationResyncAction),
						Action(SiteReplicationInfoAction),
						Action(SiteReplicationOperationAction),
						// Tables replication management
						Action(TablesReplicationAddAction),
						Action(TablesReplicationRemoveAction),
						Action(TablesReplicationInfoAction),
						Action(TablesReplicationStartFailoverAction),
						Action(TablesReplicationCatalogAdminAction),
						// Replication diagnostics
						Action(ReplicationDiff),
					),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// Bucket-level replication config
						GetReplicationConfigurationAction,
						PutReplicationConfigurationAction,
						ResetBucketReplicationStateAction,
						GetObjectVersionForReplicationAction,
					),
					Resources:  NewResourceSet(NewResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// SecurityAuditAdmin - provides read-only access to IAM configuration,
	// server topology, diagnostics, and bucket security settings for compliance
	// auditing. Mirrors the intent of AWS SecurityAudit. No write, delete, or
	// S3 data access.
	{
		Name: "securityAuditAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// IAM read
						Action(ListUsersAdminAction),
						Action(GetUserAdminAction),
						Action(ListGroupsAdminAction),
						Action(GetGroupAdminAction),
						Action(GetPolicyAdminAction),
						Action(ListUserPoliciesAdminAction),
						Action(ListServiceAccountsAdminAction),
						Action(ListTemporaryAccountsAdminAction),
						Action(ExportIAMAction),
						// Replication info (read-only)
						Action(SiteReplicationInfoAction),
						Action(TablesReplicationInfoAction),
						// Server & cluster topology (read-only)
						Action(ServerInfoAdminAction),
						Action(StorageInfoAdminAction),
						Action(DataUsageInfoAdminAction),
						Action(LicenseInfoAdminAction),
						Action(ClusterInfoAction),
						Action(PoolListAction),
						Action(PoolInfoAction),
						Action(NodeListAction),
						Action(NodeInfoAction),
						Action(SetInfoAction),
						Action(DriveListAction),
						Action(DriveInfoAction),
						// Diagnostics (read-only)
						Action(ProfilingAdminAction),
						Action(TraceAdminAction),
						Action(ConsoleLogAdminAction),
						Action(TopLocksAdminAction),
						Action(HealthInfoAdminAction),
						Action(BandwidthMonitorAction),
						Action(PrometheusAdminAction),
					),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						// Bucket security config (read-only)
						GetBucketPolicyAction,
						GetBucketLocationAction,
						GetBucketNotificationAction,
						GetBucketObjectLockConfigurationAction,
						GetBucketEncryptionAction,
						GetBucketTaggingAction,
						GetBucketVersioningAction,
						GetReplicationConfigurationAction,
					),
					Resources:  NewResourceSet(NewResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// Admin - provides admin all-access canned policy
	{
		Name: "consoleAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(Action(AllAdminActions)),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(Action(AllKMSActions)),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(AllActions),
					Resources:  NewResourceSet(NewResource("*")),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(Action(AllS3TablesActions)),
					Resources:  NewResourceSet(NewS3TablesResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},
}
