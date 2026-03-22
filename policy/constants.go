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
					Actions:   NewActionSet(CreateUserAdminAction),
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
					Actions: NewActionSet(ProfilingAdminAction,
						TraceAdminAction, ConsoleLogAdminAction,
						ServerInfoAdminAction, TopLocksAdminAction,
						HealthInfoAdminAction, BandwidthMonitorAction,
						PrometheusAdminAction,
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
					Actions:    NewActionSet(AllS3TablesActions),
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
						CreateUserAdminAction,
						DeleteUserAdminAction,
						ListUsersAdminAction,
						EnableUserAdminAction,
						DisableUserAdminAction,
						GetUserAdminAction,
						// Group management
						AddUserToGroupAdminAction,
						RemoveUserFromGroupAdminAction,
						GetGroupAdminAction,
						ListGroupsAdminAction,
						EnableGroupAdminAction,
						DisableGroupAdminAction,
						// Policy management
						CreatePolicyAdminAction,
						DeletePolicyAdminAction,
						GetPolicyAdminAction,
						AttachPolicyAdminAction,
						UpdatePolicyAssociationAction,
						ListUserPoliciesAdminAction,
						// Service account management
						CreateServiceAccountAdminAction,
						UpdateServiceAccountAdminAction,
						RemoveServiceAccountAdminAction,
						ListServiceAccountsAdminAction,
						// Temporary accounts
						ListTemporaryAccountsAdminAction,
						// IAM import/export
						ExportIAMAction,
						ImportIAMAction,
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
						ServerUpdateAdminAction,
						ServiceRestartAdminAction,
						ServiceStopAdminAction,
						ServiceFreezeAdminAction,
						ServiceCordonAdminAction,
						// Server info
						ServerInfoAdminAction,
						StorageInfoAdminAction,
						// Configuration
						ConfigUpdateAdminAction,
						// Healing & recovery
						HealAdminAction,
						ForceUnlockAdminAction,
						// Pool management
						DecommissionAdminAction,
						RebalanceAdminAction,
						// Bucket admin
						SetBucketQuotaAdminAction,
						GetBucketQuotaAdminAction,
						// Tiers
						SetTierAction,
						ListTierAction,
						// Data & license info
						LicenseInfoAdminAction,
						DataUsageInfoAdminAction,
						// Bucket metadata import/export
						ImportBucketMetadataAction,
						ExportBucketMetadataAction,
						// Batch jobs
						StartBatchJobAction,
						ListBatchJobsAction,
						DescribeBatchJobAction,
						CancelBatchJobAction,
						GenerateBatchJobAction,
						// Inventory
						InventoryControlAction,
						// Cluster topology (v4 APIs)
						ClusterInfoAction,
						PoolListAction,
						PoolInfoAction,
						NodeListAction,
						NodeInfoAction,
						SetInfoAction,
						DriveListAction,
						DriveInfoAction,
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
						S3TablesGetWarehouseAction,
						S3TablesGetWarehouseEncryptionAction,
						S3TablesGetWarehouseMaintenanceConfigurationAction,
						S3TablesGetWarehousePolicyAction,
						S3TablesListWarehousesAction,
						// Namespace read + property updates
						S3TablesGetNamespaceAction,
						S3TablesListNamespacesAction,
						S3TablesUpdateNamespacePropertiesAction,
						// Table read + data write
						S3TablesGetTableAction,
						S3TablesListTablesAction,
						S3TablesGetTableDataAction,
						S3TablesPutTableDataAction,
						S3TablesGetTableEncryptionAction,
						S3TablesGetTableMaintenanceConfigurationAction,
						S3TablesGetTableMaintenanceJobStatusAction,
						S3TablesGetTableMetadataLocationAction,
						S3TablesGetTablePolicyAction,
						// Table mutations (non-destructive)
						S3TablesCreateTableAction,
						S3TablesUpdateTableAction,
						S3TablesUpdateTableMetadataLocationAction,
						S3TablesRenameTableAction,
						S3TablesRegisterTableAction,
						// Views full CRUD
						S3TablesGetViewAction,
						S3TablesListViewsAction,
						S3TablesCreateViewAction,
						S3TablesUpdateViewAction,
						S3TablesRenameViewAction,
						S3TablesDeleteViewAction,
						S3TablesRegisterViewAction,
						// Catalog config + metrics
						S3TablesGetConfigAction,
						S3TablesTableMetricsAction,
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
						S3TablesGetWarehouseAction,
						S3TablesGetWarehouseEncryptionAction,
						S3TablesGetWarehouseMaintenanceConfigurationAction,
						S3TablesGetWarehousePolicyAction,
						S3TablesListWarehousesAction,
						// Namespace read
						S3TablesGetNamespaceAction,
						S3TablesListNamespacesAction,
						// Table read
						S3TablesGetTableAction,
						S3TablesListTablesAction,
						S3TablesGetTableDataAction,
						S3TablesGetTableEncryptionAction,
						S3TablesGetTableMaintenanceConfigurationAction,
						S3TablesGetTableMaintenanceJobStatusAction,
						S3TablesGetTableMetadataLocationAction,
						S3TablesGetTablePolicyAction,
						// View read
						S3TablesGetViewAction,
						S3TablesListViewsAction,
						// Catalog config + metrics
						S3TablesGetConfigAction,
						S3TablesTableMetricsAction,
					),
					Resources:  NewResourceSet(NewS3TablesResource("*")),
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
					Actions:    NewActionSet(AllAdminActions),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
				{
					SID:        ID(""),
					Effect:     Allow,
					Actions:    NewActionSet(AllKMSActions),
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
					Actions:    NewActionSet(AllS3TablesActions),
					Resources:  NewResourceSet(NewS3TablesResource("*")),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},
}
