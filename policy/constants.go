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
	// (config, pools, healing, tiers, batch jobs, site replication) but no
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
						SetBucketTargetAction,
						GetBucketTargetAction,
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
						// Replication
						ReplicationDiff,
					),
					Resources:  NewResourceSet(),
					Conditions: condition.NewFunctions(),
				},
			},
		},
	},

	// DiagnosticsAdmin - provides monitoring and observability access
	// (metrics, profiling, tracing, logs) but no mutating operations or
	// S3 data access. Extended version of the "diagnostics" policy.
	{
		Name: "diagnosticsAdmin",
		Definition: Policy{
			Version: DefaultVersion,
			Statements: []Statement{
				{
					SID:    ID(""),
					Effect: Allow,
					Actions: NewActionSet(
						PrometheusAdminAction,
						ProfilingAdminAction,
						TraceAdminAction,
						ConsoleLogAdminAction,
						ServerInfoAdminAction,
						StorageInfoAdminAction,
						HealthInfoAdminAction,
						TopLocksAdminAction,
						BandwidthMonitorAction,
						DataUsageInfoAdminAction,
						LicenseInfoAdminAction,
						InspectDataAction,
					),
					Resources:  NewResourceSet(),
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
