// Copyright (c) 2015-2025 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
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

// TableAction - S3 Tables policy action.
type TableAction string

const (
	// S3TablesCreateNamespaceAction maps to the AWS `CreateNamespace` S3 Tables action.
	S3TablesCreateNamespaceAction = "s3tables:CreateNamespace"

	// S3TablesCreateTableAction maps to the AWS `CreateTable` S3 Tables action.
	S3TablesCreateTableAction = "s3tables:CreateTable"

	// S3TablesDeleteNamespaceAction maps to the AWS `DeleteNamespace` S3 Tables action.
	S3TablesDeleteNamespaceAction = "s3tables:DeleteNamespace"

	// S3TablesDeleteTableAction maps to the AWS `DeleteTable` S3 Tables action.
	S3TablesDeleteTableAction = "s3tables:DeleteTable"

	// S3TablesDeleteTablePolicyAction maps to the AWS `DeleteTablePolicy` S3 Tables action.
	S3TablesDeleteTablePolicyAction = "s3tables:DeleteTablePolicy"

	// S3TablesGetNamespaceAction maps to the AWS `GetNamespace` S3 Tables action.
	S3TablesGetNamespaceAction = "s3tables:GetNamespace"

	// S3TablesGetTableAction maps to the AWS `GetTable` S3 Tables action.
	S3TablesGetTableAction = "s3tables:GetTable"

	// S3TablesGetTableDataAction maps to the AWS `GetTableData` S3 Tables action.
	S3TablesGetTableDataAction = "s3tables:GetTableData"

	// S3TablesGetTableEncryptionAction maps to the AWS `GetTableEncryption` S3 Tables action.
	S3TablesGetTableEncryptionAction = "s3tables:GetTableEncryption"

	// S3TablesGetTableMaintenanceConfigurationAction maps to the AWS `GetTableMaintenanceConfiguration` S3 Tables action.
	S3TablesGetTableMaintenanceConfigurationAction = "s3tables:GetTableMaintenanceConfiguration"

	// S3TablesGetTableMaintenanceJobStatusAction maps to the AWS `GetTableMaintenanceJobStatus` S3 Tables action.
	S3TablesGetTableMaintenanceJobStatusAction = "s3tables:GetTableMaintenanceJobStatus"

	// S3TablesGetTableMetadataLocationAction maps to the AWS `GetTableMetadataLocation` S3 Tables action.
	S3TablesGetTableMetadataLocationAction = "s3tables:GetTableMetadataLocation"

	// S3TablesGetTablePolicyAction maps to the AWS `GetTablePolicy` S3 Tables action.
	S3TablesGetTablePolicyAction = "s3tables:GetTablePolicy"

	// S3TablesListNamespacesAction maps to the AWS `ListNamespaces` S3 Tables action.
	S3TablesListNamespacesAction = "s3tables:ListNamespaces"

	// S3TablesListTablesAction maps to the AWS `ListTables` S3 Tables action.
	S3TablesListTablesAction = "s3tables:ListTables"

	// S3TablesPutTableDataAction maps to the AWS `PutTableData` S3 Tables action.
	S3TablesPutTableDataAction = "s3tables:PutTableData"

	// S3TablesPutTableEncryptionAction maps to the AWS `PutTableEncryption` S3 Tables action.
	S3TablesPutTableEncryptionAction = "s3tables:PutTableEncryption"

	// S3TablesPutTableMaintenanceConfigurationAction maps to the AWS `PutTableMaintenanceConfiguration` S3 Tables action.
	S3TablesPutTableMaintenanceConfigurationAction = "s3tables:PutTableMaintenanceConfiguration"

	// S3TablesPutTablePolicyAction maps to the AWS `PutTablePolicy` S3 Tables action.
	S3TablesPutTablePolicyAction = "s3tables:PutTablePolicy"

	// S3TablesRegisterTableAction maps to the AWS `RegisterTable` S3 Tables action.
	S3TablesRegisterTableAction = "s3tables:RegisterTable"

	// S3TablesRenameTableAction maps to the AWS `RenameTable` S3 Tables action.
	S3TablesRenameTableAction = "s3tables:RenameTable"

	// S3TablesUpdateTableMetadataLocationAction maps to the AWS `UpdateTableMetadataLocation` S3 Tables action.
	S3TablesUpdateTableMetadataLocationAction = "s3tables:UpdateTableMetadataLocation"

	// S3TablesCreateWarehouseAction is a MinIO extension for Iceberg warehouse provisioning.
	S3TablesCreateWarehouseAction = "s3tables:CreateWarehouse"

	// S3TablesCreateTableBucketAction maps to the AWS `CreateTableBucket` S3 Tables action.
	// Prefer using S3TablesCreateWarehouseAction instead.
	S3TablesCreateTableBucketAction = "s3tables:CreateTableBucket"

	// S3TablesDeleteWarehouseAction is a MinIO extension for deleting Iceberg warehouses.
	S3TablesDeleteWarehouseAction = "s3tables:DeleteWarehouse"

	// S3TablesDeleteTableBucketAction maps to the AWS `DeleteTableBucket` S3 Tables action.
	// Prefer using S3TablesDeleteWarehouseAction instead.
	S3TablesDeleteTableBucketAction = "s3tables:DeleteTableBucket"

	// S3TablesDeleteWarehouseEncryptionAction is a MinIO extension for deleting warehouse encryption configuration.
	S3TablesDeleteWarehouseEncryptionAction = "s3tables:DeleteWarehouseEncryption"

	// S3TablesDeleteTableBucketEncryptionAction maps to the AWS `DeleteTableBucketEncryption` S3 Tables action.
	// Prefer using S3TablesDeleteWarehouseEncryptionAction instead.
	S3TablesDeleteTableBucketEncryptionAction = "s3tables:DeleteTableBucketEncryption"

	// S3TablesDeleteWarehousePolicyAction is a MinIO extension for deleting warehouse policies.
	S3TablesDeleteWarehousePolicyAction = "s3tables:DeleteWarehousePolicy"

	// S3TablesDeleteTableBucketPolicyAction maps to the AWS `DeleteTableBucketPolicy` S3 Tables action.
	// Prefer using S3TablesDeleteWarehousePolicyAction instead.
	S3TablesDeleteTableBucketPolicyAction = "s3tables:DeleteTableBucketPolicy"

	// S3TablesGetWarehouseAction is a MinIO extension for retrieving warehouse details.
	S3TablesGetWarehouseAction = "s3tables:GetWarehouse"

	// S3TablesGetTableBucketAction maps to the AWS `GetTableBucket` S3 Tables action.
	// Prefer using S3TablesGetWarehouseAction instead.
	S3TablesGetTableBucketAction = "s3tables:GetTableBucket"

	// S3TablesGetWarehouseEncryptionAction is a MinIO extension for retrieving warehouse encryption configuration.
	S3TablesGetWarehouseEncryptionAction = "s3tables:GetWarehouseEncryption"

	// S3TablesGetTableBucketEncryptionAction maps to the AWS `GetTableBucketEncryption` S3 Tables action.
	// Prefer using S3TablesGetWarehouseEncryptionAction instead.
	S3TablesGetTableBucketEncryptionAction = "s3tables:GetTableBucketEncryption"

	// S3TablesGetWarehouseMaintenanceConfigurationAction is a MinIO extension for retrieving warehouse maintenance configuration.
	S3TablesGetWarehouseMaintenanceConfigurationAction = "s3tables:GetWarehouseMaintenanceConfiguration"

	// S3TablesGetTableBucketMaintenanceConfigurationAction maps to the AWS `GetTableBucketMaintenanceConfiguration` S3 Tables action.
	// Prefer using S3TablesGetWarehouseMaintenanceConfigurationAction instead.
	S3TablesGetTableBucketMaintenanceConfigurationAction = "s3tables:GetTableBucketMaintenanceConfiguration"

	// S3TablesGetWarehousePolicyAction is a MinIO extension for retrieving warehouse policies.
	S3TablesGetWarehousePolicyAction = "s3tables:GetWarehousePolicy"

	// S3TablesGetTableBucketPolicyAction maps to the AWS `GetTableBucketPolicy` S3 Tables action.
	// Prefer using S3TablesGetWarehousePolicyAction instead.
	S3TablesGetTableBucketPolicyAction = "s3tables:GetTableBucketPolicy"

	// S3TablesListWarehousesAction is a MinIO extension for listing Iceberg warehouses.
	S3TablesListWarehousesAction = "s3tables:ListWarehouses"

	// S3TablesListTableBucketsAction maps to the AWS `ListTableBuckets` S3 Tables action.
	// Prefer using S3TablesListWarehousesAction instead.
	S3TablesListTableBucketsAction = "s3tables:ListTableBuckets"

	// S3TablesPutWarehouseEncryptionAction is a MinIO extension for setting warehouse encryption configuration.
	S3TablesPutWarehouseEncryptionAction = "s3tables:PutWarehouseEncryption"

	// S3TablesPutTableBucketEncryptionAction maps to the AWS `PutTableBucketEncryption` S3 Tables action.
	// Prefer using S3TablesPutWarehouseEncryptionAction instead.
	S3TablesPutTableBucketEncryptionAction = "s3tables:PutTableBucketEncryption"

	// S3TablesPutWarehouseMaintenanceConfigurationAction is a MinIO extension for setting warehouse maintenance configuration.
	S3TablesPutWarehouseMaintenanceConfigurationAction = "s3tables:PutWarehouseMaintenanceConfiguration"

	// S3TablesPutTableBucketMaintenanceConfigurationAction maps to the AWS `PutTableBucketMaintenanceConfiguration` S3 Tables action.
	// Prefer using S3TablesPutWarehouseMaintenanceConfigurationAction instead.
	S3TablesPutTableBucketMaintenanceConfigurationAction = "s3tables:PutTableBucketMaintenanceConfiguration"

	// S3TablesPutWarehousePolicyAction is a MinIO extension for setting warehouse policies.
	S3TablesPutWarehousePolicyAction = "s3tables:PutWarehousePolicy"

	// S3TablesPutTableBucketPolicyAction maps to the AWS `PutTableBucketPolicy` S3 Tables action.
	// Prefer using S3TablesPutWarehousePolicyAction instead.
	S3TablesPutTableBucketPolicyAction = "s3tables:PutTableBucketPolicy"

	// S3TablesGetConfigAction is a MinIO extension for retrieving catalog configuration.
	S3TablesGetConfigAction = "s3tables:GetConfig"

	// S3TablesTableMetricsAction is a MinIO extension exposing table metrics.
	S3TablesTableMetricsAction = "s3tables:TableMetrics"

	// S3TablesUpdateTableAction is a MinIO extension for Iceberg-compatible table updates.
	S3TablesUpdateTableAction = "s3tables:UpdateTable"

	// S3TablesCreateViewAction is a MinIO extension for creating Iceberg views.
	S3TablesCreateViewAction = "s3tables:CreateView"

	// S3TablesDeleteViewAction is a MinIO extension for deleting Iceberg views.
	S3TablesDeleteViewAction = "s3tables:DeleteView"

	// S3TablesGetViewAction is a MinIO extension for retrieving Iceberg views.
	S3TablesGetViewAction = "s3tables:GetView"

	// S3TablesRenameViewAction is a MinIO extension for renaming Iceberg views.
	S3TablesRenameViewAction = "s3tables:RenameView"

	// S3TablesUpdateViewAction is a MinIO extension for updating Iceberg views.
	S3TablesUpdateViewAction = "s3tables:UpdateView"

	// S3TablesListViewsAction is a MinIO extension for listing Iceberg views.
	S3TablesListViewsAction = "s3tables:ListViews"

	// S3TablesRegisterViewAction is a MinIO extension for registering Iceberg views.
	S3TablesRegisterViewAction = "s3tables:RegisterView"

	// S3TablesCreateFunctionAction is a MinIO extension for creating Iceberg functions (SQL UDFs).
	S3TablesCreateFunctionAction = "s3tables:CreateFunction"

	// S3TablesDeleteFunctionAction is a MinIO extension for deleting Iceberg functions (SQL UDFs).
	S3TablesDeleteFunctionAction = "s3tables:DeleteFunction"

	// S3TablesGetFunctionAction is a MinIO extension for retrieving Iceberg functions (SQL UDFs).
	S3TablesGetFunctionAction = "s3tables:GetFunction"

	// S3TablesRenameFunctionAction is a MinIO extension for renaming Iceberg functions (SQL UDFs).
	S3TablesRenameFunctionAction = "s3tables:RenameFunction"

	// S3TablesUpdateFunctionAction is a MinIO extension for updating Iceberg functions (SQL UDFs).
	S3TablesUpdateFunctionAction = "s3tables:UpdateFunction"

	// S3TablesListFunctionsAction is a MinIO extension for listing Iceberg functions (SQL UDFs).
	S3TablesListFunctionsAction = "s3tables:ListFunctions"

	// S3TablesRegisterFunctionAction is a MinIO extension for registering Iceberg functions (SQL UDFs).
	S3TablesRegisterFunctionAction = "s3tables:RegisterFunction"

	// S3TablesUpdateNamespacePropertiesAction is a MinIO extension for updating namespace properties.
	S3TablesUpdateNamespacePropertiesAction = "s3tables:UpdateNamespaceProperties"

	// S3TablesTagWarehouseAction is a MinIO extension for tagging Iceberg warehouses.
	S3TablesTagWarehouseAction = "s3tables:TagWarehouse"
	// S3TablesUntagWarehouseAction is a MinIO extension for removing tags from Iceberg warehouses.
	S3TablesUntagWarehouseAction = "s3tables:UntagWarehouse"
	// S3TablesListTagsForWarehouseAction is a MinIO extension for listing tags on Iceberg warehouses.
	S3TablesListTagsForWarehouseAction = "s3tables:ListTagsForWarehouse"

	// S3TablesTagTableAction is a MinIO extension for tagging tables.
	S3TablesTagTableAction = "s3tables:TagTable"
	// S3TablesUntagTableAction is a MinIO extension for removing tags from tables.
	S3TablesUntagTableAction = "s3tables:UntagTable"
	// S3TablesListTagsForTableAction is a MinIO extension for listing tags on tables.
	S3TablesListTagsForTableAction = "s3tables:ListTagsForTable"

	// AllS3TablesActions - all Amazon S3 Tables actions
	AllS3TablesActions = "s3tables:*"
)

// SupportedTableActions - list of all supported S3 Tables actions.
var SupportedTableActions = map[TableAction]struct{}{
	S3TablesCreateNamespaceAction:                        {},
	S3TablesCreateTableAction:                            {},
	S3TablesCreateTableBucketAction:                      {},
	S3TablesDeleteNamespaceAction:                        {},
	S3TablesDeleteTableAction:                            {},
	S3TablesDeleteTableBucketAction:                      {},
	S3TablesDeleteTableBucketEncryptionAction:            {},
	S3TablesDeleteTableBucketPolicyAction:                {},
	S3TablesDeleteTablePolicyAction:                      {},
	S3TablesGetNamespaceAction:                           {},
	S3TablesGetTableAction:                               {},
	S3TablesGetTableBucketAction:                         {},
	S3TablesGetTableBucketEncryptionAction:               {},
	S3TablesGetTableBucketMaintenanceConfigurationAction: {},
	S3TablesGetTableBucketPolicyAction:                   {},
	S3TablesGetTableDataAction:                           {},
	S3TablesGetTableEncryptionAction:                     {},
	S3TablesGetTableMaintenanceConfigurationAction:       {},
	S3TablesGetTableMaintenanceJobStatusAction:           {},
	S3TablesGetTableMetadataLocationAction:               {},
	S3TablesGetTablePolicyAction:                         {},
	S3TablesListNamespacesAction:                         {},
	S3TablesListTableBucketsAction:                       {},
	S3TablesListTablesAction:                             {},
	S3TablesPutTableBucketEncryptionAction:               {},
	S3TablesPutTableBucketMaintenanceConfigurationAction: {},
	S3TablesPutTableBucketPolicyAction:                   {},
	S3TablesPutTableDataAction:                           {},
	S3TablesPutTableEncryptionAction:                     {},
	S3TablesPutTableMaintenanceConfigurationAction:       {},
	S3TablesPutTablePolicyAction:                         {},
	S3TablesRegisterTableAction:                          {},
	S3TablesRenameTableAction:                            {},
	S3TablesUpdateTableMetadataLocationAction:            {},
	S3TablesCreateWarehouseAction:                        {},
	S3TablesDeleteWarehouseAction:                        {},
	S3TablesDeleteWarehouseEncryptionAction:              {},
	S3TablesDeleteWarehousePolicyAction:                  {},
	S3TablesGetWarehouseAction:                           {},
	S3TablesGetWarehouseEncryptionAction:                 {},
	S3TablesGetWarehouseMaintenanceConfigurationAction:   {},
	S3TablesGetWarehousePolicyAction:                     {},
	S3TablesListWarehousesAction:                         {},
	S3TablesPutWarehouseEncryptionAction:                 {},
	S3TablesPutWarehouseMaintenanceConfigurationAction:   {},
	S3TablesPutWarehousePolicyAction:                     {},
	S3TablesGetConfigAction:                              {},
	S3TablesTableMetricsAction:                           {},
	S3TablesUpdateTableAction:                            {},
	S3TablesCreateViewAction:                             {},
	S3TablesDeleteViewAction:                             {},
	S3TablesGetViewAction:                                {},
	S3TablesRenameViewAction:                             {},
	S3TablesUpdateViewAction:                             {},
	S3TablesListViewsAction:                              {},
	S3TablesRegisterViewAction:                           {},
	S3TablesCreateFunctionAction:                         {},
	S3TablesDeleteFunctionAction:                         {},
	S3TablesGetFunctionAction:                            {},
	S3TablesRenameFunctionAction:                         {},
	S3TablesUpdateFunctionAction:                         {},
	S3TablesListFunctionsAction:                          {},
	S3TablesRegisterFunctionAction:                       {},
	S3TablesUpdateNamespacePropertiesAction:              {},
	S3TablesTagWarehouseAction:                           {},
	S3TablesUntagWarehouseAction:                         {},
	S3TablesListTagsForWarehouseAction:                   {},
	S3TablesTagTableAction:                               {},
	S3TablesUntagTableAction:                             {},
	S3TablesListTagsForTableAction:                       {},
	AllS3TablesActions:                                   {},
}

// IsValid - checks if action is valid or not.
func (action TableAction) IsValid() bool {
	_, ok := SupportedTableActions[action]
	return ok
}

func createTableActionConditionKeyMap() map[Action]condition.KeySet {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	s3TablesNamespaceKey := condition.S3TablesNamespace.ToKey()
	s3TablesTableNameKey := condition.S3TablesTableName.ToKey()
	s3TablesViewNameKey := condition.S3TablesViewName.ToKey()
	s3TablesFunctionNameKey := condition.S3TablesFunctionName.ToKey()
	s3TablesKMSKeyKey := condition.S3TablesKMSKeyArn.ToKey()
	s3TablesSSEAlgorithmKey := condition.S3TablesSSEAlgorithm.ToKey()
	s3TablesRegisterLocationKey := condition.S3TablesRegisterLocation.ToKey()
	s3TablesWarehouseTagKey := condition.S3TablesWarehouseTag.ToKey()
	s3TablesTableTagKey := condition.S3TablesTableTag.ToKey()

	withCommon := func(keys ...condition.Key) condition.KeySet {
		merged := append([]condition.Key{}, commonKeys...)
		merged = append(merged, keys...)
		return condition.NewKeySet(merged...)
	}

	withWarehouseCommon := func(keys ...condition.Key) condition.KeySet {
		return withCommon(append([]condition.Key{s3TablesWarehouseTagKey}, keys...)...)
	}

	withTableCommon := func(keys ...condition.Key) condition.KeySet {
		return withWarehouseCommon(append([]condition.Key{
			s3TablesNamespaceKey,
			s3TablesTableNameKey,
			s3TablesTableTagKey,
		}, keys...)...)
	}

	withViewCommon := func(keys ...condition.Key) condition.KeySet {
		return withWarehouseCommon(append([]condition.Key{
			s3TablesNamespaceKey,
			s3TablesViewNameKey,
		}, keys...)...)
	}

	withFunctionCommon := func(keys ...condition.Key) condition.KeySet {
		return withWarehouseCommon(append([]condition.Key{
			s3TablesNamespaceKey,
			s3TablesFunctionNameKey,
		}, keys...)...)
	}

	tableActionConditionKeyMap := map[Action]condition.KeySet{}
	for act := range SupportedTableActions {
		tableActionConditionKeyMap[Action(act)] = condition.NewKeySet(commonKeys...)
	}

	// Override specific actions with their condition keys
	tableActionConditionKeyMap[AllS3TablesActions] = withCommon(
		s3TablesNamespaceKey,
		s3TablesTableNameKey,
		s3TablesViewNameKey,
		s3TablesFunctionNameKey,
		s3TablesKMSKeyKey,
		s3TablesSSEAlgorithmKey,
		s3TablesRegisterLocationKey,
		s3TablesWarehouseTagKey,
		s3TablesTableTagKey,
	)
	tableActionConditionKeyMap[S3TablesCreateNamespaceAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesCreateTableAction] = withWarehouseCommon(s3TablesNamespaceKey, s3TablesTableNameKey, s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey)
	tableActionConditionKeyMap[S3TablesCreateTableBucketAction] = withCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey)
	tableActionConditionKeyMap[S3TablesDeleteNamespaceAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesDeleteTableAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesDeleteTableBucketAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesDeleteTableBucketEncryptionAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesDeleteTableBucketPolicyAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesDeleteTablePolicyAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetNamespaceAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesGetTableAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetTableBucketAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetTableBucketEncryptionAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetTableBucketMaintenanceConfigurationAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetTableBucketPolicyAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetTableDataAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetTableEncryptionAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetTableMaintenanceConfigurationAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetTableMaintenanceJobStatusAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetTableMetadataLocationAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesGetTablePolicyAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesListNamespacesAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesListTableBucketsAction] = withCommon()
	tableActionConditionKeyMap[S3TablesListTablesAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesPutTableBucketEncryptionAction] = withWarehouseCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey)
	tableActionConditionKeyMap[S3TablesPutTableBucketMaintenanceConfigurationAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesPutTableBucketPolicyAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesPutTableDataAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesPutTableEncryptionAction] = withTableCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey)
	tableActionConditionKeyMap[S3TablesPutTableMaintenanceConfigurationAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesPutTablePolicyAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesRegisterTableAction] = withTableCommon(s3TablesRegisterLocationKey)
	tableActionConditionKeyMap[S3TablesRenameTableAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesUpdateTableMetadataLocationAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesCreateWarehouseAction] = withCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey)
	tableActionConditionKeyMap[S3TablesDeleteWarehouseAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesDeleteWarehouseEncryptionAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesDeleteWarehousePolicyAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetWarehouseAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetWarehouseEncryptionAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetWarehouseMaintenanceConfigurationAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetWarehousePolicyAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesListWarehousesAction] = withCommon()
	tableActionConditionKeyMap[S3TablesPutWarehouseEncryptionAction] = withWarehouseCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey)
	tableActionConditionKeyMap[S3TablesPutWarehouseMaintenanceConfigurationAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesPutWarehousePolicyAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesGetConfigAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesTableMetricsAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesUpdateTableAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesCreateViewAction] = withWarehouseCommon(s3TablesNamespaceKey, s3TablesViewNameKey)
	tableActionConditionKeyMap[S3TablesDeleteViewAction] = withViewCommon()
	tableActionConditionKeyMap[S3TablesGetViewAction] = withViewCommon()
	tableActionConditionKeyMap[S3TablesRenameViewAction] = withViewCommon()
	tableActionConditionKeyMap[S3TablesUpdateViewAction] = withViewCommon()
	tableActionConditionKeyMap[S3TablesRegisterViewAction] = withViewCommon(s3TablesRegisterLocationKey)
	tableActionConditionKeyMap[S3TablesListViewsAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesCreateFunctionAction] = withWarehouseCommon(s3TablesNamespaceKey, s3TablesFunctionNameKey)
	tableActionConditionKeyMap[S3TablesDeleteFunctionAction] = withFunctionCommon()
	tableActionConditionKeyMap[S3TablesGetFunctionAction] = withFunctionCommon()
	tableActionConditionKeyMap[S3TablesRenameFunctionAction] = withFunctionCommon()
	tableActionConditionKeyMap[S3TablesUpdateFunctionAction] = withFunctionCommon()
	tableActionConditionKeyMap[S3TablesRegisterFunctionAction] = withFunctionCommon(s3TablesRegisterLocationKey)
	tableActionConditionKeyMap[S3TablesListFunctionsAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesUpdateNamespacePropertiesAction] = withWarehouseCommon(s3TablesNamespaceKey)
	tableActionConditionKeyMap[S3TablesTagWarehouseAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesUntagWarehouseAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesListTagsForWarehouseAction] = withWarehouseCommon()
	tableActionConditionKeyMap[S3TablesTagTableAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesUntagTableAction] = withTableCommon()
	tableActionConditionKeyMap[S3TablesListTagsForTableAction] = withTableCommon()

	return tableActionConditionKeyMap
}

// tableActionConditionKeyMap - holds mapping of supported condition key for a table action.
var tableActionConditionKeyMap = createTableActionConditionKeyMap()
