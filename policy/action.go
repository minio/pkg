// Copyright (c) 2015-2023 MinIO, Inc.
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

// Action - policy action.
// Refer https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html
// for more information about available actions.
type Action string

const (
	// AbortMultipartUploadAction - AbortMultipartUpload Rest API action.
	AbortMultipartUploadAction Action = "s3:AbortMultipartUpload"

	// CreateBucketAction - CreateBucket Rest API action.
	CreateBucketAction = "s3:CreateBucket"

	// DeleteBucketAction - DeleteBucket Rest API action.
	DeleteBucketAction = "s3:DeleteBucket"

	// ForceDeleteBucketAction - DeleteBucket Rest API action when x-minio-force-delete flag
	// is specified.
	ForceDeleteBucketAction = "s3:ForceDeleteBucket"

	// DeleteBucketPolicyAction - DeleteBucketPolicy Rest API action.
	DeleteBucketPolicyAction = "s3:DeleteBucketPolicy"

	// DeleteBucketCorsAction - DeleteBucketCors Rest API action.
	DeleteBucketCorsAction = "s3:DeleteBucketCors"

	// DeleteObjectAction - DeleteObject Rest API action.
	DeleteObjectAction = "s3:DeleteObject"

	// GetBucketLocationAction - GetBucketLocation Rest API action.
	GetBucketLocationAction = "s3:GetBucketLocation"

	// GetBucketNotificationAction - GetBucketNotification Rest API action.
	GetBucketNotificationAction = "s3:GetBucketNotification"

	// GetBucketPolicyAction - GetBucketPolicy Rest API action.
	GetBucketPolicyAction = "s3:GetBucketPolicy"

	// GetBucketCorsAction - GetBucketCors Rest API action.
	GetBucketCorsAction = "s3:GetBucketCors"

	// GetObjectAction - GetObject Rest API action.
	GetObjectAction = "s3:GetObject"

	// GetObjectAttributesAction - GetObjectVersionAttributes Rest API action.
	GetObjectAttributesAction = "s3:GetObjectAttributes"

	// HeadBucketAction - HeadBucket Rest API action. This action is unused in minio.
	HeadBucketAction = "s3:HeadBucket"

	// ListAllMyBucketsAction - ListAllMyBuckets (List buckets) Rest API action.
	ListAllMyBucketsAction = "s3:ListAllMyBuckets"

	// ListBucketAction - ListBucket Rest API action.
	ListBucketAction = "s3:ListBucket"

	// GetBucketPolicyStatusAction - Retrieves the policy status for a bucket.
	GetBucketPolicyStatusAction = "s3:GetBucketPolicyStatus"

	// ListBucketVersionsAction - ListBucketVersions Rest API action.
	ListBucketVersionsAction = "s3:ListBucketVersions"

	// ListBucketMultipartUploadsAction - ListMultipartUploads Rest API action.
	ListBucketMultipartUploadsAction = "s3:ListBucketMultipartUploads"

	// ListenNotificationAction - ListenNotification Rest API action.
	// This is MinIO extension.
	ListenNotificationAction = "s3:ListenNotification"

	// ListenBucketNotificationAction - ListenBucketNotification Rest API action.
	// This is MinIO extension.
	ListenBucketNotificationAction = "s3:ListenBucketNotification"

	// ListMultipartUploadPartsAction - ListParts Rest API action.
	ListMultipartUploadPartsAction = "s3:ListMultipartUploadParts"

	// PutBucketLifecycleAction - PutBucketLifecycle Rest API action.
	PutBucketLifecycleAction = "s3:PutLifecycleConfiguration"

	// GetBucketLifecycleAction - GetBucketLifecycle Rest API action.
	GetBucketLifecycleAction = "s3:GetLifecycleConfiguration"

	// PutBucketNotificationAction - PutObjectNotification Rest API action.
	PutBucketNotificationAction = "s3:PutBucketNotification"

	// PutBucketPolicyAction - PutBucketPolicy Rest API action.
	PutBucketPolicyAction = "s3:PutBucketPolicy"

	// PutBucketCorsAction - PutBucketCors Rest API action.
	PutBucketCorsAction = "s3:PutBucketCors"

	//  PutBucketQOSAction - allow set QOS configuration
	PutBucketQOSAction = "s3:PutBucketQOS"

	//  GetBucketQOSAction - allow get QOS configuration
	GetBucketQOSAction = "s3:GetBucketQOS"

	// PutObjectAction - PutObject Rest API action.
	PutObjectAction = "s3:PutObject"

	// DeleteObjectVersionAction - DeleteObjectVersion Rest API action.
	DeleteObjectVersionAction = "s3:DeleteObjectVersion"

	// DeleteObjectVersionTaggingAction - DeleteObjectVersionTagging Rest API action.
	DeleteObjectVersionTaggingAction = "s3:DeleteObjectVersionTagging"

	// GetObjectVersionAction - GetObjectVersionAction Rest API action.
	GetObjectVersionAction = "s3:GetObjectVersion"

	// GetObjectVersionAttributesAction - GetObjectVersionAttributes Rest API action.
	GetObjectVersionAttributesAction = "s3:GetObjectVersionAttributes"

	// GetObjectVersionTaggingAction - GetObjectVersionTagging Rest API action.
	GetObjectVersionTaggingAction = "s3:GetObjectVersionTagging"

	// PutObjectVersionTaggingAction - PutObjectVersionTagging Rest API action.
	PutObjectVersionTaggingAction = "s3:PutObjectVersionTagging"

	// BypassGovernanceRetentionAction - bypass governance retention for PutObjectRetention, PutObject and DeleteObject Rest API action.
	BypassGovernanceRetentionAction = "s3:BypassGovernanceRetention"

	// PutObjectRetentionAction - PutObjectRetention Rest API action.
	PutObjectRetentionAction = "s3:PutObjectRetention"

	// GetObjectRetentionAction - GetObjectRetention, GetObject, HeadObject Rest API action.
	GetObjectRetentionAction = "s3:GetObjectRetention"

	// GetObjectLegalHoldAction - GetObjectLegalHold, GetObject Rest API action.
	GetObjectLegalHoldAction = "s3:GetObjectLegalHold"

	// PutObjectLegalHoldAction - PutObjectLegalHold, PutObject Rest API action.
	PutObjectLegalHoldAction = "s3:PutObjectLegalHold"

	// GetBucketObjectLockConfigurationAction - GetBucketObjectLockConfiguration Rest API action
	GetBucketObjectLockConfigurationAction = "s3:GetBucketObjectLockConfiguration"

	// PutBucketObjectLockConfigurationAction - PutBucketObjectLockConfiguration Rest API action
	PutBucketObjectLockConfigurationAction = "s3:PutBucketObjectLockConfiguration"

	// GetBucketTaggingAction - GetBucketTagging Rest API action
	GetBucketTaggingAction = "s3:GetBucketTagging"

	// PutBucketTaggingAction - PutBucketTagging Rest API action
	PutBucketTaggingAction = "s3:PutBucketTagging"

	// GetObjectTaggingAction - Get Object Tags API action
	GetObjectTaggingAction = "s3:GetObjectTagging"

	// PutObjectTaggingAction - Put Object Tags API action
	PutObjectTaggingAction = "s3:PutObjectTagging"

	// DeleteObjectTaggingAction - Delete Object Tags API action
	DeleteObjectTaggingAction = "s3:DeleteObjectTagging"

	// PutBucketEncryptionAction - PutBucketEncryption REST API action
	PutBucketEncryptionAction = "s3:PutEncryptionConfiguration"

	// GetBucketEncryptionAction - GetBucketEncryption REST API action
	GetBucketEncryptionAction = "s3:GetEncryptionConfiguration"

	// PutBucketVersioningAction - PutBucketVersioning REST API action
	PutBucketVersioningAction = "s3:PutBucketVersioning"

	// GetBucketVersioningAction - GetBucketVersioning REST API action
	GetBucketVersioningAction = "s3:GetBucketVersioning"
	// GetReplicationConfigurationAction  - GetReplicationConfiguration REST API action
	GetReplicationConfigurationAction = "s3:GetReplicationConfiguration"
	// PutReplicationConfigurationAction  - PutReplicationConfiguration REST API action
	PutReplicationConfigurationAction = "s3:PutReplicationConfiguration"

	// ReplicateObjectAction  - ReplicateObject REST API action
	ReplicateObjectAction = "s3:ReplicateObject"

	// ReplicateDeleteAction  - ReplicateDelete REST API action
	ReplicateDeleteAction = "s3:ReplicateDelete"

	// ReplicateTagsAction  - ReplicateTags REST API action
	ReplicateTagsAction = "s3:ReplicateTags"

	// GetObjectVersionForReplicationAction  - GetObjectVersionForReplication REST API action
	GetObjectVersionForReplicationAction = "s3:GetObjectVersionForReplication"

	// RestoreObjectAction - RestoreObject REST API action
	RestoreObjectAction = "s3:RestoreObject"
	// ResetBucketReplicationStateAction - MinIO extension API ResetBucketReplicationState to reset replication state
	// on a bucket
	ResetBucketReplicationStateAction = "s3:ResetBucketReplicationState"

	// PutObjectFanOutAction - PutObject like API action but allows PostUpload() fan-out.
	PutObjectFanOutAction = "s3:PutObjectFanOut"

	// Inventory configuration actions

	// PutInventoryConfigurationAction - Bucket inventory write operations actions
	PutInventoryConfigurationAction = "s3:PutInventoryConfiguration"
	// GetInventoryConfigurationAction - Bucket inventory read operations actions
	GetInventoryConfigurationAction = "s3:GetInventoryConfiguration"

	// CreateSessionAction - S3Express REST API action
	CreateSessionAction = "s3express:CreateSession"

	// S3TablesCreateNamespaceAction maps to the AWS `CreateNamespace` S3 Tables action.
	S3TablesCreateNamespaceAction Action = "s3tables:CreateNamespace"

	// S3TablesCreateTableAction maps to the AWS `CreateTable` S3 Tables action.
	S3TablesCreateTableAction Action = "s3tables:CreateTable"

	// S3TablesCreateTableBucketAction maps to the AWS `CreateTableBucket` S3 Tables action.
	S3TablesCreateTableBucketAction Action = "s3tables:CreateTableBucket"

	// S3TablesDeleteNamespaceAction maps to the AWS `DeleteNamespace` S3 Tables action.
	S3TablesDeleteNamespaceAction Action = "s3tables:DeleteNamespace"

	// S3TablesDeleteTableAction maps to the AWS `DeleteTable` S3 Tables action.
	S3TablesDeleteTableAction Action = "s3tables:DeleteTable"

	// S3TablesDeleteTableBucketAction maps to the AWS `DeleteTableBucket` S3 Tables action.
	S3TablesDeleteTableBucketAction Action = "s3tables:DeleteTableBucket"

	// S3TablesDeleteTableBucketEncryptionAction maps to the AWS `DeleteTableBucketEncryption` S3 Tables action.
	S3TablesDeleteTableBucketEncryptionAction Action = "s3tables:DeleteTableBucketEncryption"

	// S3TablesDeleteTableBucketPolicyAction maps to the AWS `DeleteTableBucketPolicy` S3 Tables action.
	S3TablesDeleteTableBucketPolicyAction Action = "s3tables:DeleteTableBucketPolicy"

	// S3TablesDeleteTablePolicyAction maps to the AWS `DeleteTablePolicy` S3 Tables action.
	S3TablesDeleteTablePolicyAction Action = "s3tables:DeleteTablePolicy"

	// S3TablesGetNamespaceAction maps to the AWS `GetNamespace` S3 Tables action.
	S3TablesGetNamespaceAction Action = "s3tables:GetNamespace"

	// S3TablesGetTableAction maps to the AWS `GetTable` S3 Tables action.
	S3TablesGetTableAction Action = "s3tables:GetTable"

	// S3TablesGetTableBucketAction maps to the AWS `GetTableBucket` S3 Tables action.
	S3TablesGetTableBucketAction Action = "s3tables:GetTableBucket"

	// S3TablesGetTableBucketEncryptionAction maps to the AWS `GetTableBucketEncryption` S3 Tables action.
	S3TablesGetTableBucketEncryptionAction Action = "s3tables:GetTableBucketEncryption"

	// S3TablesGetTableBucketMaintenanceConfigurationAction maps to the AWS `GetTableBucketMaintenanceConfiguration` S3 Tables action.
	S3TablesGetTableBucketMaintenanceConfigurationAction Action = "s3tables:GetTableBucketMaintenanceConfiguration"

	// S3TablesGetTableBucketPolicyAction maps to the AWS `GetTableBucketPolicy` S3 Tables action.
	S3TablesGetTableBucketPolicyAction Action = "s3tables:GetTableBucketPolicy"

	// S3TablesGetTableDataAction maps to the AWS `GetTableData` S3 Tables action.
	S3TablesGetTableDataAction Action = "s3tables:GetTableData"

	// S3TablesGetTableEncryptionAction maps to the AWS `GetTableEncryption` S3 Tables action.
	S3TablesGetTableEncryptionAction Action = "s3tables:GetTableEncryption"

	// S3TablesGetTableMaintenanceConfigurationAction maps to the AWS `GetTableMaintenanceConfiguration` S3 Tables action.
	S3TablesGetTableMaintenanceConfigurationAction Action = "s3tables:GetTableMaintenanceConfiguration"

	// S3TablesGetTableMaintenanceJobStatusAction maps to the AWS `GetTableMaintenanceJobStatus` S3 Tables action.
	S3TablesGetTableMaintenanceJobStatusAction Action = "s3tables:GetTableMaintenanceJobStatus"

	// S3TablesGetTableMetadataLocationAction maps to the AWS `GetTableMetadataLocation` S3 Tables action.
	S3TablesGetTableMetadataLocationAction Action = "s3tables:GetTableMetadataLocation"

	// S3TablesGetTablePolicyAction maps to the AWS `GetTablePolicy` S3 Tables action.
	S3TablesGetTablePolicyAction Action = "s3tables:GetTablePolicy"

	// S3TablesListNamespacesAction maps to the AWS `ListNamespaces` S3 Tables action.
	S3TablesListNamespacesAction Action = "s3tables:ListNamespaces"

	// S3TablesListTableBucketsAction maps to the AWS `ListTableBuckets` S3 Tables action.
	S3TablesListTableBucketsAction Action = "s3tables:ListTableBuckets"

	// S3TablesListTablesAction maps to the AWS `ListTables` S3 Tables action.
	S3TablesListTablesAction Action = "s3tables:ListTables"

	// S3TablesPutTableBucketEncryptionAction maps to the AWS `PutTableBucketEncryption` S3 Tables action.
	S3TablesPutTableBucketEncryptionAction Action = "s3tables:PutTableBucketEncryption"

	// S3TablesPutTableBucketMaintenanceConfigurationAction maps to the AWS `PutTableBucketMaintenanceConfiguration` S3 Tables action.
	S3TablesPutTableBucketMaintenanceConfigurationAction Action = "s3tables:PutTableBucketMaintenanceConfiguration"

	// S3TablesPutTableBucketPolicyAction maps to the AWS `PutTableBucketPolicy` S3 Tables action.
	S3TablesPutTableBucketPolicyAction Action = "s3tables:PutTableBucketPolicy"

	// S3TablesPutTableDataAction maps to the AWS `PutTableData` S3 Tables action.
	S3TablesPutTableDataAction Action = "s3tables:PutTableData"

	// S3TablesPutTableEncryptionAction maps to the AWS `PutTableEncryption` S3 Tables action.
	S3TablesPutTableEncryptionAction Action = "s3tables:PutTableEncryption"

	// S3TablesPutTableMaintenanceConfigurationAction maps to the AWS `PutTableMaintenanceConfiguration` S3 Tables action.
	S3TablesPutTableMaintenanceConfigurationAction Action = "s3tables:PutTableMaintenanceConfiguration"

	// S3TablesPutTablePolicyAction maps to the AWS `PutTablePolicy` S3 Tables action.
	S3TablesPutTablePolicyAction Action = "s3tables:PutTablePolicy"

	// S3TablesRenameTableAction maps to the AWS `RenameTable` S3 Tables action.
	S3TablesRenameTableAction Action = "s3tables:RenameTable"

	// S3TablesUpdateTableMetadataLocationAction maps to the AWS `UpdateTableMetadataLocation` S3 Tables action.
	S3TablesUpdateTableMetadataLocationAction Action = "s3tables:UpdateTableMetadataLocation"

	// S3TablesCreateWarehouseAction is a MinIO extension for Iceberg warehouse provisioning.
	S3TablesCreateWarehouseAction Action = "s3tables:CreateWarehouse"

	// S3TablesListWarehousesAction is a MinIO extension for listing Iceberg warehouses.
	S3TablesListWarehousesAction Action = "s3tables:ListWarehouses"

	// S3TablesCommitMultiTableTransactionAction is a MinIO extension enabling multi-table transactions.
	S3TablesCommitMultiTableTransactionAction Action = "s3tables:CommitMultiTableTransaction"

	// S3TablesGetConfigAction is a MinIO extension for retrieving catalog configuration.
	S3TablesGetConfigAction Action = "s3tables:GetConfig"

	// S3TablesTableMetricsAction is a MinIO extension exposing table metrics.
	S3TablesTableMetricsAction Action = "s3tables:TableMetrics"

	// S3TablesUpdateTableAction is a MinIO extension for Iceberg-compatible table updates.
	S3TablesUpdateTableAction Action = "s3tables:UpdateTable"

	// AllActions - all API actions
	AllActions = "s3:*"

	// AllS3TablesActions - all Amazon S3 Tables actions
	AllS3TablesActions = "s3tables:*"
)

// List of all supported actions.
var supportedActions = map[Action]struct{}{
	AbortMultipartUploadAction:                           {},
	CreateBucketAction:                                   {},
	DeleteBucketAction:                                   {},
	ForceDeleteBucketAction:                              {},
	DeleteBucketPolicyAction:                             {},
	DeleteBucketCorsAction:                               {},
	DeleteObjectAction:                                   {},
	GetBucketLocationAction:                              {},
	GetBucketNotificationAction:                          {},
	GetBucketPolicyAction:                                {},
	GetBucketCorsAction:                                  {},
	GetObjectAction:                                      {},
	HeadBucketAction:                                     {},
	ListAllMyBucketsAction:                               {},
	ListBucketAction:                                     {},
	GetBucketPolicyStatusAction:                          {},
	ListBucketVersionsAction:                             {},
	ListBucketMultipartUploadsAction:                     {},
	ListenNotificationAction:                             {},
	ListenBucketNotificationAction:                       {},
	ListMultipartUploadPartsAction:                       {},
	PutBucketLifecycleAction:                             {},
	GetBucketLifecycleAction:                             {},
	PutBucketNotificationAction:                          {},
	PutBucketPolicyAction:                                {},
	PutBucketCorsAction:                                  {},
	PutBucketQOSAction:                                   {},
	GetBucketQOSAction:                                   {},
	PutObjectAction:                                      {},
	BypassGovernanceRetentionAction:                      {},
	PutObjectRetentionAction:                             {},
	GetObjectRetentionAction:                             {},
	GetObjectLegalHoldAction:                             {},
	PutObjectLegalHoldAction:                             {},
	GetBucketObjectLockConfigurationAction:               {},
	PutBucketObjectLockConfigurationAction:               {},
	GetBucketTaggingAction:                               {},
	PutBucketTaggingAction:                               {},
	GetObjectVersionAction:                               {},
	GetObjectAttributesAction:                            {},
	GetObjectVersionAttributesAction:                     {},
	GetObjectVersionTaggingAction:                        {},
	DeleteObjectVersionAction:                            {},
	DeleteObjectVersionTaggingAction:                     {},
	PutObjectVersionTaggingAction:                        {},
	GetObjectTaggingAction:                               {},
	PutObjectTaggingAction:                               {},
	DeleteObjectTaggingAction:                            {},
	PutBucketEncryptionAction:                            {},
	GetBucketEncryptionAction:                            {},
	PutBucketVersioningAction:                            {},
	GetBucketVersioningAction:                            {},
	GetReplicationConfigurationAction:                    {},
	PutReplicationConfigurationAction:                    {},
	ReplicateObjectAction:                                {},
	ReplicateDeleteAction:                                {},
	ReplicateTagsAction:                                  {},
	GetObjectVersionForReplicationAction:                 {},
	RestoreObjectAction:                                  {},
	ResetBucketReplicationStateAction:                    {},
	PutObjectFanOutAction:                                {},
	CreateSessionAction:                                  {},
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
	S3TablesRenameTableAction:                            {},
	S3TablesUpdateTableMetadataLocationAction:            {},
	S3TablesCreateWarehouseAction:                        {},
	S3TablesListWarehousesAction:                         {},
	S3TablesCommitMultiTableTransactionAction:            {},
	S3TablesGetConfigAction:                              {},
	S3TablesTableMetricsAction:                           {},
	S3TablesUpdateTableAction:                            {},
	AllActions:                                           {},
	AllS3TablesActions:                                   {},
}

// List of all supported object actions.
var supportedObjectActions = map[Action]struct{}{
	AllActions:                           {},
	AbortMultipartUploadAction:           {},
	DeleteObjectAction:                   {},
	GetObjectAction:                      {},
	ListMultipartUploadPartsAction:       {},
	PutObjectAction:                      {},
	BypassGovernanceRetentionAction:      {},
	PutObjectRetentionAction:             {},
	GetObjectRetentionAction:             {},
	PutObjectLegalHoldAction:             {},
	GetObjectLegalHoldAction:             {},
	GetObjectTaggingAction:               {},
	PutObjectTaggingAction:               {},
	DeleteObjectTaggingAction:            {},
	GetObjectVersionAction:               {},
	GetObjectVersionTaggingAction:        {},
	DeleteObjectVersionAction:            {},
	DeleteObjectVersionTaggingAction:     {},
	PutObjectVersionTaggingAction:        {},
	ReplicateObjectAction:                {},
	ReplicateDeleteAction:                {},
	ReplicateTagsAction:                  {},
	GetObjectVersionForReplicationAction: {},
	RestoreObjectAction:                  {},
	ResetBucketReplicationStateAction:    {},
	PutObjectFanOutAction:                {},
	GetObjectAttributesAction:            {},
	GetObjectVersionAttributesAction:     {},
}

// IsObjectAction - returns whether action is object type or not.
func (action Action) IsObjectAction() bool {
	for supAction := range supportedObjectActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

// Match - matches action name with action patter.
func (action Action) Match(a Action) bool {
	return wildcard.Match(string(action), string(a))
}

// IsValid - checks if action is valid or not.
func (action Action) IsValid() bool {
	for supAction := range supportedActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

// ActionConditionKeyMap is alias for the map type used here.
type ActionConditionKeyMap map[Action]condition.KeySet

// Lookup - looks up the action in the condition key map.
func (a ActionConditionKeyMap) Lookup(action Action) condition.KeySet {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	ckeysMerged := condition.NewKeySet(commonKeys...)
	for act, ckey := range a {
		if action.Match(act) {
			ckeysMerged.Merge(ckey)
		}
	}
	return ckeysMerged
}

// IAMActionConditionKeyMap - holds mapping of supported condition key for an action.
var IAMActionConditionKeyMap = createActionConditionKeyMap()

func createActionConditionKeyMap() ActionConditionKeyMap {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	allSupportedKeys := []condition.Key{}
	for _, keyName := range condition.AllSupportedKeys {
		allSupportedKeys = append(allSupportedKeys, keyName.ToKey())
	}

	s3TablesNamespaceKey := condition.S3TablesNamespace.ToKey()
	s3TablesTableNameKey := condition.S3TablesTableName.ToKey()
	s3TablesKMSKeyKey := condition.S3TablesKMSKeyArn.ToKey()
	s3TablesSSEAlgorithmKey := condition.S3TablesSSEAlgorithm.ToKey()

	withCommon := func(keys ...condition.Key) condition.KeySet {
		merged := append([]condition.Key{}, commonKeys...)
		merged = append(merged, keys...)
		return condition.NewKeySet(merged...)
	}

	return ActionConditionKeyMap{
		AllActions: condition.NewKeySet(allSupportedKeys...),

		AbortMultipartUploadAction: condition.NewKeySet(commonKeys...),

		CreateBucketAction: condition.NewKeySet(commonKeys...),

		DeleteObjectAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
			}, commonKeys...)...),

		GetBucketLocationAction: condition.NewKeySet(commonKeys...),

		GetBucketPolicyStatusAction: condition.NewKeySet(commonKeys...),

		GetObjectAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3XAmzServerSideEncryption.ToKey(),
				condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
				condition.S3XAmzServerSideEncryptionAwsKmsKeyID.ToKey(),
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),

		HeadBucketAction: condition.NewKeySet(commonKeys...),

		GetObjectAttributesAction: condition.NewKeySet(
			append([]condition.Key{
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),

		GetObjectVersionAttributesAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),

		ListAllMyBucketsAction: condition.NewKeySet(commonKeys...),

		ListBucketAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3Prefix.ToKey(),
				condition.S3Delimiter.ToKey(),
				condition.S3MaxKeys.ToKey(),
			}, commonKeys...)...),

		ListBucketVersionsAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3Prefix.ToKey(),
				condition.S3Delimiter.ToKey(),
				condition.S3MaxKeys.ToKey(),
			}, commonKeys...)...),

		ListBucketMultipartUploadsAction: condition.NewKeySet(commonKeys...),

		ListenNotificationAction: condition.NewKeySet(commonKeys...),

		ListenBucketNotificationAction: condition.NewKeySet(commonKeys...),

		ListMultipartUploadPartsAction: condition.NewKeySet(commonKeys...),

		PutObjectAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3XAmzCopySource.ToKey(),
				condition.S3XAmzServerSideEncryption.ToKey(),
				condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
				condition.S3XAmzServerSideEncryptionAwsKmsKeyID.ToKey(),
				condition.S3XAmzMetadataDirective.ToKey(),
				condition.S3XAmzStorageClass.ToKey(),
				condition.S3VersionID.ToKey(),
				condition.S3ObjectLockRetainUntilDate.ToKey(),
				condition.S3ObjectLockMode.ToKey(),
				condition.S3ObjectLockLegalHold.ToKey(),
				condition.RequestObjectTagKeys.ToKey(),
				condition.RequestObjectTag.ToKey(),
			}, commonKeys...)...),

		// https://docs.aws.amazon.com/AmazonS3/latest/dev/list_amazons3.html
		// LockLegalHold is not supported with PutObjectRetentionAction
		PutObjectRetentionAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3XAmzServerSideEncryption.ToKey(),
				condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
				condition.S3XAmzServerSideEncryptionAwsKmsKeyID.ToKey(),
				condition.S3ObjectLockRemainingRetentionDays.ToKey(),
				condition.S3ObjectLockRetainUntilDate.ToKey(),
				condition.S3ObjectLockMode.ToKey(),
				condition.S3VersionID.ToKey(),
			}, commonKeys...)...),

		GetObjectRetentionAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3XAmzServerSideEncryption.ToKey(),
				condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
				condition.S3XAmzServerSideEncryptionAwsKmsKeyID.ToKey(),
				condition.S3VersionID.ToKey(),
			}, commonKeys...)...),

		PutObjectLegalHoldAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3XAmzServerSideEncryption.ToKey(),
				condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
				condition.S3XAmzServerSideEncryptionAwsKmsKeyID.ToKey(),
				condition.S3ObjectLockLegalHold.ToKey(),
				condition.S3VersionID.ToKey(),
			}, commonKeys...)...),
		GetObjectLegalHoldAction: condition.NewKeySet(commonKeys...),

		// https://docs.aws.amazon.com/AmazonS3/latest/dev/list_amazons3.html
		BypassGovernanceRetentionAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.S3ObjectLockRemainingRetentionDays.ToKey(),
				condition.S3ObjectLockRetainUntilDate.ToKey(),
				condition.S3ObjectLockMode.ToKey(),
				condition.S3ObjectLockLegalHold.ToKey(),
				condition.RequestObjectTagKeys.ToKey(),
				condition.RequestObjectTag.ToKey(),
			}, commonKeys...)...),

		GetBucketObjectLockConfigurationAction: condition.NewKeySet(commonKeys...),
		PutBucketObjectLockConfigurationAction: condition.NewKeySet(commonKeys...),
		GetBucketTaggingAction:                 condition.NewKeySet(commonKeys...),
		PutBucketTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.RequestObjectTagKeys.ToKey(),
				condition.RequestObjectTag.ToKey(),
			}, commonKeys...)...),
		PutObjectTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
				condition.RequestObjectTagKeys.ToKey(),
				condition.RequestObjectTag.ToKey(),
			}, commonKeys...)...),
		GetObjectTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		DeleteObjectTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),

		PutObjectVersionTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
				condition.RequestObjectTagKeys.ToKey(),
				condition.RequestObjectTag.ToKey(),
			}, commonKeys...)...),
		GetObjectVersionAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		GetObjectVersionTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		DeleteObjectVersionAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
			}, commonKeys...)...),
		DeleteObjectVersionTaggingAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		GetReplicationConfigurationAction: condition.NewKeySet(commonKeys...),
		PutReplicationConfigurationAction: condition.NewKeySet(commonKeys...),
		ReplicateObjectAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		ReplicateDeleteAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		ReplicateTagsAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		GetObjectVersionForReplicationAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		RestoreObjectAction:               condition.NewKeySet(commonKeys...),
		ResetBucketReplicationStateAction: condition.NewKeySet(commonKeys...),
		PutObjectFanOutAction:             condition.NewKeySet(commonKeys...),

		// S3 Tables actions
		AllS3TablesActions: withCommon(
			s3TablesNamespaceKey,
			s3TablesTableNameKey,
			s3TablesKMSKeyKey,
			s3TablesSSEAlgorithmKey,
		),
		S3TablesCreateNamespaceAction:                        withCommon(),
		S3TablesCreateTableAction:                            withCommon(s3TablesNamespaceKey, s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey),
		S3TablesCreateTableBucketAction:                      withCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey),
		S3TablesDeleteNamespaceAction:                        withCommon(s3TablesNamespaceKey),
		S3TablesDeleteTableAction:                            withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesDeleteTableBucketAction:                      withCommon(),
		S3TablesDeleteTableBucketEncryptionAction:            withCommon(),
		S3TablesDeleteTableBucketPolicyAction:                withCommon(),
		S3TablesDeleteTablePolicyAction:                      withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetNamespaceAction:                           withCommon(s3TablesNamespaceKey),
		S3TablesGetTableAction:                               withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetTableBucketAction:                         withCommon(),
		S3TablesGetTableBucketEncryptionAction:               withCommon(),
		S3TablesGetTableBucketMaintenanceConfigurationAction: withCommon(),
		S3TablesGetTableBucketPolicyAction:                   withCommon(),
		S3TablesGetTableDataAction:                           withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetTableEncryptionAction:                     withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetTableMaintenanceConfigurationAction:       withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetTableMaintenanceJobStatusAction:           withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetTableMetadataLocationAction:               withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetTablePolicyAction:                         withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesListNamespacesAction:                         withCommon(),
		S3TablesListTableBucketsAction:                       withCommon(),
		S3TablesListTablesAction:                             withCommon(s3TablesNamespaceKey),
		S3TablesPutTableBucketEncryptionAction:               withCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey),
		S3TablesPutTableBucketMaintenanceConfigurationAction: withCommon(),
		S3TablesPutTableBucketPolicyAction:                   withCommon(),
		S3TablesPutTableDataAction:                           withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesPutTableEncryptionAction:                     withCommon(s3TablesNamespaceKey, s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey),
		S3TablesPutTableMaintenanceConfigurationAction:       withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesPutTablePolicyAction:                         withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesRenameTableAction:                            withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesUpdateTableMetadataLocationAction:            withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesCreateWarehouseAction:                        withCommon(s3TablesKMSKeyKey, s3TablesSSEAlgorithmKey),
		S3TablesListWarehousesAction:                         withCommon(),
		S3TablesCommitMultiTableTransactionAction:            withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesGetConfigAction:                              withCommon(),
		S3TablesTableMetricsAction:                           withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
		S3TablesUpdateTableAction:                            withCommon(s3TablesNamespaceKey, s3TablesTableNameKey),
	}
}
