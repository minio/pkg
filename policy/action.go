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
	CreateBucketAction Action = "s3:CreateBucket"

	// DeleteBucketAction - DeleteBucket Rest API action.
	DeleteBucketAction Action = "s3:DeleteBucket"

	// ForceDeleteBucketAction - DeleteBucket Rest API action when x-minio-force-delete flag
	// is specified.
	ForceDeleteBucketAction Action = "s3:ForceDeleteBucket"

	// DeleteBucketPolicyAction - DeleteBucketPolicy Rest API action.
	DeleteBucketPolicyAction Action = "s3:DeleteBucketPolicy"

	// DeleteBucketCorsAction - DeleteBucketCors Rest API action.
	DeleteBucketCorsAction Action = "s3:DeleteBucketCors"

	// DeleteObjectAction - DeleteObject Rest API action.
	DeleteObjectAction Action = "s3:DeleteObject"

	// GetBucketLocationAction - GetBucketLocation Rest API action.
	GetBucketLocationAction Action = "s3:GetBucketLocation"

	// GetBucketNotificationAction - GetBucketNotification Rest API action.
	GetBucketNotificationAction Action = "s3:GetBucketNotification"

	// GetBucketPolicyAction - GetBucketPolicy Rest API action.
	GetBucketPolicyAction Action = "s3:GetBucketPolicy"

	// GetBucketCorsAction - GetBucketCors Rest API action.
	GetBucketCorsAction Action = "s3:GetBucketCors"

	// GetObjectAction - GetObject Rest API action.
	GetObjectAction Action = "s3:GetObject"

	// GetObjectAttributesAction - GetObjectVersionAttributes Rest API action.
	GetObjectAttributesAction Action = "s3:GetObjectAttributes"

	// HeadBucketAction - HeadBucket Rest API action. This action is unused in minio.
	HeadBucketAction Action = "s3:HeadBucket"

	// ListAllMyBucketsAction - ListAllMyBuckets (List buckets) Rest API action.
	ListAllMyBucketsAction Action = "s3:ListAllMyBuckets"

	// ListBucketAction - ListBucket Rest API action.
	ListBucketAction Action = "s3:ListBucket"

	// GetBucketPolicyStatusAction - Retrieves the policy status for a bucket.
	GetBucketPolicyStatusAction Action = "s3:GetBucketPolicyStatus"

	// ListBucketVersionsAction - ListBucketVersions Rest API action.
	ListBucketVersionsAction Action = "s3:ListBucketVersions"

	// ListBucketMultipartUploadsAction - ListMultipartUploads Rest API action.
	ListBucketMultipartUploadsAction Action = "s3:ListBucketMultipartUploads"

	// ListenNotificationAction - ListenNotification Rest API action.
	// This is MinIO extension.
	ListenNotificationAction Action = "s3:ListenNotification"

	// ListenBucketNotificationAction - ListenBucketNotification Rest API action.
	// This is MinIO extension.
	ListenBucketNotificationAction Action = "s3:ListenBucketNotification"

	// ListMultipartUploadPartsAction - ListParts Rest API action.
	ListMultipartUploadPartsAction Action = "s3:ListMultipartUploadParts"

	// PutBucketLifecycleAction - PutBucketLifecycle Rest API action.
	PutBucketLifecycleAction Action = "s3:PutLifecycleConfiguration"

	// GetBucketLifecycleAction - GetBucketLifecycle Rest API action.
	GetBucketLifecycleAction Action = "s3:GetLifecycleConfiguration"

	// PutBucketNotificationAction - PutObjectNotification Rest API action.
	PutBucketNotificationAction Action = "s3:PutBucketNotification"

	// PutBucketPolicyAction - PutBucketPolicy Rest API action.
	PutBucketPolicyAction Action = "s3:PutBucketPolicy"

	// PutBucketCorsAction - PutBucketCors Rest API action.
	PutBucketCorsAction Action = "s3:PutBucketCors"

	//  PutBucketQOSAction - allow set QOS configuration
	PutBucketQOSAction Action = "s3:PutBucketQOS"

	//  GetBucketQOSAction - allow get QOS configuration
	GetBucketQOSAction Action = "s3:GetBucketQOS"

	// PutObjectAction - PutObject Rest API action.
	PutObjectAction Action = "s3:PutObject"

	// DeleteObjectVersionAction - DeleteObjectVersion Rest API action.
	DeleteObjectVersionAction Action = "s3:DeleteObjectVersion"

	// DeleteObjectVersionTaggingAction - DeleteObjectVersionTagging Rest API action.
	DeleteObjectVersionTaggingAction Action = "s3:DeleteObjectVersionTagging"

	// GetObjectVersionAction - GetObjectVersionAction Rest API action.
	GetObjectVersionAction Action = "s3:GetObjectVersion"

	// GetObjectVersionAttributesAction - GetObjectVersionAttributes Rest API action.
	GetObjectVersionAttributesAction Action = "s3:GetObjectVersionAttributes"

	// GetObjectVersionTaggingAction - GetObjectVersionTagging Rest API action.
	GetObjectVersionTaggingAction Action = "s3:GetObjectVersionTagging"

	// PutObjectVersionTaggingAction - PutObjectVersionTagging Rest API action.
	PutObjectVersionTaggingAction Action = "s3:PutObjectVersionTagging"

	// BypassGovernanceRetentionAction - bypass governance retention for PutObjectRetention, PutObject and DeleteObject Rest API action.
	BypassGovernanceRetentionAction Action = "s3:BypassGovernanceRetention"

	// PutObjectRetentionAction - PutObjectRetention Rest API action.
	PutObjectRetentionAction Action = "s3:PutObjectRetention"

	// GetObjectRetentionAction - GetObjectRetention, GetObject, HeadObject Rest API action.
	GetObjectRetentionAction Action = "s3:GetObjectRetention"

	// GetObjectLegalHoldAction - GetObjectLegalHold, GetObject Rest API action.
	GetObjectLegalHoldAction Action = "s3:GetObjectLegalHold"

	// PutObjectLegalHoldAction - PutObjectLegalHold, PutObject Rest API action.
	PutObjectLegalHoldAction Action = "s3:PutObjectLegalHold"

	// GetBucketObjectLockConfigurationAction - GetBucketObjectLockConfiguration Rest API action
	GetBucketObjectLockConfigurationAction Action = "s3:GetBucketObjectLockConfiguration"

	// PutBucketObjectLockConfigurationAction - PutBucketObjectLockConfiguration Rest API action
	PutBucketObjectLockConfigurationAction Action = "s3:PutBucketObjectLockConfiguration"

	// GetBucketTaggingAction - GetBucketTagging Rest API action
	GetBucketTaggingAction Action = "s3:GetBucketTagging"

	// PutBucketTaggingAction - PutBucketTagging Rest API action
	PutBucketTaggingAction Action = "s3:PutBucketTagging"

	// GetObjectTaggingAction - Get Object Tags API action
	GetObjectTaggingAction Action = "s3:GetObjectTagging"

	// PutObjectTaggingAction - Put Object Tags API action
	PutObjectTaggingAction Action = "s3:PutObjectTagging"

	// DeleteObjectTaggingAction - Delete Object Tags API action
	DeleteObjectTaggingAction Action = "s3:DeleteObjectTagging"

	// PutObjectAnnotationAction - PutObjectAnnotation API action
	PutObjectAnnotationAction Action = "s3:PutObjectAnnotation"

	// GetObjectAnnotationAction - GetObjectAnnotation API action
	GetObjectAnnotationAction Action = "s3:GetObjectAnnotation"

	// DeleteObjectAnnotationAction - DeleteObjectAnnotation API action
	DeleteObjectAnnotationAction Action = "s3:DeleteObjectAnnotation"

	// ListObjectAnnotationsAction - ListObjectAnnotations API action
	ListObjectAnnotationsAction Action = "s3:ListObjectAnnotations"

	// UpdateObjectEncryptionAction - UpdateObjectEncryption REST API action
	UpdateObjectEncryptionAction Action = "s3:UpdateObjectEncryption"

	// PutBucketEncryptionAction - PutBucketEncryption REST API action
	PutBucketEncryptionAction Action = "s3:PutEncryptionConfiguration"

	// GetBucketEncryptionAction - GetBucketEncryption REST API action
	GetBucketEncryptionAction Action = "s3:GetEncryptionConfiguration"

	// PutBucketVersioningAction - PutBucketVersioning REST API action
	PutBucketVersioningAction Action = "s3:PutBucketVersioning"

	// GetBucketVersioningAction - GetBucketVersioning REST API action
	GetBucketVersioningAction Action = "s3:GetBucketVersioning"
	// GetReplicationConfigurationAction  - GetReplicationConfiguration REST API action
	GetReplicationConfigurationAction Action = "s3:GetReplicationConfiguration"
	// PutReplicationConfigurationAction  - PutReplicationConfiguration REST API action
	PutReplicationConfigurationAction Action = "s3:PutReplicationConfiguration"

	// ReplicateObjectAction  - ReplicateObject REST API action
	ReplicateObjectAction Action = "s3:ReplicateObject"

	// ReplicateDeleteAction  - ReplicateDelete REST API action
	ReplicateDeleteAction Action = "s3:ReplicateDelete"

	// ReplicateTagsAction  - ReplicateTags REST API action
	ReplicateTagsAction Action = "s3:ReplicateTags"

	// GetObjectVersionForReplicationAction  - GetObjectVersionForReplication REST API action
	GetObjectVersionForReplicationAction Action = "s3:GetObjectVersionForReplication"

	// ReplicateObjectAnnotationAction - ReplicateObjectAnnotation REST API action
	ReplicateObjectAnnotationAction Action = "s3:ReplicateObjectAnnotation"

	// GetObjectVersionAnnotationForReplicationAction - GetObjectVersionAnnotationForReplication REST API action
	GetObjectVersionAnnotationForReplicationAction Action = "s3:GetObjectVersionAnnotationForReplication"

	// RestoreObjectAction - RestoreObject REST API action
	RestoreObjectAction Action = "s3:RestoreObject"
	// ResetBucketReplicationStateAction - MinIO extension API ResetBucketReplicationState to reset replication state
	// on a bucket
	ResetBucketReplicationStateAction Action = "s3:ResetBucketReplicationState"

	// PutObjectFanOutAction - PutObject like API action but allows PostUpload() fan-out.
	PutObjectFanOutAction Action = "s3:PutObjectFanOut"

	// Inventory configuration actions

	// PutInventoryConfigurationAction - Bucket inventory write operations actions
	PutInventoryConfigurationAction Action = "s3:PutInventoryConfiguration"
	// GetInventoryConfigurationAction - Bucket inventory read operations actions
	GetInventoryConfigurationAction Action = "s3:GetInventoryConfiguration"

	// CreateSessionAction - S3Express REST API action
	CreateSessionAction Action = "s3express:CreateSession"

	// AllActions - all API actions
	AllActions Action = "s3:*"
)

// SupportedActions - list of all supported actions.
var SupportedActions = map[Action]struct{}{
	AbortMultipartUploadAction:                     {},
	CreateBucketAction:                             {},
	DeleteBucketAction:                             {},
	ForceDeleteBucketAction:                        {},
	DeleteBucketPolicyAction:                       {},
	DeleteBucketCorsAction:                         {},
	DeleteObjectAction:                             {},
	GetBucketLocationAction:                        {},
	GetBucketNotificationAction:                    {},
	GetBucketPolicyAction:                          {},
	GetBucketCorsAction:                            {},
	GetObjectAction:                                {},
	HeadBucketAction:                               {},
	ListAllMyBucketsAction:                         {},
	ListBucketAction:                               {},
	GetBucketPolicyStatusAction:                    {},
	ListBucketVersionsAction:                       {},
	ListBucketMultipartUploadsAction:               {},
	ListenNotificationAction:                       {},
	ListenBucketNotificationAction:                 {},
	ListMultipartUploadPartsAction:                 {},
	PutBucketLifecycleAction:                       {},
	GetBucketLifecycleAction:                       {},
	PutBucketNotificationAction:                    {},
	PutBucketPolicyAction:                          {},
	PutBucketCorsAction:                            {},
	PutBucketQOSAction:                             {},
	GetBucketQOSAction:                             {},
	PutObjectAction:                                {},
	BypassGovernanceRetentionAction:                {},
	PutObjectRetentionAction:                       {},
	GetObjectRetentionAction:                       {},
	GetObjectLegalHoldAction:                       {},
	PutObjectLegalHoldAction:                       {},
	GetBucketObjectLockConfigurationAction:         {},
	PutBucketObjectLockConfigurationAction:         {},
	GetBucketTaggingAction:                         {},
	PutBucketTaggingAction:                         {},
	GetObjectVersionAction:                         {},
	GetObjectAttributesAction:                      {},
	GetObjectVersionAttributesAction:               {},
	GetObjectVersionTaggingAction:                  {},
	DeleteObjectVersionAction:                      {},
	DeleteObjectVersionTaggingAction:               {},
	PutObjectVersionTaggingAction:                  {},
	GetObjectTaggingAction:                         {},
	PutObjectTaggingAction:                         {},
	DeleteObjectTaggingAction:                      {},
	PutObjectAnnotationAction:                      {},
	GetObjectAnnotationAction:                      {},
	DeleteObjectAnnotationAction:                   {},
	ListObjectAnnotationsAction:                    {},
	UpdateObjectEncryptionAction:                   {},
	PutBucketEncryptionAction:                      {},
	GetBucketEncryptionAction:                      {},
	PutBucketVersioningAction:                      {},
	GetBucketVersioningAction:                      {},
	GetReplicationConfigurationAction:              {},
	PutReplicationConfigurationAction:              {},
	ReplicateObjectAction:                          {},
	ReplicateDeleteAction:                          {},
	ReplicateTagsAction:                            {},
	GetObjectVersionForReplicationAction:           {},
	ReplicateObjectAnnotationAction:                {},
	GetObjectVersionAnnotationForReplicationAction: {},
	RestoreObjectAction:                            {},
	ResetBucketReplicationStateAction:              {},
	PutObjectFanOutAction:                          {},
	PutInventoryConfigurationAction:                {},
	GetInventoryConfigurationAction:                {},
	CreateSessionAction:                            {},
	AllActions:                                     {},
}

// SupportedObjectActions - list of all supported object actions.
var SupportedObjectActions = map[Action]struct{}{
	AllActions:                                     {},
	AbortMultipartUploadAction:                     {},
	DeleteObjectAction:                             {},
	GetObjectAction:                                {},
	ListMultipartUploadPartsAction:                 {},
	PutObjectAction:                                {},
	BypassGovernanceRetentionAction:                {},
	PutObjectRetentionAction:                       {},
	GetObjectRetentionAction:                       {},
	PutObjectLegalHoldAction:                       {},
	GetObjectLegalHoldAction:                       {},
	GetObjectTaggingAction:                         {},
	PutObjectTaggingAction:                         {},
	DeleteObjectTaggingAction:                      {},
	PutObjectAnnotationAction:                      {},
	GetObjectAnnotationAction:                      {},
	DeleteObjectAnnotationAction:                   {},
	ListObjectAnnotationsAction:                    {},
	UpdateObjectEncryptionAction:                   {},
	GetObjectVersionAction:                         {},
	GetObjectVersionTaggingAction:                  {},
	DeleteObjectVersionAction:                      {},
	DeleteObjectVersionTaggingAction:               {},
	PutObjectVersionTaggingAction:                  {},
	ReplicateObjectAction:                          {},
	ReplicateDeleteAction:                          {},
	ReplicateTagsAction:                            {},
	GetObjectVersionForReplicationAction:           {},
	ReplicateObjectAnnotationAction:                {},
	GetObjectVersionAnnotationForReplicationAction: {},
	RestoreObjectAction:                            {},
	ResetBucketReplicationStateAction:              {},
	PutObjectFanOutAction:                          {},
	GetObjectAttributesAction:                      {},
	GetObjectVersionAttributesAction:               {},
}

// IsObjectAction - returns whether action is object type or not.
func (action Action) IsObjectAction() bool {
	for supAction := range SupportedObjectActions {
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
	for supAction := range SupportedActions {
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
				condition.S3XAmzAnnotationDirective.ToKey(),
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

		PutObjectAnnotationAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
				condition.S3XAmzObjectIfMatch.ToKey(),
			}, commonKeys...)...),
		GetObjectAnnotationAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		DeleteObjectAnnotationAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
				condition.S3XAmzObjectIfMatch.ToKey(),
			}, commonKeys...)...),
		ListObjectAnnotationsAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
			}, commonKeys...)...),

		UpdateObjectEncryptionAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3XAmzServerSideEncryption.ToKey(),
				condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
				condition.S3XAmzServerSideEncryptionAwsKmsKeyID.ToKey(),
				condition.S3VersionID.ToKey(),
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
		ReplicateObjectAnnotationAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		GetObjectVersionAnnotationForReplicationAction: condition.NewKeySet(
			append([]condition.Key{
				condition.S3VersionID.ToKey(),
				condition.ExistingObjectTag.ToKey(),
			}, commonKeys...)...),
		RestoreObjectAction:               condition.NewKeySet(commonKeys...),
		ResetBucketReplicationStateAction: condition.NewKeySet(commonKeys...),
		PutObjectFanOutAction:             condition.NewKeySet(commonKeys...),
	}
}
