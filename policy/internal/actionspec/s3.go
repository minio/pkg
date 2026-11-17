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

// S3 is the s3 action namespace.
var S3 = &Namespace{
	Prefix:       "s3",
	Title:        "S3",
	Desc:         "Object storage buckets and objects.",
	GoNameFormat: "%sAction",
	BaseKeys:     CommonKeys,
	Resource:     ResourceBucket,
	Actions: []Action{
		{
			Name:     "AbortMultipartUpload",
			Category: CategoryWrite,
			Desc:     "AbortMultipartUpload Rest API action.",
			Resource: ResourceObject,
		},
		{
			Name:     "CreateBucket",
			Category: CategoryCreateDelete,
			Desc:     "CreateBucket Rest API action.",
		},
		{
			Name:     "DeleteBucket",
			Category: CategoryCreateDelete,
			Desc:     "DeleteBucket Rest API action.",
		},
		{
			Name:     "ForceDeleteBucket",
			Category: CategoryCreateDelete,
			Desc:     "DeleteBucket Rest API action when x-minio-force-delete flag\nis specified.",
		},
		{
			Name:     "DeleteBucketPolicy",
			Category: CategoryPermissions,
			Desc:     "DeleteBucketPolicy Rest API action.",
		},
		{
			Name:     "DeleteBucketCors",
			Category: CategoryConfigure,
			Desc:     "DeleteBucketCors Rest API action.",
		},
		{
			Name:     "DeleteObject",
			Category: CategoryWrite,
			Desc:     "DeleteObject Rest API action.",
			Keys:     []*Key{S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetBucketLocation",
			Category: CategoryRead,
			Desc:     "GetBucketLocation Rest API action.",
		},
		{
			Name:     "GetBucketNotification",
			Category: CategoryViewSettings,
			Desc:     "GetBucketNotification Rest API action.",
		},
		{
			Name:     "GetBucketPolicy",
			Category: CategoryViewSettings,
			Desc:     "GetBucketPolicy Rest API action.",
		},
		{
			Name:     "GetBucketCors",
			Category: CategoryViewSettings,
			Desc:     "GetBucketCors Rest API action.",
		},
		{
			Name:     "GetObject",
			Category: CategoryRead,
			Desc:     "GetObject Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectAttributes",
			Category: CategoryRead,
			Desc:     "GetObjectVersionAttributes Rest API action.",
			Keys:     []*Key{ExistingObjectTag},
			Resource: ResourceObject,
		},
		{
			Name:     "HeadBucket",
			Category: CategoryRead,
			Desc:     "HeadBucket Rest API action. This action is unused in minio.",
		},
		{
			Name:     "ListAllMyBuckets",
			Category: CategoryList,
			Desc:     "ListAllMyBuckets (List buckets) Rest API action.",
		},
		{
			Name:     "ListBucket",
			Category: CategoryList,
			Desc:     "ListBucket Rest API action.",
			Keys:     []*Key{S3Delimiter, S3MaxKeys, S3Prefix},
		},
		{
			Name:     "GetBucketPolicyStatus",
			Category: CategoryViewSettings,
			Desc:     "Retrieves the policy status for a bucket.",
		},
		{
			Name:     "ListBucketVersions",
			Category: CategoryList,
			Desc:     "ListBucketVersions Rest API action.",
			Keys:     []*Key{S3Delimiter, S3MaxKeys, S3Prefix},
		},
		{
			Name:     "ListBucketMultipartUploads",
			Category: CategoryList,
			Desc:     "ListMultipartUploads Rest API action.",
		},
		{
			Name:     "ListenNotification",
			Category: CategoryViewSettings,
			Desc:     "ListenNotification Rest API action.\nThis is an AIStor extension.",
		},
		{
			Name:     "ListenBucketNotification",
			Category: CategoryViewSettings,
			Desc:     "ListenBucketNotification Rest API action.\nThis is an AIStor extension.",
		},
		{
			Name:     "ListMultipartUploadParts",
			Category: CategoryList,
			Desc:     "ListParts Rest API action.",
			Resource: ResourceObject,
		},
		{
			Name:     "PutLifecycleConfiguration",
			Category: CategoryConfigure,
			GoName:   "PutBucketLifecycleAction",
			Desc:     "PutBucketLifecycle Rest API action.",
		},
		{
			Name:     "GetLifecycleConfiguration",
			Category: CategoryViewSettings,
			GoName:   "GetBucketLifecycleAction",
			Desc:     "GetBucketLifecycle Rest API action.",
		},
		{
			Name:     "PutBucketNotification",
			Category: CategoryConfigure,
			Desc:     "PutObjectNotification Rest API action.",
		},
		{
			Name:     "PutBucketPolicy",
			Category: CategoryPermissions,
			Desc:     "PutBucketPolicy Rest API action.",
		},
		{
			Name:     "PutBucketCors",
			Category: CategoryConfigure,
			Desc:     "PutBucketCors Rest API action.",
		},
		{
			Name:     "PutBucketQOS",
			Category: CategoryConfigure,
			Desc:     "Allow set QOS configuration",
		},
		{
			Name:     "GetBucketQOS",
			Category: CategoryViewSettings,
			Desc:     "Allow get QOS configuration",
		},
		{
			Name:     "PutObject",
			Category: CategoryWrite,
			Desc:     "PutObject Rest API action.",
			Keys:     []*Key{RequestObjectTag, RequestObjectTagKeys, S3ObjectLockLegalHold, S3ObjectLockMode, S3ObjectLockRetainUntilDate, S3VersionID, S3XAmzAnnotationDirective, S3XAmzCopySource, S3XAmzMetadataDirective, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm, S3XAmzStorageClass},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectVersion",
			Category: CategoryWrite,
			Desc:     "DeleteObjectVersion Rest API action.",
			Keys:     []*Key{S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectVersionTagging",
			Category: CategoryWrite,
			Desc:     "DeleteObjectVersionTagging Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersion",
			Category: CategoryRead,
			Desc:     "GetObjectVersionAction Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Implies:  []string{"s3:GetObject"},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionAttributes",
			Category: CategoryRead,
			Desc:     "GetObjectVersionAttributes Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionTagging",
			Category: CategoryRead,
			Desc:     "GetObjectVersionTagging Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectVersionTagging",
			Category: CategoryWrite,
			Desc:     "PutObjectVersionTagging Rest API action.",
			Keys:     []*Key{ExistingObjectTag, RequestObjectTag, RequestObjectTagKeys, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "BypassGovernanceRetention",
			Category: CategoryProtection,
			Desc:     "Bypass governance retention for PutObjectRetention, PutObject and DeleteObject Rest API action.",
			Keys:     []*Key{RequestObjectTag, RequestObjectTagKeys, S3ObjectLockLegalHold, S3ObjectLockMode, S3ObjectLockRemainingRetentionDays, S3ObjectLockRetainUntilDate, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectRetention",
			Category: CategoryProtection,
			Desc:     "PutObjectRetention Rest API action.",
			// LockLegalHold is not supported with PutObjectRetention:
			// https://docs.aws.amazon.com/AmazonS3/latest/dev/list_amazons3.html
			Keys:     []*Key{S3ObjectLockMode, S3ObjectLockRemainingRetentionDays, S3ObjectLockRetainUntilDate, S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectRetention",
			Category: CategoryRead,
			Desc:     "GetObjectRetention, GetObject, HeadObject Rest API action.",
			Keys:     []*Key{S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectLegalHold",
			Category: CategoryRead,
			Desc:     "GetObjectLegalHold, GetObject Rest API action.",
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectLegalHold",
			Category: CategoryProtection,
			Desc:     "PutObjectLegalHold, PutObject Rest API action.",
			Keys:     []*Key{S3ObjectLockLegalHold, S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetBucketObjectLockConfiguration",
			Category: CategoryViewSettings,
			Desc:     "GetBucketObjectLockConfiguration Rest API action",
		},
		{
			Name:     "PutBucketObjectLockConfiguration",
			Category: CategoryProtection,
			Desc:     "PutBucketObjectLockConfiguration Rest API action",
		},
		{
			Name:     "GetBucketTagging",
			Category: CategoryViewSettings,
			Desc:     "GetBucketTagging Rest API action",
		},
		{
			Name:     "PutBucketTagging",
			Category: CategoryConfigure,
			Desc:     "PutBucketTagging Rest API action",
			Keys:     []*Key{AWSRequestTag, AWSTagKeys, RequestObjectTag, RequestObjectTagKeys},
		},
		{
			Name:     "GetObjectTagging",
			Category: CategoryRead,
			Desc:     "Get Object Tags API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectTagging",
			Category: CategoryWrite,
			Desc:     "Put Object Tags API action",
			Keys:     []*Key{ExistingObjectTag, RequestObjectTag, RequestObjectTagKeys, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectTagging",
			Category: CategoryWrite,
			Desc:     "Delete Object Tags API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectAnnotation",
			Category: CategoryWrite,
			Desc:     "PutObjectAnnotation API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID, S3XAmzObjectIfMatch},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectAnnotation",
			Category: CategoryRead,
			Desc:     "GetObjectAnnotation API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectAnnotation",
			Category: CategoryWrite,
			Desc:     "DeleteObjectAnnotation API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID, S3XAmzObjectIfMatch},
			Resource: ResourceObject,
		},
		{
			Name:     "ListObjectAnnotations",
			Category: CategoryList,
			Desc:     "ListObjectAnnotations API action",
			Keys:     []*Key{S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "UpdateObjectEncryption",
			Category: CategoryConfigure,
			Desc:     "UpdateObjectEncryption REST API action",
			Keys:     []*Key{S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "PutEncryptionConfiguration",
			Category: CategoryConfigure,
			GoName:   "PutBucketEncryptionAction",
			Desc:     "PutBucketEncryption REST API action",
		},
		{
			Name:     "GetEncryptionConfiguration",
			Category: CategoryViewSettings,
			GoName:   "GetBucketEncryptionAction",
			Desc:     "GetBucketEncryption REST API action",
		},
		{
			Name:     "PutBucketVersioning",
			Category: CategoryConfigure,
			Desc:     "PutBucketVersioning REST API action",
		},
		{
			Name:     "GetBucketVersioning",
			Category: CategoryViewSettings,
			Desc:     "GetBucketVersioning REST API action",
		},
		{
			Name:     "GetReplicationConfiguration",
			Category: CategoryViewSettings,
			Desc:     "GetReplicationConfiguration REST API action",
		},
		{
			Name:     "PutReplicationConfiguration",
			Category: CategoryConfigure,
			Desc:     "PutReplicationConfiguration REST API action",
		},
		{
			Name:     "ReplicateObject",
			Category: CategoryReplication,
			Desc:     "ReplicateObject REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "ReplicateDelete",
			Category: CategoryReplication,
			Desc:     "ReplicateDelete REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "ReplicateTags",
			Category: CategoryReplication,
			Desc:     "ReplicateTags REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionForReplication",
			Category: CategoryReplication,
			Desc:     "GetObjectVersionForReplication REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "ReplicateObjectAnnotation",
			Category: CategoryReplication,
			Desc:     "ReplicateObjectAnnotation REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionAnnotationForReplication",
			Category: CategoryReplication,
			Desc:     "GetObjectVersionAnnotationForReplication REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "RestoreObject",
			Category: CategoryWrite,
			Desc:     "RestoreObject REST API action",
			Resource: ResourceObject,
		},
		{
			Name:     "ResetBucketReplicationState",
			Category: CategoryConfigure,
			Desc:     "AIStor extension API ResetBucketReplicationState to reset replication state\non a bucket",
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectFanOut",
			Category: CategoryWrite,
			Desc:     "PutObject like API action but allows PostUpload() fan-out.",
			Resource: ResourceObject,
		},
		// Inventory configuration actions
		{
			Name:     "PutInventoryConfiguration",
			Category: CategoryConfigure,
			Desc:     "Bucket inventory write operations actions",
		},
		{
			Name:     "GetInventoryConfiguration",
			Category: CategoryViewSettings,
			Desc:     "Bucket inventory read operations actions",
		},
		{
			Name:     "*",
			GoName:   "AllActions",
			Desc:     "All API actions",
			Keys:     AllNonAdminKeys(),
			Resource: ResourceBucketOrObject,
		},
	},
}
