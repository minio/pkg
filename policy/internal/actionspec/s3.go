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
	GoNameFormat: "%sAction",
	BaseKeys:     CommonKeys,
	Resource:     ResourceBucket,
	Actions: []Action{
		{
			Name:     "AbortMultipartUpload",
			Desc:     "AbortMultipartUpload Rest API action.",
			Resource: ResourceObject,
		},
		{
			Name: "CreateBucket",
			Desc: "CreateBucket Rest API action.",
		},
		{
			Name: "DeleteBucket",
			Desc: "DeleteBucket Rest API action.",
		},
		{
			Name: "ForceDeleteBucket",
			Desc: "DeleteBucket Rest API action when x-minio-force-delete flag\nis specified.",
		},
		{
			Name: "DeleteBucketPolicy",
			Desc: "DeleteBucketPolicy Rest API action.",
		},
		{
			Name: "DeleteBucketCors",
			Desc: "DeleteBucketCors Rest API action.",
		},
		{
			Name:     "DeleteObject",
			Desc:     "DeleteObject Rest API action.",
			Keys:     []*Key{S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name: "GetBucketLocation",
			Desc: "GetBucketLocation Rest API action.",
		},
		{
			Name: "GetBucketNotification",
			Desc: "GetBucketNotification Rest API action.",
		},
		{
			Name: "GetBucketPolicy",
			Desc: "GetBucketPolicy Rest API action.",
		},
		{
			Name: "GetBucketCors",
			Desc: "GetBucketCors Rest API action.",
		},
		{
			Name:     "GetObject",
			Desc:     "GetObject Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectAttributes",
			Desc:     "GetObjectVersionAttributes Rest API action.",
			Keys:     []*Key{ExistingObjectTag},
			Resource: ResourceObject,
		},
		{
			Name: "HeadBucket",
			Desc: "HeadBucket Rest API action. This action is unused in minio.",
		},
		{
			Name: "ListAllMyBuckets",
			Desc: "ListAllMyBuckets (List buckets) Rest API action.",
		},
		{
			Name: "ListBucket",
			Desc: "ListBucket Rest API action.",
			Keys: []*Key{S3Delimiter, S3MaxKeys, S3Prefix},
		},
		{
			Name: "GetBucketPolicyStatus",
			Desc: "Retrieves the policy status for a bucket.",
		},
		{
			Name: "ListBucketVersions",
			Desc: "ListBucketVersions Rest API action.",
			Keys: []*Key{S3Delimiter, S3MaxKeys, S3Prefix},
		},
		{
			Name: "ListBucketMultipartUploads",
			Desc: "ListMultipartUploads Rest API action.",
		},
		{
			Name: "ListenNotification",
			Desc: "ListenNotification Rest API action.\nThis is an AIStor extension.",
		},
		{
			Name: "ListenBucketNotification",
			Desc: "ListenBucketNotification Rest API action.\nThis is an AIStor extension.",
		},
		{
			Name:     "ListMultipartUploadParts",
			Desc:     "ListParts Rest API action.",
			Resource: ResourceObject,
		},
		{
			Name:   "PutLifecycleConfiguration",
			GoName: "PutBucketLifecycleAction",
			Desc:   "PutBucketLifecycle Rest API action.",
		},
		{
			Name:   "GetLifecycleConfiguration",
			GoName: "GetBucketLifecycleAction",
			Desc:   "GetBucketLifecycle Rest API action.",
		},
		{
			Name: "PutBucketNotification",
			Desc: "PutObjectNotification Rest API action.",
		},
		{
			Name: "PutBucketPolicy",
			Desc: "PutBucketPolicy Rest API action.",
		},
		{
			Name: "PutBucketCors",
			Desc: "PutBucketCors Rest API action.",
		},
		{
			Name: "PutBucketQOS",
			Desc: "Allow set QOS configuration",
		},
		{
			Name: "GetBucketQOS",
			Desc: "Allow get QOS configuration",
		},
		{
			Name:     "PutObject",
			Desc:     "PutObject Rest API action.",
			Keys:     []*Key{RequestObjectTag, RequestObjectTagKeys, S3ObjectLockLegalHold, S3ObjectLockMode, S3ObjectLockRetainUntilDate, S3VersionID, S3XAmzAnnotationDirective, S3XAmzCopySource, S3XAmzMetadataDirective, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm, S3XAmzStorageClass},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectVersion",
			Desc:     "DeleteObjectVersion Rest API action.",
			Keys:     []*Key{S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectVersionTagging",
			Desc:     "DeleteObjectVersionTagging Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersion",
			Desc:     "GetObjectVersionAction Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Implies:  []string{"s3:GetObject"},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionAttributes",
			Desc:     "GetObjectVersionAttributes Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionTagging",
			Desc:     "GetObjectVersionTagging Rest API action.",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectVersionTagging",
			Desc:     "PutObjectVersionTagging Rest API action.",
			Keys:     []*Key{ExistingObjectTag, RequestObjectTag, RequestObjectTagKeys, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "BypassGovernanceRetention",
			Desc:     "Bypass governance retention for PutObjectRetention, PutObject and DeleteObject Rest API action.",
			Keys:     []*Key{RequestObjectTag, RequestObjectTagKeys, S3ObjectLockLegalHold, S3ObjectLockMode, S3ObjectLockRemainingRetentionDays, S3ObjectLockRetainUntilDate, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name: "PutObjectRetention",
			Desc: "PutObjectRetention Rest API action.",
			// LockLegalHold is not supported with PutObjectRetention:
			// https://docs.aws.amazon.com/AmazonS3/latest/dev/list_amazons3.html
			Keys:     []*Key{S3ObjectLockMode, S3ObjectLockRemainingRetentionDays, S3ObjectLockRetainUntilDate, S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectRetention",
			Desc:     "GetObjectRetention, GetObject, HeadObject Rest API action.",
			Keys:     []*Key{S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectLegalHold",
			Desc:     "GetObjectLegalHold, GetObject Rest API action.",
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectLegalHold",
			Desc:     "PutObjectLegalHold, PutObject Rest API action.",
			Keys:     []*Key{S3ObjectLockLegalHold, S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name: "GetBucketObjectLockConfiguration",
			Desc: "GetBucketObjectLockConfiguration Rest API action",
		},
		{
			Name: "PutBucketObjectLockConfiguration",
			Desc: "PutBucketObjectLockConfiguration Rest API action",
		},
		{
			Name: "GetBucketTagging",
			Desc: "GetBucketTagging Rest API action",
		},
		{
			Name: "PutBucketTagging",
			Desc: "PutBucketTagging Rest API action",
			Keys: []*Key{AWSRequestTag, AWSTagKeys, RequestObjectTag, RequestObjectTagKeys},
		},
		{
			Name:     "GetObjectTagging",
			Desc:     "Get Object Tags API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectTagging",
			Desc:     "Put Object Tags API action",
			Keys:     []*Key{ExistingObjectTag, RequestObjectTag, RequestObjectTagKeys, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectTagging",
			Desc:     "Delete Object Tags API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectAnnotation",
			Desc:     "PutObjectAnnotation API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID, S3XAmzObjectIfMatch},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectAnnotation",
			Desc:     "GetObjectAnnotation API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "DeleteObjectAnnotation",
			Desc:     "DeleteObjectAnnotation API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID, S3XAmzObjectIfMatch},
			Resource: ResourceObject,
		},
		{
			Name:     "ListObjectAnnotations",
			Desc:     "ListObjectAnnotations API action",
			Keys:     []*Key{S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "UpdateObjectEncryption",
			Desc:     "UpdateObjectEncryption REST API action",
			Keys:     []*Key{S3VersionID, S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzServerSideEncryptionCustomerAlgorithm},
			Resource: ResourceObject,
		},
		{
			Name:   "PutEncryptionConfiguration",
			GoName: "PutBucketEncryptionAction",
			Desc:   "PutBucketEncryption REST API action",
		},
		{
			Name:   "GetEncryptionConfiguration",
			GoName: "GetBucketEncryptionAction",
			Desc:   "GetBucketEncryption REST API action",
		},
		{
			Name: "PutBucketVersioning",
			Desc: "PutBucketVersioning REST API action",
		},
		{
			Name: "GetBucketVersioning",
			Desc: "GetBucketVersioning REST API action",
		},
		{
			Name: "GetReplicationConfiguration",
			Desc: "GetReplicationConfiguration REST API action",
		},
		{
			Name: "PutReplicationConfiguration",
			Desc: "PutReplicationConfiguration REST API action",
		},
		{
			Name:     "ReplicateObject",
			Desc:     "ReplicateObject REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "ReplicateDelete",
			Desc:     "ReplicateDelete REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "ReplicateTags",
			Desc:     "ReplicateTags REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionForReplication",
			Desc:     "GetObjectVersionForReplication REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "ReplicateObjectAnnotation",
			Desc:     "ReplicateObjectAnnotation REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "GetObjectVersionAnnotationForReplication",
			Desc:     "GetObjectVersionAnnotationForReplication REST API action",
			Keys:     []*Key{ExistingObjectTag, S3VersionID},
			Resource: ResourceObject,
		},
		{
			Name:     "RestoreObject",
			Desc:     "RestoreObject REST API action",
			Resource: ResourceObject,
		},
		{
			Name:     "ResetBucketReplicationState",
			Desc:     "AIStor extension API ResetBucketReplicationState to reset replication state\non a bucket",
			Resource: ResourceObject,
		},
		{
			Name:     "PutObjectFanOut",
			Desc:     "PutObject like API action but allows PostUpload() fan-out.",
			Resource: ResourceObject,
		},
		// Inventory configuration actions
		{
			Name: "PutInventoryConfiguration",
			Desc: "Bucket inventory write operations actions",
		},
		{
			Name: "GetInventoryConfiguration",
			Desc: "Bucket inventory read operations actions",
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
