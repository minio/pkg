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

import "strings"

// S3SignatureVersion is the s3:signatureversion condition key.
var S3SignatureVersion = &Key{
	GoName: "S3SignatureVersion",
	Name:   "s3:signatureversion",
	Desc:   "Identifies the version of AWS Signature that you want to support for authenticated requests.",
}

// S3AuthType is the s3:authType condition key.
var S3AuthType = &Key{
	GoName: "S3AuthType",
	Name:   "s3:authType",
	Desc:   "Optionally use this condition key to restrict incoming requests to use a specific authentication method.",
}

// S3SignatureAge is the s3:signatureAge condition key.
var S3SignatureAge = &Key{
	GoName: "S3SignatureAge",
	Name:   "s3:signatureAge",
	Desc:   "Identifies the maximum age of presgiend URL allowed",
}

// S3XAmzCopySource is the s3:x-amz-copy-source condition key.
var S3XAmzCopySource = &Key{
	GoName: "S3XAmzCopySource",
	Name:   "s3:x-amz-copy-source",
	Desc:   "Key representing x-amz-copy-source HTTP header applicable to PutObject API only.",
}

// S3XAmzServerSideEncryption is the s3:x-amz-server-side-encryption condition key.
var S3XAmzServerSideEncryption = &Key{
	GoName: "S3XAmzServerSideEncryption",
	Name:   "s3:x-amz-server-side-encryption",
	Desc:   "Key representing x-amz-server-side-encryption HTTP header applicable\nto PutObject API only.",
}

// S3XAmzServerSideEncryptionCustomerAlgorithm is the s3:x-amz-server-side-encryption-customer-algorithm condition key.
var S3XAmzServerSideEncryptionCustomerAlgorithm = &Key{
	GoName: "S3XAmzServerSideEncryptionCustomerAlgorithm",
	Name:   "s3:x-amz-server-side-encryption-customer-algorithm",
	Desc:   "Key representing\nx-amz-server-side-encryption-customer-algorithm HTTP header applicable to PutObject API only.",
}

// S3XAmzMetadataDirective is the s3:x-amz-metadata-directive condition key.
var S3XAmzMetadataDirective = &Key{
	GoName: "S3XAmzMetadataDirective",
	Name:   "s3:x-amz-metadata-directive",
	Desc:   "Key representing x-amz-metadata-directive HTTP header applicable to\nPutObject API only.",
}

// S3XAmzStorageClass is the s3:x-amz-storage-class condition key.
var S3XAmzStorageClass = &Key{
	GoName: "S3XAmzStorageClass",
	Name:   "s3:x-amz-storage-class",
	Desc:   "Key representing x-amz-storage-class HTTP header applicable to PutObject API\nonly.",
}

// S3XAmzServerSideEncryptionAwsKmsKeyID is the s3:x-amz-server-side-encryption-aws-kms-key-id condition key.
var S3XAmzServerSideEncryptionAwsKmsKeyID = &Key{
	GoName: "S3XAmzServerSideEncryptionAwsKmsKeyID",
	Name:   "s3:x-amz-server-side-encryption-aws-kms-key-id",
	Desc:   "Key representing x-amz-server-side-encryption-aws-kms-key-id\nHTTP header for S3 API calls",
}

// S3XAmzObjectIfMatch is the s3:x-amz-object-if-match condition key.
var S3XAmzObjectIfMatch = &Key{
	GoName: "S3XAmzObjectIfMatch",
	Name:   "s3:x-amz-object-if-match",
	Desc:   "Key representing the x-amz-object-if-match HTTP header used by the\nobject annotation APIs (PutObjectAnnotation/DeleteObjectAnnotation) for optimistic concurrency.",
}

// S3XAmzAnnotationDirective is the s3:x-amz-annotation-directive condition key.
var S3XAmzAnnotationDirective = &Key{
	GoName: "S3XAmzAnnotationDirective",
	Name:   "s3:x-amz-annotation-directive",
	Desc:   "Key representing the x-amz-annotation-directive HTTP header\nof CopyObject, which controls whether annotations are copied (COPY) or excluded (EXCLUDE).",
}

// S3XAmzContentSha256 is the s3:x-amz-content-sha256 condition key.
var S3XAmzContentSha256 = &Key{
	GoName: "S3XAmzContentSha256",
	Name:   "s3:x-amz-content-sha256",
	Desc:   "Set a static content-sha256 for all calls for a given action.",
}

// S3LocationConstraint is the s3:LocationConstraint condition key.
var S3LocationConstraint = &Key{
	GoName: "S3LocationConstraint",
	Name:   "s3:LocationConstraint",
	Desc:   "Key representing LocationConstraint XML tag of CreateBucket API only.",
}

// S3Prefix is the s3:prefix condition key.
var S3Prefix = &Key{
	GoName: "S3Prefix",
	Name:   "s3:prefix",
	Desc:   "Key representing prefix query parameter of ListBucket API only.",
}

// S3Delimiter is the s3:delimiter condition key.
var S3Delimiter = &Key{
	GoName: "S3Delimiter",
	Name:   "s3:delimiter",
	Desc:   "Key representing delimiter query parameter of ListBucket API only.",
}

// S3MaxKeys is the s3:max-keys condition key.
var S3MaxKeys = &Key{
	GoName: "S3MaxKeys",
	Name:   "s3:max-keys",
	Desc:   "Key representing max-keys query parameter of ListBucket API only.",
}

// MemoryPrefix is the memory:prefix condition key.
var MemoryPrefix = &Key{
	GoName: "MemoryPrefix",
	Name:   "memory:prefix",
	Desc:   "Key representing the prefix query parameter of the AIStor\nMemory list and search APIs. It scopes enumeration within a cortex, which\na resource ARN cannot express: a list names a query, not a record, so\nputting the prefix in the resource path would make one ARN mean a single\nrecord under a read action and a set of siblings under a list action.\n\nmemory:Search takes it for the same reason and depends on it more, since\nsearch returns object content: without the key its grant has only two\nstates, none or the whole cortex.",
}

// MemoryMaxKeys is the memory:max-keys condition key.
var MemoryMaxKeys = &Key{
	GoName: "MemoryMaxKeys",
	Name:   "memory:max-keys",
	Desc:   "Key representing the limit query parameter of the AIStor\nMemory list APIs only. It caps a single page, bounding what one request\ncan enumerate.",
}

// S3VersionID is the s3:versionid condition key.
var S3VersionID = &Key{
	GoName: "S3VersionID",
	Name:   "s3:versionid",
	Desc:   "Enables you to limit the permission for the\ns3:PutObjectVersionTagging action to a specific object version.",
}

// S3ObjectLockRemainingRetentionDays is the s3:object-lock-remaining-retention-days condition key.
var S3ObjectLockRemainingRetentionDays = &Key{
	GoName: "S3ObjectLockRemainingRetentionDays",
	Name:   "s3:object-lock-remaining-retention-days",
	Desc:   "Key representing object-lock-remaining-retention-days\nEnables enforcement of an object relative to the remaining retention days, you can set\nminimum and maximum allowable retention periods for a bucket using a bucket policy.\nThis key are specific for s3:PutObjectRetention API.",
}

// S3ObjectLockMode is the s3:object-lock-mode condition key.
var S3ObjectLockMode = &Key{
	GoName: "S3ObjectLockMode",
	Name:   "s3:object-lock-mode",
	Desc:   "Key representing object-lock-mode\nEnables enforcement of the specified object retention mode",
}

// S3ObjectLockLegalHold is the s3:object-lock-legal-hold condition key.
var S3ObjectLockLegalHold = &Key{
	GoName: "S3ObjectLockLegalHold",
	Name:   "s3:object-lock-legal-hold",
	Desc:   "Key representing object-local-legal-hold\nEnables enforcement of the specified object legal hold status",
}

// S3ObjectLockRetainUntilDate is the s3:object-lock-retain-until-date condition key.
var S3ObjectLockRetainUntilDate = &Key{
	GoName: "S3ObjectLockRetainUntilDate",
	Name:   "s3:object-lock-retain-until-date",
	Desc:   "Key representing object-lock-retain-util-date\nEnables enforcement of a specific retain-until-date",
}

// S3TablesKMSKeyArn is the s3tables:KMSKeyArn condition key.
var S3TablesKMSKeyArn = &Key{
	GoName: "S3TablesKMSKeyArn",
	Name:   "s3tables:KMSKeyArn",
	Desc:   "filters access by the AWS KMS key ARN used for S3 Tables encryption.",
}

// S3TablesSSEAlgorithm is the s3tables:SSEAlgorithm condition key.
var S3TablesSSEAlgorithm = &Key{
	GoName: "S3TablesSSEAlgorithm",
	Name:   "s3tables:SSEAlgorithm",
	Desc:   "filters access by the server-side encryption algorithm for S3 Tables.",
}

// S3TablesNamespace is the s3tables:namespace condition key.
var S3TablesNamespace = &Key{
	GoName: "S3TablesNamespace",
	Name:   "s3tables:namespace",
	Desc:   "filters access by the namespace within an S3 Tables bucket.",
}

// S3TablesTableName is the s3tables:tableName condition key.
var S3TablesTableName = &Key{
	GoName: "S3TablesTableName",
	Name:   "s3tables:tableName",
	Desc:   "filters access by the S3 Tables table name within a namespace.",
}

// S3TablesViewName is the s3tables:viewName condition key.
var S3TablesViewName = &Key{
	GoName: "S3TablesViewName",
	Name:   "s3tables:viewName",
	Desc:   "filters access by the S3 Tables view name within a namespace.",
}

// S3TablesFunctionName is the s3tables:functionName condition key.
var S3TablesFunctionName = &Key{
	GoName: "S3TablesFunctionName",
	Name:   "s3tables:functionName",
	Desc:   "filters access by the S3 Tables function name within a namespace.",
}

// S3TablesRegisterLocation is the s3tables:registerLocation condition key.
var S3TablesRegisterLocation = &Key{
	GoName: "S3TablesRegisterLocation",
	Name:   "s3tables:registerLocation",
	Desc:   "filters access by the metadata location for table/view registration.",
}

// S3TablesWarehouseTag is the s3tables:WarehouseTag condition key.
var S3TablesWarehouseTag = &Key{
	GoName:   "S3TablesWarehouseTag",
	Name:     "s3tables:WarehouseTag",
	Desc:     "filters access by tags on the table warehouse.",
	Variable: true,
}

// S3TablesTableTag is the s3tables:TableTag condition key.
var S3TablesTableTag = &Key{
	GoName:   "S3TablesTableTag",
	Name:     "s3tables:TableTag",
	Desc:     "filters access by tags on the table.",
	Variable: true,
}

// AWSReferer is the aws:Referer condition key.
var AWSReferer = &Key{
	GoName: "AWSReferer",
	Name:   "aws:Referer",
	Desc:   "Key representing Referer header of any API.",
}

// AWSSourceIP is the aws:SourceIp condition key.
var AWSSourceIP = &Key{
	GoName: "AWSSourceIP",
	Name:   "aws:SourceIp",
	Desc:   "Key representing client's IP address (not intermittent proxies) of any API.",
}

// AWSUserAgent is the aws:UserAgent condition key.
var AWSUserAgent = &Key{
	GoName: "AWSUserAgent",
	Name:   "aws:UserAgent",
	Desc:   "Key representing UserAgent header for any API.",
}

// AWSSecureTransport is the aws:SecureTransport condition key.
var AWSSecureTransport = &Key{
	GoName: "AWSSecureTransport",
	Name:   "aws:SecureTransport",
	Desc:   "Key representing if the clients request is authenticated or not.",
}

// AWSCurrentTime is the aws:CurrentTime condition key.
var AWSCurrentTime = &Key{
	GoName: "AWSCurrentTime",
	Name:   "aws:CurrentTime",
	Desc:   "Key representing the current time.",
}

// AWSEpochTime is the aws:EpochTime condition key.
var AWSEpochTime = &Key{
	GoName: "AWSEpochTime",
	Name:   "aws:EpochTime",
	Desc:   "Key representing the current epoch time.",
}

// AWSPrincipalType is the aws:principaltype condition key.
var AWSPrincipalType = &Key{
	GoName: "AWSPrincipalType",
	Name:   "aws:principaltype",
	Desc:   "User principal type currently supported values are \"User\" and \"Anonymous\".",
}

// AWSUserID is the aws:userid condition key.
var AWSUserID = &Key{
	GoName: "AWSUserID",
	Name:   "aws:userid",
	Desc:   "User unique ID, in MinIO this value is same as your user Access Key.",
}

// AWSUsername is the aws:username condition key.
var AWSUsername = &Key{
	GoName: "AWSUsername",
	Name:   "aws:username",
	Desc:   "User friendly name, in MinIO this value is same as your user Access Key.",
}

// AWSGroups is the aws:groups condition key.
var AWSGroups = &Key{
	GoName: "AWSGroups",
	Name:   "aws:groups",
	Desc:   "Groups for any authenticating Access Key.",
}

// AWSSourceIdentity is the aws:SourceIdentity condition key.
var AWSSourceIdentity = &Key{
	GoName: "AWSSourceIdentity",
	Name:   "aws:SourceIdentity",
	Desc:   "The source identity of the session that signed the\nrequest, set when the session was assumed and fixed for its lifetime.",
}

// AWSRequestTag is the aws:RequestTag condition key.
var AWSRequestTag = &Key{
	GoName:   "AWSRequestTag",
	Name:     "aws:RequestTag",
	Desc:     "filters a tagging request by the value it sets for one\ntag key, as in aws:RequestTag/<key>.",
	Variable: true,
}

// AWSTagKeys is the aws:TagKeys condition key.
var AWSTagKeys = &Key{
	GoName: "AWSTagKeys",
	Name:   "aws:TagKeys",
	Desc:   "filters a tagging request by the tag keys it sets or removes.",
}

// AWSResourceTag is the aws:ResourceTag condition key.
var AWSResourceTag = &Key{
	GoName:   "AWSResourceTag",
	Name:     "aws:ResourceTag",
	Desc:     "filters access by the value of one tag on the bucket the\nrequest acts on, or holds the object it acts on, as in\naws:ResourceTag/<key>.",
	Variable: true,
}

// S3BucketTag is the s3:BucketTag condition key.
var S3BucketTag = &Key{
	GoName:   "S3BucketTag",
	Name:     "s3:BucketTag",
	Desc:     "filters access by the value of one tag on the bucket the\nrequest is authorized against, as in s3:BucketTag/<key>.",
	Variable: true,
}

// LDAPUser is the ldap:user condition key.
var LDAPUser = &Key{
	GoName: "LDAPUser",
	Name:   "ldap:user",
	Desc:   "LDAP username, in MinIO this value is equal to your authenticating LDAP user DN.",
}

// LDAPUsername is the ldap:username condition key.
var LDAPUsername = &Key{
	GoName: "LDAPUsername",
	Name:   "ldap:username",
	Desc:   "LDAP username, in MinIO is the authenticated simple user.",
}

// LDAPGroups is the ldap:groups condition key.
var LDAPGroups = &Key{
	GoName: "LDAPGroups",
	Name:   "ldap:groups",
	Desc:   "LDAP groups, in MinIO this value is equal LDAP Group DNs for the authenticating user.",
}

// RequestObjectTag is the s3:RequestObjectTag condition key.
var RequestObjectTag = &Key{
	GoName:   "RequestObjectTag",
	Name:     "s3:RequestObjectTag",
	Variable: true,
}

// ExistingObjectTag is the s3:ExistingObjectTag condition key.
var ExistingObjectTag = &Key{
	GoName:   "ExistingObjectTag",
	Name:     "s3:ExistingObjectTag",
	Desc:     "Refer https://docs.aws.amazon.com/AmazonS3/latest/userguide/tagging-and-policies.html",
	Variable: true,
}

// RequestObjectTagKeys is the s3:RequestObjectTagKeys condition key.
var RequestObjectTagKeys = &Key{
	GoName: "RequestObjectTagKeys",
	Name:   "s3:RequestObjectTagKeys",
}

// JWTSub is the jwt:sub condition key.
var JWTSub = &Key{
	GoName: "JWTSub",
	Name:   "jwt:sub",
	Desc:   "JWT subject claim substitution.",
}

// JWTIss is the jwt:iss condition key.
var JWTIss = &Key{
	GoName: "JWTIss",
	Name:   "jwt:iss",
	Desc:   "issuer claim substitution.",
}

// JWTAud is the jwt:aud condition key.
var JWTAud = &Key{
	GoName: "JWTAud",
	Name:   "jwt:aud",
	Desc:   "audience claim substitution.",
}

// JWTJti is the jwt:jti condition key.
var JWTJti = &Key{
	GoName: "JWTJti",
	Name:   "jwt:jti",
	Desc:   "JWT unique identifier claim substitution.",
}

// JWTName is the jwt:name condition key.
var JWTName = &Key{
	GoName: "JWTName",
	Name:   "jwt:name",
}

// JWTUpn is the jwt:upn condition key.
var JWTUpn = &Key{
	GoName: "JWTUpn",
	Name:   "jwt:upn",
}

// JWTGroups is the jwt:groups condition key.
var JWTGroups = &Key{
	GoName: "JWTGroups",
	Name:   "jwt:groups",
}

// JWTGivenName is the jwt:given_name condition key.
var JWTGivenName = &Key{
	GoName: "JWTGivenName",
	Name:   "jwt:given_name",
}

// JWTFamilyName is the jwt:family_name condition key.
var JWTFamilyName = &Key{
	GoName: "JWTFamilyName",
	Name:   "jwt:family_name",
}

// JWTMiddleName is the jwt:middle_name condition key.
var JWTMiddleName = &Key{
	GoName: "JWTMiddleName",
	Name:   "jwt:middle_name",
}

// JWTNickName is the jwt:nickname condition key.
var JWTNickName = &Key{
	GoName: "JWTNickName",
	Name:   "jwt:nickname",
}

// JWTPrefUsername is the jwt:preferred_username condition key.
var JWTPrefUsername = &Key{
	GoName: "JWTPrefUsername",
	Name:   "jwt:preferred_username",
}

// JWTProfile is the jwt:profile condition key.
var JWTProfile = &Key{
	GoName: "JWTProfile",
	Name:   "jwt:profile",
}

// JWTPicture is the jwt:picture condition key.
var JWTPicture = &Key{
	GoName: "JWTPicture",
	Name:   "jwt:picture",
}

// JWTWebsite is the jwt:website condition key.
var JWTWebsite = &Key{
	GoName: "JWTWebsite",
	Name:   "jwt:website",
}

// JWTEmail is the jwt:email condition key.
var JWTEmail = &Key{
	GoName: "JWTEmail",
	Name:   "jwt:email",
}

// JWTGender is the jwt:gender condition key.
var JWTGender = &Key{
	GoName: "JWTGender",
	Name:   "jwt:gender",
}

// JWTBirthdate is the jwt:birthdate condition key.
var JWTBirthdate = &Key{
	GoName: "JWTBirthdate",
	Name:   "jwt:birthdate",
}

// JWTPhoneNumber is the jwt:phone_number condition key.
var JWTPhoneNumber = &Key{
	GoName: "JWTPhoneNumber",
	Name:   "jwt:phone_number",
}

// JWTAddress is the jwt:address condition key.
var JWTAddress = &Key{
	GoName: "JWTAddress",
	Name:   "jwt:address",
}

// JWTScope is the jwt:scope condition key.
var JWTScope = &Key{
	GoName: "JWTScope",
	Name:   "jwt:scope",
}

// JWTClientID is the jwt:client_id condition key.
var JWTClientID = &Key{
	GoName: "JWTClientID",
	Name:   "jwt:client_id",
}

// STSDurationSeconds is the sts:DurationSeconds condition key.
var STSDurationSeconds = &Key{
	GoName: "STSDurationSeconds",
	Name:   "sts:DurationSeconds",
	Desc:   "Duration seconds condition for STS policy",
}

// STSSourceIdentity is the sts:SourceIdentity condition key.
var STSSourceIdentity = &Key{
	GoName:    "STSSourceIdentity",
	Name:      "sts:SourceIdentity",
	Desc:      "The source identity the session being assumed will\ncarry: the one requested, or the one inherited from the caller's session.",
	Untrimmed: true,
}

// SVCDurationSeconds is the svc:DurationSeconds condition key.
var SVCDurationSeconds = &Key{
	GoName: "SVCDurationSeconds",
	Name:   "svc:DurationSeconds",
	Desc:   "Duration seconds condition for Admin policy",
}

// AdminPolicyName is the admin:PolicyName condition key.
var AdminPolicyName = &Key{
	GoName: "AdminPolicyName",
	Name:   "admin:PolicyName",
	Desc:   "The name of the policy a policy admin action\n(admin:CreatePolicy, admin:DeletePolicy, admin:GetPolicy) works on, so a\nstatement can grant those actions on a set of policies, for example\nStringLike {\"admin:PolicyName\": [\"app-*\"]}.",
}

// S3ExpressSessionMode is the s3express:SessionMode condition key.
var S3ExpressSessionMode = &Key{
	GoName:   "S3ExpressSessionMode",
	Name:     "s3express:SessionMode",
	Desc:     "Optionally use this condition key to control who can create a ReadWrite or ReadOnly session.",
	Unlisted: true,
}

// Keys lists every condition key in declaration order, which is the order of
// AllSupportedKeys.
var Keys = []*Key{
	S3SignatureVersion, S3AuthType, S3SignatureAge, S3XAmzCopySource,
	S3XAmzServerSideEncryption, S3XAmzServerSideEncryptionCustomerAlgorithm,
	S3XAmzMetadataDirective, S3XAmzStorageClass,
	S3XAmzServerSideEncryptionAwsKmsKeyID, S3XAmzObjectIfMatch,
	S3XAmzAnnotationDirective, S3XAmzContentSha256, S3LocationConstraint,
	S3Prefix, S3Delimiter, S3MaxKeys, MemoryPrefix, MemoryMaxKeys, S3VersionID,
	S3ObjectLockRemainingRetentionDays, S3ObjectLockMode, S3ObjectLockLegalHold,
	S3ObjectLockRetainUntilDate, S3TablesKMSKeyArn, S3TablesSSEAlgorithm,
	S3TablesNamespace, S3TablesTableName, S3TablesViewName, S3TablesFunctionName,
	S3TablesRegisterLocation, S3TablesWarehouseTag, S3TablesTableTag, AWSReferer,
	AWSSourceIP, AWSUserAgent, AWSSecureTransport, AWSCurrentTime, AWSEpochTime,
	AWSPrincipalType, AWSUserID, AWSUsername, AWSGroups, AWSSourceIdentity,
	AWSRequestTag, AWSTagKeys, AWSResourceTag, S3BucketTag, LDAPUser,
	LDAPUsername, LDAPGroups, RequestObjectTag, ExistingObjectTag,
	RequestObjectTagKeys, JWTSub, JWTIss, JWTAud, JWTJti, JWTName, JWTUpn,
	JWTGroups, JWTGivenName, JWTFamilyName, JWTMiddleName, JWTNickName,
	JWTPrefUsername, JWTProfile, JWTPicture, JWTWebsite, JWTEmail, JWTGender,
	JWTBirthdate, JWTPhoneNumber, JWTAddress, JWTScope, JWTClientID,
	STSDurationSeconds, STSSourceIdentity, SVCDurationSeconds, AdminPolicyName,
	S3ExpressSessionMode,
}

// KeyPrefixes are the service prefixes of condition keys. A prefix missing
// from here keeps its whole name and reads a value nothing populates.
var KeyPrefixes = []KeyPrefix{
	{Name: "aws", Trim: true},
	{Name: "jwt", Trim: true},
	{Name: "ldap", Trim: true},
	{Name: "sts", Trim: true},
	{Name: "svc", Trim: true},
	{Name: "s3", Trim: true},
	{Name: "s3tables", Trim: true},
	{Name: "memory", Trim: true},
	// The server sets the values of the admin keys itself, so a policy may use
	// them on admin actions only, and no request header supplies them.
	{Name: "admin", Trim: true},
	{Name: "s3express"},
}

// JWTKeys are the JWT claims a policy may test; the list grows as claims are
// standardized.
var JWTKeys = []*Key{
	JWTSub, JWTIss, JWTAud, JWTJti, JWTName, JWTUpn, JWTGroups, JWTGivenName,
	JWTFamilyName, JWTMiddleName, JWTNickName, JWTPrefUsername, JWTProfile,
	JWTPicture, JWTWebsite, JWTEmail, JWTGender, JWTBirthdate, JWTPhoneNumber,
	JWTAddress, JWTScope, JWTClientID,
}

// CommonKeys are the condition keys every action outside admin and STS takes.
var CommonKeys = append([]*Key{
	S3SignatureVersion,
	S3AuthType,
	S3SignatureAge,
	S3XAmzContentSha256,
	S3LocationConstraint,
	S3ExpressSessionMode,
	AWSReferer,
	AWSSourceIP,
	AWSUserAgent,
	AWSSecureTransport,
	AWSCurrentTime,
	AWSEpochTime,
	AWSPrincipalType,
	AWSUserID,
	AWSUsername,
	AWSGroups,
	AWSSourceIdentity,
	LDAPUser,
	LDAPUsername,
	LDAPGroups,
}, JWTKeys...)

// CommonAdminKeys are the condition keys every admin action takes: they
// describe the request and its principal, not what the action works on.
var CommonAdminKeys = append([]*Key{
	AWSReferer,
	AWSSourceIP,
	AWSUserAgent,
	AWSSecureTransport,
	AWSCurrentTime,
	AWSEpochTime,
	AWSPrincipalType,
	AWSUserID,
	AWSUsername,
	AWSGroups,
	AWSSourceIdentity,
	LDAPUser,
	LDAPUsername,
	LDAPGroups,
	SVCDurationSeconds,
}, JWTKeys...)

// AdminActionKeys are the condition keys that describe what one kind of admin
// action works on, such as the policy it names.
var AdminActionKeys = []*Key{
	AdminPolicyName,
}

// AllSupportedSTSKeys are the condition keys every STS action takes.
var AllSupportedSTSKeys = []*Key{
	AWSPrincipalType,
	AWSSecureTransport,
	STSDurationSeconds,
	STSSourceIdentity,
	AWSSourceIdentity,
	LDAPUser,
	AWSUserID,
	AWSGroups,
	LDAPGroups,
	LDAPUsername,
	AWSUsername,
}

// AllNonAdminKeys returns every listed key outside the admin prefix: an S3
// request never carries an admin key.
func AllNonAdminKeys() []*Key {
	var keys []*Key
	for _, k := range Keys {
		if !k.Unlisted && !strings.HasPrefix(k.Name, "admin:") {
			keys = append(keys, k)
		}
	}
	return keys
}
