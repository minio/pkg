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

// KMS is the kms action namespace.
var KMS = &Namespace{
	Prefix:       "kms",
	Title:        "KMS",
	Desc:         "Key management: keys, identities and policies of the KMS.",
	GoNameFormat: "KMS%sAction",
	Actions: []Action{
		{
			Name:     "CreateKey",
			Category: CategoryCreateDelete,
			Desc:     "Allow creating a new KMS master key",
		},
		{
			Name:     "DeleteKey",
			Category: CategoryCreateDelete,
			Desc:     "Allow deleting a KMS master key",
		},
		{
			Name:     "ListKeys",
			Category: CategoryList,
			Desc:     "Allow getting list of KMS keys",
		},
		{
			Name:     "ImportKey",
			Category: CategoryCreateDelete,
			Desc:     "Allow importing KMS key",
		},
		{
			Name:     "DescribePolicy",
			Category: CategoryViewSettings,
			Desc:     "Allow getting KMS policy",
		},
		{
			Name:     "AssignPolicy",
			Category: CategoryPermissions,
			Desc:     "Allow assigning an identity to a KMS policy",
		},
		{
			Name:     "DeletePolicy",
			Category: CategoryPermissions,
			Desc:     "Allow deleting a policy",
		},
		{
			Name:     "SetPolicy",
			Category: CategoryPermissions,
			Desc:     "Allow creating or updating a policy",
		},
		{
			Name:     "GetPolicy",
			Category: CategoryViewSettings,
			Desc:     "Allow getting a policy",
		},
		{
			Name:     "ListPolicies",
			Category: CategoryList,
			Desc:     "Allow getting list of KMS policies",
		},
		{
			Name:     "DescribeIdentity",
			Category: CategoryViewSettings,
			Desc:     "Allow getting KMS identity",
		},
		{
			Name:     "DescribeSelfIdentity",
			Category: CategoryViewSettings,
			Desc:     "Allow getting self KMS identity",
		},
		{
			Name:     "DeleteIdentity",
			Category: CategoryIdentity,
			Desc:     "Allow deleting a policy",
		},
		{
			Name:     "ListIdentities",
			Category: CategoryList,
			Desc:     "Allow getting list of KMS identities",
		},
		{
			Name:     "KeyStatus",
			Category: CategoryMonitor,
			Desc:     "Allow getting KMS key status",
		},
		{
			Name:     "Status",
			Category: CategoryMonitor,
			Desc:     "Allow getting KMS status",
		},
		{
			Name:     "API",
			Category: CategoryMonitor,
			Desc:     "Allow getting a list of supported API endpoints",
		},
		{
			Name:     "Metrics",
			Category: CategoryMonitor,
			Desc:     "Allow getting server metrics in the Prometheus exposition format",
		},
		{
			Name:     "Version",
			Category: CategoryMonitor,
			Desc:     "Allow getting version information",
		},
		{
			Name:     "AuditLog",
			Category: CategoryMonitor,
			Desc:     "Subscribes to the audit log",
		},
		{
			Name:     "ErrorLog",
			Category: CategoryMonitor,
			Desc:     "Subscribes to the error log",
		},
		{
			Name:     "Enable",
			Category: CategoryOperate,
			Desc:     "Allows enabling builtin KMS",
		},
		{
			Name:     "KeyRotate",
			Category: CategoryOperate,
			Desc:     "Allows rotating KMS keys",
		},
		{
			Name:     "MigrateKeys",
			Category: CategoryOperate,
			Desc:     "Allows importing the builtin KMS keys into MinKMS. It is an AIStor extension.",
		},
		{
			Name:     "CleanupLocalKeys",
			Category: CategoryOperate,
			Desc:     "Allows deleting the builtin KMS keys after their import into MinKMS. It is an AIStor extension.",
		},
		{
			Name:   "*",
			GoName: "AllKMSActions",
			Desc:   "Provides all admin permissions",
		},
	},
}
