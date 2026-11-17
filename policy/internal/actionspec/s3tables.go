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

func warehouseKeys(extra ...*Key) []*Key {
	return append([]*Key{S3TablesWarehouseTag}, extra...)
}

func tableKeys(extra ...*Key) []*Key {
	return warehouseKeys(append([]*Key{S3TablesNamespace, S3TablesTableName, S3TablesTableTag}, extra...)...)
}

func viewKeys(extra ...*Key) []*Key {
	return warehouseKeys(append([]*Key{S3TablesNamespace, S3TablesViewName}, extra...)...)
}

func functionKeys(extra ...*Key) []*Key {
	return warehouseKeys(append([]*Key{S3TablesNamespace, S3TablesFunctionName}, extra...)...)
}

// S3Tables is the s3tables action namespace.
var S3Tables = &Namespace{
	Prefix:       "s3tables",
	Title:        "S3 Tables",
	Desc:         "Iceberg table warehouses, namespaces, tables, views and functions.",
	GoNameFormat: "S3Tables%sAction",
	BaseKeys:     CommonKeys,
	Actions: []Action{
		{
			Name:     "CreateNamespace",
			Category: CategoryManage,
			Desc:     "maps to the AWS `CreateNamespace` S3 Tables action.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "CreateTable",
			Category: CategoryManage,
			Desc:     "maps to the AWS `CreateTable` S3 Tables action.",
			Keys:     warehouseKeys(AWSRequestTag, AWSTagKeys, S3TablesKMSKeyArn, S3TablesNamespace, S3TablesSSEAlgorithm, S3TablesTableName),
		},
		{
			Name:     "DeleteNamespace",
			Category: CategoryManage,
			Desc:     "maps to the AWS `DeleteNamespace` S3 Tables action.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "DeleteTable",
			Category: CategoryManage,
			Desc:     "maps to the AWS `DeleteTable` S3 Tables action.",
			Keys:     tableKeys(),
			// Spark's DROP TABLE ... PURGE deletes the table's files from the
			// client instead of passing purgeRequested=true to the catalog, so
			// dropping a table needs s3:DeleteObject until Spark/Iceberg fix it:
			// https://github.com/apache/iceberg/issues/14743
			// https://github.com/apache/iceberg/issues/11023
			Implies: []string{"s3:DeleteObject"},
		},
		{
			Name:     "DeleteTableEncryption",
			Category: CategoryConfigure,
			Desc:     "is an AIStor extension for deleting a\ntable-level encryption configuration override.",
			Keys:     tableKeys(),
		},
		{
			Name:     "DeleteTablePolicy",
			Category: CategoryPermissions,
			Desc:     "maps to the AWS `DeleteTablePolicy` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetNamespace",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetNamespace` S3 Tables action.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "GetTable",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetTable` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetTableData",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetTableData` S3 Tables action.",
			Keys:     tableKeys(),
			Implies:  []string{"s3:GetObject", "s3:ListMultipartUploadParts"},
		},
		{
			Name:     "GetTableEncryption",
			Category: CategoryViewSettings,
			Desc:     "maps to the AWS `GetTableEncryption` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetTableMaintenanceConfiguration",
			Category: CategoryViewSettings,
			Desc:     "maps to the AWS `GetTableMaintenanceConfiguration` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetTableMaintenanceJobStatus",
			Category: CategoryViewSettings,
			Desc:     "maps to the AWS `GetTableMaintenanceJobStatus` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetTableMetadataLocation",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetTableMetadataLocation` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetTablePolicy",
			Category: CategoryViewSettings,
			Desc:     "maps to the AWS `GetTablePolicy` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "ListNamespaces",
			Category: CategoryList,
			Desc:     "maps to the AWS `ListNamespaces` S3 Tables action.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "ListTables",
			Category: CategoryList,
			Desc:     "maps to the AWS `ListTables` S3 Tables action.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "PutTableData",
			Category: CategoryWrite,
			Desc:     "maps to the AWS `PutTableData` S3 Tables action.",
			Keys:     tableKeys(),
			Implies:  []string{"s3:AbortMultipartUpload", "s3:ListBucket", "s3:PutObject"},
		},
		{
			Name:     "PutTableEncryption",
			Category: CategoryConfigure,
			Desc:     "maps to the AWS `PutTableEncryption` S3 Tables action.",
			Keys:     tableKeys(S3TablesKMSKeyArn, S3TablesSSEAlgorithm),
		},
		{
			Name:     "PutTableMaintenanceConfiguration",
			Category: CategoryConfigure,
			Desc:     "maps to the AWS `PutTableMaintenanceConfiguration` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "PutTablePolicy",
			Category: CategoryPermissions,
			Desc:     "maps to the AWS `PutTablePolicy` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "RegisterTable",
			Category: CategoryManage,
			Desc:     "maps to the AWS `RegisterTable` S3 Tables action.",
			Keys:     tableKeys(S3TablesRegisterLocation),
		},
		{
			Name:     "RenameTable",
			Category: CategoryManage,
			Desc:     "maps to the AWS `RenameTable` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "UpdateTableMetadataLocation",
			Category: CategoryWrite,
			Desc:     "maps to the AWS `UpdateTableMetadataLocation` S3 Tables action.",
			Keys:     tableKeys(),
		},
		{
			Name:     "CreateWarehouse",
			Category: CategoryCreateDelete,
			Desc:     "is an AIStor extension for Iceberg warehouse provisioning.",
			Aliases:  []string{"CreateTableBucket"},
			Keys:     []*Key{S3TablesKMSKeyArn, S3TablesSSEAlgorithm},
		},
		{
			Name:     "DeleteWarehouse",
			Category: CategoryCreateDelete,
			Desc:     "is an AIStor extension for deleting Iceberg warehouses.",
			Aliases:  []string{"DeleteTableBucket"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "DeleteWarehouseEncryption",
			Category: CategoryConfigure,
			Desc:     "is an AIStor extension for deleting warehouse encryption configuration.",
			Aliases:  []string{"DeleteTableBucketEncryption"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "DeleteWarehousePolicy",
			Category: CategoryPermissions,
			Desc:     "is an AIStor extension for deleting warehouse policies.",
			Aliases:  []string{"DeleteTableBucketPolicy"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "GetWarehouse",
			Category: CategoryRead,
			Desc:     "is an AIStor extension for retrieving warehouse details.",
			Aliases:  []string{"GetTableBucket"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "GetWarehouseEncryption",
			Category: CategoryViewSettings,
			Desc:     "is an AIStor extension for retrieving warehouse encryption configuration.",
			Aliases:  []string{"GetTableBucketEncryption"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "GetWarehouseMaintenanceConfiguration",
			Category: CategoryViewSettings,
			Desc:     "is an AIStor extension for retrieving warehouse maintenance configuration.",
			Aliases:  []string{"GetTableBucketMaintenanceConfiguration"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "GetWarehousePolicy",
			Category: CategoryViewSettings,
			Desc:     "is an AIStor extension for retrieving warehouse policies.",
			Aliases:  []string{"GetTableBucketPolicy"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "ListWarehouses",
			Category: CategoryList,
			Desc:     "is an AIStor extension for listing Iceberg warehouses.",
			Aliases:  []string{"ListTableBuckets"},
		},
		{
			Name:     "PutWarehouseEncryption",
			Category: CategoryConfigure,
			Desc:     "is an AIStor extension for setting warehouse encryption configuration.",
			Aliases:  []string{"PutTableBucketEncryption"},
			Keys:     warehouseKeys(S3TablesKMSKeyArn, S3TablesSSEAlgorithm),
		},
		{
			Name:     "PutWarehouseMaintenanceConfiguration",
			Category: CategoryConfigure,
			Desc:     "is an AIStor extension for setting warehouse maintenance configuration.",
			Aliases:  []string{"PutTableBucketMaintenanceConfiguration"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "PutWarehousePolicy",
			Category: CategoryPermissions,
			Desc:     "is an AIStor extension for setting warehouse policies.",
			Aliases:  []string{"PutTableBucketPolicy"},
			Keys:     warehouseKeys(),
		},
		{
			Name:     "GetConfig",
			Category: CategoryRead,
			Desc:     "is an AIStor extension for retrieving catalog configuration.",
			Keys:     warehouseKeys(),
		},
		{
			Name:     "TableMetrics",
			Category: CategoryViewSettings,
			Desc:     "is an AIStor extension exposing table metrics.",
			Keys:     tableKeys(),
		},
		{
			Name:     "UpdateTable",
			Category: CategoryWrite,
			Desc:     "is an AIStor extension for Iceberg-compatible table updates.",
			Keys:     tableKeys(),
		},
		{
			Name:     "CreateView",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for creating Iceberg views.",
			Keys:     viewKeys(),
		},
		{
			Name:     "DeleteView",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for deleting Iceberg views.",
			Keys:     viewKeys(),
		},
		{
			Name:     "GetView",
			Category: CategoryRead,
			Desc:     "is an AIStor extension for retrieving Iceberg views.",
			Keys:     viewKeys(),
		},
		{
			Name:     "RenameView",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for renaming Iceberg views.",
			Keys:     viewKeys(),
		},
		{
			Name:     "UpdateView",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for updating Iceberg views.",
			Keys:     viewKeys(),
		},
		{
			Name:     "ListViews",
			Category: CategoryList,
			Desc:     "is an AIStor extension for listing Iceberg views.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "RegisterView",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for registering Iceberg views.",
			Keys:     viewKeys(S3TablesRegisterLocation),
		},
		{
			Name:     "CreateFunction",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for creating Iceberg functions (SQL UDFs).",
			Keys:     functionKeys(),
		},
		{
			Name:     "DeleteFunction",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for deleting Iceberg functions (SQL UDFs).",
			Keys:     functionKeys(),
		},
		{
			Name:     "GetFunction",
			Category: CategoryRead,
			Desc:     "is an AIStor extension for retrieving Iceberg functions (SQL UDFs).",
			Keys:     functionKeys(),
		},
		{
			Name:     "RenameFunction",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for renaming Iceberg functions (SQL UDFs).",
			Keys:     functionKeys(),
		},
		{
			Name:     "UpdateFunction",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for updating Iceberg functions (SQL UDFs).",
			Keys:     functionKeys(),
		},
		{
			Name:     "ListFunctions",
			Category: CategoryList,
			Desc:     "is an AIStor extension for listing Iceberg functions (SQL UDFs).",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "RegisterFunction",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for registering Iceberg functions (SQL UDFs).",
			Keys:     functionKeys(S3TablesRegisterLocation),
		},
		{
			Name:     "UpdateNamespaceProperties",
			Category: CategoryManage,
			Desc:     "is an AIStor extension for updating namespace properties.",
			Keys:     warehouseKeys(S3TablesNamespace),
		},
		{
			Name:     "TagWarehouse",
			Category: CategoryConfigure,
			Desc:     "is an AIStor extension for tagging Iceberg warehouses.",
			Keys:     warehouseKeys(AWSRequestTag, AWSTagKeys),
		},
		{
			Name:     "UntagWarehouse",
			Category: CategoryConfigure,
			Desc:     "is an AIStor extension for removing tags from Iceberg warehouses.",
			Keys:     warehouseKeys(AWSTagKeys),
		},
		{
			Name:     "ListTagsForWarehouse",
			Category: CategoryViewSettings,
			Desc:     "is an AIStor extension for listing tags on Iceberg warehouses.",
			Keys:     warehouseKeys(),
		},
		{
			Name:     "TagTable",
			Category: CategoryWrite,
			Desc:     "is an AIStor extension for tagging tables.",
			Keys:     tableKeys(AWSRequestTag, AWSTagKeys),
		},
		{
			Name:     "UntagTable",
			Category: CategoryWrite,
			Desc:     "is an AIStor extension for removing tags from tables.",
			Keys:     tableKeys(AWSTagKeys),
		},
		{
			Name:     "ListTagsForTable",
			Category: CategoryRead,
			Desc:     "is an AIStor extension for listing tags on tables.",
			Keys:     tableKeys(),
		},
		{
			Name:     "PutTableAnnotation",
			Category: CategoryWrite,
			Desc:     "is an AIStor extension for attaching a\nnamed annotation payload to a table.",
			Keys:     tableKeys(),
		},
		{
			Name:     "GetTableAnnotation",
			Category: CategoryRead,
			Desc:     "is an AIStor extension for reading one of a\ntable's annotations.",
			Keys:     tableKeys(),
		},
		{
			Name:     "ListTableAnnotations",
			Category: CategoryList,
			Desc:     "is an AIStor extension for listing a\ntable's annotations.",
			Keys:     tableKeys(),
		},
		{
			Name:     "DeleteTableAnnotation",
			Category: CategoryWrite,
			Desc:     "is an AIStor extension for removing one\nof a table's annotations.",
			Keys:     tableKeys(),
		},
		{
			Name:    "*",
			GoName:  "AllS3TablesActions",
			Desc:    "All Amazon S3 Tables actions",
			Keys:    []*Key{S3TablesNamespace, S3TablesTableName, S3TablesViewName, S3TablesFunctionName, S3TablesKMSKeyArn, S3TablesSSEAlgorithm, S3TablesRegisterLocation, S3TablesWarehouseTag, S3TablesTableTag},
			Implies: []string{"s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:ListBucket", "s3:ListMultipartUploadParts", "s3:PutObject"},
		},
	},
}
