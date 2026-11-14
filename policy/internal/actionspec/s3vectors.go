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

// S3Vectors is the s3vectors action namespace.
var S3Vectors = &Namespace{
	Prefix:       "s3vectors",
	Title:        "S3 Vectors",
	Desc:         "Vector buckets, indexes and vectors.",
	GoNameFormat: "S3Vectors%sAction",
	BaseKeys:     CommonKeys,
	Actions: []Action{
		{
			Name:     "CreateVectorBucket",
			Category: CategoryCreateDelete,
			Desc:     "maps to the AWS `CreateVectorBucket` S3 Vectors action.",
		},
		{
			Name:     "DeleteVectorBucket",
			Category: CategoryCreateDelete,
			Desc:     "maps to the AWS `DeleteVectorBucket` S3 Vectors action.",
		},
		{
			Name:     "GetVectorBucket",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetVectorBucket` S3 Vectors action.",
		},
		{
			Name:     "ListVectorBuckets",
			Category: CategoryList,
			Desc:     "maps to the AWS `ListVectorBuckets` S3 Vectors action.",
		},
		{
			Name:     "CreateIndex",
			Category: CategoryManage,
			Desc:     "maps to the AWS `CreateIndex` S3 Vectors action.",
		},
		{
			Name:     "DeleteIndex",
			Category: CategoryManage,
			Desc:     "maps to the AWS `DeleteIndex` S3 Vectors action.",
		},
		{
			Name:     "GetIndex",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetIndex` S3 Vectors action.",
		},
		{
			Name:     "ListIndexes",
			Category: CategoryList,
			Desc:     "maps to the AWS `ListIndexes` S3 Vectors action.",
		},
		{
			Name:     "PutVectors",
			Category: CategoryWrite,
			Desc:     "maps to the AWS `PutVectors` S3 Vectors action.",
		},
		{
			Name:     "GetVectors",
			Category: CategoryRead,
			Desc:     "maps to the AWS `GetVectors` S3 Vectors action.",
		},
		{
			Name:     "DeleteVectors",
			Category: CategoryWrite,
			Desc:     "maps to the AWS `DeleteVectors` S3 Vectors action.",
		},
		{
			Name:     "ListVectors",
			Category: CategoryList,
			Desc:     "maps to the AWS `ListVectors` S3 Vectors action.",
		},
		{
			Name:     "QueryVectors",
			Category: CategoryRead,
			Desc:     "maps to the AWS `QueryVectors` S3 Vectors action.",
		},
		{
			Name:   "*",
			GoName: "AllS3VectorsActions",
			Desc:   "All Amazon S3 Vectors actions",
		},
	},
}
