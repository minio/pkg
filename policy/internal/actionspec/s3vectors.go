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
	GoNameFormat: "S3Vectors%sAction",
	BaseKeys:     CommonKeys,
	Actions: []Action{
		{
			Name: "CreateVectorBucket",
			Desc: "maps to the AWS `CreateVectorBucket` S3 Vectors action.",
		},
		{
			Name: "DeleteVectorBucket",
			Desc: "maps to the AWS `DeleteVectorBucket` S3 Vectors action.",
		},
		{
			Name: "GetVectorBucket",
			Desc: "maps to the AWS `GetVectorBucket` S3 Vectors action.",
		},
		{
			Name: "ListVectorBuckets",
			Desc: "maps to the AWS `ListVectorBuckets` S3 Vectors action.",
		},
		{
			Name: "CreateIndex",
			Desc: "maps to the AWS `CreateIndex` S3 Vectors action.",
		},
		{
			Name: "DeleteIndex",
			Desc: "maps to the AWS `DeleteIndex` S3 Vectors action.",
		},
		{
			Name: "GetIndex",
			Desc: "maps to the AWS `GetIndex` S3 Vectors action.",
		},
		{
			Name: "ListIndexes",
			Desc: "maps to the AWS `ListIndexes` S3 Vectors action.",
		},
		{
			Name: "PutVectors",
			Desc: "maps to the AWS `PutVectors` S3 Vectors action.",
		},
		{
			Name: "GetVectors",
			Desc: "maps to the AWS `GetVectors` S3 Vectors action.",
		},
		{
			Name: "DeleteVectors",
			Desc: "maps to the AWS `DeleteVectors` S3 Vectors action.",
		},
		{
			Name: "ListVectors",
			Desc: "maps to the AWS `ListVectors` S3 Vectors action.",
		},
		{
			Name: "QueryVectors",
			Desc: "maps to the AWS `QueryVectors` S3 Vectors action.",
		},
		{
			Name:   "*",
			GoName: "AllS3VectorsActions",
			Desc:   "All Amazon S3 Vectors actions",
		},
	},
}
