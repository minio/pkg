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

// S3Files is the s3files action namespace.
var S3Files = &Namespace{
	Prefix:       "s3files",
	Title:        "AIStor Files",
	Desc:         "File exports of buckets.",
	GoNameFormat: "Files%sAction",
	BaseKeys:     CommonKeys,
	Resource:     ResourceNone,
	Actions: []Action{
		{
			Name:     "CreateExport",
			Category: CategoryCreateDelete,
			Desc:     "Add an export.",
		},
		{
			Name:     "DeleteExport",
			Category: CategoryCreateDelete,
			Desc:     "Remove an export.",
		},
		{
			Name:     "UpdateExport",
			Category: CategoryConfigure,
			Desc:     "Change an existing export's settings, such as\nits quota.",
		},
		{
			Name:     "SetExportAccess",
			Category: CategoryPermissions,
			Desc:     "Set or clear an export's access rules.\nSeparate from FilesUpdateExportAction because the access rules decide\nwhich clients may mount the export, so a grant to resize an export must\nnot also be a grant to open it to more hosts.",
		},
		{
			Name:     "GetExportStatus",
			Category: CategoryViewSettings,
			Desc:     "List exports and read an export's\nconfiguration and status.",
		},
		{
			Name:     "GetExportStats",
			Category: CategoryViewSettings,
			Desc:     "Read per-export and fleet statistics.",
		},
		{
			Name:   "*",
			GoName: "AllFilesActions",
			Desc:   "All AIStor Files management actions.",
		},
	},
}
