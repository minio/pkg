// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import (
	"github.com/minio/pkg/v3/policy/condition"
)

// FilesAction - AIStor Files management policy action. AIStor Files is an
// NFSv4.1 gateway; these actions govern its management API (the exports it
// serves), not the NFS data path. They are granted independently of AIStor
// admin, so they live in their own namespace rather than under admin:.
type FilesAction string

const (
	// FilesCreateExportAction - add an export.
	FilesCreateExportAction FilesAction = "s3files:CreateExport"

	// FilesDeleteExportAction - remove an export.
	FilesDeleteExportAction FilesAction = "s3files:DeleteExport"

	// FilesUpdateExportAction - change an existing export's settings, such as
	// its quota.
	FilesUpdateExportAction FilesAction = "s3files:UpdateExport"

	// FilesSetExportAccessAction - set or clear an export's access rules.
	// Separate from FilesUpdateExportAction because the access rules decide
	// which clients may mount the export, so a grant to resize an export must
	// not also be a grant to open it to more hosts.
	FilesSetExportAccessAction FilesAction = "s3files:SetExportAccess"

	// FilesGetExportStatusAction - list exports and read an export's
	// configuration and status.
	FilesGetExportStatusAction FilesAction = "s3files:GetExportStatus"

	// FilesGetExportStatsAction - read per-export and fleet statistics.
	FilesGetExportStatsAction FilesAction = "s3files:GetExportStats"

	// AllFilesActions - all AIStor Files management actions.
	AllFilesActions FilesAction = "s3files:*"
)

// SupportedFilesActions - list of all supported AIStor Files management actions.
var SupportedFilesActions = map[FilesAction]struct{}{
	FilesCreateExportAction:    {},
	FilesDeleteExportAction:    {},
	FilesUpdateExportAction:    {},
	FilesSetExportAccessAction: {},
	FilesGetExportStatusAction: {},
	FilesGetExportStatsAction:  {},
	AllFilesActions:            {},
}

// IsValid - checks if action is valid or not.
func (action FilesAction) IsValid() bool {
	_, ok := SupportedFilesActions[action]
	return ok
}

func createFilesActionConditionKeyMap() map[Action]condition.KeySet {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	filesActionConditionKeyMap := map[Action]condition.KeySet{}
	for act := range SupportedFilesActions {
		filesActionConditionKeyMap[Action(act)] = condition.NewKeySet(commonKeys...)
	}

	return filesActionConditionKeyMap
}

// FilesActionConditionKeyMap - holds mapping of Files actions to condition keys.
var FilesActionConditionKeyMap = createFilesActionConditionKeyMap()
