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

// FilesAction - AIStor Files management policy action. AIStor Files is an
// NFSv4.1 gateway; these actions govern its management API (the exports it
// serves), not the NFS data path. They are granted independently of AIStor
// admin, so they live in their own namespace rather than under admin:.
type FilesAction string

// IsValid - checks if action is valid or not.
func (action FilesAction) IsValid() bool {
	_, ok := SupportedFilesActions[action]
	return ok
}
