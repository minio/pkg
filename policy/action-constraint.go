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

// ActionType constrains the set of policy action types. It lets generic helpers
// accept any typed action — S3 (Action), admin, STS, KMS, Tables, Vectors, or
// Memory — without forcing callers to convert to Action at each call site. A
// bare string is intentionally excluded so only real policy action types match.
type ActionType interface {
	Action | AdminAction | STSAction | KMSAction | TableAction | VectorsAction | MemoryAction
}
