// Copyright (c) 2015-2022 MinIO, Inc.
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

package subnet

// CurrentSummaryVersion - current version of the ClusterSummary struct
const CurrentSummaryVersion = "v1"

// ClusterInfo - Cluster information sent to subnet as part of callhome
type ClusterInfo struct {
	DeploymentID   string         `json:"deploymentId"`
	DataUsage      uint64         `json:"dataUsage"`
	SummaryVersion string         `json:"summaryVersion"` // version of the "summary" node format
	Summary        ClusterSummary `json:"summary"`
}

// ClusterSummary - The "summary" sub-node of the cluster information struct
// Intended to be extensible i.e. more fields will be added as and when required
type ClusterSummary struct {
	MinioVersion    string `json:"minioVersion"`
	NoOfServerPools int    `json:"noOfServerPools"`
	NoOfServers     int    `json:"noOfServers"`
	NoOfDrives      int    `json:"noOfDrives"`
	NoOfBuckets     uint64 `json:"noOfBuckets"`
	NoOfObjects     uint64 `json:"noOfObjects"`
	TotalDriveSpace uint64 `json:"totalDriveSpace"`
	UsedDriveSpace  uint64 `json:"usedDriveSpace"`
}
