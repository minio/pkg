// Copyright (c) 2015-2025 MinIO, Inc.
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

// VectorsAction - S3 Vectors policy action.
type VectorsAction string

const (
	// S3VectorsCreateVectorBucketAction maps to the AWS `CreateVectorBucket` S3 Vectors action.
	S3VectorsCreateVectorBucketAction VectorsAction = "s3vectors:CreateVectorBucket"

	// S3VectorsDeleteVectorBucketAction maps to the AWS `DeleteVectorBucket` S3 Vectors action.
	S3VectorsDeleteVectorBucketAction = "s3vectors:DeleteVectorBucket"

	// S3VectorsGetVectorBucketAction maps to the AWS `GetVectorBucket` S3 Vectors action.
	S3VectorsGetVectorBucketAction = "s3vectors:GetVectorBucket"

	// S3VectorsListVectorBucketsAction maps to the AWS `ListVectorBuckets` S3 Vectors action.
	S3VectorsListVectorBucketsAction = "s3vectors:ListVectorBuckets"

	// S3VectorsCreateIndexAction maps to the AWS `CreateIndex` S3 Vectors action.
	S3VectorsCreateIndexAction = "s3vectors:CreateIndex"

	// S3VectorsDeleteIndexAction maps to the AWS `DeleteIndex` S3 Vectors action.
	S3VectorsDeleteIndexAction = "s3vectors:DeleteIndex"

	// S3VectorsGetIndexAction maps to the AWS `GetIndex` S3 Vectors action.
	S3VectorsGetIndexAction = "s3vectors:GetIndex"

	// S3VectorsListIndexesAction maps to the AWS `ListIndexes` S3 Vectors action.
	S3VectorsListIndexesAction = "s3vectors:ListIndexes"

	// S3VectorsPutVectorsAction maps to the AWS `PutVectors` S3 Vectors action.
	S3VectorsPutVectorsAction = "s3vectors:PutVectors"

	// S3VectorsGetVectorsAction maps to the AWS `GetVectors` S3 Vectors action.
	S3VectorsGetVectorsAction = "s3vectors:GetVectors"

	// S3VectorsDeleteVectorsAction maps to the AWS `DeleteVectors` S3 Vectors action.
	S3VectorsDeleteVectorsAction = "s3vectors:DeleteVectors"

	// S3VectorsListVectorsAction maps to the AWS `ListVectors` S3 Vectors action.
	S3VectorsListVectorsAction = "s3vectors:ListVectors"

	// S3VectorsQueryVectorsAction maps to the AWS `QueryVectors` S3 Vectors action.
	S3VectorsQueryVectorsAction = "s3vectors:QueryVectors"

	// AllS3VectorsActions - all Amazon S3 Vectors actions
	AllS3VectorsActions = "s3vectors:*"
)

// SupportedVectorsActions - list of all supported S3 Vectors actions.
var SupportedVectorsActions = map[VectorsAction]struct{}{
	S3VectorsCreateVectorBucketAction: {},
	S3VectorsDeleteVectorBucketAction: {},
	S3VectorsGetVectorBucketAction:    {},
	S3VectorsListVectorBucketsAction:  {},
	S3VectorsCreateIndexAction:        {},
	S3VectorsDeleteIndexAction:        {},
	S3VectorsGetIndexAction:           {},
	S3VectorsListIndexesAction:        {},
	S3VectorsPutVectorsAction:         {},
	S3VectorsGetVectorsAction:         {},
	S3VectorsDeleteVectorsAction:      {},
	S3VectorsListVectorsAction:        {},
	S3VectorsQueryVectorsAction:       {},
	AllS3VectorsActions:               {},
}

// IsValid - checks if action is valid or not.
func (action VectorsAction) IsValid() bool {
	_, ok := SupportedVectorsActions[action]
	return ok
}

func createVectorsActionConditionKeyMap() map[Action]condition.KeySet {
	commonKeys := []condition.Key{}
	for _, keyName := range condition.CommonKeys {
		commonKeys = append(commonKeys, keyName.ToKey())
	}

	vectorsActionConditionKeyMap := map[Action]condition.KeySet{}
	for act := range SupportedVectorsActions {
		vectorsActionConditionKeyMap[Action(act)] = condition.NewKeySet(commonKeys...)
	}

	// Override specific actions with their condition keys as needed
	// For now, all actions use only common keys

	return vectorsActionConditionKeyMap
}

// VectorsActionConditionKeyMap - holds mapping of Vectors actions to condition keys.
var VectorsActionConditionKeyMap = createVectorsActionConditionKeyMap()
