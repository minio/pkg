// Copyright (c) 2015-2023 MinIO, Inc.
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

package batch

import (
	"context"
	"time"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/pkg/v3/xtime"
)

type BatchJobRequest struct {
	ID        string               `yaml:"-" json:"name"`
	User      string               `yaml:"-" json:"user"`
	Started   time.Time            `yaml:"-" json:"started"`
	Replicate *BatchJobReplicateV1 `yaml:"replicate" json:"replicate"`
	KeyRotate *BatchJobKeyRotateV1 `yaml:"keyrotate" json:"keyrotate"`
	Expire    *BatchJobExpire      `yaml:"expire" json:"expire"`
	ctx       context.Context      `msg:"-"`
}

type BatchJobReplicateV1 struct {
	APIVersion string                  `yaml:"apiVersion" json:"apiVersion"`
	Flags      BatchJobReplicateFlags  `yaml:"flags" json:"flags"`
	Target     BatchJobReplicateTarget `yaml:"target" json:"target"`
	Source     BatchJobReplicateSource `yaml:"source" json:"source"`

	clnt *miniogo.Core `msg:"-"`
}

type BatchJobReplicateFlags struct {
	Filter BatchReplicateFilter `yaml:"filter" json:"filter"`
	Notify BatchJobNotification `yaml:"notify" json:"notify"`
	Retry  BatchJobRetry        `yaml:"retry" json:"retry"`
}

type BatchReplicateFilter struct {
	NewerThan     xtime.Duration `yaml:"newerThan,omitempty" json:"newerThan"`
	OlderThan     xtime.Duration `yaml:"olderThan,omitempty" json:"olderThan"`
	CreatedAfter  time.Time      `yaml:"createdAfter,omitempty" json:"createdAfter"`
	CreatedBefore time.Time      `yaml:"createdBefore,omitempty" json:"createdBefore"`
	Tags          []BatchJobKV   `yaml:"tags,omitempty" json:"tags"`
	Metadata      []BatchJobKV   `yaml:"metadata,omitempty" json:"metadata"`
}

type BatchJobKV struct {
	line, col int
	Key       string `yaml:"key" json:"key"`
	Value     string `yaml:"value" json:"value"`
}

type BatchJobNotification struct {
	line, col int
	Endpoint  string `yaml:"endpoint" json:"endpoint"`
	Token     string `yaml:"token" json:"token"`
}

type BatchJobRetry struct {
	line, col int
	Attempts  int           `yaml:"attempts" json:"attempts"` // number of retry attempts
	Delay     time.Duration `yaml:"delay" json:"delay"`       // delay between each retries
}

type BatchJobReplicateTarget struct {
	Type     BatchJobReplicateResourceType `yaml:"type" json:"type"`
	Bucket   string                        `yaml:"bucket" json:"bucket"`
	Prefix   string                        `yaml:"prefix" json:"prefix"`
	Endpoint string                        `yaml:"endpoint" json:"endpoint"`
	Path     string                        `yaml:"path" json:"path"`
	Creds    BatchJobReplicateCredentials  `yaml:"credentials" json:"credentials"`
}

type BatchJobReplicateResourceType string

type BatchJobReplicateCredentials struct {
	AccessKey    string `xml:"AccessKeyId" json:"accessKey,omitempty" yaml:"accessKey"`
	SecretKey    string `xml:"SecretAccessKey" json:"secretKey,omitempty" yaml:"secretKey"`
	SessionToken string `xml:"SessionToken" json:"sessionToken,omitempty" yaml:"sessionToken"`
}


type BatchJobReplicateSource struct {
	Type     BatchJobReplicateResourceType `yaml:"type" json:"type"`
	Bucket   string                        `yaml:"bucket" json:"bucket"`
	Prefix   BatchJobPrefix                `yaml:"prefix" json:"prefix"`
	Endpoint string                        `yaml:"endpoint" json:"endpoint"`
	Path     string                        `yaml:"path" json:"path"`
	Creds    BatchJobReplicateCredentials  `yaml:"credentials" json:"credentials"`
	Snowball BatchJobSnowball              `yaml:"snowball" json:"snowball"`
}

type BatchJobPrefix []string

type BatchJobSnowball struct {
	line, col   int
	Disable     *bool   `yaml:"disable" json:"disable"`
	Batch       *int    `yaml:"batch" json:"batch"`
	InMemory    *bool   `yaml:"inmemory" json:"inmemory"`
	Compress    *bool   `yaml:"compress" json:"compress"`
	SmallerThan *string `yaml:"smallerThan" json:"smallerThan"`
	SkipErrs    *bool   `yaml:"skipErrs" json:"skipErrs"`
}

type BatchJobKeyRotateV1 struct {
	APIVersion string                      `yaml:"apiVersion" json:"apiVersion"`
	Flags      BatchJobKeyRotateFlags      `yaml:"flags" json:"flags"`
	Bucket     string                      `yaml:"bucket" json:"bucket"`
	Prefix     string                      `yaml:"prefix" json:"prefix"`
	Encryption BatchJobKeyRotateEncryption `yaml:"encryption" json:"encryption"`
}

type BatchJobKeyRotateFlags struct {
	Filter BatchKeyRotateFilter `yaml:"filter" json:"filter"`
	Notify BatchJobNotification `yaml:"notify" json:"notify"`
	Retry  BatchJobRetry        `yaml:"retry" json:"retry"`
}


type BatchKeyRotateFilter struct {
	NewerThan     time.Duration `yaml:"newerThan,omitempty" json:"newerThan"`
	OlderThan     time.Duration `yaml:"olderThan,omitempty" json:"olderThan"`
	CreatedAfter  time.Time     `yaml:"createdAfter,omitempty" json:"createdAfter"`
	CreatedBefore time.Time     `yaml:"createdBefore,omitempty" json:"createdBefore"`
	Tags          []BatchJobKV  `yaml:"tags,omitempty" json:"tags"`
	Metadata      []BatchJobKV  `yaml:"metadata,omitempty" json:"metadata"`
	KMSKeyID      string        `yaml:"kmskeyid" json:"kmskey"`
}

type BatchJobKeyRotateEncryption struct {
	Type       BatchKeyRotationType `yaml:"type" json:"type"`
	Key        string               `yaml:"key" json:"key"`
	Context    string               `yaml:"context" json:"context"`
	kmsContext map[string]string    `msg:"-"`
}

type BatchKeyRotationType string

type BatchJobExpire struct {
	line, col       int
	APIVersion      string                 `yaml:"apiVersion" json:"apiVersion"`
	Bucket          string                 `yaml:"bucket" json:"bucket"`
	Prefix          BatchJobPrefix         `yaml:"prefix" json:"prefix"`
	NotificationCfg BatchJobNotification   `yaml:"notify" json:"notify"`
	Retry           BatchJobRetry          `yaml:"retry" json:"retry"`
	Rules           []BatchJobExpireFilter `yaml:"rules" json:"rules"`
}

type BatchJobExpireFilter struct {
	line, col     int
	OlderThan     xtime.Duration      `yaml:"olderThan,omitempty" json:"olderThan"`
	CreatedBefore *time.Time          `yaml:"createdBefore,omitempty" json:"createdBefore"`
	Tags          []BatchJobKV        `yaml:"tags,omitempty" json:"tags"`
	Metadata      []BatchJobKV        `yaml:"metadata,omitempty" json:"metadata"`
	Size          BatchJobSizeFilter  `yaml:"size" json:"size"`
	Type          string              `yaml:"type" json:"type"`
	Name          string              `yaml:"name" json:"name"`
	Purge         BatchJobExpirePurge `yaml:"purge" json:"purge"`
}

type BatchJobSizeFilter struct {
	line, col  int
	UpperBound BatchJobSize `yaml:"lessThan" json:"lessThan"`
	LowerBound BatchJobSize `yaml:"greaterThan" json:"greaterThan"`
}

type BatchJobExpirePurge struct {
	line, col      int
	RetainVersions int `yaml:"retainVersions" json:"retainVersions"`
}

type BatchJobSize int64