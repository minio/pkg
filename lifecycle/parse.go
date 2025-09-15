// Copyright (c) 2015-2025 MinIO, Inc.
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

package lifecycle

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7/pkg/lifecycle"
)

// Used in tags. Ex: --tags "key1=value1&key2=value2&key3=value3"
const (
	tagSeperator    string = "&"
	keyValSeperator string = "="
)

func extractILMTags(tagLabelVal string) []lifecycle.Tag {
	var ilmTagKVList []lifecycle.Tag
	for _, tag := range strings.Split(tagLabelVal, tagSeperator) {
		if tag == "" {
			// split returns empty for empty tagLabelVal, skip it.
			continue
		}
		lfcTag := lifecycle.Tag{}
		kvs := strings.SplitN(tag, keyValSeperator, 2)
		if len(kvs) == 2 {
			lfcTag.Key = kvs[0]
			lfcTag.Value = kvs[1]
		} else {
			lfcTag.Key = kvs[0]
		}
		ilmTagKVList = append(ilmTagKVList, lfcTag)
	}
	return ilmTagKVList
}

func parseTransitionDate(transitionDateStr string) (lifecycle.ExpirationDate, error) {
	transitionDate, e := time.Parse(defaultILMDateFormat, transitionDateStr)
	if e != nil {
		return lifecycle.ExpirationDate{}, e
	}
	return lifecycle.ExpirationDate{Time: transitionDate}, nil
}

func parseTransitionDays(transitionDaysStr string) (lifecycle.ExpirationDays, error) {
	transitionDays, e := strconv.Atoi(transitionDaysStr)
	if e != nil {
		return lifecycle.ExpirationDays(0), e
	}
	return lifecycle.ExpirationDays(transitionDays), nil
}

func parseExpiryDate(expiryDateStr string) (lifecycle.ExpirationDate, error) {
	date, e := time.Parse(defaultILMDateFormat, expiryDateStr)
	if e != nil {
		return lifecycle.ExpirationDate{}, e
	}
	if date.IsZero() {
		return lifecycle.ExpirationDate{}, errors.New("expiration date cannot be set to zero")
	}
	return lifecycle.ExpirationDate{Time: date}, nil
}

func parseExpiryDays(expiryDayStr string) (lifecycle.ExpirationDays, error) {
	days, e := strconv.Atoi(expiryDayStr)
	if e != nil {
		return lifecycle.ExpirationDays(0), e
	}
	if days == 0 {
		return lifecycle.ExpirationDays(0), errors.New("expiration days cannot be set to zero")
	}
	return lifecycle.ExpirationDays(days), nil
}
