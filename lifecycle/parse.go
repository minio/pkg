// MinIO, Inc. CONFIDENTIAL
//
// [2014] - [2025] MinIO, Inc. All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains the property
// of MinIO, Inc and its suppliers, if any.  The intellectual and technical
// concepts contained herein are proprietary to MinIO, Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from MinIO, Inc.

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
