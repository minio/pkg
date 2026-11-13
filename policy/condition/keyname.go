// Copyright (c) 2015-2021 MinIO, Inc.
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

package condition

import (
	"fmt"
	"sort"
	"strings"
)

// KeyName - conditional key which is used to fetch values for any condition.
// Refer https://docs.aws.amazon.com/IAM/latest/UserGuide/list_s3.html
// for more information about available condition keys.
type KeyName string

// adminKeyPrefix is the service prefix of the keys that describe an admin API
// request, such as admin:PolicyName. The server sets their values itself, so a
// policy may use them on admin actions only, and no request header supplies
// them.
const adminKeyPrefix = "admin"

// Name - returns the key name with its service prefix stripped, so a key reads
// the request value of the same name. The prefixes that are stripped are the
// keys of toTrim; a service missing from there keeps its whole name and reads a
// value nothing populates. A key in untrimmedKeys keeps its whole name too.
func (key KeyName) Name() string {
	idx := strings.IndexByte(string(key), ':')
	if idx == -1 || !toTrim[string(key[:idx])] || untrimmedKeys[key] {
		return string(key)
	}
	return string(key[idx+1:])
}

func variableKeyNames() []string {
	names := make([]string, 0, len(variableKeys))
	for name := range variableKeys {
		names = append(names, string(name))
	}
	sort.Strings(names)
	return names
}

// TakesVariable reports whether key may carry a /<variable> suffix.
func (key KeyName) TakesVariable() bool {
	return variableKeys[key]
}

// IsAdmin reports whether key describes an admin API request.
func (key KeyName) IsAdmin() bool {
	return strings.HasPrefix(string(key), adminKeyPrefix+":")
}

// VarName - returns variable key name, such as "${aws:username}"
func (key KeyName) VarName() string {
	return fmt.Sprintf("${%s}", key)
}

// ToKey - creates key from name.
func (key KeyName) ToKey() Key {
	return NewKey(key, "")
}

// CommonKeysMap is a lookup of CommonKeys.
var CommonKeysMap map[KeyName]bool

func init() {
	CommonKeysMap = make(map[KeyName]bool, len(CommonKeys))
	for _, key := range CommonKeys {
		CommonKeysMap[key] = true
	}
}
