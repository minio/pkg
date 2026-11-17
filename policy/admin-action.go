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

package policy

import (
	"strings"

	"github.com/minio/pkg/v3/wildcard"
)

// AdminAction - admin policy action.
type AdminAction string

// HasResource reports whether this admin action operates on a bucket resource.
func (action AdminAction) HasResource() bool {
	if _, ok := AdminActionsWithResource[action]; ok {
		return true
	}
	if !wildcard.Has(string(action)) {
		// A literal action can only match by being in the set.
		return false
	}
	for a := range AdminActionsWithResource {
		if action.Match(a) {
			return true
		}
	}
	return false
}

// Match - matches action name with action pattern.
func (action AdminAction) Match(a AdminAction) bool {
	return wildcard.Match(string(action), string(a))
}

// IsValid - checks if action is valid or not.
//
// The receiver is the pattern, so this asks whether the pattern matches any
// supported admin action.
func (action AdminAction) IsValid() bool {
	if _, ok := SupportedAdminActions[action]; ok {
		return true
	}
	s := string(action)
	star := strings.IndexAny(s, "*?")
	if star < 0 {
		// A literal action can only match by being in the set above.
		return false
	}
	if !canMatchPrefix(s[:star], adminActionPrefix) {
		// computeClass runs this for every action of every statement it
		// classifies, so a pattern is only scanned against the whole set when
		// its literal head is prefix-compatible with the admin namespace.
		return false
	}
	for supAction := range SupportedAdminActions {
		if action.Match(supAction) {
			return true
		}
	}
	return false
}

// adminActionPrefix is the namespace every supported admin action carries.
const adminActionPrefix = "admin:"

// canMatchPrefix reports whether a wildcard pattern whose literal head (the
// part before its first metacharacter) is head could match any string starting
// with prefix. Everything up to the first metacharacter has to match literally,
// so head and prefix must agree wherever they overlap.
func canMatchPrefix(head, prefix string) bool {
	if len(head) > len(prefix) {
		return strings.HasPrefix(head, prefix)
	}
	return strings.HasPrefix(prefix, head)
}
