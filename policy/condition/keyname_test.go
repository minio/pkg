// Copyright (c) 2015-2026 MinIO, Inc.
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

import "testing"

// TestServicePrefixedKeysResolveToRequestNames guards the mapping from a
// condition key to the request value it reads.
//
// A key's service prefix is trimmed before lookup, so "s3:prefix" reads the
// request's "prefix". A service missing from toTrim keeps its whole name and
// therefore reads a value nothing populates: the condition then evaluates
// false, and every statement carrying it silently grants nothing.
func TestServicePrefixedKeysResolveToRequestNames(t *testing.T) {
	testCases := []struct {
		key  KeyName
		want string
	}{
		{S3Prefix, "prefix"},
		{S3Delimiter, "delimiter"},
		{S3MaxKeys, "max-keys"},
		{MemoryPrefix, "prefix"},
		{MemoryMaxKeys, "max-keys"},
		{AWSUsername, "username"},
	}

	for _, tc := range testCases {
		if got := tc.key.Name(); got != tc.want {
			t.Errorf("%s.Name() = %q, want %q; a key that keeps its service prefix reads a value nothing sets",
				tc.key, got, tc.want)
		}
	}
}

// TestMemoryPrefixConditionEvaluates proves the key reaches a real request
// value rather than merely parsing.
func TestMemoryPrefixConditionEvaluates(t *testing.T) {
	fn, err := newStringLikeFunc(MemoryPrefix.ToKey(), NewValueSet(NewStringValue("alpha*")), "")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if !fn.evaluate(map[string][]string{"prefix": {"alpha"}}) {
		t.Error(`prefix "alpha" must satisfy "alpha*"`)
	}
	if !fn.evaluate(map[string][]string{"prefix": {"alphabet"}}) {
		t.Error(`prefix "alphabet" must satisfy "alpha*"`)
	}
	if fn.evaluate(map[string][]string{"prefix": {"beta"}}) {
		t.Error(`prefix "beta" must not satisfy "alpha*"`)
	}
	// An unscoped listing must not pass a scoped condition.
	if fn.evaluate(map[string][]string{}) {
		t.Error("an absent prefix must not satisfy a scoped condition")
	}
}
