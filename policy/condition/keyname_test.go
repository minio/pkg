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

import (
	"strings"
	"testing"
)

// TestServicePrefixedKeysResolveToRequestNames guards the mapping from every
// supported condition key to the request value it reads.
//
// A key's service prefix is stripped before lookup, so "s3:prefix" reads the
// request's "prefix". A service missing from toTrim keeps its whole name and
// therefore reads a value nothing populates: the condition evaluates false, and
// every statement carrying it silently grants nothing.
//
// The sweep is over AllSupportedKeys rather than a hand-picked list, so adding a
// key for a new service without extending toTrim fails here instead of shipping
// inert.
func TestServicePrefixedKeysResolveToRequestNames(t *testing.T) {
	for _, key := range AllSupportedKeys {
		full := string(key)
		idx := strings.IndexByte(full, ':')
		if idx < 0 {
			// Unprefixed keys read their own name.
			if got := key.Name(); got != full {
				t.Errorf("%s.Name() = %q, want %q", key, got, full)
			}
			continue
		}

		want := full[idx+1:]
		if got := key.Name(); got != want {
			t.Errorf("%s.Name() = %q, want %q; a key that keeps its service prefix reads a value nothing sets — add %q to toTrim",
				key, got, want, full[:idx])
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
