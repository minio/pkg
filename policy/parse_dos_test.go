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

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Validating a statement classifies every action against each namespace, and a
// star-heavy action pattern used to make that cost time exponential in the star
// count: "*********x" held ParseConfig for a minute and the same action in a
// bucket policy held ParseBucketPolicyConfig for nineteen seconds. Both are
// caller-supplied, so parsing has to stay bounded.
func TestParseStarHeavyActionIsBounded(t *testing.T) {
	const budget = 2 * time.Second
	for _, stars := range []int{9, 16, 64} {
		action := strings.Repeat("*", stars) + "x"

		t.Run("iam", func(t *testing.T) {
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["` +
				action + `"],"Resource":["arn:aws:s3:::b/*"]}]}`
			start := time.Now()
			ParseConfig(bytes.NewReader([]byte(doc)))
			if d := time.Since(start); d > budget {
				t.Errorf("ParseConfig with %d stars took %v, want under %v", stars, d, budget)
			}
		})

		t.Run("bucket", func(t *testing.T) {
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["` +
				action + `"],"Resource":["arn:aws:s3:::b/*"]}]}`
			start := time.Now()
			ParseBucketPolicyConfig(bytes.NewReader([]byte(doc)), "b")
			if d := time.Since(start); d > budget {
				t.Errorf("ParseBucketPolicyConfig with %d stars took %v, want under %v", stars, d, budget)
			}
		})
	}
}
