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

package condition

import (
	"strings"
	"testing"
	"time"

	"github.com/minio/pkg/v3/wildcard"
)

func TestSubstitute(t *testing.T) {
	values := map[string][]string{
		"username": {"david"},
		"userid":   {""},
	}

	// wantMatch, when set, is a string the escaped pattern must match.
	testCases := []struct {
		pattern     string
		wantLiteral string
		wantEscaped string
		wantMatch   string
	}{
		{"mybucket/foo", "mybucket/foo", "mybucket/foo", ""},
		{"mybucket/${aws:username}/*", "mybucket/david/*", "mybucket/david/*", ""},
		// A key with no value, or one that is not a known key, stays as written.
		{"mybucket/${aws:userid}/*", "mybucket/${aws:userid}/*", "mybucket/${aws:userid}/*", ""},
		{"mybucket/${aws:nosuchkey}", "mybucket/${aws:nosuchkey}", "mybucket/${aws:nosuchkey}", ""},
		// The predefined escapes.
		{"mybucket/${*}", "mybucket/*", `mybucket/\*`, "mybucket/*"},
		{"mybucket/${?}", "mybucket/?", `mybucket/\?`, "mybucket/?"},
		{"mybucket/${$}", "mybucket/$", `mybucket/\$`, "mybucket/$"},
		{"${*}${?}${$}", "*?$", `\*\?\$`, "*?$"},
		// An expansion is not rescanned, so ${$} does not build a variable.
		{"${$}{aws:username}", "${aws:username}", `\${aws:username}`, "${aws:username}"},
		// A backslash the policy wrote stands for itself either way.
		{`my\bucket/${*}`, `my\bucket/*`, `my\\bucket/\*`, `my\bucket/*`},
		{`my\bucket`, `my\bucket`, `my\\bucket`, `my\bucket`},
		// Incomplete variable syntax is emitted as written.
		{"mybucket/$", "mybucket/$", "mybucket/$", ""},
		{"mybucket/${", "mybucket/${", "mybucket/${", ""},
		{"mybucket/${aws:username", "mybucket/${aws:username", "mybucket/${aws:username", ""},
		{"mybucket/${}", "mybucket/${}", "mybucket/${}", ""},
		{"mybucket/$${aws:username}", "mybucket/$david", "mybucket/$david", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			if got := Substitute(tc.pattern, values, false); got != tc.wantLiteral {
				t.Fatalf("Substitute(%q, false) = %q, want %q", tc.pattern, got, tc.wantLiteral)
			}
			if got := Substitute(tc.pattern, values, true); got != tc.wantEscaped {
				t.Fatalf("Substitute(%q, true) = %q, want %q", tc.pattern, got, tc.wantEscaped)
			}
			if tc.wantMatch != "" && !wildcard.MatchEscaped(tc.wantEscaped, tc.wantMatch) {
				t.Fatalf("escaped pattern %q does not match %q", tc.wantEscaped, tc.wantMatch)
			}
		})
	}
}

// An unclosed '${' must not restart the scan for '}' one byte later. Doing so
// is quadratic in the pattern length.
func TestSubstituteUnterminatedVariablesAreLinear(t *testing.T) {
	values := map[string][]string{"username": {"david"}}

	for _, n := range []int{1 << 10, 1 << 12, 1 << 14, 1 << 16} {
		pattern := strings.Repeat("${", n)
		start := time.Now()
		got := Substitute(pattern, values, true)
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Errorf("Substitute over %d bytes took %v, want well under 50ms", len(pattern), d)
		}
		if got != pattern {
			t.Fatalf("Substitute(%d unterminated variables) rewrote the pattern", n)
		}
	}
}
