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

func BenchmarkStringLikeFuncEvaluate(b *testing.B) {
	values := map[string][]string{
		"prefix":   {"home/alice/docs/"},
		"username": {"alice"},
	}
	benchCases := []struct {
		name     string
		patterns []string
	}{
		{"NoVariable", []string{"home/*", "public/*", "shared/*"}},
		{"Variable", []string{"home/${aws:username}/*", "public/*", "shared/*"}},
		{"Escape", []string{"home/${aws:username}/${*}", "public/*", "shared/*"}},
	}
	for _, bc := range benchCases {
		function, err := NewStringLikeFunc("", S3Prefix.ToKey(), bc.patterns...)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				function.evaluate(values)
			}
		})
	}
}

func BenchmarkSubstitute(b *testing.B) {
	values := map[string][]string{"username": {"alice"}}
	benchCases := []struct {
		name, pattern string
	}{
		{"NoVariable", "test-bucket/home/alice/*"},
		{"Variable", "test-bucket/home/${aws:username}/*"},
		{"UnknownVariable", "test-bucket/home/${aws:nosuchkey}/*"},
		{"Escape", `test-bucket/home/${aws:username}/${*}\file`},
	}
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Substitute(bc.pattern, values, true)
			}
		})
	}
}
