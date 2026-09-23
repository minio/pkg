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

package policy

import "testing"

func BenchmarkResourceMatch(b *testing.B) {
	conditionValues := map[string][]string{"username": {"alice"}}
	benchCases := []struct {
		name, pattern, resource string
	}{
		{"NoVariable", "test-bucket/home/*", "test-bucket/home/alice/file.txt"},
		{"Variable", "test-bucket/home/${aws:username}/*", "test-bucket/home/alice/file.txt"},
		{"VariableLong", "test-bucket/some/deeper/prefix/path/home/${aws:username}/sub/*", "test-bucket/some/deeper/prefix/path/home/alice/sub/dir/file.txt"},
		{"Escape", "test-bucket/home/${aws:username}/${*}/*", "test-bucket/home/alice/*/file.txt"},
	}
	for _, bc := range benchCases {
		r := NewResource(bc.pattern)
		if !r.Match(bc.resource, conditionValues) {
			b.Fatalf("%s: want a match", bc.name)
		}
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r.Match(bc.resource, conditionValues)
			}
		})
	}
}
