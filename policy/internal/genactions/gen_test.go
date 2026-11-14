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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedUpToDate fails when the checked-in generated files differ from
// what the spec renders; run go generate in the policy package to fix it.
func TestGeneratedUpToDate(t *testing.T) {
	files, err := render()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sortedPaths(files) {
		got, err := os.ReadFile(filepath.Join("..", "..", p))
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if !bytes.Equal(got, files[p]) {
			t.Errorf("%s is stale: run go generate in the policy package", p)
		}
	}
}
