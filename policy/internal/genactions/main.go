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

// Command genactions renders policy/internal/actionspec into the generated
// files of the policy and condition packages. Run it through go generate in
// the policy package.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dir := flag.String("dir", ".", "policy package directory")
	flag.Parse()
	files, err := render()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genactions:", err)
		os.Exit(1)
	}
	for _, p := range sortedPaths(files) {
		if err := os.WriteFile(filepath.Join(*dir, p), files[p], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "genactions:", err)
			os.Exit(1)
		}
	}
}
