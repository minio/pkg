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

package randreader

import (
	"io"
	"math/rand"
	"testing"
)

func BenchmarkReader(b *testing.B) {
	const size = 100000

	buf := make([]byte, size)
	src := New()
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := io.ReadFull(src, buf)
		if err != nil {
			b.Fatal(err)
		}
		if n != size {
			b.Fatalf("want read size %d, got %d", size, n)
		}
	}
}

func BenchmarkMathRand(b *testing.B) {
	const size = 100000

	buf := make([]byte, size)
	src := rand.New(rand.NewSource(0))
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := io.ReadFull(src, buf)
		if err != nil {
			b.Fatal(err)
		}
		if n != size {
			b.Fatalf("want read size %d, got %d", size, n)
		}
	}
}
