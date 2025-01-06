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

package rng

import (
	"bytes"
	"io"
	"math/rand"
	"strconv"
	"testing"
)

func BenchmarkReader(b *testing.B) {
	for _, size := range []int{1000, 1024, 16384, 1 << 20} {
		r, err := NewReader()
		if err != nil {
			b.Fatal(err)
		}
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			buf := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := io.ReadFull(r, buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReaderReadAt(b *testing.B) {
	for _, size := range []int{1000, 1024, 16384, 1 << 20} {
		r, err := NewReader()
		if err != nil {
			b.Fatal(err)
		}
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			buf := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				nr, err := r.ReadAt(buf, int64(n*size))
				if err != nil {
					b.Fatal(err)
				}
				if nr != len(buf) {
					b.Fatalf("expected %d bytes, got %d", len(buf), nr)
				}
			}
		})
	}
}

func TestReaderReadAt(t *testing.T) {
	for _, size := range []int{1000, 1024, 16384, 1 << 20} {
		r, err := NewReader()
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, size)
		bufAt := make([]byte, size)
		rng := rand.New(rand.NewSource(0))
		offset := 0
		for i := 0; i < 1000; i++ {
			n := rng.Intn(size)
			buf := buf[:n]
			_, err := io.ReadFull(r, buf)
			if err != nil {
				t.Fatal(err)
			}
			bufAt := bufAt[:n]
			n2, err := r.ReadAt(bufAt, int64(offset))
			if err != nil {
				t.Fatal(err)
			}
			if n != n2 {
				t.Fatalf("expected %d bytes, got %d", n, n2)
			}
			if !bytes.Equal(bufAt, buf) {
				t.Fatalf("\nexpected (%d) %x\ngot      (%d) %x", len(buf), buf, len(bufAt), bufAt)
			}
			offset += n
		}
	}
}

func TestReaderSeeker(t *testing.T) {
	for _, size := range []int{1000, 1024, 16384, 1 << 20} {
		r, err := NewReader()
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, size)
		bufAt := make([]byte, size)
		rng := rand.New(rand.NewSource(0))
		for i := 0; i < 1000; i++ {
			offset := rng.Int63()
			_, err := r.Seek(offset, io.SeekStart)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadFull(r, buf)
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.ReadAt(bufAt, offset)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bufAt, buf) {
				t.Fatalf("\nexpected (%d) %x\ngot      (%d) %x", len(buf), buf, len(bufAt), bufAt)
			}
		}
	}
}

func TestXor(t *testing.T) {
	// Validate asm, if any, otherwise validate ourselves.
	rng := rand.New(rand.NewSource(0))
	for _, size := range []int{1000, 1024, 16384, 1 << 20} {
		bufIn := make([]byte, size)
		_, err := io.ReadFull(rng, bufIn)
		if err != nil {
			t.Fatal(err)
		}
		bufOut := make([]byte, size)
		bufOut2 := make([]byte, size)
		var keys [4]uint64
		for i := range keys {
			keys[i] = rng.Uint64()
		}
		for i := 0; i < 1000; i++ {
			bSize := (rand.Intn(size) / 32) * 32
			bufOut := bufOut[:bSize]
			for i := 0; i < len(bufOut); i++ {
				bufOut[i] = 0
			}
			bufOut2 := bufOut2[:bSize]
			for i := 0; i < len(bufOut2); i++ {
				bufOut2[i] = 0
			}
			xorSlice(bufIn, bufOut, &keys)
			xor32Go(bufIn, bufOut2, &keys)
			if !bytes.Equal(bufOut, bufOut2) {
				t.Fatalf("\nexpected %x\ngot      %x", bufOut, bufOut2)
			}
		}
	}
}
