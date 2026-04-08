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
	"encoding/binary"
	"io"
	"math/rand"
	"strconv"
	"testing"

	"github.com/klauspost/cpuid/v2"
)

func TestSubkeysInitialized(t *testing.T) {
	src := rand.New(rand.NewSource(12345))
	r, err := NewReader(WithRNG(src))
	if err != nil {
		t.Fatal(err)
	}

	allZero := true
	for _, v := range r.subxor {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("subxor keys are all zero after initialization")
	}

	// With fullReset=false (default), the buffer is reused across Reset.
	// If subkeys were always zero, output would be identical after reset.
	buf1 := make([]byte, 1024)
	io.ReadFull(r, buf1)

	r.Reset()

	buf2 := make([]byte, 1024)
	io.ReadFull(r, buf2)

	if bytes.Equal(buf1, buf2) {
		t.Fatal("output identical after reset — subkeys not re-initialized")
	}
}

func TestResetSizeProducesUniqueOutput(t *testing.T) {
	const size = 64 << 20 // 64 MiB
	r, _ := NewReader(WithSize(size))

	out1 := make([]byte, size)
	io.ReadFull(r, out1)

	r.ResetSize(size)
	out2 := make([]byte, size)
	io.ReadFull(r, out2)

	if bytes.Equal(out1, out2) {
		t.Fatal("ResetSize produced identical output: subxor keys are not being randomized")
	}
}

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

func BenchmarkReaderReset(b *testing.B) {
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
				r.Reset()
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

func forEachXorImpl(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	if !cpuid.CPU.Has(cpuid.SSE2) {
		fn(t)
		return
	}
	avx2 := cpuid.CPU.Has(cpuid.AVX2)
	if avx2 {
		t.Run("AVX2", func(t *testing.T) {
			fn(t)
		})
		t.Run("SSE2", func(t *testing.T) {
			cpuid.CPU.Disable(cpuid.AVX2)
			defer cpuid.CPU.Enable(cpuid.AVX2)
			fn(t)
		})
		return

	}
	fn(t)
}

func TestXor(t *testing.T) {
	forEachXorImpl(t, func(t *testing.T) {
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
	})
}

func TestXorZeroKey(t *testing.T) {
	forEachXorImpl(t, func(t *testing.T) {
		var keys [4]uint64
		for _, size := range []int{0, 32, 64, 96, 128, 1024} {
			in := make([]byte, size)
			for i := range in {
				in[i] = byte(i)
			}
			out := make([]byte, size)
			xorSlice(in, out, &keys)
			if !bytes.Equal(in, out) {
				t.Fatalf("size %d: zero-key xor should copy input\nexpected %x\ngot      %x", size, in, out)
			}
			out2 := make([]byte, size)
			xor32Go(in, out2, &keys)
			if !bytes.Equal(in, out2) {
				t.Fatalf("size %d: zero-key xor32Go should copy input", size)
			}
		}
	})
}

func TestXorDoubleApply(t *testing.T) {
	forEachXorImpl(t, func(t *testing.T) {
		rng := rand.New(rand.NewSource(42))
		var keys [4]uint64
		for i := range keys {
			keys[i] = rng.Uint64()
		}
		for _, size := range []int{32, 64, 96, 128, 256, 1024, 4096} {
			in := make([]byte, size)
			_, _ = io.ReadFull(rng, in)
			orig := make([]byte, size)
			copy(orig, in)

			tmp := make([]byte, size)
			out := make([]byte, size)
			xorSlice(in, tmp, &keys)
			xorSlice(tmp, out, &keys)
			if !bytes.Equal(orig, out) {
				t.Fatalf("size %d: double xor should return original\nexpected %x\ngot      %x", size, orig[:32], out[:32])
			}
		}
	})
}

func TestXorAllSizes(t *testing.T) {
	forEachXorImpl(t, func(t *testing.T) {
		rng := rand.New(rand.NewSource(99))
		var keys [4]uint64
		for i := range keys {
			keys[i] = rng.Uint64()
		}
		in := make([]byte, 8192)
		_, _ = io.ReadFull(rng, in)

		for size := 0; size <= len(in); size += 32 {
			outAsm := make([]byte, size)
			outGo := make([]byte, size)
			xorSlice(in[:size], outAsm, &keys)
			xor32Go(in[:size], outGo, &keys)
			if !bytes.Equal(outAsm, outGo) {
				t.Fatalf("size %d: asm and Go disagree\nasm %x\ngo  %x", size, outAsm[:min(64, size)], outGo[:min(64, size)])
			}
		}
	})
}

func TestXorDistinctKeys(t *testing.T) {
	forEachXorImpl(t, func(t *testing.T) {
		in := make([]byte, 256)
		for i := range in {
			in[i] = byte(i)
		}
		keys1 := [4]uint64{1, 2, 3, 4}
		keys2 := [4]uint64{5, 6, 7, 8}
		out1 := make([]byte, 256)
		out2 := make([]byte, 256)
		xorSlice(in, out1, &keys1)
		xorSlice(in, out2, &keys2)
		if bytes.Equal(out1, out2) {
			t.Fatal("different keys should produce different output")
		}
	})
}

func TestXorKnownValues(t *testing.T) {
	forEachXorImpl(t, func(t *testing.T) {
		in := make([]byte, 32)
		for i := range in {
			in[i] = byte(i)
		}
		keys := [4]uint64{0x0807060504030201, 0x100f0e0d0c0b0a09, 0x1817161514131211, 0x201f1e1d1c1b1a19}
		out := make([]byte, 32)
		xor32Go(in, out, &keys)

		expected := make([]byte, 32)
		for i := 0; i < 32; i++ {
			keyBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(keyBytes, keys[i/8])
			expected[i] = in[i] ^ keyBytes[i%8]
		}
		if !bytes.Equal(out, expected) {
			t.Fatalf("known values mismatch\nexpected %x\ngot      %x", expected, out)
		}

		outAsm := make([]byte, 32)
		xorSlice(in, outAsm, &keys)
		if !bytes.Equal(outAsm, expected) {
			t.Fatalf("xorSlice known values mismatch\nexpected %x\ngot      %x", expected, outAsm)
		}
	})
}
