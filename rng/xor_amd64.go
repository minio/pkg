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

//go:build !noasm && !appengine && !gccgo && !purego

package rng

import "github.com/klauspost/cpuid/v2"

func xorSlice(in, out []byte, v *[4]uint64) {
	if cpuid.CPU.Has(cpuid.AVX2) {
		xorSliceAvx2(in, out, v)
	} else {
		xorSliceSSE2(in, out, v)
	}
}

//go:noescape
func xorSliceSSE2(in, out []byte, v *[4]uint64)

//go:noescape
func xorSliceAvx2(in, out []byte, v *[4]uint64)
