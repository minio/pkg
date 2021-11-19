//go:build !amd64 || noasm || appengine || gccgo
// +build !amd64 noasm appengine gccgo

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

import "encoding/binary"

func xorSlice(rand, out []byte) {
	var a0, a1 uint64
	a0 = binary.LittleEndian.Uint64(rand)
	a1 = binary.LittleEndian.Uint64(rand[8:])
	for len(out) >= 32 {
		v0 := binary.LittleEndian.Uint64(out[:]) ^ a0
		v1 := binary.LittleEndian.Uint64(out[8:]) ^ a1
		v2 := binary.LittleEndian.Uint64(out[16:]) ^ a0
		v3 := binary.LittleEndian.Uint64(out[24:]) ^ a1
		binary.LittleEndian.PutUint64(out[:], v0)
		binary.LittleEndian.PutUint64(out[8:], v1)
		binary.LittleEndian.PutUint64(out[16:], v2)
		binary.LittleEndian.PutUint64(out[24:], v3)
		out = out[32:]
	}
}
