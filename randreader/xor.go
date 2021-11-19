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
	"errors"
	"math/rand"
)

type xorBuffer struct {
	data []byte
	// left aliases the data at the current read position.
	left []byte

	tmp [16]byte
	rng *rand.Rand
}

func newXorBuffer(data []byte, rng *rand.Rand) *xorBuffer {
	return &xorBuffer{
		data: data,
		left: data,
		rng:  rng,
	}
}

func (c *xorBuffer) Read(p []byte) (n int, err error) {
	if len(c.data) == 0 {
		return 0, errors.New("circularBuffer: no data")
	}
	for len(p) > 0 {
		if len(c.left) == 0 {
			// Read 16 random bytes for xor
			c.rng.Read(c.tmp[:])
			xorSlice(c.tmp[:], c.data)
			c.left = c.data
		}

		// Make sure we don't overread.
		toDo := c.left
		copied := copy(p, toDo)
		// Assign remaining back to c.left
		c.left = toDo[copied:]
		p = p[copied:]
		n += copied
	}
	return n, nil
}
