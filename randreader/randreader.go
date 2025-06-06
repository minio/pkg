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
	"time"

	"github.com/minio/pkg/v3/rng"
)

// New returns an infinite reader that will return pseudo-random data.
// Data should not be used for cryptographic functions.
// A random time based seed is used.
func New() io.Reader {
	return NewSource(rand.NewSource(time.Now().UnixNano()))
}

// NewSource returns an infinite reader that will return pseudo-random data.
// Data should not be used for cryptographic functions.
// The data is seeded from the provided source.
func NewSource(src rand.Source) io.Reader {
	r, err := rng.NewReader(rng.WithRNG(rand.New(src)))
	if err != nil {
		panic(err)
	}
	return r
}
