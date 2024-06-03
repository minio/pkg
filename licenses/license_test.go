// Copyright (c) 2015-2024 MinIO, Inc.
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

package license_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	license "github.com/minio/pkg/v3/licenses"
)

func ExampleParse() {
	const License = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrYW5hZ2FyYWorYzFAbWluaW8uaW8iLCJjYXAiOjUwLCJvcmciOiJHcmluZ290dHMgSW5jLiIsImV4cCI6MS42NDE0NDYxNjkwMDExOTg4OTRlOSwicGxhbiI6IlNUQU5EQVJEIiwiaXNzIjoic3VibmV0QG1pbi5pbyIsImFpZCI6MSwiaWF0IjoxLjYwOTkxMDE2OTAwMTE5ODg5NGU5fQ.EhTL2xwMHnUoLQF4UR-5bjUCja3whseLU5mb9XEj7PvAae6HEIDCOMEF8Hhh20DN_v_LRE283j2ZlA5zulcXSZXS0CLcrKqbVy6QLvZfvvLuerOjJI-NBa9dSJWJ0WoN"
	const Skew = 30 * 24 * time.Hour // 30 days

	options := []jwt.ParseOption{
		jwt.WithKeySet(publicKey()),
		jwt.UseDefaultKey(true),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(Skew),

		// Fix the clock such that the license seems to be not expired, yet.
		// Don't use this in production.
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return time.Unix(int64(1609910169), 0) })),
	}

	l, err := license.Parse(License, options...)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Org.:     ", l.Organization)
	fmt.Println("Plan:     ", l.Plan)
	fmt.Println("Capacrity:", l.StorageCap)
	fmt.Println("IssuedAt: ", l.IssuedAt)
	fmt.Println("ExpiresAt:", l.ExpiresAt)
	// Output:
	// Org.:      Gringotts Inc.
	// Plan:      STANDARD
	// Capacrity: 50
	// IssuedAt:  2021-01-06 05:16:09 +0000 UTC
	// ExpiresAt: 2022-01-06 05:16:09 +0000 UTC
}

func publicKey() jwk.Set {
	keyPEM := []byte(`-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbo+e1wpBY4tBq9AONKww3Kq7m6QP/TBQ
mr/cKCUyBL7rcAvg0zNq1vcSrUSGlAmY3SEDCu3GOKnjG/U4E7+p957ocWSV+mQU
9NKlTdQFGF3+aO6jbQ4hX/S5qPyF+a3z
-----END PUBLIC KEY-----`)

	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	jwKey, err := jwk.New(key.(*ecdsa.PublicKey))
	if err != nil {
		panic(err)
	}
	jwKey.Set(jwk.AlgorithmKey, jwa.ES384)

	set := jwk.NewSet()
	set.Add(jwKey)
	return set
}
