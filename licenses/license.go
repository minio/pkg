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

// Package license provides functions for verifying MinIO licenses.
//
// A simple way to do that is:
//
//	func init() {
//		l, err := license.Verify()
//		if err != nil {
//			fmt.Fprintln(os.Stderr, "Error:", err)
//			os.Exit(1)
//		}
//		if time.Now().After(l.ExpiresAt) {
//			fmt.Fprintf(os.Stderr, "Warning: license expired on %v! Renew and restart immediately to avoid outage.\n", l.ExpiresAt)
//		}
//		if time.Now().After(l.NotAfter) {
//			fmt.Fprintln(os.Stderr, "Error: license has expired. Terminating process...")
//			os.Exit(1)
//		}
//		go func() {
//			<-time.NewTimer(time.Until(l.ExpiresAt)).C
//			fmt.Fprintf(os.Stderr, "Warning: license expired on %v! Process will be terminated soon. Renew and restart immediately to avoid outage.\n", l.ExpiresAt)
//
//			<-time.NewTimer(time.Until(l.NotAfter)).C
//			fmt.Fprintln(os.Stderr, "Error: license has expired. Terminating process...")
//			os.Exit(1)
//		}()
//	}
//
// For a smooth developer experience, consider enabling license verification only for release builds.
// This can be achieved via build tags. For example, create a license.go file containing the init
// function from above and use the build tag "//go:build !dev". When building the binary using
// "go build -tags dev", license verification is disabled. Otherwise, a license is required.
package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"

	"time"
)

const publicKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaK31xujr6/rZ7ZfXZh3SlwovjC+X8wGq
qkltaKyTLRENd4w3IRktYYCRgzpDLPn/nrf7snV/ERO5qcI7fkEES34IVEr+2Uff
JkO2PfyyAYEO/5dBlPh1Undu9WQl6J7B
-----END PUBLIC KEY-----`

const (
	licenseFile = "minio.license"
	licenseVar  = "MINIO_LICENSE"
	licenseSkew = 30 * 24 * time.Hour

	licenseIssuer = "subnet@min.io"
)

// license plans
const (
	planEnterpriseLite = "ENTERPRISE-LITE"
	planEnterprisePlus = "ENTERPRISE-PLUS"
)

// license token field names
const (
	jwtLicenseID       = "lid"
	jwtAccountID       = "aid"
	jwtOrganization    = "org"
	jwtStorageCapacity = "cap"
	jwtPlan            = "plan"
	jwtTrial           = "trial"
)

// License is a structure containing MinIO license information.
type License struct {
	ID           string    // The license ID
	Organization string    // Name of the organization using the license
	AccountID    uint64    // ID of the account using the license
	Plan         string    // License plan. E.g. "ENTERPRISE-PLUS"
	StorageCap   uint64    // Storage capacity in bytes covered by the license
	IssuedAt     time.Time // Point in time when the license was issued
	ExpiresAt    time.Time // Point in time when the license expires
	NotAfter     time.Time // Point in time when the license must no longer considered valid
	Trial        bool      // Whether the license is on trial
}

// Parse parses s as MinIO license. The license parsing and verification
// can be customized using JWT parse options. Returns a verified license
// on success.
//
// To verify whether the license has been issued by the expected private
// key, pass the public key as parse option via jwt.WithKeySet.
func Parse(s string, opts ...jwt.ParseOption) (License, error) {
	fail := func(err error) (License, error) { return License{}, err }

	token, err := jwt.Parse([]byte(s), opts...)
	if err != nil {
		return fail(err)
	}

	claims, err := token.AsMap(context.Background())
	if err != nil {
		return fail(err)
	}
	if token.Issuer() != licenseIssuer {
		return fail(errors.New("license: not issued by " + licenseIssuer))
	}

	accountID, ok := claims[jwtAccountID].(float64)
	if !ok || accountID < 0 {
		return fail(errors.New("license: token contains no or invalid account ID"))
	}
	org, ok := claims[jwtOrganization].(string)
	if !ok {
		return fail(errors.New("license: token contains no organization"))
	}
	storageCap, ok := claims[jwtStorageCapacity].(float64)
	if !ok {
		return fail(errors.New("license: token contains no storage capacity"))
	}
	plan, ok := claims[jwtPlan].(string)
	if !ok {
		return fail(errors.New("license: token contains no plan"))
	}

	// The following fields are not present in older licenses.
	// Hence, we cannot require them
	licenseID, _ := claims[jwtLicenseID].(string)
	isTrial, _ := claims[jwtTrial].(bool)

	return License{
		ID:           licenseID,
		Organization: org,
		AccountID:    uint64(accountID),
		Plan:         plan,
		StorageCap:   uint64(storageCap),
		IssuedAt:     token.IssuedAt(),
		ExpiresAt:    token.Expiration(),
		NotAfter:     token.Expiration(),
		Trial:        isTrial,
	}, nil
}

// Verify checks whether a valid license is provided.
//
// Therefore, it first searches for a license in the following order:
//  1. File referenced by MINIO_LICENSE env var, if any.
//  2. A "./minio.license" file in the current working directory.
//  3. The $HOME/"." + os.Args[0]/minio.license file if there are os.Args.
//
// If no license is present, Verify returns an error.
// The license must also be issued after time.Now and,
// in case of a trial license, must not be expired.
// For non-trial licenses, a 30 day grace period is granted.
func Verify() (License, error) {
	fail := func(err error) (License, error) { return License{}, err }

	var (
		license []byte
		err     error
	)
	if filename, ok := os.LookupEnv(licenseVar); ok && filename != "" {
		license, err = os.ReadFile(filename)
		if err != nil {
			return fail(fmt.Errorf("license: %v", err))
		}
	}
	if license == nil {
		license, _ = os.ReadFile(licenseFile)
	}
	if license == nil && len(os.Args) > 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return fail(fmt.Errorf("license: %v", err))
		}

		if license, err = os.ReadFile(filepath.Join(home, "."+os.Args[0], licenseFile)); err != nil {
			return fail(fmt.Errorf("license: %v", err))
		}
	}
	if license == nil {
		return fail(errors.New("license: no license provided"))
	}

	l, err := Parse(string(license), jwt.WithKeySet(PublicKey()), jwt.UseDefaultKey(true), jwt.WithValidate(true), jwt.WithAcceptableSkew(licenseSkew))
	if err != nil {
		return fail(err)
	}
	if l.IssuedAt.After(time.Now()) {
		return fail(errors.New("license: license is not yet valid"))
	}
	if l.Plan != planEnterpriseLite && l.Plan != planEnterprisePlus {
		return fail(fmt.Errorf("license: either %s or %s plan required", planEnterpriseLite, planEnterprisePlus))
	}
	if l.Trial && time.Now().After(l.ExpiresAt) {
		return fail(fmt.Errorf("license: trial license expired on %v", l.ExpiresAt))
	}
	if !l.Trial {
		l.NotAfter = l.NotAfter.Add(licenseSkew)
	}
	return l, nil
}

// PublicKey returns the MinIO default public key for verifying a license.
func PublicKey() jwk.Set {
	key, err := parsePublicKey([]byte(publicKey))
	if err != nil {
		panic(err)
	}
	jwKey, err := jwk.New(key)
	if err != nil {
		panic(err)
	}
	jwKey.Set(jwk.AlgorithmKey, jwa.ES384)

	set := jwk.NewSet()
	set.Add(jwKey)
	return set
}

// parsePublicKey extracts an ECDSA public key from the given PEM block.
// It returns an error if the PEM data contains no ECDSA public key.
func parsePublicKey(keyPEM []byte) (*ecdsa.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(keyPEM); block == nil {
		return nil, errors.New("license: invalid public key: key must be a PEM encoded PKCS1 or PKCS8 key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			key = cert.PublicKey
		} else {
			return nil, fmt.Errorf("license: failed to parse public key: %v", err)
		}
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("license: public key is not a valid ECDSA key")
	}
	return ecKey, nil
}
