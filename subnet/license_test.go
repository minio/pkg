// Copyright (c) 2015-2023 MinIO, Inc.
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

package subnet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// newTestLicenseKey returns an ECDSA key and its PKIX PEM encoding, which is
// what LicenseValidator expects in offlinePubKey.
func newTestLicenseKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate license key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal license public key: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// signTestLicense builds a license JWT with the claims licverifier requires.
func signTestLicense(t *testing.T, key *ecdsa.PrivateKey, plan string, expiresAt time.Time) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Subject("test@min.io").
		Claim("aid", int64(1)).
		Claim("org", "Test Org").
		Claim("cap", int64(1)).
		Claim("plan", plan).
		IssuedAt(time.Now().Add(-time.Hour)).
		Expiration(expiresAt).
		Build()
	if err != nil {
		t.Fatalf("failed to build test license: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES384(), key))
	if err != nil {
		t.Fatalf("failed to sign test license: %v", err)
	}
	return string(signed)
}

// TestValidateEnterpriseLicenseSchedulesOneCheck verifies that repeated
// validation calls replace the pending check instead of scheduling more.
func TestValidateEnterpriseLicenseSchedulesOneCheck(t *testing.T) {
	key, pubKey := newTestLicenseKey(t)
	lv := &LicenseValidator{
		LicenseToken:  signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second)),
		offlinePubKey: pubKey,
	}
	licExpiredChan := make(chan string, 5)

	for i := range 5 {
		if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, licExpiredChan); err != nil {
			t.Fatalf("validation %d failed: %v", i, err)
		}
	}

	select {
	case <-licExpiredChan:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the license expiry notification")
	}

	// A leaked check would report the same expiry again.
	select {
	case <-licExpiredChan:
		t.Fatal("multiple license checks were scheduled")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestValidateEnterpriseLicenseKeepsRenewalAfterExpiry verifies that a renewal
// issued immediately after receiving the expiry notification is monitored.
func TestValidateEnterpriseLicenseKeepsRenewalAfterExpiry(t *testing.T) {
	key, pubKey := newTestLicenseKey(t)
	lv := &LicenseValidator{
		LicenseToken:  signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second)),
		offlinePubKey: pubKey,
	}
	licExpiredChan := make(chan string)

	if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, licExpiredChan); err != nil {
		t.Fatalf("initial validation failed: %v", err)
	}

	select {
	case <-licExpiredChan:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the license expiry notification")
	}

	// Renew immediately after the notification.
	lv.LicenseToken = signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second))
	if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, licExpiredChan); err != nil {
		t.Fatalf("validation of renewed license failed: %v", err)
	}

	select {
	case <-licExpiredChan:
	case <-time.After(10 * time.Second):
		t.Fatal("renewed license expiry was not reported")
	}
}

// TestValidateEnterpriseLicenseRenewalRetargetsAndRearms verifies that a
// renewal replaces the pending check so the renewed expiry is used and the
// notification goes to the channel of the most recent successful call.
func TestValidateEnterpriseLicenseRenewalRetargetsAndRearms(t *testing.T) {
	key, pubKey := newTestLicenseKey(t)
	lv := &LicenseValidator{
		LicenseToken:  signTestLicense(t, key, "STANDARD", time.Now().Add(30*time.Second)),
		offlinePubKey: pubKey,
	}
	prevChan := make(chan string, 1)
	nextChan := make(chan string, 1)

	if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, prevChan); err != nil {
		t.Fatalf("initial validation failed: %v", err)
	}

	// Renew with a license that expires much sooner, on a new channel. The
	// pending check must not keep waiting for the original 30s expiry.
	lv.LicenseToken = signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second))
	if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, nextChan); err != nil {
		t.Fatalf("validation of renewed license failed: %v", err)
	}

	select {
	case <-nextChan:
	case <-time.After(10 * time.Second):
		t.Fatal("renewed license expiry was not reported on the new channel")
	}

	select {
	case <-prevChan:
		t.Fatal("expiry notification was sent to the previous channel")
	default:
	}
}
