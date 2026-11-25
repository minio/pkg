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
	"runtime"
	"strings"
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

// countLicenseSchedulers counts the background license schedulers of this
// process by looking for their stack frames.
func countLicenseSchedulers() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "scheduleNextLicenseCheck")
}

// waitForSchedulerStop waits for the background scheduler to exit, so tests do
// not leak goroutines into each other.
func waitForSchedulerStop(t *testing.T, lv *LicenseValidator) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for lv.schedulerRunning.Load() {
		if time.Now().After(deadline) {
			t.Fatal("license scheduler did not stop")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestValidateEnterpriseLicenseStartsOneScheduler verifies that repeated
// validation calls do not keep spawning background schedulers.
func TestValidateEnterpriseLicenseStartsOneScheduler(t *testing.T) {
	key, pubKey := newTestLicenseKey(t)
	lv := &LicenseValidator{
		LicenseToken:  signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second)),
		offlinePubKey: pubKey,
	}
	licExpiredChan := make(chan string, 1)

	for i := range 5 {
		if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, licExpiredChan); err != nil {
			t.Fatalf("validation %d failed: %v", i, err)
		}
	}

	// Give the started goroutines a chance to show up in the stack dump.
	time.Sleep(100 * time.Millisecond)

	if got := countLicenseSchedulers(); got != 1 {
		t.Fatalf("expected exactly 1 background license check, got %d", got)
	}

	waitForSchedulerStop(t, lv)
}

// TestValidateEnterpriseLicenseResumesSchedulerAfterExpiry verifies that a
// failed check releases the scheduler, so a renewed license is monitored again.
func TestValidateEnterpriseLicenseResumesSchedulerAfterExpiry(t *testing.T) {
	key, pubKey := newTestLicenseKey(t)
	lv := &LicenseValidator{
		LicenseToken:  signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second)),
		offlinePubKey: pubKey,
	}
	licExpiredChan := make(chan string, 1)

	if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, licExpiredChan); err != nil {
		t.Fatalf("initial validation failed: %v", err)
	}

	select {
	case <-licExpiredChan:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the license expiry notification")
	}

	// Wait for the scheduler to fully exit before renewing the license.
	waitForSchedulerStop(t, lv)

	lv.LicenseToken = signTestLicense(t, key, "STANDARD", time.Now().Add(2*time.Second))
	if _, err := lv.ValidateEnterpriseLicense([]string{"STANDARD"}, licExpiredChan); err != nil {
		t.Fatalf("validation of renewed license failed: %v", err)
	}

	select {
	case <-licExpiredChan:
	case <-time.After(10 * time.Second):
		t.Fatal("renewed license expiry was not reported, scheduler was not restarted")
	}

	waitForSchedulerStop(t, lv)
}
