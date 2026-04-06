// Copyright (c) 2025 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//go:build unix

package certs

import (
	"context"
	"crypto/tls"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestManager2_ReloadOnSIGHUP(t *testing.T) {
	callCount := 0
	loadCerts := func() ([]*Certificate2, error) {
		certFile, keyFile := "public.crt", "private.key"
		if callCount%2 == 1 {
			certFile, keyFile = "new-public.crt", "new-private.key"
		}
		callCount++

		cert, err := NewCertificate2(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Close()

	originalCerts := mgr.certs.Load()
	originalCert := (*originalCerts)[0].Load()

	updateReloadWithWait(t, mgr, func() {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("Failed to send SIGHUP: %v", err)
		}
	})

	newCerts := mgr.certs.Load()
	newCert := (*newCerts)[0].Load()

	if reflect.DeepEqual(originalCert.Certificate, newCert.Certificate) {
		t.Error("Expected certificates to be reloaded after SIGHUP")
	}

	expectedCert, err := tls.LoadX509KeyPair("new-public.crt", "new-private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Reloaded certificate doesn't match expected certificate")
	}
}

func updateReloadWithWait(t *testing.T, mgr *Manager2, update func()) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	unsub := mgr.Subscribe(func(c *Certificate2) {
		if c == nil {
			close(done)
		}
	})
	defer unsub()

	update()

	select {
	case <-done:
		// expected result
	case <-ctx.Done():
		t.Error("Timeout waiting for certificate update")
	}
}
