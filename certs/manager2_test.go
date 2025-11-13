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

package certs

import (
	"context"
	"crypto/tls"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestManager2_Close(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt", "private.key")
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	mgr.Close()

	time.Sleep(100 * time.Millisecond)

	certs := mgr.certs.Load()
	if len(*certs) != 0 {
		t.Error("Expected certificates to be cleared after close")
	}
}

func TestManager2_CloseMultipleTimes(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt", "private.key")
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	mgr.Close()
	mgr.Close()
	mgr.Close()
}

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

// TestManager2_NoCertificates tests GetCertificate with no loaded certificates.
func TestManager2_NoCertificates(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		return []*Certificate2{}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Close()

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	_, err = mgr.GetCertificate(hello)
	if err == nil {
		t.Error("Expected error when no certificates are loaded")
	}

	reqInfo := &tls.CertificateRequestInfo{}
	_, err = mgr.GetClientCertificate(reqInfo)
	if err == nil {
		t.Error("Expected error when no certificates are loaded for mTLS")
	}
}

// TestManager2_GetCertificateNilHello tests GetCertificate with nil client hello.
func TestManager2_GetCertificateNilHello(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt", "private.key")
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

	_, err = mgr.GetCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil client hello")
	}
}

// TestManager2_GetClientCertificateNilReqInfo tests GetClientCertificate with nil request info.
func TestManager2_GetClientCertificateNilReqInfo(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt", "private.key")
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

	_, err = mgr.GetClientCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil certificate request info")
	}
}

// TestManager2_ConcurrentGetCertificate tests concurrent calls to GetCertificate.
func TestManager2_ConcurrentGetCertificate(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt", "private.key")
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

	done := make(chan error, 100)
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}

	// Launch concurrent calls
	for i := 0; i < 100; i++ {
		go func() {
			_, err := mgr.GetCertificate(hello)
			done <- err
		}()
	}

	// Wait for all to complete and check for errors
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < 100; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Concurrent GetCertificate failed: %v", err)
			}
		case <-ctx.Done():
			t.Error("Timeout waiting for concurrent calls to complete")
		}
	}
}

// TestManager2_HasCerts tests HasCerts method.
func TestManager2_HasCerts(t *testing.T) {
	// Test with no certificates
	loadCertsEmpty := func() ([]*Certificate2, error) {
		return []*Certificate2{}, nil
	}

	mgr, err := NewManager2(loadCertsEmpty)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Close()

	if mgr.HasCerts() {
		t.Error("Expected HasCerts to return false when no certificates are loaded")
	}

	// Test with certificates
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt", "private.key")
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr2, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr2.Close()

	if !mgr2.HasCerts() {
		t.Error("Expected HasCerts to return true when certificates are loaded")
	}
}
