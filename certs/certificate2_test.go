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
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func init() {
	// Reload symlinks every second for faster tests
	symlinkReloadInterval = time.Second
}

func TestNewCertificate2(t *testing.T) {
	cert, err := NewCertificate2("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to create certificate with key: %v", err)
	}
	defer cert.Close()

	if cert.Load() == nil {
		t.Error("Expected loaded certificate, got nil")
	}

	expectedCert, err := tls.LoadX509KeyPair("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	loadedCert := cert.Load()
	if !reflect.DeepEqual(loadedCert.Certificate, expectedCert.Certificate) {
		t.Error("Loaded certificate doesn't match expected certificate")
	}
}

func TestNewCertificate2_InvalidCertFile(t *testing.T) {
	_, err := NewCertificate2("nonexistent.crt", "private.key")
	if err == nil {
		t.Error("Expected error for nonexistent cert file, got nil")
	}
}

func TestNewCertificate2_InvalidKeyFile(t *testing.T) {
	_, err := NewCertificate2("public.crt", "nonexistent.key")
	if err == nil {
		t.Error("Expected error for nonexistent key file, got nil")
	}
}

func TestNewCertificate2_MismatchedPair(t *testing.T) {
	_, err := NewCertificate2("new-public.crt", "private.key")
	if err == nil {
		t.Error("Expected error for mismatched cert/key pair, got nil")
	}
}

func TestCertificate2Close(t *testing.T) {
	cert, err := NewCertificate2("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert.Close()
}

func TestCertificate2_AutoReload(t *testing.T) {
	testCertificate2AutoReload(t, false, false)
}

func TestCertificate2_AutoReloadWithRename(t *testing.T) {
	testCertificate2AutoReload(t, false, true)
}

func TestCertificate2_AutoReloadSymlink(t *testing.T) {
	testCertificate2AutoReload(t, true, false)
}

func testCertificate2AutoReload(t *testing.T, symlink, rename bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")
	tmpKey := filepath.Join(tmpDir, "test.key")

	copyFile(t, "public.crt", tmpCert, symlink)
	copyFile(t, "private.key", tmpKey, symlink)

	cert, err := NewCertificate2(tmpCert, tmpKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	originalCert := cert.Load()

	updateCertWithWait(t, cert, symlink, func() {
		overwriteFile(t, "new-public.crt", tmpCert, symlink, rename)
		overwriteFile(t, "new-private.key", tmpKey, symlink, rename)
	})

	newCert := cert.Load()
	if reflect.DeepEqual(originalCert.Certificate, newCert.Certificate) {
		t.Error("Certificate was not reloaded after file change")
	}

	expectedCert, err := tls.LoadX509KeyPair("new-public.crt", "new-private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Reloaded certificate doesn't match expected certificate")
	}
}

func TestCertificate2_AutoReloadCertFileOnly(t *testing.T) {
	testCertificate2AutoReloadCertFileOnly(t, false)
}

func TestCertificate2_AutoReloadCertFileOnlySymlink(t *testing.T) {
	testCertificate2AutoReloadCertFileOnly(t, true)
}

func testCertificate2AutoReloadCertFileOnly(t *testing.T, symlink bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")
	tmpKey := filepath.Join(tmpDir, "test.key")

	copyFile(t, "public.crt", tmpCert, symlink)
	copyFile(t, "private.key", tmpKey, symlink)

	cert, err := NewCertificate2(tmpCert, tmpKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	updateCertWithWait(t, cert, symlink, func() {
		overwriteFile(t, "new-public.crt", tmpCert, symlink, false)
		overwriteFile(t, "new-private.key", tmpKey, symlink, false)
	})

	newCert := cert.Load()

	expectedCert, err := tls.LoadX509KeyPair("new-public.crt", "new-private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Certificate was not reloaded after cert file change")
	}
}

func TestCertificate2_InvalidReloadIgnored(t *testing.T) {
	testCertificate2InvalidReloadIgnored(t, false)
}

func TestCertificate2_InvalidReloadIgnoredSymlink(t *testing.T) {
	testCertificate2InvalidReloadIgnored(t, true)
}

func testCertificate2InvalidReloadIgnored(t *testing.T, symlink bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")

	copyFile(t, "public.crt", tmpCert, symlink)

	cert, err := NewCertificate2(tmpCert, "private.key")
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	validCert := cert.Load()

	if symlink {
		tmpCert = tmpCert + ".tmp"
	}

	if err := os.WriteFile(tmpCert, []byte("invalid certificate data"), 0o600); err != nil {
		t.Fatalf("Failed to write invalid cert: %v", err)
	}

	waitForCert(symlink)

	currentCert := cert.Load()
	if !reflect.DeepEqual(validCert.Certificate, currentCert.Certificate) {
		t.Error("Certificate should remain unchanged after invalid reload attempt")
	}
}

func copyFile(t *testing.T, src, dst string, symlink bool) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read source file %s: %v", src, err)
	}
	tmp := dst
	if symlink {
		tmp = dst + ".tmp"
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("Failed to write destination file %s: %v", dst, err)
	}
	if symlink {
		if err := os.Symlink(tmp, dst); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}
	}
}

func overwriteFile(t *testing.T, src, dst string, symlink, rename bool) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read source file %s: %v", src, err)
	}
	if symlink {
		dst = dst + ".tmp"
	}
	if rename {
		tmpFile := dst + ".rename"
		if err := os.WriteFile(tmpFile, data, 0o600); err != nil {
			t.Fatalf("Failed to write destination file %s: %v", tmpFile, err)
		}
		// add a small delay to ensure the write event completes before the rename,
		// so the test verifies that the InMovedTo event triggers the reload
		time.Sleep(100 * time.Millisecond)
		if err := os.Rename(tmpFile, dst); err != nil {
			t.Fatalf("Failed to rename file %s to %s: %v", tmpFile, dst, err)
		}
	} else {
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatalf("Failed to write destination file %s: %v", dst, err)
		}
	}
}

func updateCertWithWait(t *testing.T, cert *Certificate2, symlink bool, update func()) {
	done := make(chan struct{})
	wait := 5 * time.Second
	if symlink {
		wait = wait + symlinkReloadInterval // can take up to symlinkReloadInterval to detect changes
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	unsub := cert.Subscribe(func(c *Certificate2) {
		if c != cert {
			t.Error("Received certificate does not match subscribed certificate")
		}
		close(done)
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

func waitForCert(symlink bool) {
	if symlink {
		time.Sleep(symlinkReloadInterval + time.Second)
	} else {
		time.Sleep(500 * time.Millisecond)
	}
}

// TestCertificate2_ConcurrentSubscriptions tests multiple subscribers receiving updates.
func TestCertificate2_ConcurrentSubscriptions(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")
	tmpKey := filepath.Join(tmpDir, "test.key")

	copyFile(t, "public.crt", tmpCert, false)
	copyFile(t, "private.key", tmpKey, false)

	cert, err := NewCertificate2(tmpCert, tmpKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	// Subscribe multiple subscribers concurrently
	const numSubscribers = 10
	done := make([]chan struct{}, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		done[i] = make(chan struct{})
		idx := i
		unsub := cert.Subscribe(func(c *Certificate2) {
			if c != cert {
				t.Errorf("Subscriber %d: received certificate does not match", idx)
			}
			done[idx] <- struct{}{}
		})
		defer unsub()
	}

	// Update the certificate
	updateCertWithWait(t, cert, false, func() {
		overwriteFile(t, "new-public.crt", tmpCert, false, false)
		overwriteFile(t, "new-private.key", tmpKey, false, false)
	})

	// Wait for all subscribers to be notified
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < numSubscribers; i++ {
		select {
		case <-done[i]:
			// Expected
		case <-ctx.Done():
			t.Errorf("Timeout waiting for subscriber %d notification", i)
		}
	}
}

// TestCertificate2_UnsubscribeDuringCallback tests unsubscribing while a callback is executing.
func TestCertificate2_UnsubscribeDuringCallback(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")
	tmpKey := filepath.Join(tmpDir, "test.key")

	copyFile(t, "public.crt", tmpCert, false)
	copyFile(t, "private.key", tmpKey, false)

	cert, err := NewCertificate2(tmpCert, tmpKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	var unsub func()
	callbackExecuted := make(chan struct{})

	unsub = cert.Subscribe(func(_ *Certificate2) {
		// Unsubscribe while callback is executing
		unsub()
		callbackExecuted <- struct{}{}
	})

	// Trigger an update
	updateCertWithWait(t, cert, false, func() {
		overwriteFile(t, "new-public.crt", tmpCert, false, false)
		overwriteFile(t, "new-private.key", tmpKey, false, false)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-callbackExecuted:
		// Expected - callback should execute and unsubscribe
	case <-ctx.Done():
		t.Error("Timeout waiting for callback execution")
	}

	// Verify we can still close cleanly
	cert.Close()
}

// TestCertificate2_MultipleUnsubscribes tests unsubscribing multiple times returns cleanly.
func TestCertificate2_MultipleUnsubscribes(t *testing.T) {
	cert, err := NewCertificate2("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	unsub := cert.Subscribe(func(_ *Certificate2) {})

	// Unsubscribe multiple times - should not panic
	unsub()
	unsub()
	unsub()
}

// TestCertificate2_LoadAfterClose tests that Load() works after Close().
func TestCertificate2_LoadAfterClose(t *testing.T) {
	cert, err := NewCertificate2("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	loadedBefore := cert.Load()
	if loadedBefore == nil {
		t.Fatal("Expected certificate before close")
	}

	cert.Close()

	// After close, Load() should still return the last loaded certificate
	loadedAfter := cert.Load()
	if loadedAfter == nil {
		t.Fatal("Expected certificate after close")
	}

	if !reflect.DeepEqual(loadedBefore.Certificate, loadedAfter.Certificate) {
		t.Fatal("Certificate changed after close")
	}
}
