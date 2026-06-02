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

package certs_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/minio/pkg/v3/certs"
)

func updateCerts(crt, key string) {
	// ignore error handling
	crtSource, _ := os.Open(crt)
	defer crtSource.Close()
	crtDest, _ := os.Create("public.crt")
	defer crtDest.Close()
	io.Copy(crtDest, crtSource)

	keySource, _ := os.Open(key)
	defer keySource.Close()
	keyDest, _ := os.Create("private.key")
	defer keyDest.Close()
	io.Copy(keyDest, keySource)
}

func TestNewManager(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	c, err := certs.NewManager(ctx, "public.crt", "private.key", tls.LoadX509KeyPair)
	if err != nil {
		t.Fatal(err)
	}
	hello := &tls.ClientHelloInfo{}
	gcert, err := c.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	expectedCert, err := tls.LoadX509KeyPair("public.crt", "private.key")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gcert.Certificate, expectedCert.Certificate) {
		t.Error("certificate doesn't match expected certificate")
	}
	_, err = certs.NewManager(ctx, "public.crt", "new-private.key", tls.LoadX509KeyPair)
	if err == nil {
		t.Fatal("Expected to fail but got success")
	}

	allCerts := c.GetAllCertificates()
	var found bool
	for _, cert := range allCerts {
		if cert.Issuer.String() != "CN=minio.io,OU=Engineering,O=Minio,L=Redwood City,ST=CA,C=US" {
			t.Error("Unexpected cert issuer found")
		}
		found = true
	}
	if !found {
		t.Error("atleast one public cert is expected")
	}

	var nilMgr *certs.Manager
	if len(nilMgr.GetAllCertificates()) != 0 {
		t.Error("no public cert is expected")
	}
}

func TestValidPairAfterWrite(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	expectedCert, err := tls.LoadX509KeyPair("new-public.crt", "new-private.key")
	if err != nil {
		t.Fatal(err)
	}

	c, err := certs.NewManager(ctx, "public.crt", "private.key", tls.LoadX509KeyPair)
	if err != nil {
		t.Fatal(err)
	}

	updateCerts("new-public.crt", "new-private.key")
	defer updateCerts("original-public.crt", "original-private.key")

	// Wait for the write event. On Windows, file watching uses polling
	// instead of fsnotify, so we need a longer wait.
	wait := 200 * time.Millisecond
	if runtime.GOOS == "windows" {
		wait = 2 * time.Second
	}
	time.Sleep(wait)

	hello := &tls.ClientHelloInfo{}
	gcert, err := c.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gcert.Certificate, expectedCert.Certificate) {
		t.Error("certificate doesn't match expected certificate")
	}

	rInfo := &tls.CertificateRequestInfo{}
	gcert, err = c.GetClientCertificate(rInfo)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gcert.Certificate, expectedCert.Certificate) {
		t.Error("client certificate doesn't match expected certificate")
	}
}

func TestNonMatchingCertificate(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	c, err := certs.NewManager(ctx, "public.crt", "private.key", tls.LoadX509KeyPair)
	if err != nil {
		t.Fatal(err)
	}
	err = c.AddCertificate("server.crt", "server.key")
	if err != nil {
		t.Fatal(err)
	}

	hello := &tls.ClientHelloInfo{ServerName: "non-matching"}
	gcert, err := c.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	expectedCert, err := tls.LoadX509KeyPair("public.crt", "private.key")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gcert.Certificate, expectedCert.Certificate) {
		t.Error("certificate doesn't match expected certificate")
	}
	_, err = certs.NewManager(ctx, "public.crt", "new-private.key", tls.LoadX509KeyPair)
	if err == nil {
		t.Fatal("Expected to fail but got success")
	}
}

// copyTempCert copies src into dir/name and returns the full path.
func copyTempCert(t *testing.T, dir, name, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	return dst
}

func TestGetAllGlobalCertificates_ReturnsCert(t *testing.T) {
	dir := t.TempDir()
	crtFile := copyTempCert(t, dir, "public.crt", "public.crt")
	keyFile := copyTempCert(t, dir, "private.key", "private.key")

	expected, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	if _, err := certs.GetCertificate(crtFile, keyFile); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	var found bool
	for _, c := range certs.GetAllGlobalCertificates() {
		if bytes.Equal(c.Raw, expected.Certificate[0]) {
			found = true
			break
		}
	}
	if !found {
		t.Error("registered certificate not found in GetAllGlobalCertificates")
	}
}

func TestGetAllGlobalCertificates_DeduplicatesSamePair(t *testing.T) {
	dir := t.TempDir()
	crtFile := copyTempCert(t, dir, "public.crt", "public.crt")
	keyFile := copyTempCert(t, dir, "private.key", "private.key")

	if _, err := certs.GetCertificate(crtFile, keyFile); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	before := len(certs.GetAllGlobalCertificates())

	if _, err := certs.GetClientCertificate(crtFile, keyFile); err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	after := len(certs.GetAllGlobalCertificates())

	if after != before {
		t.Errorf("duplicate pair increased count from %d to %d", before, after)
	}
}

func TestGetAllGlobalCertificates_DeepCopy(t *testing.T) {
	dir := t.TempDir()
	crtFile := copyTempCert(t, dir, "public.crt", "public.crt")
	keyFile := copyTempCert(t, dir, "private.key", "private.key")

	if _, err := certs.GetCertificate(crtFile, keyFile); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	first := certs.GetAllGlobalCertificates()
	for i := range first {
		first[i].Subject.CommonName = "mutated"
	}

	for _, c := range certs.GetAllGlobalCertificates() {
		if c.Subject.CommonName == "mutated" {
			t.Error("GetAllGlobalCertificates returned a shared pointer instead of a deep copy")
		}
	}
}
