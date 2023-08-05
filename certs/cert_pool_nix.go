//go:build !windows
// +build !windows

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

package certs

import (
	"crypto/x509"
	"os"
	"strings"
)

// Possible directories with certificate files, this is an extended
// list from https://golang.org/src/crypto/x509/root_unix.go?#L18
// for k8s platform
var certDirectories = []string{
	"/var/run/secrets/kubernetes.io/serviceaccount",
}

func loadSystemRoots() (*x509.CertPool, error) {
	// Add additional ENV to load k8s CA certs.
	os.Setenv("SSL_CERT_DIR", strings.Join(certDirectories, ":"))
	defer os.Unsetenv("SSL_CERT_DIR")

	caPool, err := x509.SystemCertPool()
	if err != nil {
		return caPool, err
	}
	return caPool, nil
}
