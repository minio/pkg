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

package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/rjeczalik/notify"
)

// LoadX509KeyPairFunc is a function that parses a private key and
// certificate file and returns a TLS certificate on success.
type LoadX509KeyPairFunc func(certFile, keyFile string) (tls.Certificate, error)

// GetCertificateFunc is a callback that allows a TLS stack deliver different
// certificates based on the client trying to establish a TLS connection.
//
// For example, a GetCertificateFunc can return different TLS certificates depending
// upon the TLS SNI sent by the client.
type GetCertificateFunc func(hello *tls.ClientHelloInfo) (*tls.Certificate, error)

// Manager is a TLS certificate manager that can handle multiple certificates.
// When a client tries to establish a TLS connection, Manager will try to
// pick a certificate that can be validated by the client.
//
// For instance, if the client specifies a TLS SNI then Manager will try to
// find the corresponding certificate. If there is no such certificate it
// will fallback to the certificate named public.crt.
//
// Manager will automatically reload certificates if the corresponding file changes.
type Manager struct {
	lock         sync.RWMutex
	certificates map[pair]*tls.Certificate // Mapping: certificate file name => TLS certificates
	defaultCert  pair

	loadX509KeyPair LoadX509KeyPairFunc
	done            <-chan struct{}
	reloadCerts     []chan struct{}
}

// pair represents a certificate and private key file tuple.
type pair struct {
	KeyFile  string
	CertFile string
}

// NewManager returns a new Manager that handles one certificate specified via
// the certFile and keyFile. It will use the loadX509KeyPair function to (re)load
// certificates.
//
// The certificate loaded from certFile is considered the default certificate.
// If a client does not send the TLS SNI extension then Manager will return
// this certificate.
func NewManager(ctx context.Context, certFile, keyFile string, loadX509KeyPair LoadX509KeyPairFunc) (manager *Manager, err error) {
	certFile, err = filepath.Abs(certFile)
	if err != nil {
		return nil, err
	}
	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return nil, err
	}

	manager = &Manager{
		certificates: map[pair]*tls.Certificate{},
		defaultCert: pair{
			KeyFile:  keyFile,
			CertFile: certFile,
		},
		loadX509KeyPair: loadX509KeyPair,
		done:            ctx.Done(),
	}
	if err := manager.AddCertificate(certFile, keyFile); err != nil {
		return nil, err
	}
	return manager, nil
}

// AddCertificate adds the TLS certificate in certFile resp. keyFile
// to the Manager.
//
// If there is already a certificate with the same base name it will be
// replaced by the newly added one.
func (m *Manager) AddCertificate(certFile, keyFile string) (err error) {
	certFile, err = filepath.Abs(certFile)
	if err != nil {
		return err
	}
	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return err
	}
	certFileIsLink, err := isSymlink(certFile)
	if err != nil {
		return err
	}
	keyFileIsLink, err := isSymlink(keyFile)
	if err != nil {
		return err
	}
	if certFileIsLink && !keyFileIsLink {
		return fmt.Errorf("certs: '%s' is a symlink but '%s' is a regular file", certFile, keyFile)
	}
	if keyFileIsLink && !certFileIsLink {
		return fmt.Errorf("certs: '%s' is a symlink but '%s' is a regular file", keyFile, certFile)
	}

	certificate, err := m.loadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We set the certificate leaf to the actual certificate such that
	// we don't have to do the parsing (multiple times) when matching the
	// certificate to the client hello. This a performance optimisation.
	if certificate.Leaf == nil {
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return err
		}
	}

	p := pair{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	// We don't allow IP SANs in certificates - except for the "default" certificate
	// which is, by convention, the first certificate added to the manager. The problem
	// with allowing IP SANs in more than one certificate is that the manager usually can't
	// match the client SNI to a SAN since the SNI is meant to communicate the destination
	// host name and clients will not set the SNI to an IP address.
	// Allowing multiple certificates with IP SANs lead to errors that confuses users - like:
	// "It works for `https://instance.minio.local` but not for `https://10.0.2.1`"
	if len(m.certificates) > 0 && len(certificate.Leaf.IPAddresses) > 0 {
		return errors.New("cert: certificate must not contain any IP SANs: only the default certificate may contain IP SANs")
	}
	m.certificates[p] = &certificate

	if certFileIsLink && keyFileIsLink {
		go m.watchSymlinks(p, m.reloader())
	} else {
		// Windows doesn't allow for watching file changes but instead allows
		// for directory changes only, while we can still watch for changes
		// on files on other platforms. Watch parent directory on all platforms
		// for simplicity.
		events := make(chan notify.EventInfo, 1)

		if err = notify.Watch(filepath.Dir(certFile), events, eventWrite...); err != nil {
			return err
		}
		if err = notify.Watch(filepath.Dir(keyFile), events, eventWrite...); err != nil {
			return err
		}
		go m.watchFileEvents(p, events, m.reloader())
	}
	return nil
}

// reloader creates and registers a reloader.
// m must be locked when called.
func (m *Manager) reloader() <-chan struct{} {
	ch := make(chan struct{}, 1)
	m.reloadCerts = append(m.reloadCerts, ch)
	return ch
}

// ReloadOnSignal specifies one or more signals that will trigger certificates reloading.
// If called multiple times with the same signal certificates
func (m *Manager) ReloadOnSignal(sig ...os.Signal) {
	if len(sig) == 0 {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			select {
			case <-m.done:
				signal.Stop(ch)
				return
			case <-ch:
				m.ReloadCerts()
			}
		}
	}()
}

// ReloadCerts will forcefully reload all certs.
func (m *Manager) ReloadCerts() {
	m.lock.RLock()
	defer m.lock.RUnlock()
	for _, ch := range m.reloadCerts {
		// Non-blocking
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// watchSymlinks starts an endless loop reloading the
// certFile and keyFile periodically.
func (m *Manager) watchSymlinks(watch pair, reload <-chan struct{}) {
	t := time.NewTimer(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return // Once stopped exits this routine.
		case <-t.C:
		case <-reload:
		}
		certificate, err := m.loadX509KeyPair(watch.CertFile, watch.KeyFile)
		if err != nil {
			continue
		}
		if certificate.Leaf == nil { // This is a performance optimisation
			certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				continue
			}
		}

		m.lock.Lock()
		m.certificates[watch] = &certificate
		m.lock.Unlock()
	}
}

// watchFileEvents starts an endless loop waiting for file systems events.
// Once an event occurs it reloads the private key and certificate that
// has changed, if any.
func (m *Manager) watchFileEvents(watch pair, events chan notify.EventInfo, reload <-chan struct{}) {
	for {
		select {
		case <-m.done:
			return
		case event := <-events:
			if !isWriteEvent(event.Event()) {
				continue
			}
			p := event.Path()
			if watch.KeyFile != p && watch.CertFile != p {
				continue
			}
		case <-reload:
		}
		// Do reload
		certificate, err := m.loadX509KeyPair(watch.CertFile, watch.KeyFile)
		if err != nil {
			continue
		}
		if certificate.Leaf == nil { // This is performance optimisation
			certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				continue
			}
		}
		m.lock.Lock()
		m.certificates[watch] = &certificate
		m.lock.Unlock()
	}
}

// GetCertificate returns a TLS certificate based on the client hello.
//
// It tries to find a certificate that would be accepted by the client
// according to the client hello. However, if no certificate can be
// found GetCertificate returns the certificate loaded from the
// Public file.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	// If the client does not send a SNI we return the "default"
	// certificate. A client may not send a SNI - e.g. when trying
	// to connect to an IP directly (https://<ip>:<port>).
	//
	// In this case we don't know which the certificate the client
	// asks for. It may be a public-facing certificate issued by a
	// public CA or an internal certificate containing internal domain
	// names.
	// Now, we should not serve "the first" certificate that would be
	// accepted by the client based on the Client Hello. Otherwise, we
	// may expose an internal certificate to the client that contains
	// internal domain names. That way we would disclose internal
	// infrastructure details.
	//
	// Therefore, we serve the "default" certificate - which by convention
	// is the first certificate added to the Manager. It's the calling code's
	// responsibility to ensure that the "public-facing" certificate is used
	// when creating a Manager instance.
	if hello.ServerName == "" {
		certificate := m.certificates[m.defaultCert]
		return certificate, nil
	}

	// Optimization: If there is just one certificate, always serve that one.
	if len(m.certificates) == 1 {
		for _, certificate := range m.certificates {
			return certificate, nil
		}
	}

	// Iterate over all certificates and return the first one that would
	// be accepted by the peer (TLS client) based on the client hello.
	// In particular, the client usually specifies the requested host/domain
	// via SNI.
	//
	// Note: The certificate.Leaf should be non-nil and contain the actual
	// client certificate of MinIO that should be presented to the peer (TLS client).
	// Otherwise, the leaf certificate has to be parsed again - which is kind of
	// expensive and may cause a performance issue. For more information, check the
	// docs of tls.ClientHelloInfo.SupportsCertificate.
	for _, certificate := range m.certificates {
		if err := hello.SupportsCertificate(certificate); err == nil {
			return certificate, nil
		}
	}
	return nil, errors.New("certs: no server certificate is supported by peer")
}

// GetClientCertificate returns a TLS certificate for mTLS based on the
// certificate request.
//
// It tries to find a certificate that would be accepted by the server
// according to the certificate request. However, if no certificate can be
// found GetClientCertificate returns the certificate loaded from the
// Public file.
func (m *Manager) GetClientCertificate(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	// Optimization: If there is just one certificate, always serve that one.
	if len(m.certificates) == 1 {
		for _, certificate := range m.certificates {
			return certificate, nil
		}
	}

	// Iterate over all certificates and return the first one that would
	// be accepted by the peer (TLS server) based on reqInfo.
	//
	// Note: The certificate.Leaf should be non-nil and contain the actual
	// client certificate of MinIO that should be presented to the peer (TLS server).
	// Otherwise, the leaf certificate has to be parsed again - which is kind of
	// expensive and may cause a performance issue. For more information, check the
	// docs of tls.CertificateRequestInfo.SupportsCertificate.
	for _, certificate := range m.certificates {
		if err := reqInfo.SupportsCertificate(certificate); err == nil {
			return certificate, nil
		}
	}
	return nil, errors.New("certs: no client certificate is supported by peer")
}

// isSymlink returns true if the given file
// is a symbolic link.
func isSymlink(file string) (bool, error) {
	st, err := os.Lstat(file)
	if err != nil {
		return false, err
	}
	return st.Mode()&os.ModeSymlink == os.ModeSymlink, nil
}
