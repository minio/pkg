// Copyright (c) 2025 MinIO, Inc.
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

// Manager2 manages TLS certificates and automatically reloads them
// when the underlying files change or a SIGHUP signal is received.
type Manager2 struct {
	closed           int32
	close            chan<- struct{}
	certs            atomic.Pointer[[]*Certificate2]
	subscriptionLock sync.Mutex
	subscriptions    []chan *Certificate2
}

// NewManager2 creates a new certificate manager which loads certificates
// using the provided loadCerts function. The manager will automatically
// update the loaded certificates when:
//   - The underlying file changed (reloads a single certificate)
//   - A SIGHUP signal is received (this will rescan all certificates)
//
// The manager is using internal synchronization and is safe for concurrent
// use. Make sure to call Close when the manager is no longer needed.
func NewManager2(loadCerts func() ([]*Certificate2, error)) (*Manager2, error) {
	certUpdateCh := make(chan *Certificate2, 1)

	// Load initial certificates
	certs, err := loadCerts()
	if err != nil {
		return nil, err
	}

	// Subscribe to initial certificates
	for _, cert := range certs {
		// no need to store the close function, because
		// certificates are closed when they are replaced
		// and that will automatically close all subscriptions.
		cert.Subscribe(func(updatedCert *Certificate2) {
			certUpdateCh <- updatedCert
		})
	}

	closeCh := make(chan struct{})

	mgr := Manager2{
		close: closeCh,
	}
	mgr.certs.Store(&certs)

	replaceCerts := func(newCerts []*Certificate2) {
		oldCerts := mgr.certs.Swap(&newCerts)
		for i := range *oldCerts {
			(*oldCerts)[i].Close()
		}

		for _, cert := range newCerts {
			cert.Subscribe(func(updatedCert *Certificate2) {
				certUpdateCh <- updatedCert
			})
		}
		certUpdateCh <- nil
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		defer signal.Stop(signalCh)
		defer func() {
			mgr.subscriptionLock.Lock()
			defer mgr.subscriptionLock.Unlock()
			for _, sub := range mgr.subscriptions {
				close(sub)
			}
		}()

		for {
			select {
			case <-closeCh:
				// clear certificates on close
				replaceCerts([]*Certificate2{})
				return
			case cert := <-certUpdateCh:
				// certificates are updated
				mgr.subscriptionLock.Lock()
				// use a copy to prevent deadlocks when sending to the channel
				subs := append([]chan *Certificate2{}, mgr.subscriptions...)
				mgr.subscriptionLock.Unlock()
				for _, sub := range subs {
					select {
					case sub <- cert:
					default:
						// Channel is full; subscriber is not consuming notifications.
						// Skip this notification to avoid blocking the reload goroutine.
					}
				}
			case <-signalCh:
				certs, err := loadCerts()
				if err == nil {
					replaceCerts(certs)
				}
				// Silently skip reload on SIGHUP if loadCerts fails.
				// Keep using the currently loaded certificates.
			}
		}
	}()

	return &mgr, nil
}

// Close stops the certificate manager and releases all resources.
func (m *Manager2) Close() {
	// only close once
	if atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		close(m.close)
	}
}

// Subscribe will register a callback which is called when one or all
// certificates have been reloaded. The callback receives the updated
// certificate when a single certificate is reloaded or `nil` when
// all certificates have been reloaded. Closing the manager will
// automatically unsubscribe all subscribers.
//
// Make sure not to block in the callback to avoid blocking the
// internal certificate reloading goroutine.
func (m *Manager2) Subscribe(callback func(*Certificate2)) func() {
	ch := make(chan *Certificate2, 1)
	m.subscriptionLock.Lock()
	defer m.subscriptionLock.Unlock()
	m.subscriptions = append(m.subscriptions, ch)
	go func() {
		for cert := range ch {
			callback(cert)
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.subscriptionLock.Lock()
			defer m.subscriptionLock.Unlock()
			for i, sub := range m.subscriptions {
				if sub == ch {
					m.subscriptions = append(m.subscriptions[:i], m.subscriptions[i+1:]...)
					close(ch)
					break
				}
			}
		})
	}
}

// GetCertificate returns a TLS certificate based on the client hello.
//
// It tries to find a certificate that would be accepted by the client
// according to the client hello. However, if no certificate can be
// found GetCertificate returns the first certificate as the "default"
func (m *Manager2) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m == nil {
		return nil, errors.New("certs: no server certificate is supported by peer")
	}

	if hello == nil {
		return nil, errors.New("certs: client hello info is nil")
	}

	certs := m.certs.Load()
	switch len(*certs) {
	case 0:
		// No certificates available
		return nil, errors.New("certs: no server certificate is supported by peer")
	case 1:
		// Optimization: If there is just one certificate, always serve that one.
		return (*certs)[0].Load(), nil
	}

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
		return (*certs)[0].Load(), nil
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
	for i := range *certs {
		cert := (*certs)[i].Load()
		if err := hello.SupportsCertificate(cert); err == nil {
			return cert, nil
		}
	}

	// Return default certificate if nothing matched
	return (*certs)[0].Load(), nil
}

// GetClientCertificate returns a TLS certificate for mTLS based on the
// certificate request.
//
// It tries to find a certificate that would be accepted by the server
// according to the certificate request. If no matching certificate can
// be found, an error is returned.
//
// BREAKING CHANGE:
// Compared to `Manager.GetClientCertificate` this implementation won't
// return the first certificate if only one certificate is loaded. This is
// because in mTLS scenarios the server usually requests specific client
// certificates and we should not present a certificate that is not
// requested by the server. It was also inconsistent with the behavior when
// more certificates have been loaded and none of them matches the client
// hello.
func (m *Manager2) GetClientCertificate(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if m == nil {
		return nil, errors.New("certs: no client certificate is supported by peer")
	}

	if reqInfo == nil {
		return nil, errors.New("certs: certificate request info is nil")
	}

	// Iterate over all certificates and return the first one that would
	// be accepted by the peer (TLS server) based on reqInfo.
	//
	// Note: The certificate.Leaf should be non-nil and contain the actual
	// client certificate of MinIO that should be presented to the peer (TLS server).
	// Otherwise, the leaf certificate has to be parsed again - which is kind of
	// expensive and may cause a performance issue. For more information, check the
	// docs of tls.CertificateRequestInfo.SupportsCertificate.
	certs := m.certs.Load()
	for i := range *certs {
		cert := (*certs)[i].Load()
		if err := reqInfo.SupportsCertificate(cert); err == nil {
			return cert, nil
		}
	}

	return nil, errors.New("certs: no client certificate is supported by peer")
}

// GetAllCertificates returns a copy of all loaded certificates
func (m *Manager2) GetAllCertificates() []*x509.Certificate {
	if m == nil {
		return nil
	}

	certs := m.certs.Load()
	result := make([]*x509.Certificate, 0, len(*certs))
	for i := range *certs {
		c := *((*certs)[i].Load())
		if c.Leaf != nil {
			cert, err := x509.ParseCertificate(c.Leaf.Raw)
			if err != nil {
				continue
			}
			result = append(result, cert)
		}
	}
	return result
}

// HasCerts checks if any certificates have been loaded
func (m *Manager2) HasCerts() bool {
	if m == nil {
		return false
	}

	certs := m.certs.Load()
	return len(*certs) > 0
}
