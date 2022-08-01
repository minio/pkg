// Copyright (c) 2015-2022 MinIO, Inc.
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

// Certificate is a chain of one or more reloadable certificates.
type Certificate struct {
	certFile        string
	keyFile         string
	loadX509KeyPair LoadX509KeyPairFunc

	lock        sync.RWMutex
	certificate tls.Certificate

	listenerLock sync.Mutex
	listeners    []chan<- tls.Certificate
}

// NewCertificate returns a new Certificate from the given certficate and private key file.
// On a reload event, the certificate is reloaded using the loadX509KeyPair function.
func NewCertificate(certFile, keyFile string, loadX509KeyPair LoadX509KeyPairFunc) (*Certificate, error) {
	certFile, err := filepath.Abs(certFile)
	if err != nil {
		return nil, err
	}
	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return nil, err
	}
	c := &Certificate{
		certFile:        certFile,
		keyFile:         keyFile,
		loadX509KeyPair: loadX509KeyPair,
	}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// Get returns the current TLS certificate.
func (c *Certificate) Get() tls.Certificate {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.certificate
}

// Notify notifies the given events channel whenever the
// certificate has been reloaded successfully. The new
// certificate is sent to the channel receiver.
func (c *Certificate) Notify(events chan<- tls.Certificate) {
	c.listenerLock.Lock()
	c.listeners = append(c.listeners, events)
	c.listenerLock.Unlock()
}

// Stop stops notifying the given events channel whenever the
// certificate has been reloaded successfully.
func (c *Certificate) Stop(events chan<- tls.Certificate) {
	c.listenerLock.Lock()
	defer c.listenerLock.Unlock()

	listeners := make([]chan<- tls.Certificate, 0, len(c.listeners))
	for _, listener := range c.listeners {
		if listener != events {
			listeners = append(listeners, listener)
		}
	}
	c.listeners = listeners
}

// Reload reloads the certificate and sends notifications to
// all listeners that subscribed via Notify.
func (c *Certificate) Reload() error {
	certificate, err := c.loadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	if certificate.Leaf == nil {
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return err
		}
	}

	c.lock.Lock()
	c.certificate = certificate
	c.lock.Unlock()

	c.listenerLock.Lock()
	for _, listener := range c.listeners {
		select {
		case listener <- certificate:
		default:
		}
	}
	c.listenerLock.Unlock()
	return nil
}

// Watch starts watching the certificate and private key file for any changes and reloads
// the Certificate whenever a change is detected.
//
// Additionally, Watch listens on the given list of OS signals and reloads the Certificate
// whenever it encounters one of the signals. Further, Watch reloads the certificate periodically
// if interval > 0.
func (c *Certificate) Watch(ctx context.Context, interval time.Duration, signals ...os.Signal) {
	certFileSymLink, _ := isSymlink(c.certFile)
	keyFileSymLink, _ := isSymlink(c.keyFile)
	if !certFileSymLink && !keyFileSymLink && !isk8s {
		go func() {
			events := make(chan notify.EventInfo, 1)
			if err := notify.Watch(filepath.Dir(c.certFile), events, eventWrite...); err != nil {
				return
			}
			if err := notify.Watch(filepath.Dir(c.keyFile), events, eventWrite...); err != nil {
				notify.Stop(events)
				return
			}
			defer notify.Stop(events)
			for {
				select {
				case <-events:
					c.Reload()
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	if interval > 0 {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					c.Reload()
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	if len(signals) > 0 {
		go func() {
			events := make(chan os.Signal, 1)
			signal.Notify(events, signals...)
			defer signal.Stop(events)
			for {
				select {
				case <-events:
					c.Reload()
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}
