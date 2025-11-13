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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rjeczalik/notify"
)

var symlinkReloadInterval = 10 * time.Second

// Certificate2 wraps a tls.Certificate and automatically reloads it
// when the underlying files change. It is safe for concurrent use.
//
// The certificate is reloaded when filesystem events occur on the
// underlying cert and key files. Reloads happen automatically and
// transparently to callers. If a reload fails (e.g., due to invalid
// cert data or read errors during file update), the certificate
// remains unchanged and subscribers are not notified. This allows
// graceful degradation if cert files are temporarily inconsistent.
type Certificate2 struct {
	atomic.Pointer[tls.Certificate]
	close         func()
	lock          sync.Mutex
	subscriptions []chan *Certificate2
}

// NewCertificate2 creates a new Certificate which watches the given certFile
// and keyFile for changes and reloads them automatically.
func NewCertificate2(certFile, keyFile string) (*Certificate2, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}

	certHash := sha256.Sum256(certPEMBlock)
	keyHash := sha256.Sum256(keyPEMBlock)

	ch := make(chan notify.EventInfo, 1)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	var c Certificate2
	var once sync.Once
	c.close = func() {
		once.Do(func() {
			notify.Stop(ch)
			cancel()
			wg.Wait() // don't close channel before goroutine is done
			close(ch)

			c.lock.Lock()
			subs := c.subscriptions
			c.subscriptions = nil
			c.lock.Unlock()
			for _, sub := range subs {
				close(sub)
			}
		})
	}
	c.Store(&cert)

	if err := watchFile(ctx, certFile, ch, &wg); err != nil {
		c.close()
		return nil, err
	}
	if err := watchFile(ctx, keyFile, ch, &wg); err != nil {
		c.close()
		return nil, err
	}

	go func() {
		for range ch {
			certPEMBlock, err := os.ReadFile(certFile)
			if err != nil {
				// Silently skip reload if cert file cannot be read.
				// This gracefully handles files being updated (not yet written fully).
				continue
			}
			keyPEMBlock, err := os.ReadFile(keyFile)
			if err != nil {
				// Silently skip reload if key file cannot be read.
				continue
			}
			newCertHash := sha256.Sum256(certPEMBlock)
			newKeyHash := sha256.Sum256(keyPEMBlock)
			if newCertHash == certHash && newKeyHash == keyHash {
				continue
			}

			newCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
			if err != nil {
				// Silently skip reload if the cert/key pair is invalid.
				// This prevents using partially written or corrupted cert files.
				continue
			}

			// Save updated hashes
			certHash = newCertHash
			keyHash = newKeyHash

			c.Store(&newCert)
			func() {
				c.lock.Lock()
				// use a copy to prevent deadlocks when sending to the channel
				subs := append([]chan *Certificate2{}, c.subscriptions...)
				c.lock.Unlock()
				for _, sub := range subs {
					select {
					case sub <- &c:
					default:
						// Channel is full; subscriber is not consuming notifications.
						// Skip this notification to avoid blocking the reload goroutine.
					}
				}
			}()
		}
	}()
	return &c, nil
}

// Subscribe will register a callback which is called with the updated
// Certificate2 instance each time the certificate is reloaded. The
// returned function should be called to unsubscribe when the certificate
// is no longer needed. Closing the certificate will automatically
// unsubscribe all subscribers.
//
// The callback runs in a dedicated goroutine per subscription. The callback
// must not block indefinitely; if it does, that subscription's goroutine
// will hang and the internal notification channel will not be consumed.
// A hung callback will not prevent other subscriptions from being notified,
// but will leak a goroutine until the certificate is closed.
//
// Make sure not to block in the callback to avoid blocking the internal
// certificate reloading goroutine and to ensure prompt cleanup of resources.
func (c *Certificate2) Subscribe(callback func(*Certificate2)) func() {
	ch := make(chan *Certificate2, 1)
	c.lock.Lock()
	defer c.lock.Unlock()
	c.subscriptions = append(c.subscriptions, ch)
	go func() {
		for range ch {
			callback(c)
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.lock.Lock()
			defer c.lock.Unlock()
			for i, sub := range c.subscriptions {
				if sub == ch {
					c.subscriptions = append(c.subscriptions[:i], c.subscriptions[i+1:]...)
					close(ch)
					break
				}
			}
		})
	}
}

// Close stops watching the certificate files and releases all resources.
func (c *Certificate2) Close() {
	c.close()
}

func watchFile(ctx context.Context, path string, ch chan notify.EventInfo, wg *sync.WaitGroup) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	symLink := st.Mode()&os.ModeSymlink == os.ModeSymlink
	if !symLink {
		// Windows doesn't allow for watching file changes but instead allows
		// for directory changes only, while we can still watch for changes
		// on files on other platforms. For other platforms it's also better
		// to watch the directory to catch all changes. Some updates are written
		// to a new file and then renamed to the destination file. This method
		// ensures we catch all such changes.
		//
		// Note: Certificate reloading relies on atomic file updates (write new
		// file, then rename). If certificate files are updated in-place without
		// atomicity, there is a window where partial/corrupted data may be read.
		// The hash comparison will skip reloads when content hasn't changed, but
		// does not protect against temporary inconsistency during partial writes.
		return notify.Watch(filepath.Dir(path), ch, eventWrite...)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		t := time.NewTicker(symlinkReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ch <- eventInfo{path, notify.Write}
			}
		}
	}()
	return nil
}

type eventInfo struct {
	path  string
	event notify.Event
}

func (e eventInfo) Event() notify.Event { return e.event }
func (e eventInfo) Path() string        { return e.path }
func (e eventInfo) Sys() any            { return nil }
