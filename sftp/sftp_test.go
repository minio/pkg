// Copyright (c) 2026 MinIO, Inc.
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

package sftp

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type handshakeLogger struct {
	errs chan *HandshakeError
}

func (l *handshakeLogger) Info(LogType, string) {}

func (l *handshakeLogger) Error(tag LogType, err error) {
	var he *HandshakeError
	if tag == SSHKeyExchangeError && errors.As(err, &he) {
		l.errs <- he
	}
}

func (l *handshakeLogger) next(t *testing.T) *HandshakeError {
	t.Helper()
	select {
	case he := <-l.errs:
		return he
	case <-time.After(10 * time.Second):
		t.Fatal("no handshake error was logged")
		return nil
	}
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startHandshakeServer serves cfg on a loopback port and returns its address.
func startHandshakeServer(t *testing.T, cfg *ssh.ServerConfig) (string, *handshakeLogger) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	cfg.AddHostKey(newSigner(t))
	logger := &handshakeLogger{errs: make(chan *HandshakeError, 16)}
	srv, err := NewServer(&Options{
		Port:                 port,
		PublicIP:             "127.0.0.1",
		Logger:               logger,
		SSHConfig:            cfg,
		SSHHandshakeDeadline: 10 * time.Second,
		HandleSFTPSession:    func(ssh.Channel, *ssh.ServerConn) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Listen()
	t.Cleanup(func() { srv.ShutDown() })
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), logger
}

func dial(addr, user string, methods ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

func TestHandshakeError(t *testing.T) {
	const goodPass = "good-pass"
	goodKey := newSigner(t)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) != goodPass {
				return nil, errors.New("bad password")
			}
			return nil, nil
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) != string(goodKey.PublicKey().Marshal()) {
				return nil, errors.New("bad key")
			}
			return nil, nil
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return nil, errors.New("keyboard-interactive refused")
		},
	}
	addr, logger := startHandshakeServer(t, cfg)

	t.Run("refused-password", func(t *testing.T) {
		if _, err := dial(addr, "alice", ssh.Password("wrong")); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		he := logger.next(t)
		if !he.Refused || he.User != "alice" {
			t.Fatalf("got Refused=%v User=%q, want true and alice", he.Refused, he.User)
		}
		if he.Addr == nil || he.Addr.(*net.TCPAddr).IP.String() != "127.0.0.1" {
			t.Fatalf("got Addr=%v, want a loopback address", he.Addr)
		}
		if he.Error() != he.Err.Error() || errors.Unwrap(he) != he.Err {
			t.Fatalf("Error and Unwrap do not match Err: %v", he)
		}
	})

	t.Run("refused-key", func(t *testing.T) {
		if _, err := dial(addr, "bob", ssh.PublicKeys(newSigner(t))); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); !he.Refused || he.User != "bob" {
			t.Fatalf("got Refused=%v User=%q, want true and bob", he.Refused, he.User)
		}
	})

	t.Run("refused-keyboard-interactive", func(t *testing.T) {
		answer := ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
			return nil, nil
		})
		if _, err := dial(addr, "carol", answer); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); !he.Refused || he.User != "carol" {
			t.Fatalf("got Refused=%v User=%q, want true and carol", he.Refused, he.User)
		}
	})

	t.Run("two-refused-keys-are-one-error", func(t *testing.T) {
		if _, err := dial(addr, "dave", ssh.PublicKeys(newSigner(t), newSigner(t))); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); !he.Refused || he.User != "dave" {
			t.Fatalf("got Refused=%v User=%q, want true and dave", he.Refused, he.User)
		}
		if _, err := dial(addr, "erin", ssh.Password("wrong")); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); he.User != "erin" {
			t.Fatalf("a second error was logged for dave: got User=%q, want erin", he.User)
		}
	})

	t.Run("refused-then-valid-logs-nothing", func(t *testing.T) {
		tries := 0
		pass := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			tries++
			if tries == 1 {
				return "wrong", nil
			}
			return goodPass, nil
		}), 3)
		client, err := dial(addr, "frank", pass)
		if err != nil {
			t.Fatalf("valid retry failed: %v", err)
		}
		client.Close()
		if tries != 2 {
			t.Fatalf("got %d password tries, want 2", tries)
		}
		if _, err := dial(addr, "grace", ssh.Password("wrong")); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); he.User != "grace" {
			t.Fatalf("the valid login logged an error: got User=%q, want grace", he.User)
		}
	})

	t.Run("connect-and-close", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if he := logger.next(t); he.Refused || he.User != "" {
			t.Fatalf("got Refused=%v User=%q, want false and empty", he.Refused, he.User)
		}
	})

	t.Run("protocol-failure", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("SSH-2.0-test\r\n" + strings.Repeat("\xff", 64))); err != nil {
			t.Fatal(err)
		}
		if he := logger.next(t); he.Refused || he.User != "" {
			t.Fatalf("got Refused=%v User=%q, want false and empty", he.Refused, he.User)
		}
	})
}

func TestHandshakeErrorNilErr(t *testing.T) {
	if got := (&HandshakeError{}).Error(); got == "" {
		t.Fatal("Error returned an empty string for a nil Err")
	}
}
