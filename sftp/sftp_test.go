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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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

// forgedSigner offers pub but signs with another key.
type forgedSigner struct {
	pub   ssh.PublicKey
	other ssh.Signer
}

func (f forgedSigner) PublicKey() ssh.PublicKey { return f.pub }

func (f forgedSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return f.other.Sign(r, data)
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
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ssh.NewSignerFromKey(ecdsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	authLogs := make(chan string, 8)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) != goodPass {
				return nil, errors.New("bad password")
			}
			if c.User() == "wrapped-partial" {
				return nil, fmt.Errorf("wrapped: %w", &ssh.PartialSuccessError{})
			}
			if c.User() == "source-address" {
				return &ssh.Permissions{CriticalOptions: map[string]string{"source-address": "192.0.2.1/32"}}, nil
			}
			return nil, nil
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) != string(goodKey.PublicKey().Marshal()) {
				return nil, errors.New("bad key")
			}
			return nil, nil
		},
		VerifiedPublicKeyCallback: func(c ssh.ConnMetadata, _ ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			if c.User() == "verified-refused" {
				return nil, errors.New("verified key refused")
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
					return nil, errors.New("second factor refused")
				},
			}}
		},
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if _, err := client("", "", []string{"code: "}, []bool{false}); err != nil {
				return nil, err
			}
			return nil, errors.New("keyboard-interactive refused")
		},
		AuthLogCallback: func(c ssh.ConnMetadata, method string, err error) {
			if c.User() == "auth-log" {
				authLogs <- fmt.Sprintf("%s:%v", method, err)
			}
		},
		PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoED25519},
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
			return []string{"123456"}, nil
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

	for _, tc := range []struct {
		name, user string
		refused    bool
		methods    []ssh.AuthMethod
	}{
		{"refused-after-the-callback", "source-address", true, []ssh.AuthMethod{ssh.Password(goodPass)}},
		{"refused-by-verified-key-callback", "verified-refused", true, []ssh.AuthMethod{ssh.PublicKeys(goodKey)}},
		{"refused-second-factor", "mfa", true, []ssh.AuthMethod{ssh.PublicKeys(goodKey), ssh.Password("wrong")}},
		{"partial-success-is-not-refused", "mfa-abandoned", false, []ssh.AuthMethod{ssh.Password("wrong"), ssh.PublicKeys(goodKey)}},
		{"key-algorithm-refused", "ecdsa", true, []ssh.AuthMethod{ssh.PublicKeys(ecdsaKey)}},
		{"wrapped-partial-success-is-refused", "wrapped-partial", true, []ssh.AuthMethod{ssh.Password(goodPass)}},
		{"hang-up-at-a-prompt-is-refused", "hangup", true, []ssh.AuthMethod{ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
			return nil, errors.New("client gives up")
		})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dial(addr, tc.user, tc.methods...); err == nil {
				t.Fatal("login unexpectedly succeeded")
			}
			if he := logger.next(t); he.Refused != tc.refused || he.User != tc.user {
				t.Fatalf("got Refused=%v User=%q, want %v and %s", he.Refused, he.User, tc.refused, tc.user)
			}
		})
	}

	t.Run("forged-signature-keeps-the-previous-verdict", func(t *testing.T) {
		if _, err := dial(addr, "victim", ssh.Password("wrong"), ssh.PublicKeys(forgedSigner{goodKey.PublicKey(), newSigner(t)})); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); !he.Refused || he.User != "victim" || !strings.Contains(he.Error(), "signature") {
			t.Fatalf("got Refused=%v User=%q Err=%v, want true, victim and a signature error", he.Refused, he.User, he.Err)
		}
	})

	t.Run("no-credential-is-not-refused", func(t *testing.T) {
		if _, err := dial(addr, "nobody"); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := logger.next(t); he.Refused || he.User != "" {
			t.Fatalf("got Refused=%v User=%q, want false and empty", he.Refused, he.User)
		}
	})

	t.Run("caller-auth-log-sees-every-attempt", func(t *testing.T) {
		if _, err := dial(addr, "auth-log", ssh.Password("wrong")); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		logger.next(t)
		var got []string
		for len(authLogs) > 0 {
			got = append(got, <-authLogs)
		}
		want := []string{"none:" + ssh.ErrNoAuth.Error(), "password:bad password"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("the caller's AuthLogCallback got %q, want %q", got, want)
		}
	})

	t.Run("refused-none-attempt", func(t *testing.T) {
		anonAddr, anonLogger := startHandshakeServer(t, &ssh.ServerConfig{
			NoClientAuth: true,
			NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) {
				return nil, errors.New("anonymous login refused")
			},
		})
		if _, err := dial(anonAddr, "anon"); err == nil {
			t.Fatal("login unexpectedly succeeded")
		}
		if he := anonLogger.next(t); !he.Refused || he.User != "anon" {
			t.Fatalf("got Refused=%v User=%q, want true and anon", he.Refused, he.User)
		}
	})

	t.Run("connect-and-close", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		he := logger.next(t)
		if he.Refused || he.User != "" {
			t.Fatalf("got Refused=%v User=%q, want false and empty", he.Refused, he.User)
		}
		if he.Addr == nil || he.Addr.String() != conn.LocalAddr().String() {
			t.Fatalf("got Addr=%v, want the client address %v", he.Addr, conn.LocalAddr())
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
