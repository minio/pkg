// Copyright (c) 2015-2025 MinIO, Inc.
//
// # This file is part of MinIO Object Storage stack
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

package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7/pkg/credentials"
)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

// randStr generates a random string of length n using the alphabet constant.
func randStr(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Map random bytes to alphabet
	for i := 0; i < n; i++ {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// CallbackServer represents a local HTTP server that handles OAuth callback redirects.
type CallbackServer struct {
	port      int
	reqID     string
	credsChan chan credentials.Value
	errChan   chan error
	server    *http.Server
}

// NewCallbackServer creates and starts a new callback server on a random available port.
// The server will be automatically shut down when the provided context is canceled.
func NewCallbackServer(ctx context.Context) (*CallbackServer, error) {
	reqID, err := randStr(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Start a local HTTP listener on a random available port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start listener: %w", err)
	}

	// Get the actual port that was assigned
	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port

	cs := &CallbackServer{
		port:      port,
		reqID:     reqID,
		credsChan: make(chan credentials.Value, 1),
		errChan:   make(chan error, 1),
	}

	// Start HTTP server to handle the callback
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Parse credentials from query parameters
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code parameter", http.StatusBadRequest)
			return
		}

		creds, err := ParseSignedCredentials(code, reqID)
		if err != nil {
			http.Error(w, "Invalid code parameter: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Send success response
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Credentials received successfully. You can close this window.")

		// Send credentials through channel
		cs.credsChan <- creds
	})

	cs.server = &http.Server{Handler: mux}
	go func() {
		if err := cs.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cs.errChan <- err
		}
	}()

	// Shutdown server when context is canceled
	go func() {
		<-ctx.Done()
		// Use a separate context with timeout for graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cs.server.Shutdown(shutdownCtx)
	}()

	return cs, nil
}

type reqClient interface {
	GetOpenIDLoginURL(ctx context.Context, reqID, configName string, port int) (string, error)
}

// GetLoginURL retrieves the OpenID login URL from the server using the anonymous client.
func (cs *CallbackServer) GetLoginURL(ctx context.Context, client reqClient, configName string) (string, error) {
	loginURL, err := client.GetOpenIDLoginURL(ctx, cs.reqID, configName, cs.port)
	if err != nil {
		return "", fmt.Errorf("failed to get login URL: %w", err)
	}
	return loginURL, nil
}

// WaitForCredentials waits for credentials to be received via the callback or for an error/timeout.
func (cs *CallbackServer) WaitForCredentials(ctx context.Context) (credentials.Value, error) {
	select {
	case creds := <-cs.credsChan:
		return creds, nil
	case err := <-cs.errChan:
		return credentials.Value{}, fmt.Errorf("callback server error: %w", err)
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return credentials.Value{}, fmt.Errorf("timeout waiting for authentication callback")
		}
		return credentials.Value{}, fmt.Errorf("authentication canceled: %w", ctx.Err())
	}
}
