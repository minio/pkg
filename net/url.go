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

package net

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"syscall"
)

// URL - improved JSON friendly url.URL.
type URL url.URL

// IsEmpty - checks URL is empty or not.
func (u URL) IsEmpty() bool {
	return u.String() == ""
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// splitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
func splitHostPort(hostPort string) (host, port string) {
	host = hostPort

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// Hostname returns u.Host, stripping any valid port number if present
//
// If the result is enclosed in square brackets, as literal IPv6 addresses are,
// the square brackets are removed from the result.
func (u URL) Hostname() string {
	host, _ := splitHostPort(u.Host)
	return host
}

// Port returns the port part of u.Host, without the leading colon.
//
// If u.Host doesn't contain a valid numeric port, Port returns an empty string.
func (u URL) Port() string {
	_, port := splitHostPort(u.Host)
	return port
}

// String - returns string representation of URL.
func (u URL) String() string {
	// if port number 80 and 443, remove for http and https scheme respectively
	if u.Host != "" {
		host, err := ParseHost(u.Host)
		if err != nil {
			panic(err)
		}
		switch {
		case u.Scheme == "http" && host.Port == 80:
			fallthrough
		case u.Scheme == "https" && host.Port == 443:
			u.Host = host.Name
		}
	}

	uu := url.URL(u)
	return uu.String()
}

// MarshalJSON - converts to JSON string data.
func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON - parses given data into URL.
func (u *URL) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}

	// Allow empty string
	if s == "" {
		*u = URL{}
		return nil
	}

	var ru *URL
	if ru, err = ParseURL(s); err != nil {
		return err
	}

	*u = *ru
	return nil
}

// ParseHTTPURL - parses a string into HTTP URL, string is
// expected to be of form http:// or https://
func ParseHTTPURL(s string) (u *URL, err error) {
	u, err = ParseURL(s)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	default:
		return nil, fmt.Errorf("unexpected scheme found %s", u.Scheme)
	case "http", "https":
		return u, nil
	}
}

// ParseURL - parses string into URL.
func ParseURL(s string) (u *URL, err error) {
	var uu *url.URL
	if uu, err = url.Parse(s); err != nil {
		return nil, err
	}

	if uu.Hostname() == "" {
		if uu.Scheme != "" {
			return nil, errors.New("scheme appears with empty host")
		}
	} else {
		portStr := uu.Port()
		if portStr == "" {
			switch uu.Scheme {
			case "http":
				portStr = "80"
			case "https":
				portStr = "443"
			}
		}
		if _, err = ParseHost(net.JoinHostPort(uu.Hostname(), portStr)); err != nil {
			return nil, err
		}
	}

	// Clean path in the URL.
	// Note: path.Clean() is used on purpose because in MS Windows filepath.Clean() converts
	// `/` into `\` ie `/foo` becomes `\foo`
	if uu.Path != "" {
		uu.Path = path.Clean(uu.Path)
	}

	// path.Clean removes the trailing '/' and converts '//' to '/'.
	if strings.HasSuffix(s, "/") && !strings.HasSuffix(uu.Path, "/") {
		uu.Path += "/"
	}

	v := URL(*uu)
	u = &v
	return u, nil
}

// IsNetworkOrHostDown - if there was a network error or if the host is down.
// expectTimeouts indicates that *context* timeouts are expected and does not
// indicate a downed host. Other timeouts still returns down.
func IsNetworkOrHostDown(err error, expectTimeouts bool) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) {
		return false
	}

	if expectTimeouts && errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// We need to figure if the error either a timeout
	// or a non-temporary error.
	urlErr := &url.Error{}
	if errors.As(err, &urlErr) {
		switch urlErr.Err.(type) {
		case *net.DNSError, *net.OpError, net.UnknownNetworkError:
			return true
		}
	}

	var e net.Error
	if errors.As(err, &e) {
		if e.Timeout() {
			return true
		}
	}

	// If write to an closed connection, It will make this error
	opErr := &net.OpError{}
	if errors.As(err, &opErr) {
		if opErr.Op == "write" && opErr.Net == "tcp" {
			if es, ok := opErr.Err.(*os.SyscallError); ok && es.Syscall == "wsasend" {
				return true
			}
		}
	}

	// Fallback to other mechanisms.
	switch {
	case strings.Contains(err.Error(), "Connection closed by foreign host"):
		return true
	case strings.Contains(err.Error(), "TLS handshake timeout"):
		// If error is - tlsHandshakeTimeoutError.
		return true
	case strings.Contains(err.Error(), "i/o timeout"):
		// If error is - tcp timeoutError.
		return true
	case strings.Contains(err.Error(), "connection timed out"):
		// If err is a net.Dial timeout.
		return true
	case strings.Contains(err.Error(), "connection reset by peer"):
		// IF err is a peer reset on a socket.
		return true
	case strings.Contains(err.Error(), "broken pipe"):
		// IF err is a broken pipe on a socket.
		return true
	case strings.Contains(strings.ToLower(err.Error()), "503 service unavailable"):
		// Denial errors
		return true
	}
	return false
}

// IsConnResetErr - Checks for "connection reset" errors.
func IsConnResetErr(err error) bool {
	if strings.Contains(err.Error(), "connection reset by peer") {
		return true
	}
	// incase if error message is wrapped.
	return errors.Is(err, syscall.ECONNRESET)
}

// IsConnRefusedErr - Checks for "connection refused" errors.
func IsConnRefusedErr(err error) bool {
	if strings.Contains(err.Error(), "connection refused") {
		return true
	}
	// incase if error message is wrapped.
	return errors.Is(err, syscall.ECONNREFUSED)
}
