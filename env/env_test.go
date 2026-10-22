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

package env

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/mux"
)

func GetenvHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if vars["namespace"] != "default" {
		http.Error(w, "namespace not found", http.StatusNotFound)
		return
	}
	if vars["name"] != "minio" {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	if vars["key"] != "MINIO_ARGS" {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	w.Write([]byte("http://127.0.0.{1..4}:9000/data{1...4}"))
	w.(http.Flusher).Flush()
}

func startTestServer(t *testing.T) *httptest.Server {
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	router.Methods(http.MethodGet).
		Path("/webhook/v1/getenv/{namespace}/{name}").
		HandlerFunc(GetenvHandler).Queries("key", "{key:.*}")

	ts := httptest.NewServer(router)
	t.Cleanup(func() {
		ts.Close()
	})

	return ts
}

func TestWebEnv(t *testing.T) {
	ts := startTestServer(t)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	v, user, pwd, err := getEnvValueFromHTTP(
		fmt.Sprintf("env://minio:minio123@%s/webhook/v1/getenv/default/minio",
			u.Host),
		"MINIO_ARGS")
	if err != nil {
		t.Fatal(err)
	}

	if v != "http://127.0.0.{1..4}:9000/data{1...4}" {
		t.Fatalf("Unexpected value %s", v)
	}

	if user != "minio" {
		t.Fatalf("Unexpected value %s", v)
	}

	if pwd != "minio123" {
		t.Fatalf("Unexpected value %s", v)
	}
}

func TestIsSetType(t *testing.T) {
	t.Setenv("_TEST_ENV", "")

	v, err := GetInt("_TEST_ENV", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Fatal("unexpected")
	}

	t.Setenv("_TEST_ENV", "1")

	v, err = GetInt("_TEST_ENV", 0)
	if err != nil {
		t.Fatal(err)
	}

	if v != 1 {
		t.Fatal("unexpected")
	}

	t.Setenv("_TEST_ENV", "10s")

	d, err := GetDuration("_TEST_ENV", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if d != 10*time.Second {
		t.Fatal("unexpected")
	}

	t.Setenv("_TEST_ENV", "")
	d, err = GetDuration("_TEST_ENV", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if d != time.Second {
		t.Fatal("unexpected")
	}
}

func TestIsSet(t *testing.T) {
	t.Setenv("_TEST_ENV", "")
	if IsSet("_TEST_ENV") {
		t.Fatal("Expected IsSet(false) but found IsSet(true)")
	}

	t.Setenv("_TEST_ENV", "v")
	if !IsSet("_TEST_ENV") {
		t.Fatal("Expected IsSet(true) but found IsSet(false)")
	}
}

func TestGetEnv(t *testing.T) {
	// Set empty env-value, this test covers situation
	// where env is set but with empty value, choose
	// to fallback to default value at this point.
	t.Setenv("_TEST_ENV", "")

	if v := Get("_TEST_ENV", "value"); v != "value" {
		t.Fatalf("Expected 'value', but got %s", v)
	}

	t.Setenv("_TEST_ENV", "")
	if v := Get("_TEST_ENV", "value"); v != "value" {
		t.Fatalf("Expected 'value', but got %s", v)
	}

	t.Setenv("_TEST_ENV", "value-new")
	if v := Get("_TEST_ENV", "value"); v != "value-new" {
		t.Fatalf("Expected 'value-new', but got %s", v)
	}
}

func TestLookupEnvReferenceScheme(t *testing.T) {
	ts := startTestServer(t)
	tlsTS := httptest.NewTLSServer(ts.Config.Handler)
	t.Cleanup(tlsTS.Close)
	pool := x509.NewCertPool()
	pool.AddCert(tlsTS.Certificate())
	prevCAs := globalRootCAs
	RegisterGlobalCAs(pool)
	t.Cleanup(func() { RegisterGlobalCAs(prevCAs) })
	unparsableLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unparsableLn.Close() })
	var unparsableConns atomic.Int32
	go func() {
		for {
			c, err := unparsableLn.Accept()
			if err != nil {
				return
			}
			unparsableConns.Add(1)
			c.Close()
		}
	}()

	host := func(s *httptest.Server) string {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		return u.Host
	}
	const path = "/webhook/v1/getenv/default/minio"
	const fetched = "http://127.0.0.{1..4}:9000/data{1...4}"

	testCases := []struct {
		name, value, cached      string
		want, wantUser, wantPass string
		wantParseErr             bool
	}{
		{name: "plain envroot", value: "envroot", want: "envroot"},
		{name: "plain value with stale cache", value: "envroot", cached: "stale", want: "envroot"},
		{name: "plain env", value: "env", want: "env"},
		{name: "plain environment", value: "environment", want: "environment"},
		{name: "plain env+tlsx", value: "env+tlsx", want: "env+tlsx"},
		{name: "opaque env colon", value: "env:foo", want: "env:foo"},
		{name: "single slash", value: "env:/x", want: "env:/x"},
		{name: "other scheme envs", value: "envs://h/x", want: "envs://h/x"},
		{name: "other scheme env-tls", value: "env-tls://h/x", want: "env-tls://h/x"},
		{name: "other scheme env+tlsx", value: "env+tlsx://h/x", want: "env+tlsx://h/x"},
		{name: "leading space", value: " env://x", want: " env://x"},
		{name: "unicode fold of tls", value: "ENV+TL\u017f://x", want: "ENV+TL\u017f://x"},
		{name: "env reference", value: "env://minio:minio123@" + host(ts) + path, want: fetched, wantUser: "minio", wantPass: "minio123"},
		{name: "upper case env reference", value: "ENV://minio:minio123@" + host(ts) + path, want: fetched, wantUser: "minio", wantPass: "minio123"},
		{name: "env+tls reference", value: "env+tls://minio:minio123@" + host(tlsTS) + path, want: fetched, wantUser: "minio", wantPass: "minio123"},
		{name: "mixed case env+tls reference", value: "env+TLS://minio:minio123@" + host(tlsTS) + path, want: fetched, wantUser: "minio", wantPass: "minio123"},
		{name: "unparsable reference", value: "env://minio:minio123@" + unparsableLn.Addr().String() + "/%zz", wantParseErr: true},
		{name: "unreachable reference uses cache", value: "env://minio:minio123@127.0.0.1:1" + path, cached: "cached", want: "cached"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MINIO_ARGS", tc.value)
			t.Setenv("_MINIO_ARGS", tc.cached)
			if tc.cached == "" {
				if err := os.Unsetenv("_MINIO_ARGS"); err != nil {
					t.Fatal(err)
				}
			}
			got, user, pass, err := LookupEnv("MINIO_ARGS")
			if (err != nil) != tc.wantParseErr {
				t.Fatalf("got error %v, want error %v", err, tc.wantParseErr)
			}
			var escapeErr url.EscapeError
			if tc.wantParseErr && !errors.As(err, &escapeErr) {
				t.Fatalf("got error %v, want a url.Parse escape error", err)
			}
			if got != tc.want || user != tc.wantUser || pass != tc.wantPass {
				t.Fatalf("got (%q, %q, %q), want (%q, %q, %q)", got, user, pass, tc.want, tc.wantUser, tc.wantPass)
			}
			cache, cached := os.LookupEnv("_MINIO_ARGS")
			switch {
			case tc.wantUser != "":
				if cache != tc.want {
					t.Fatalf("cache holds %q, want %q", cache, tc.want)
				}
			case tc.cached == "":
				if cached {
					t.Fatalf("cache set to %q, want unset", cache)
				}
			case cache != tc.cached:
				t.Fatalf("cache holds %q, want %q", cache, tc.cached)
			}
			want := strings.TrimSpace(tc.want)
			if tc.wantParseErr {
				want = "default"
			}
			if v := Get("MINIO_ARGS", "default"); v != want {
				t.Fatalf("Get returned %q, want %q", v, want)
			}
			if n := unparsableConns.Load(); tc.wantParseErr && n != 0 {
				t.Fatalf("unparsable reference opened %d connection(s), want 0", n)
			}
		})
	}
}

func TestLookupEnvRejectsErrorStatus(t *testing.T) {
	var status atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		code := int(status.Load())
		w.WriteHeader(code)
		if code == http.StatusOK {
			w.Write([]byte("fetched-value"))
			return
		}
		w.Write([]byte(http.StatusText(code)))
	}))
	t.Cleanup(ts.Close)
	const key = "_TEST_ENV_STATUS"
	t.Setenv(key, "env://minio:minio123@"+strings.TrimPrefix(ts.URL, "http://"))

	for _, code := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	} {
		t.Setenv("_"+key, "")
		os.Unsetenv("_" + key)
		status.Store(int32(code))
		v, _, _, err := LookupEnv(key)
		if err == nil || v != "" {
			t.Errorf("HTTP %d: LookupEnv = %q, %v; want an error", code, v, err)
		}
		if c, ok := os.LookupEnv("_" + key); ok {
			t.Errorf("HTTP %d: cached %q, want no cache", code, c)
		}
	}

	t.Setenv("_"+key, "")
	os.Unsetenv("_" + key)
	status.Store(http.StatusOK)
	if v, _, _, err := LookupEnv(key); err != nil || v != "fetched-value" {
		t.Fatalf("HTTP 200: LookupEnv = %q, %v; want fetched-value", v, err)
	}
	status.Store(http.StatusServiceUnavailable)
	if v, _, _, err := LookupEnv(key); err != nil || v != "fetched-value" {
		t.Errorf("HTTP 503 after a fetch: LookupEnv = %q, %v; want the cached fetched-value", v, err)
	}
	if c := os.Getenv("_" + key); c != "fetched-value" {
		t.Errorf("HTTP 503 after a fetch: cache = %q, want fetched-value", c)
	}
}
