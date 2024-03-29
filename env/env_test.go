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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

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

func TestIsSet(t *testing.T) {
	os.Setenv("_TEST_ENV", "")
	defer os.Unsetenv("_TEST_ENV")

	if IsSet("_TEST_ENV") {
		t.Fatal("Expected IsSet(false) but found IsSet(true)")
	}

	os.Setenv("_TEST_ENV", "v")
	if !IsSet("_TEST_ENV") {
		t.Fatal("Expected IsSet(true) but found IsSet(false)")
	}
}

func TestGetEnv(t *testing.T) {
	// Set empty env-value, this test covers situation
	// where env is set but with empty value, choose
	// to fallback to default value at this point.
	os.Setenv("_TEST_ENV", "")

	if v := Get("_TEST_ENV", "value"); v != "value" {
		t.Fatalf("Expected 'value', but got %s", v)
	}

	os.Unsetenv("_TEST_ENV")
	if v := Get("_TEST_ENV", "value"); v != "value" {
		t.Fatalf("Expected 'value', but got %s", v)
	}

	os.Setenv("_TEST_ENV", "value-new")
	defer os.Unsetenv("_TEST_ENV")
	if v := Get("_TEST_ENV", "value"); v != "value-new" {
		t.Fatalf("Expected 'value-new', but got %s", v)
	}
}
