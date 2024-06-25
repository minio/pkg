// Copyright (c) 2015-2024 MinIO, Inc.
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

package cors

import (
	"bytes"
	"encoding/xml"
	"os"
	"reflect"
	"strings"
	"testing"
)

var defaultXMLName = xml.Name{Space: "http://s3.amazonaws.com/doc/2006-03-01/", Local: "CORSConfiguration"}

func TestCORSFilterHeaders(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		headers []string

		wantOk      bool
		wantHeaders []string
	}{
		{
			name:        "plain single header",
			rule:        Rule{AllowedHeader: []string{"x-custom-header"}},
			headers:     []string{"x-custom-header"},
			wantOk:      true,
			wantHeaders: []string{"x-custom-header"},
		},
		{
			name:        "single header case insensitive",
			rule:        Rule{AllowedHeader: []string{"x-CUSTOM-header"}},
			headers:     []string{"x-custom-HEADER"},
			wantOk:      true,
			wantHeaders: []string{"x-custom-header"},
		},
		{
			name:        "plain multiple headers in order",
			rule:        Rule{AllowedHeader: []string{"x-custom-header-1", "x-custom-header-2"}},
			headers:     []string{"x-custom-header-1", "x-custom-header-2"},
			wantOk:      true,
			wantHeaders: []string{"x-custom-header-1", "x-custom-header-2"},
		},
		{
			name:        "plain multiple headers out of order",
			rule:        Rule{AllowedHeader: []string{"x-custom-header-2", "x-custom-header-1"}},
			headers:     []string{"x-custom-header-1", "x-custom-header-2"},
			wantOk:      true,
			wantHeaders: []string{"x-custom-header-1", "x-custom-header-2"},
		},
		{
			name:        "plain multiple headers with unknown header",
			rule:        Rule{AllowedHeader: []string{"x-custom-header-1", "x-custom-header-2"}},
			headers:     []string{"x-custom-header-1", "x-custom-header-2", "x-custom-header-3"},
			wantOk:      false,
			wantHeaders: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{
				CORSRules: []Rule{test.rule},
			}
			for _, rule := range config.CORSRules {
				headers, ok := rule.FilterAllowedHeaders(test.headers)
				if ok != test.wantOk {
					t.Errorf("got: %v, want: %v", ok, test.wantOk)
				}
				if !reflect.DeepEqual(headers, test.wantHeaders) {
					t.Errorf("got: %v, want: %v", headers, test.wantHeaders)
				}
			}
		})
	}
}

func TestCORSInvalid(t *testing.T) {
	tests := []struct {
		name            string
		config          *Config
		wantErrContains string
	}{
		{
			name: "no CORS rules",
			config: &Config{
				CORSRules: []Rule{},
			},
			wantErrContains: "no CORS rules found",
		},
		{
			name: "too many CORS rules",
			config: &Config{
				CORSRules: make([]Rule, 101),
			},
			wantErrContains: "too many CORS rules",
		},
		{
			name: "no AllowedOrigin",
			config: &Config{
				CORSRules: []Rule{
					{
						ID:            "1",
						AllowedOrigin: []string{},
						AllowedMethod: []string{"GET"},
					},
				},
			},
			wantErrContains: "no AllowedOrigin found in CORS rule, id: 1",
		},
		{
			name: "invalid origin multiple wildcards",
			config: &Config{
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"https", "http://*.example.*"},
						AllowedMethod: []string{"GET"},
					},
				},
			},
			wantErrContains: "can not have more than one wildcard",
		},
		{
			name: "no AllowedMethod",
			config: &Config{
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"*"},
						AllowedMethod: []string{},
					},
				},
			},
			wantErrContains: "no AllowedMethod found in CORS rule",
		},
		{
			name: "invalid method",
			config: &Config{
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"*"},
						AllowedMethod: []string{"GET", "POST", "PATCH"},
					},
				},
			},
			wantErrContains: "Unsupported method is PATCH",
		},
		{
			name: "invalid method lowercase",
			config: &Config{
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"*"},
						AllowedMethod: []string{"get"},
					},
				},
			},
			wantErrContains: "Unsupported method is get",
		},
		{
			name: "invalid header multiple wildcards",
			config: &Config{
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"*"},
						AllowedMethod: []string{"GET"},
						AllowedHeader: []string{"X-*-Header-*"},
					},
				},
			},
			wantErrContains: "not have more than one wildcard",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), test.wantErrContains) {
				t.Errorf("got: %v, want contains: %v", err, test.wantErrContains)
			}
		})
	}
}

func TestCORSXMLValid(t *testing.T) {
	tests := []struct {
		name           string
		filename       string
		wantCORSConfig *Config
	}{
		{
			name:     "example1 cors config",
			filename: "example1.xml",
			wantCORSConfig: &Config{
				XMLName: defaultXMLName,
				XMLNS:   defaultXMLNS,
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"http://www.example1.com"},
						AllowedMethod: []string{"PUT", "POST", "DELETE"},
						AllowedHeader: []string{"*"},
					},
					{
						AllowedOrigin: []string{"http://www.example2.com"},
						AllowedMethod: []string{"PUT", "POST", "DELETE"},
						AllowedHeader: []string{"*"},
					},
					{
						AllowedOrigin: []string{"*"},
						AllowedMethod: []string{"GET"},
					},
				},
			},
		},
		{
			name:     "example2 cors config",
			filename: "example2.xml",
			wantCORSConfig: &Config{
				XMLName: defaultXMLName,
				XMLNS:   defaultXMLNS,
				CORSRules: []Rule{
					{
						AllowedOrigin: []string{"http://www.example.com"},
						AllowedMethod: []string{"PUT", "POST", "DELETE"},
						AllowedHeader: []string{"*"},
						MaxAgeSeconds: 3000,
						ExposeHeader:  []string{"x-amz-server-side-encryption", "x-amz-request-id", "x-amz-id-2"},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileContents, err := os.ReadFile("testdata/" + test.filename)
			if err != nil {
				t.Fatal(err)
			}
			c, err := ParseBucketCorsConfig(bytes.NewReader(fileContents))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c, test.wantCORSConfig) {
				t.Errorf("got: %v, want: %v", c, test.wantCORSConfig)
			}
			err = c.Validate()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCORSXMLMarshal(t *testing.T) {
	fileContents, err := os.ReadFile("testdata/example3.xml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseBucketCorsConfig(bytes.NewReader(fileContents))
	if err != nil {
		t.Fatal(err)
	}
	remarshalled, err := c.ToXML()
	if err != nil {
		t.Fatal(err)
	}
	trimmedFileContents := bytes.TrimSpace(fileContents)
	if !bytes.Equal(trimmedFileContents, remarshalled) {
		t.Errorf("got: %s, want: %s", string(remarshalled), string(trimmedFileContents))
	}
}
