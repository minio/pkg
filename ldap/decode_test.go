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

package ldap

import (
	"errors"
	"fmt"
	"testing"
)

func TestDecodeDN(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		err      error
	}{
		{
			input:    "cn=foo,dc=example,dc=com",
			expected: "cn=foo,dc=example,dc=com",
		},
		{
			input:    `cn=\d0\98\d0\b2\d0\b0\d0\bd\d0\be\d0\b2 \d0\98\d0\b2\d0\b0\d0\bd,dc=example,dc=com`,
			expected: "cn=Иванов Иван,dc=example,dc=com",
		},
		{
			input:    `cn=\20foo,dc=example,dc=com`,
			expected: "cn= foo,dc=example,dc=com",
		},
		{
			input:    `cn=pr\c3\bcfen,dc=example,dc=com`,
			expected: "cn=prüfen,dc=example,dc=com",
		},
		{
			input: `cn=foo,dc=example,dc=com\`,
			err:   fmt.Errorf("got corrupted escaped character: '%s'", `cn=foo,dc=example,dc=com\`),
		},
		{
			input: `cn=foo,dc=example,dc=com\a`,
			err:   fmt.Errorf("ailed to decode escaped character: encoding/hex: invalid byte: %s", "a"),
		},
	}
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("test case %d", i), func(t *testing.T) {
			output, err := DecodeDN(testCase.input)
			if err != nil && testCase.err == nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if testCase.err != nil && errors.Is(err, testCase.err) {
				t.Fatalf("expected error `%v`, got `%v`", testCase.err, err)
			}
			if output != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, output)
			}
		})
	}
}
