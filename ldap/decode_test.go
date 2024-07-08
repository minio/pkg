// Copyright (c) 2015-2024 MinIO, Inc.
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
			input:    `cn=\d0\bf\d1\80\d0\b5\d1\86\d0\b5\d0\b4\d0\b5\d0\bd\d1\82 \d1\82\d0\b5\d1\81\d1\82,dc=example,dc=com`,
			expected: "cn=прецедент тест,dc=example,dc=com",
		},
		{
			input:    `cn=pr\c3\bcfen,dc=example,dc=com`,
			expected: "cn=prüfen,dc=example,dc=com",
		},
		{
			input:    `cn=fo\20o,dc=example,dc=com`,
			expected: "cn=fo o,dc=example,dc=com",
		},
		{
			input:    `cn=\e6\b5\8b\e8\af\95,dc=example,dc=com`,
			expected: "cn=测试,dc=example,dc=com",
		},
		{
			input:    `cn=\e6\b8\ac\e8\a9\a6,dc=example,dc=com`,
			expected: "cn=測試,dc=example,dc=com",
		},
		{
			input:    `cn=svc\ef\b9\92algorithm,dc=example,dc=com`,
			expected: "cn=svc﹒algorithm,dc=example,dc=com",
		},
		{
			input:    `cn=\e0\a4\9c\e0\a4\be\e0\a4\81\e0\a4\9a,dc=example,dc=com`,
			expected: "cn=जाँच,dc=example,dc=com",
		},
		{
			input:    `cn=\f0\9f\a7\aa\f0\9f\93\9d,dc=example,dc=com`,
			expected: "cn=🧪📝,dc=example,dc=com",
		},
		{
			input: `cn=foo,dc=example,dc=com\`,
			err:   fmt.Errorf("got corrupted escaped character: '%s'", `cn=foo,dc=example,dc=com\`),
		},
		{
			input: `cn=foo,dc=example,dc=com\a`,
			err:   fmt.Errorf("unable to decode escaped character: encoding/hex: invalid byte: %s", "a"),
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
