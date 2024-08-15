// Copyright (c) 2015-2023 MinIO, Inc.
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

package ellipses

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Test tests if args has a list sequence
func TestHasList(t *testing.T) {
	testCases := []struct {
		args       []string
		expectedOk bool
	}{
		{
			[]string{""},
			false,
		},
		{
			[]string{"64"},
			false,
		},
		{
			[]string{"{1..64}"},
			false,
		},
		{
			[]string{"{1..2..}"},
			false,
		},
		{
			[]string{"1"},
			false,
		},
		{
			[]string{"{1}"},
			false,
		},
		{
			[]string{"{1,2}"},
			true,
		},
		{
			[]string{"{a,b}"},
			true,
		},
		{
			[]string{"http://minio{1,2,3,4}/export/disk"},
			true,
		},
		{
			[]string{"http://minio{1,2,3,4}/export/disk{1,2,3,4}"},
			true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("Test%d", i+1), func(t *testing.T) {
			gotOk := HasList(testCase.args...)
			if gotOk != testCase.expectedOk {
				t.Errorf("Expected %t, got %t", testCase.expectedOk, gotOk)
			}
		})
	}
}

// Test tests find list sequences patterns.
func TestFindListPatterns(t *testing.T) {
	testCases := []struct {
		pattern string
		success bool
		want    [][]string
	}{
		// Tests for all invalid inputs
		0: {
			pattern: "{1..64}",
		},
		1: {
			pattern: "1...64",
		},
		2: {
			pattern: "...",
		},
		3: {
			pattern: "{1...",
		},
		4: {
			pattern: "...64}",
		},
		5: {
			pattern: "{...}",
		},
		6: {
			pattern: "{1}",
		},
		7: {
			pattern: "{,}",
		},
		8: {
			pattern: "{1,}",
		},
		9: {
			pattern: "{1,,}",
		},
		10: {
			pattern: "{1,2",
		},
		11: {
			pattern: "mydisk-{a,z",
		},
		// Test for valid input.
		12: {
			pattern: "{1,2}",
			success: true,
			want:    [][]string{{"1"}, {"2"}},
		},
		13: {
			pattern: "{1,2}/{3,4}",
			success: true,
			want:    [][]string{{"1/", "3"}, {"2/", "3"}, {"1/", "4"}, {"2/", "4"}},
		},
		14: {
			pattern: "/mnt/disk{1,2,3,4}/",
			success: true,
			want:    [][]string{{"/mnt/disk1/"}, {"/mnt/disk2/"}, {"/mnt/disk3/"}, {"/mnt/disk4/"}},
		},
		15: {
			pattern: "http://minio:9000/disk/{1,2,3,4}/",
			success: true,
			want:    [][]string{{"http://minio:9000/disk/1/"}, {"http://minio:9000/disk/2/"}, {"http://minio:9000/disk/3/"}, {"http://minio:9000/disk/4/"}},
		},
	}
	for i, testCase := range testCases {
		if testCase.pattern == "" {
			continue
		}
		t.Run(fmt.Sprintf("Test%d", i), func(t *testing.T) {
			argP, err := FindListPatterns(testCase.pattern)
			if err != nil && testCase.success {
				t.Errorf("Expected success but failed instead %s", err)
			}
			if err == nil && !testCase.success {
				t.Errorf("Expected failure but passed instead")
			}
			if err == nil {
				got := argP.Expand()
				gotCount := len(got)
				if gotCount != len(testCase.want) {
					t.Errorf("Expected %d, got %d", len(testCase.want), gotCount)
				}
				repl := func(v interface{}) string {
					s := fmt.Sprintf("%#v", v)
					// Clean up unneeded declarations
					s = strings.Replace(s, `[]string{"`, `{"`, -1)
					return s
				}
				if !reflect.DeepEqual(got, testCase.want) {
					t.Errorf("want %s,", repl(testCase.want))
					t.Errorf("got %s,", repl(got))
				}
			}
		})
	}
}
