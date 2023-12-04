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
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// Regex to extract ellipses syntax inputs.
	regexpList = regexp.MustCompile(`(.*)({[0-9a-z]+[,[0-9a-z]+]?})(.*)`)

	// Ellipses constants
	comma = ","
)

// HasList - returns true if input arg has list type pattern {1,3,5}
func HasList(args ...string) bool {
	ok := len(args) > 0
	for _, arg := range args {
		if !ok {
			break
		}
		ok = ok && regexpList.MatchString(arg)
	}
	return ok
}

// ErrInvalidListFormatFn error returned when invalid list format is detected.
var ErrInvalidListFormatFn = func(arg string) error {
	return fmt.Errorf("Invalid list format in (%s)", arg)
}

// FindListPatterns - finds all list patterns, recursively and parses the ranges numerically.
func FindListPatterns(arg string) (ArgPattern, error) {
	v, err := findPatterns(arg, regexpList, parseListRange)
	if err == errFormat {
		err = ErrInvalidListFormatFn(arg)
	}
	return v, err
}

// Parses a list pattern of following style `{1,3,4}`
func parseListRange(pattern string) (seq []string, err error) {
	if !strings.HasPrefix(pattern, openBraces) {
		return nil, errors.New("invalid argument")
	}
	if !strings.HasSuffix(pattern, closeBraces) {
		return nil, errors.New("invalid argument")
	}

	pattern = strings.TrimPrefix(pattern, openBraces)
	pattern = strings.TrimSuffix(pattern, closeBraces)

	seq = strings.Split(pattern, comma)
	if len(seq) < 2 {
		return nil, errors.New("invalid argument")
	}

	for i := range seq {
		if len(seq[i]) == 0 {
			return nil, errors.New("invalid argument")
		}
	}

	return seq, nil
}
