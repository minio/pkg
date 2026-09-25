// Copyright (c) 2015-2025 MinIO, Inc.
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

package condition

import (
	"strings"
)

// Predefined policy variables, each expanding to one literal character. A
// policy uses them where it needs the character itself rather than a wildcard
// or the start of a variable.
const (
	// VarAsterisk expands to a literal '*'.
	VarAsterisk = "${*}"

	// VarQuestion expands to a literal '?'.
	VarQuestion = "${?}"

	// VarDollar expands to a literal '$'.
	VarDollar = "${$}"
)

// Substitute expands the policy variables in pattern using the request's
// condition values. A variable that is unknown or carries no value is left as
// written. An expanded value is never scanned for further variables.
//
// The escapes ${*}, ${?} and ${$} expand to a literal character. Set escape to
// match the result with wildcard.MatchEscaped. Leave it unset to compare the
// result as text.
func Substitute(pattern string, values map[string][]string, escape bool) string {
	if strings.IndexByte(pattern, '$') < 0 && (!escape || strings.IndexByte(pattern, '\\') < 0) {
		return pattern
	}
	var buf [128]byte
	return string(AppendSubstitute(buf[:0], pattern, values, escape))
}

// AppendSubstitute is Substitute that appends the result to dst, so a caller
// whose result stays local can expand without allocating.
func AppendSubstitute(dst []byte, pattern string, values map[string][]string, escape bool) []byte {
	for len(pattern) > 0 {
		idx := strings.IndexByte(pattern, '$')
		if idx < 0 {
			return appendText(dst, pattern, escape)
		}
		dst = appendText(dst, pattern[:idx], escape)
		pattern = pattern[idx:]
		if len(pattern) < 3 || pattern[1] != '{' {
			dst = append(dst, '$')
			pattern = pattern[1:]
			continue
		}
		// No '}' in pattern means none in any suffix of it either. Emit the
		// rest and stop, instead of rescanning at every '${'.
		keyEnds := strings.IndexByte(pattern, '}')
		if keyEnds < 0 {
			return appendText(dst, pattern, escape)
		}

		name := pattern[2:keyEnds]
		switch pattern[:keyEnds+1] {
		case VarAsterisk, VarQuestion, VarDollar:
			if escape {
				dst = append(dst, '\\')
			}
			dst = append(dst, name...)
		default:
			ckey := KeyName(name)
			// Only replace keys we know, and only when they carry a value.
			if rvalues, ok := values[ckey.Name()]; CommonKeysMap[ckey] && ok && len(rvalues) > 0 && rvalues[0] != "" {
				dst = appendText(dst, rvalues[0], escape)
			} else {
				dst = appendText(dst, pattern[:keyEnds+1], escape)
			}
		}
		pattern = pattern[keyEnds+1:]
	}
	return dst
}

// appendText appends s to dst. With escape set, s is written so that it
// matches only itself.
func appendText(dst []byte, s string, escape bool) []byte {
	if !escape {
		return append(dst, s...)
	}
	for {
		i := strings.IndexByte(s, '\\')
		if i < 0 {
			return append(dst, s...)
		}
		dst = append(dst, s[:i]...)
		dst = append(dst, '\\', '\\')
		s = s[i+1:]
	}
}
