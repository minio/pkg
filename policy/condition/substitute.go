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
	"bytes"
	"strings"
	"sync"
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

var substBufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

// Substitute expands the policy variables in pattern using the request's
// condition values. A variable that is unknown or carries no value is left as
// written. An expanded value is never scanned for further variables.
//
// The escapes ${*}, ${?} and ${$} expand to a literal character. Set escape to
// match the result with wildcard.MatchEscaped. Leave it unset to compare the
// result as text.
func Substitute(pattern string, values map[string][]string, escape bool) string {
	idx := strings.IndexByte(pattern, '$')
	if idx < 0 {
		if !escape || !strings.Contains(pattern, `\`) {
			return pattern
		}
		idx = len(pattern)
	}

	buf := substBufPool.Get().(*bytes.Buffer)
	defer substBufPool.Put(buf)
	buf.Reset()

	writeText(buf, pattern[:idx], escape)
	remain := pattern[idx:]
	for len(remain) > 0 {
		if remain[0] != '$' || len(remain) < 3 || remain[1] != '{' {
			writeText(buf, remain[:1], escape)
			remain = remain[1:]
			continue
		}
		// No '}' in remain means none in any suffix of it either. Emit the
		// rest and stop, instead of rescanning at every '${'.
		keyEnds := strings.IndexByte(remain, '}')
		if keyEnds < 0 {
			writeText(buf, remain, escape)
			break
		}

		name := remain[2:keyEnds]
		switch remain[:keyEnds+1] {
		case VarAsterisk, VarQuestion, VarDollar:
			if escape {
				buf.WriteByte('\\')
			}
			buf.WriteString(name)
		default:
			ckey := KeyName(name)
			// Only replace keys we know, and only when they carry a value.
			if rvalues, ok := values[ckey.Name()]; CommonKeysMap[ckey] && ok && rvalues[0] != "" {
				writeText(buf, rvalues[0], escape)
			} else {
				writeText(buf, remain[:keyEnds+1], escape)
			}
		}
		remain = remain[keyEnds+1:]
	}

	return buf.String()
}

// writeText appends s to buf. With escape set, s is written so that it
// matches only itself.
func writeText(buf *bytes.Buffer, s string, escape bool) {
	if !escape {
		buf.WriteString(s)
		return
	}
	for {
		i := strings.IndexByte(s, '\\')
		if i < 0 {
			buf.WriteString(s)
			return
		}
		buf.WriteString(s[:i])
		buf.WriteString(`\\`)
		s = s[i+1:]
	}
}
