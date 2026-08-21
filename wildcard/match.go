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

package wildcard

import (
	"strings"
)

// MatchSimple - finds whether the text matches/satisfies the pattern string.
// supports '*' wildcard in the pattern and ? for single characters.
// Only difference to Match is that `?` at the end is optional,
// meaning `a?` pattern will match name `a`.
func MatchSimple(pattern, name string) bool {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	if deepMatchRune(name, pattern) {
		return true
	}
	// Reaching a '?' with name already exhausted succeeds, and succeeds for
	// the whole pattern, so the pattern also matches whenever any prefix of it
	// ending at a '?' consumes name exactly.
	if !strings.ContainsRune(pattern, '?') {
		return false
	}
	// A prefix holding no '*' consumes exactly one byte of name per byte of
	// pattern, so only the prefix as long as name can consume it: a star-free
	// pattern costs one deepMatchRune call however many '?' it carries.
	firstStar := strings.IndexByte(pattern, '*')
	if firstStar < 0 {
		firstStar = len(pattern)
	}
	// Every byte that is not a '*' consumes one byte of name, so once a prefix
	// needs more of them than name has, that prefix and every longer one is
	// too long to consume name exactly and the walk can stop.
	lits := 0
	for i := range len(pattern) {
		if pattern[i] == '?' && (i > firstStar || i == len(name)) &&
			deepMatchRune(name, pattern[:i]) {
			return true
		}
		if pattern[i] != '*' {
			lits++
			if lits > len(name) {
				break
			}
		}
	}
	return false
}

// Match -  finds whether the text matches/satisfies the pattern string.
// supports  '*' and '?' wildcards in the pattern string.
// unlike path.Match(), considers a path as a flat name space while matching the pattern.
// The difference is illustrated in the example here https://play.golang.org/p/Ega9qgD4Qz .
func Match(pattern, name string) (matched bool) {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	// Do an extended wildcard '*' and '?' match.
	return deepMatchRune(name, pattern)
}

// Has returns true if the input pattern has a wildcard (pattern).
func Has(pattern string) bool {
	return strings.ContainsAny(pattern, "*?")
}

// deepMatchRune walks pattern against str one byte at a time, remembering only
// the most recent '*' to resume from. Trying both alternatives at every '*'
// instead — as a recursive matcher does — costs time exponential in the number
// of stars, which a caller-supplied pattern can trigger: a policy action of
// "*********x" kept AdminAction.IsValid busy for a minute.
func deepMatchRune(str, pattern string) bool {
	var s, p int
	// Position of the '*' to resume from, and how much of str it has consumed.
	star, mark := -1, 0
	for s < len(str) || p < len(pattern) {
		if p < len(pattern) {
			switch pattern[p] {
			case '*':
				star, mark = p, s
				p++
				continue
			case '?':
				if s < len(str) {
					s++
					p++
					continue
				}
			default:
				if s < len(str) && pattern[p] == str[s] {
					s++
					p++
					continue
				}
			}
		}
		if star < 0 {
			return false
		}
		// Let the last '*' swallow one more byte and retry from there.
		mark++
		if mark > len(str) {
			return false
		}
		s, p = mark, star+1
	}
	return true
}

// MatchAsPatternPrefix matches text as a prefix of the given pattern. Examples:
//
//	| Pattern | Text    | Match Result |
//	====================================
//	| abc*    | ab      | True         |
//	| abc*    | abd     | False        |
//	| abc*c   | abcd    | True         |
//	| ab*??d  | abxxc   | True         |
//	| ab*??d  | abxc    | True         |
//	| ab??d   | abxc    | True         |
//	| ab??d   | abc     | True         |
//	| ab??d   | abcxdd  | False        |
//
// This function is only useful in some special situations.
func MatchAsPatternPrefix(pattern, text string) bool {
	for i := 0; i < len(text) && i < len(pattern); i++ {
		if pattern[i] == '*' {
			return true
		}
		if pattern[i] == '?' {
			continue
		}
		if pattern[i] != text[i] {
			return false
		}
	}
	return len(text) <= len(pattern)
}
