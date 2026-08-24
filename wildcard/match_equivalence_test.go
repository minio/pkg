// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package wildcard

import (
	"strings"
	"testing"
	"time"
)

// oldDeepMatchRune is the recursive matcher deepMatchRune replaced, kept here so
// the rewrite can be proven equivalent rather than asserted to be.
func oldDeepMatchRune(str, pattern string, simple bool) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '?':
			if len(str) == 0 {
				return simple
			}
		case '*':
			return len(pattern) == 1 ||
				oldDeepMatchRune(str, pattern[1:], simple) ||
				(len(str) > 0 && oldDeepMatchRune(str[1:], pattern, simple))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

func gen(alphabet string, maxLen int) []string {
	out := []string{""}
	cur := []string{""}
	for range maxLen {
		var next []string
		for _, s := range cur {
			for _, c := range alphabet {
				next = append(next, s+string(c))
			}
		}
		out = append(out, next...)
		cur = next
	}
	return out
}

// Exhaustive over a small alphabet: every pattern up to length 5 against every
// name up to length 5, for both simple modes.
func TestDeepMatchEquivalenceExhaustive(t *testing.T) {
	pats := gen("ab*?", 5)
	names := gen("ab", 5)
	var n int
	for _, p := range pats {
		for _, name := range names {
			if got, want := Match(p, name), oldMatch(p, name); got != want {
				t.Fatalf("Match(%q, %q) = %v, old = %v", p, name, got, want)
			}
			if got, want := MatchSimple(p, name), oldMatchSimple(p, name); got != want {
				t.Fatalf("MatchSimple(%q, %q) = %v, old = %v", p, name, got, want)
			}
			n += 2
		}
	}
	t.Logf("%d pattern/name/mode combinations agree", n)
}

// Same for the exported entry points, over a colon-bearing alphabet closer to
// policy actions and resource ARNs.
func TestMatchEquivalenceExhaustive(t *testing.T) {
	pats := gen("a:*?", 4)
	names := gen("a:/", 4)
	var n int
	for _, p := range pats {
		for _, name := range names {
			if got, want := Match(p, name), oldMatch(p, name); got != want {
				t.Fatalf("Match(%q, %q) = %v, old = %v", p, name, got, want)
			}
			if got, want := MatchSimple(p, name), oldMatchSimple(p, name); got != want {
				t.Fatalf("MatchSimple(%q, %q) = %v, old = %v", p, name, got, want)
			}
			n += 2
		}
	}
	t.Logf("%d exported-entry-point combinations agree", n)
}

func oldMatch(pattern, name string) bool {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	return oldDeepMatchRune(name, pattern, false)
}

func oldMatchSimple(pattern, name string) bool {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	return oldDeepMatchRune(name, pattern, true)
}

// A pattern with many stars used to take time exponential in the star count.
func TestMatchStarsAreLinear(t *testing.T) {
	name := "admin:ServerInfo"
	for _, stars := range []int{8, 16, 64, 256} {
		pattern := strings.Repeat("*", stars) + "X"
		start := time.Now()
		if Match(pattern, name) {
			t.Fatalf("pattern %d stars + X should not match %q", stars, name)
		}
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Errorf("Match with %d stars took %v, want well under 50ms", stars, d)
		}
	}
	// Interleaved stars are the harder shape.
	pattern := strings.Repeat("*a", 32) + "X"
	name = strings.Repeat("a", 128)
	start := time.Now()
	if Match(pattern, name) {
		t.Errorf("pattern %q should not match %q", pattern, name)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("Match with interleaved stars took %v, want well under 50ms", d)
	}
}

// Question-mark-heavy patterns take the MatchSimple prefix walk rather than a
// single deepMatchRune call, so they get their own before/after comparison.
// Star counts stay low: the old matcher is exponential in them.
func BenchmarkMatchSimpleQuestionMarks(b *testing.B) {
	cases := []struct {
		name    string
		pattern string
		text    string
	}{
		{"star-free", strings.Repeat("a?", 16), strings.Repeat("aa", 16)},
		{"all-marks", strings.Repeat("?", 32), strings.Repeat("a", 16)},
		{"leading-star", "*" + strings.Repeat("a?", 8), strings.Repeat("a", 24)},
		{"no-mark", "arn:aws:s3:::*", "arn:aws:s3:::bucket/object"},
	}
	for _, c := range cases {
		b.Run("new/"+c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = MatchSimple(c.pattern, c.text)
			}
		})
		b.Run("old/"+c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = oldMatchSimple(c.pattern, c.text)
			}
		})
	}
}

func FuzzDeepMatchEquivalence(f *testing.F) {
	for _, s := range []string{"", "*", "?", "a*b", "admin:*", "**?", "a", "*a*a*b"} {
		f.Add(s, "admin:Heal")
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		// Bound the old implementation's exponential blowup so the fuzzer
		// compares results instead of timing out on the bug being fixed.
		if strings.Count(pattern, "*") > 4 || len(pattern) > 24 || len(name) > 24 {
			t.Skip()
		}
		if got, want := Match(pattern, name), oldMatch(pattern, name); got != want {
			t.Fatalf("Match(%q, %q) = %v, old = %v", pattern, name, got, want)
		}
		if got, want := MatchSimple(pattern, name), oldMatchSimple(pattern, name); got != want {
			t.Fatalf("MatchSimple(%q, %q) = %v, old = %v", pattern, name, got, want)
		}
	})
}
