package condition

import (
	"testing"
)

// Two conditions that select different requests must not render to the same
// string: Functions.Equals and Statement.hash compare conditions through String,
// and dropDuplicateStatements discards whatever compares equal. A value holding
// the separator used to render like two separate values, so a Deny carrying
// "a b" was dropped as a duplicate of a Deny carrying "a" and "b" -- and the
// restriction it states with it.
func TestStringFuncStringIsInjective(t *testing.T) {
	tests := []struct {
		name   string
		build  []string
		mutate []string
	}{
		{
			// "a b" is one value that holds a space; {"a","b"} is two values.
			name:   "space in a value vs two values",
			build:  []string{"a b"},
			mutate: []string{"a", "b"},
		},
		{
			// Separators that a plain join would have to be trusted with.
			name:   "comma in a value vs two values",
			build:  []string{"a,b"},
			mutate: []string{"a", "b"},
		},
		{
			name:   "brackets in a value vs a list rendering",
			build:  []string{"[a]"},
			mutate: []string{"a"},
		},
		{
			name:   "emptiness",
			build:  []string{""},
			mutate: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := newStringEqualsFunc(S3Prefix.ToKey(), NewValueSet(stringsToValues(tc.build)...), "")
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			b, err := newStringEqualsFunc(S3Prefix.ToKey(), NewValueSet(stringsToValues(tc.mutate)...), "")
			if err != nil {
				t.Fatalf("mutate: %v", err)
			}

			// Rendering must never merge these: they select different requests,
			// so a shared string is what let dropDuplicateStatements discard one
			// of them. Confirm the difference is real and not an artifact of the
			// test's own expectations before blaming the renderer.
			distinguishable := false
			for _, prefix := range []string{"a b", "a", "b", "a,b", "[a]", ""} {
				values := map[string][]string{"prefix": {prefix}}
				if a.evaluate(values) != b.evaluate(values) {
					distinguishable = true
					break
				}
			}
			if !distinguishable {
				t.Fatalf("test case is wrong: %v and %v select the same requests", tc.build, tc.mutate)
			}
			if a.String() == b.String() {
				t.Errorf("%v and %v are distinguishable but both render as %q", tc.build, tc.mutate, a.String())
			}
		})
	}
}

// Distinct values must render to distinct strings, so that unrelated conditions
// are never merged. The values a ValueSet can hold are unordered, so {"a","b"}
// and {"b","a"} are the same condition and must render alike.
func TestStringFuncStringKeepsDistinctValuesDistinct(t *testing.T) {
	mk := func(values ...string) string {
		f, err := newStringEqualsFunc(S3Prefix.ToKey(), NewValueSet(stringsToValues(values)...), "")
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return f.String()
	}

	seen := map[string][]string{}
	for _, values := range [][]string{
		{"a"}, {"b"}, {"ab"}, {"a b"}, {"a", "b"}, {"b", "a"}, {"a:"}, {":"}, {""}, {"a", "b", "c"},
	} {
		s := mk(values...)
		if prev, ok := seen[s]; ok {
			// Only the ordering of the same set may collide.
			if !sameSet(prev, values) {
				t.Errorf("%v and %v both render as %q", prev, values, s)
			}
			continue
		}
		seen[s] = values
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// Sibling functions carry the same rendering contract, so pin ipaddrFunc too:
// its values are CIDRs and cannot hold a separator, but it must stay injective
// regardless.
func TestIPAddrFuncStringIsInjective(t *testing.T) {
	mk := func(cidrs ...string) string {
		f, err := newIPAddressFunc(AWSSourceIP.ToKey(), NewValueSet(stringsToValues(cidrs)...), "")
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return f.String()
	}

	seen := map[string][]string{}
	for _, cidrs := range [][]string{
		{"192.168.1.0/24"}, {"10.0.0.0/8"}, {"192.168.1.0/24", "10.0.0.0/8"},
	} {
		s := mk(cidrs...)
		if prev, ok := seen[s]; ok {
			t.Errorf("%v and %v both render as %q", prev, cidrs, s)
		}
		seen[s] = cidrs
	}
}

func stringsToValues(values []string) []Value {
	vs := make([]Value, 0, len(values))
	for _, v := range values {
		vs = append(vs, NewStringValue(v))
	}
	return vs
}
