package policy

// fuzz_glob_test.go adds a Go native fuzz target for the policy glob
// matcher (v1.0 item 2, sub-task 2b). It complements the testing/quick
// property tests in engine_glob_property_test.go, which assert semantic
// invariants, by pounding globMatch with arbitrary (pattern, value)
// pairs to prove the robustness invariant that matters on the hot path:
//
//	globMatch must never panic and must always return — no infinite loop
//	and no catastrophic backtracking — within a sane time bound.
//
// The matcher runs on every policy evaluation, over strings that mix
// policy-author patterns with agent-supplied values (paths, domains,
// commands). Both sides are untrusted, so the matcher must be total.
//
// NOTE: TEST-ONLY. If the fuzzer discovers a crash/hang in globMatch
// (hot-path production code) the crasher is left in place and reported
// for separate human review — engine.go is NOT patched here.

import (
	"testing"
	"time"
)

// globTimeout bounds a single globMatch call. The matcher is an O(n*m)
// two-pointer scan, so this generous ceiling only trips on a genuine
// hang or accidental super-linear blowup.
const globTimeout = 3 * time.Second

// maxGlobInputBytes caps each side so a pathological seed/mutation
// cannot make one iteration slow purely by size (which would make the
// timeout guard flaky) rather than by an algorithmic defect. Real
// patterns and values are far shorter.
const maxGlobInputBytes = 8192

// globSeeds are representative (pattern, value) pairs pulled from the
// documented contract and existing policy tests: bare/nested double
// stars, path segment globs, domain wildcards, literals, and the
// security-critical "**/secret/** must not match a sibling segment"
// case. They also stress the star-heavy inputs most likely to expose
// backtracking.
var globSeeds = [][2]string{
	{"*", "anything"},
	{"**", "/a/b/c"},
	{"a/*/b", "a/x/b"},
	{"a/*/b", "a/x/y/b"},
	{"/etc/**", "/etc/passwd"},
	{"/etc/**", "/etc"},
	{"**/secret/**", "/notsecret/x"},
	{"**/secret/**", "/app/secret/key"},
	{"*.foo.com", "api.foo.com"},
	{"*.foo.com", "foo.com"},
	{"foo.com", "foo.com"},
	{"rm -rf *", "rm -rf /tmp/x"},
	{"", ""},
	{"", "x"},
	{"x", ""},
	{"?", "a"},
	{"a?c", "abc"},
	// Star-dense adversarial inputs: worst case for a naive backtracker.
	{"*a*a*a*a*a*a*a*a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"},
	{"**/**/**/**/**", "a/b/c/d/e/f/g/h"},
	{"*/*/*/*/*/*/*/*", "a/b/c/d/e/f/g"},
	{"************", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
}

// FuzzGlobMatch feeds two arbitrary strings (pattern, value) to
// globMatch. Property: never panics, always returns within globTimeout.
func FuzzGlobMatch(f *testing.F) {
	for _, s := range globSeeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, pattern, value string) {
		if len(pattern) > maxGlobInputBytes {
			pattern = pattern[:maxGlobInputBytes]
		}
		if len(value) > maxGlobInputBytes {
			value = value[:maxGlobInputBytes]
		}

		done := make(chan interface{}, 1) // carries the recovered panic value, or nil
		go func() {
			defer func() { done <- recover() }()
			_ = globMatch(pattern, value)
		}()

		select {
		case rec := <-done:
			if rec != nil {
				// Re-raise on the fuzz-worker goroutine so the engine
				// records the reproducing input as a crasher.
				panic(rec)
			}
		case <-time.After(globTimeout):
			t.Fatalf("globMatch did not return within %v for pattern=%q value=%q (possible infinite loop / catastrophic backtracking)", globTimeout, pattern, value)
		}
	})
}
