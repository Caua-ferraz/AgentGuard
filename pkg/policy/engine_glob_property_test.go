package policy

// AT-added property-based tests for the glob matcher.
//
// These complement the table-driven tests in engine_bypass_test.go by
// exercising globMatch over randomly generated inputs. The goal is to
// catch panics, invariant violations, and the "**/secret/** must never
// match a sibling like /notsecret/x" security property documented in
// CLAUDE.md.
//
// Uses stdlib testing/quick — no external dependencies, in line with the
// "one external Go dep" rule.

import (
	"strings"
	"testing"
	"testing/quick"
)

// TestGlobMatch_LiteralReflexive asserts that any literal pattern (no glob
// metacharacters) matches itself. This is the most basic invariant — if it
// breaks, every literal-rule policy is broken.
func TestGlobMatch_LiteralReflexive(t *testing.T) {
	prop := func(s string) bool {
		// Skip strings with glob metacharacters or characters that would
		// confuse the test (we want literal-only inputs here). Empty string
		// is allowed as a corner case, but quick rarely produces it.
		if strings.ContainsAny(s, "*?[]") {
			return true
		}
		if s == "" {
			return true
		}
		return globMatch(s, s)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestGlobMatch_DoubleStarSecretSafety asserts the security invariant
// documented in CLAUDE.md: `**/secret/**` must never match a path whose
// only "secret" appearance is as a substring of a different segment
// (e.g. `/notsecret/x`). The matcher splits on `/`, so the "secret" segment
// must be present as a whole component for the pattern to match.
func TestGlobMatch_DoubleStarSecretSafety(t *testing.T) {
	prop := func(rest string) bool {
		// If `rest` itself contains a path that includes a real /secret/
		// segment, the pattern legitimately matches — skip those cases.
		// Detect by checking for `/secret/` or `/secret` at end, or starting
		// with `secret/` or equaling `secret`.
		if rest == "secret" || rest == "/secret" {
			return true
		}
		if strings.HasPrefix(rest, "secret/") || strings.HasPrefix(rest, "/secret/") {
			return true
		}
		if strings.Contains(rest, "/secret/") || strings.HasSuffix(rest, "/secret") {
			return true
		}
		// Filter out characters that would be interpreted as glob metas if
		// they leaked back into the pattern position. They wouldn't here
		// (rest only goes into value), but quick can produce them and we
		// want a clean negative.
		// Construct a value where the only "secret"-ish substring is in
		// "notsecret" — i.e. NOT a whole /secret/ segment.
		value := "/notsecret/" + rest
		return !globMatch("**/secret/**", value)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestGlobMatch_NoPanics asserts the matcher never panics on any random
// (pattern, value) pair. The matcher receives entirely untrusted strings
// in production (policy author + agent input) so it must be panic-free.
func TestGlobMatch_NoPanics(t *testing.T) {
	prop := func(pattern, input string) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("globMatch panicked on pattern=%q value=%q: %v", pattern, input, r)
				ok = false
			}
		}()
		_ = globMatch(pattern, input)
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// TestGlobMatch_BareDoubleStarMatchesEverything asserts the documented
// contract that `**` on its own matches any string. This is a property,
// not a table case, because we want to verify it across the full input
// space rather than a few hand-picked rows.
func TestGlobMatch_BareDoubleStarMatchesEverything(t *testing.T) {
	prop := func(value string) bool {
		return globMatch("**", value)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestGlobMatch_LiteralNeverMatchesDistinct: a literal pattern P (no glob
// chars) cannot match any value V != P. Locks in the "no implicit suffix
// match" guarantee — `foo.com` does not match `evil.foo.com.attacker`.
func TestGlobMatch_LiteralNeverMatchesDistinct(t *testing.T) {
	prop := func(p, v string) bool {
		if strings.ContainsAny(p, "*?[]") {
			return true // not a literal
		}
		if p == v {
			return true // reflexive case covered elsewhere
		}
		return !globMatch(p, v)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
