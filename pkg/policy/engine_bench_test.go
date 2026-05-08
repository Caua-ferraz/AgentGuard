package policy

import (
	"fmt"
	"testing"
)

// BenchmarkEngineCheck_AllowFastPath measures the hot path: a single allow
// rule whose pattern matches on the first comparison. This is the cheapest
// possible Check() and the one production traffic dominates.
func BenchmarkEngineCheck_AllowFastPath(b *testing.B) {
	pol := &Policy{
		Version: "1",
		Name:    "bench-allow",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{Pattern: "ls *"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)
	req := ActionRequest{
		Scope:   "shell",
		Command: "ls -la /tmp",
		AgentID: "bench",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := engine.Check(req, "local")
		if r.Decision != Allow {
			b.Fatalf("unexpected decision %s", r.Decision)
		}
	}
}

// BenchmarkEngineCheck_DenyDeepMatch measures the cost of walking past
// many non-matching allow rules to reach a deny rule that matches. This
// is the worst-case shape we expect from a "long allowlist + a few hard
// denies" policy.
func BenchmarkEngineCheck_DenyDeepMatch(b *testing.B) {
	const allowRules = 100
	allows := make([]Rule, 0, allowRules)
	for i := 0; i < allowRules; i++ {
		// Patterns that intentionally do not match the request command.
		allows = append(allows, Rule{Pattern: fmt.Sprintf("noop-%d *", i)})
	}
	pol := &Policy{
		Version: "1",
		Name:    "bench-deny-deep",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: allows,
				Deny: []Rule{
					{Pattern: "rm -rf *", Message: "destructive"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)
	req := ActionRequest{
		Scope:   "shell",
		Command: "rm -rf /tmp/data",
		AgentID: "bench",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := engine.Check(req, "local")
		if r.Decision != Deny {
			b.Fatalf("unexpected decision %s", r.Decision)
		}
	}
}

// BenchmarkGlobMatch_DoubleStar exercises the segment-aware ** matcher
// against a 5-segment path. We split into two sub-benchmarks so the
// matching and non-matching code paths show up separately in profiles —
// they have different early-exit characteristics.
func BenchmarkGlobMatch_DoubleStar(b *testing.B) {
	const pattern = "**/secret/**"

	b.Run("Match", func(b *testing.B) {
		const value = "/srv/app/secret/keys/prod.pem"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !globMatch(pattern, value) {
				b.Fatal("expected match")
			}
		}
	})

	b.Run("NoMatch", func(b *testing.B) {
		const value = "/srv/app/notsecret/keys/prod.pem"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if globMatch(pattern, value) {
				b.Fatal("unexpected match")
			}
		}
	})
}
