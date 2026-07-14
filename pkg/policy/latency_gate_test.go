package policy_test

// TestEngineCheck_P99LatencyGate is the hot-path latency GATE for Engine.Check
// (CLAUDE.md §1: p99 < 3ms on the streaming/decision hot path). The v0.9 surface
// notes claimed this gate existed; it did not. This test resolves that drift and
// makes the budget enforceable in CI (see the "latency-gate" job in
// .github/workflows/ci.yml, which runs it as a blocking step).
//
// It lives in the external policy_test package on purpose: it wires the
// pkg/persist Syncer over the Engine, and pkg/persist imports pkg/policy — so an
// internal (package policy) test file would form an import cycle. The external
// test package is compiled separately and may import persist.

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/persist"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// TestEngineCheck_P99LatencyGate drives many Engine.Check calls with the
// persistence syncer ACTIVE and fails if the p99 crosses the 3ms budget.
//
// Setup mirrors two existing references:
//   - engine_bench_test.go BenchmarkEngineCheck_AllowFastPath: the allow
//     fast-path shape production traffic is dominated by.
//   - persist/integration_test.go TestIntegration_HotPathLatencyWithPersistence:
//     an SQLite-backed write-behind Syncer, with reconciliation armed, running
//     its flush + reconcile loops on background goroutines during the
//     measurement. A single node makes reconcile a behavioral no-op, but the
//     Snapshot-diff + store round-trips still execute — proving the persistence
//     layer stays entirely off the Check hot path (it reads engine state only
//     through the read-locked SnapshotCosts, never the request path).
//
// Timing note (why this is not just "time each call"): on a fine-grained
// monotonic clock (Linux CI — the blocking gate's real environment) every sample
// is exactly one Check, so this is a true per-call p99 at nanosecond precision.
// On a coarse clock (Windows dev boxes advance the monotonic clock only at the
// system-timer tick, ~0.5ms here — measured), a sub-µs op reads 0, which is
// exactly why the sibling integration test could log "p99=0.000ms". To stay
// legible everywhere, the sampler keeps calling Check until the clock advances
// and records the mean-per-call for that span. The reported p99 is therefore
// always non-zero and legible in µs, and the gate never silently degenerates.
func TestEngineCheck_P99LatencyGate(t *testing.T) {
	// Engine: allow fast path (engine_bench_test.go) + a cost RuleSet so the
	// syncer's cost reconcile has a scope to snapshot (persist itPolicy). Requests
	// below are all shell-allow, so Check takes only the read lock — never the
	// cost write lock — matching the dominant production path.
	pol := &policy.Policy{
		Version: "1",
		Name:    "p99-gate",
		Rules: []policy.RuleSet{
			{Scope: "shell", Allow: []policy.Rule{{Pattern: "ls *"}}},
			{Scope: "cost", Limits: &policy.CostLimits{MaxPerSession: "$1000000.00"}},
		},
	}
	eng := policy.NewEngineFromPolicy(pol)

	// Persistence syncer ACTIVE over the same engine: SQLite store, write-behind
	// flush loop, and reconciliation armed (NodeID + a fast ReconcileInterval) so
	// the background loops run concurrently with the Check loop below.
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	sy := persist.New(persist.Config{
		Store:             st,
		Engine:            eng,
		NodeID:            "p99-gate-node",
		ReconcileInterval: 10 * time.Millisecond,
		BucketTTL:         time.Hour,
		CostTTL:           time.Hour,
	})
	if err := sy.Hydrate(context.Background()); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	sy.Start()
	defer sy.Close() // stops the loops + final flush before the store closes

	req := policy.ActionRequest{Scope: "shell", Command: "ls -la /tmp", AgentID: "gate"}

	// Warm up so first-touch allocation / caching costs do not skew samples.
	for i := 0; i < 2000; i++ {
		if r := eng.Check(req, "local"); r.Decision != policy.Allow {
			t.Fatalf("warmup: got decision %s, want ALLOW", r.Decision)
		}
	}

	const (
		// targetSamples: ≥10000 for a meaningful p99 (deliverable). On a fine clock
		// this is reached in exactly targetSamples calls.
		targetSamples = 10000
		// maxCalls bounds the coarse-clock (Windows) runtime: Check is ~0.3µs and
		// the tick is ~0.5ms, so ~1700 calls per sample. 4M calls => ~1.2s and a
		// few thousand samples locally. A fine clock reaches targetSamples long
		// before this cap, so it never applies on CI.
		maxCalls = 4_000_000
	)
	samples := make([]time.Duration, 0, targetSamples)
	totalCalls := 0
	for len(samples) < targetSamples && totalCalls < maxCalls {
		start := time.Now()
		calls := 0
		var elapsed time.Duration
		for {
			r := eng.Check(req, "local")
			if r.Decision != policy.Allow {
				t.Fatalf("got decision %s, want ALLOW", r.Decision)
			}
			calls++
			elapsed = time.Since(start)
			if elapsed > 0 {
				break // clock advanced; on a fine clock this is one call
			}
			if calls >= 1_000_000 {
				break // guard against a pathological (non-advancing) clock
			}
		}
		totalCalls += calls
		samples = append(samples, elapsed/time.Duration(calls))
	}
	if len(samples) < 200 {
		t.Fatalf("collected only %d latency samples (want >=200); clock too coarse or Check too slow", len(samples))
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := samples[len(samples)*50/100]
	p99 := samples[len(samples)*99/100]
	maxS := samples[len(samples)-1]

	us := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000.0 }
	t.Logf("Engine.Check hot path (persistence syncer ACTIVE): p50=%.3fµs p99=%.3fµs max=%.3fµs (samples=%d, calls=%d)",
		us(p50), us(p99), us(maxS), len(samples), totalCalls)

	// Hot-path budget (CLAUDE.md §1): p99 < 3ms. Persistence is write-behind, so
	// the active background syncer must not appear on this path.
	const budget = 3 * time.Millisecond
	if p99 >= budget {
		t.Errorf("Engine.Check p99 = %.3fµs violates the <3ms hot-path budget (persistence syncer active)", us(p99))
	}
}
