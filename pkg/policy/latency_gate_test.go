//go:build !race

// Build tag: this is a wall-clock p99 budget gate. The race detector's
// instrumentation inflates per-access latency by ~5–10×, which can push the
// measured p99 past the 3ms budget for reasons unrelated to a real regression.
// CI runs this gate in a dedicated step WITHOUT -race (see .github/workflows/
// ci.yml); excluding it from the broad `go test -race ./...` run keeps that
// dedicated step the single, trustworthy source of truth.

package policy

import (
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEngineCheck_P99LatencyGate is the v1.0 CI hot-path latency gate.
//
// It exercises Engine.Check on the local tenant with the persistence
// machinery active and FAILS if p99 exceeds the <3ms budget from CLAUDE.md
// ("Latency is God"). "Persistence ON" at the engine level means:
//
//   - cost-scoped checks take the engine write lock and mutate the
//     session-cost accumulator (the mutable runtime state that persistence
//     snapshots), and
//   - a background goroutine calls SnapshotCosts() on a tight tick, standing
//     in for the write-behind pkg/persist.Syncer reading that state off the
//     request path and contending for the same lock.
//
// The store is write-behind by contract and must never appear inline on
// Check. If a regression ever lands a synchronous DB / disk / network call on
// the hot path, its millisecond-scale cost trips this gate. The bare-engine
// baseline p99 is well under 0.1ms (the ~0.53ms figure in the docs is the full
// HTTP /v1/check path measured in pkg/persist); the 3ms ceiling is deliberately
// generous so only a genuine regression — not CI scheduling jitter — fails the
// build. See also TestIntegration_HotPathLatencyWithPersistence (HTTP path).
//
// Timing note (why this is not just "time each call"): on a fine-grained
// monotonic clock (Linux CI — the blocking gate's real environment) each sample
// is exactly one Check, so this is a true per-call p99 at nanosecond precision.
// On a coarse clock (Windows dev boxes advance the monotonic clock only at the
// system-timer tick, ~0.5ms here), a sub-µs op reads 0, which would silently
// degenerate the gate to "p99=0.000ms". To stay legible everywhere, the sampler
// keeps calling Check until the clock advances and records the mean-per-call for
// that span (adaptive sampler ported from the v1.0 persist integration gate), so
// the reported p99 is always non-zero and the gate never quietly no-ops.
func TestEngineCheck_P99LatencyGate(t *testing.T) {
	eng := NewEngineFromPolicy(&Policy{
		Version: "1", Name: "local",
		Rules: []RuleSet{
			{Scope: "shell", Allow: []Rule{{Pattern: "ls *"}}},
			// Effectively-unbounded cap: cost checks always ALLOW while still
			// taking the write lock and accumulating session cost — the state
			// the persistence syncer snapshots.
			{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$1000000000.00"}},
		},
	})
	defer eng.Close()

	// Background snapshotter: stand-in for pkg/persist.Syncer's periodic read
	// of the cost accumulator. The real syncer flushes on a ≥1s tick; this
	// ticks far faster on purpose to maximize lock overlap with the measured
	// loop and surface any contention the write-behind path would introduce.
	stop := make(chan struct{})
	var snapshots int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(500 * time.Microsecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = eng.SnapshotCosts()
				atomic.AddInt64(&snapshots, 1)
			}
		}
	}()

	shellReq := ActionRequest{Scope: "shell", Command: "ls -la", AgentID: "lat"}
	costReq := ActionRequest{Scope: "cost", SessionID: "lat", EstCost: 0.0001}

	// Warm up caches / branch predictors before measuring.
	for i := 0; i < 2000; i++ {
		eng.Check(shellReq, LocalTenantID)
	}

	// Adaptive, coarse-clock-safe sampler (ported from the v1.0 persist
	// integration gate). On a fine clock each span is one Check, so this is a
	// true per-call p99 at ns precision; on a coarse clock the span groups
	// enough Checks for the monotonic clock to advance and records the
	// mean-per-Check. Every 4th call mixes in the cost path so the engine write
	// lock (the state the snapshotter contends on) is exercised under load.
	const (
		// targetSamples: ≥10000 for a meaningful p99. On a fine clock this is
		// reached in ~targetSamples calls.
		targetSamples = 10000
		// maxCalls bounds the coarse-clock (Windows) runtime: Check is ~0.3µs
		// and the tick is ~0.5ms, so ~1700 calls per sample. A fine clock
		// reaches targetSamples long before this cap, so it never applies on CI.
		maxCalls = 4_000_000
	)
	samples := make([]time.Duration, 0, targetSamples)
	totalCalls := 0
	for len(samples) < targetSamples && totalCalls < maxCalls {
		start := time.Now()
		calls := 0
		var elapsed time.Duration
		for {
			req := shellReq
			if calls%4 == 0 {
				req = costReq // mix in the write-lock cost path
			}
			r := eng.Check(req, LocalTenantID)
			if req.Scope == "shell" && r.Decision != Allow {
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

	close(stop)
	wg.Wait()

	if len(samples) < 200 {
		t.Fatalf("collected only %d latency samples (want >=200); clock too coarse or Check too slow", len(samples))
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := samples[len(samples)*50/100]
	p99 := samples[len(samples)*99/100]
	maxS := samples[len(samples)-1]

	us := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000.0 }
	t.Logf("Engine.Check p99 gate (persistence active): p50=%.3fµs p99=%.3fµs max=%.3fµs (samples=%d, calls=%d, snapshots=%d)",
		us(p50), us(p99), us(maxS), len(samples), totalCalls, atomic.LoadInt64(&snapshots))

	// Hot-path budget (CLAUDE.md §1): p99 < 3ms. Persistence is write-behind, so
	// the active background snapshotter must not appear on this path.
	const budget = 3 * time.Millisecond
	if p99 >= budget {
		t.Errorf("Engine.Check p99 = %.3fµs violates the <3ms hot-path budget — a regression has put blocking work on the /v1/check hot path", us(p99))
	}
}
