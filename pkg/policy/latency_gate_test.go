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

	const n = 20000
	samples := make([]float64, n)
	for i := 0; i < n; i++ {
		req := shellReq
		if i%4 == 0 {
			req = costReq // mix in the write-lock cost path
		}
		start := time.Now()
		eng.Check(req, LocalTenantID)
		samples[i] = float64(time.Since(start).Nanoseconds()) / 1e6 // ms
	}

	close(stop)
	wg.Wait()

	sort.Float64s(samples)
	p50 := samples[n*50/100]
	p99 := samples[n*99/100]
	max := samples[n-1]
	t.Logf("Engine.Check p99 gate (persistence active): p50=%.4fms p99=%.4fms max=%.4fms n=%d snapshots=%d",
		p50, p99, max, n, atomic.LoadInt64(&snapshots))

	const budgetMs = 3.0 // CLAUDE.md hot-path contract; generous vs. the sub-0.1ms baseline.
	if p99 >= budgetMs {
		t.Errorf("Engine.Check p99 = %.4fms exceeds the %.1fms hot-path budget — a regression has put blocking work on the /v1/check hot path", p99, budgetMs)
	}
}
