//go:build !race

// Build tag: this is a wall-clock p99 budget gate (<3ms end-to-end on the
// /v1/check hot path with persistence ON). The race detector's instrumentation
// inflates per-access latency enough to push p99 past the budget for reasons
// unrelated to a real regression, so this test is excluded from the broad
// `go test -race ./...` run and executed in CI's dedicated no-race latency step
// (.github/workflows/ci.yml). The restart-durability test stays in
// integration_test.go and DOES run under -race. Shared helpers
// (newITServer/itServer/postCheck) live in integration_test.go and compile in
// all builds.

package persist

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

func TestIntegration_HotPathLatencyWithPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	s := newITServer(t, st, dir)
	defer s.close()
	if err := s.sy.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	s.sy.Start() // background flush loop running, exactly like production

	// Warm up.
	for i := 0; i < 20; i++ {
		s.postCheck(t, `{"scope":"shell","command":"ls -la","agent_id":"warm"}`)
	}

	// Measure the SERVER's self-reported END-TO-END processing time
	// (X-AgentGuard-Total-Ms) over many requests — the hot path, excluding
	// httptest/network. Total-Ms now includes the audit enqueue (see
	// pkg/proxy logAndRespond), so this gate covers policy PLUS the
	// write-behind store's buffered audit-enqueue cost, not policy alone.
	const n = 300
	samples := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		_, _, h := s.postCheck(t, `{"scope":"shell","command":"ls -la","agent_id":"lat"}`)
		total, err := strconv.ParseFloat(h.Get("X-AgentGuard-Total-Ms"), 64)
		if err != nil {
			t.Fatalf("missing/invalid X-AgentGuard-Total-Ms header: %q", h.Get("X-AgentGuard-Total-Ms"))
		}
		// Total must account for the audit write — guards the regression where
		// Total was captured before the audit enqueue and silently understated
		// the hot path.
		if audit, aerr := strconv.ParseFloat(h.Get("X-AgentGuard-Audit-Ms"), 64); aerr == nil {
			if total+0.001 < audit {
				t.Fatalf("Total-Ms %.3f < Audit-Ms %.3f: audit enqueue not included in end-to-end latency", total, audit)
			}
		}
		samples = append(samples, total)
	}
	sort.Float64s(samples)
	p50 := samples[len(samples)*50/100]
	p99 := samples[len(samples)*99/100]
	max := samples[len(samples)-1]
	t.Logf("hot-path /v1/check (end-to-end, persistence ON): p50=%.3fms p99=%.3fms max=%.3fms (n=%d)", p50, p99, max, n)

	// Contract: <3ms p99 end-to-end. The store is write-behind and the audit is
	// buffered, so neither the state sync nor the audit DB write may appear here.
	if p99 >= 3.0 {
		t.Errorf("hot-path p99 = %.3fms violates the <3ms budget with persistence on", p99)
	}

	// --- Signal 2 (folded in from the v1.0 branch): client-observed per-op
	// latency, ns-precision, adaptive ----------------------------------------
	// The X-AgentGuard-Total-Ms header above is µs-granular and floors to 0 on a
	// coarse clock (Windows advances the monotonic clock only at the ~0.5ms
	// system-timer tick), so it is not a legible headline there. Here we measure
	// the /v1/check round-trip at nanosecond precision: on a fine clock each
	// sample is one round-trip; on a coarse clock the sampler groups enough
	// round-trips for the monotonic clock to advance and records the mean-per-op.
	// The reported p99 is therefore always non-zero and legible in µs, which makes
	// this test load-bearing on every OS (it does not degenerate to "0.000ms").
	const clientTarget = 500
	cs := make([]time.Duration, 0, clientTarget)
	roundTrips := 0
	for len(cs) < clientTarget && roundTrips < 40_000 {
		start := time.Now()
		calls := 0
		var elapsed time.Duration
		for {
			s.postCheck(t, `{"scope":"shell","command":"ls -la","agent_id":"lat"}`)
			calls++
			elapsed = time.Since(start)
			if elapsed > 0 || calls >= 100_000 {
				break
			}
		}
		roundTrips += calls
		cs = append(cs, elapsed/time.Duration(calls))
	}
	if len(cs) < 100 {
		t.Fatalf("collected only %d client latency samples (want >=100)", len(cs))
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	us := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000.0 }
	cp50 := cs[len(cs)*50/100]
	cp99 := cs[len(cs)*99/100]
	cmax := cs[len(cs)-1]
	t.Logf("client-observed /v1/check per-op latency (ns-precision, adaptive): p50=%.3fµs p99=%.3fµs max=%.3fµs (samples=%d, round-trips=%d)",
		us(cp50), us(cp99), us(cmax), len(cs), roundTrips)
}
