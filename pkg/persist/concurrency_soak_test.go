package persist

// concurrency_soak_test.go adds the sustained-CONCURRENCY dimension to the
// single-request hot-path gate that already lives in integration_test.go
// (TestIntegration_HotPathLatencyWithPersistence). That test proves ONE request
// at a time stays under the <3ms p99 budget with persistence ON; this test
// proves the SAME budget holds when MANY goroutines drive /v1/check at once —
// the condition under which shared-map lock contention (rate-limiter buckets,
// cost accumulator), the write-behind flush loop, and the background reconcile
// loop could actually push the hot path over budget. It ADDS a dimension; it
// does not weaken or duplicate the existing single-request gate.
//
// It reuses the itServer wiring from integration_test.go (real proxy.Server +
// SQLite store + Syncer, persistence AND reconcile ARMED) through a load-tuned
// policy (soakPolicy) whose rate ceiling is high enough that a multi-second run
// never trips the limiter. That keeps every ALLOW/DENY decision deterministic,
// so any concurrency-induced state corruption or response mix-up surfaces as a
// decision mismatch — the unary-endpoint analogue of the streaming
// cross-request-leak assertion in llmproxy's TestAT_Concurrency_NoCrossRequestLeak.
//
// Measurement mirrors the existing integration test's dual-signal approach:
//   - ENFORCED guard: the server's own X-AgentGuard-Total-Ms (the
//     network-EXCLUDED hot-path processing time), aggregated across every
//     concurrent request -> p99 < 3ms. That header is the correct definition of
//     "hot path" per CLAUDE.md (client byte in -> forwarded upstream and back);
//     httptest loopback + goroutine scheduling are deliberately outside it. On a
//     coarse monotonic clock (this Windows box, ~0.5ms tick) the header floors
//     toward 0 but can only OVER-report by ~one tick, so a genuine multi-ms
//     regression still trips this gate on every OS.
//   - REPORTED headline: aggregate throughput and mean per-op latency, robust on
//     coarse clocks because it is a whole-run aggregate, not per-op timing.
//
// Determinism / non-flakiness: correctness depends only on the p99 and
// decision/error assertions, never on a wall-clock sleep. The load phase is
// bounded by a deadline (a stop condition, not a correctness sleep) so the
// default run stays ~2s and gates cheaply in CI; set AGENTGUARD_SOAK=1 for an
// extended soak. Worker count scales with GOMAXPROCS and is clamped to [16,64]
// so oversubscription stays modest (real lock contention, bounded scheduling
// tail) even under `go test -race`.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// soakPolicy mirrors itPolicy but lifts the rate-limit ceiling so a multi-second
// sustained-load run never trips the limiter — every ALLOW/DENY decision then
// stays deterministic under load, which is what lets the concurrency test treat
// a wrong decision as a state-corruption / cross-request signal. The limiter's
// shared bucket map is STILL exercised on every request (one bucket per worker
// agent_id), so the shared-map lock contention that this test exists to keep
// under budget is present; it just never denies.
func soakPolicy() *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Name:    "persist-soak",
		Rules: []policy.RuleSet{
			{
				Scope:     "shell",
				Allow:     []policy.Rule{{Pattern: "ls *"}},
				RateLimit: &policy.RateLimitCfg{MaxRequests: 1_000_000_000, Window: "1m"},
			},
		},
	}
}

// newSoakServer builds the same store + Syncer + buffered-async-audit wiring as
// newITServer (persistence + reconcile armed, mirroring cmd/agentguard), but
// with soakPolicy so a sustained-load run stays decision-deterministic. It
// returns the shared *itServer so the existing close() teardown is reused.
func newSoakServer(t *testing.T, st store.Store, overflowDir string) *itServer {
	t.Helper()
	eng := policy.NewEngineFromPolicy(soakPolicy())
	disp := notify.NewDispatcher(policy.NotificationCfg{})
	buflog, err := audit.NewBufferedAsyncLogger(store.NewAuditLogger(st), audit.BufferedAsyncOpts{
		QueueSize: 4096, Workers: 2, OverflowPath: filepath.Join(overflowDir, "overflow.jsonl"),
	})
	if err != nil {
		t.Fatalf("buffered logger: %v", err)
	}
	srv := proxy.NewServer(proxy.Config{
		Engine: eng, Logger: buflog, DashboardEnabled: true, Notifier: disp,
		APIKey: itAPIKey, BaseURL: "http://127.0.0.1:0", Version: "soak",
	})
	// Reconciliation ARMED (single node => behavioral no-op) so the background
	// Snapshot-diff + store round-trips run during the load and prove they stay
	// off the /v1/check path — same rationale as newITServer.
	sy := New(Config{
		Store: st, Engine: eng, Limiter: srv.Limiter(), Approvals: srv.ApprovalQueue(),
		NodeID: "soak-node", ReconcileInterval: 100 * time.Millisecond, BucketTTL: time.Hour, CostTTL: time.Hour,
	})
	ts := httptest.NewServer(srv.Handler())
	return &itServer{srv: srv, eng: eng, sy: sy, ts: ts, disp: disp, buflog: buflog}
}

// TestIntegration_ConcurrentHotPathLatencyWithPersistence drives /v1/check from
// [16,64] concurrent workers for a bounded duration (persistence + reconcile +
// write-behind flush all live) and asserts the network-excluded hot-path p99
// stays < 3ms UNDER load, with zero request failures and zero decision
// mismatches (the cross-request / state-corruption guard).
func TestIntegration_ConcurrentHotPathLatencyWithPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	s := newSoakServer(t, st, dir)
	// Teardown order (defers run LIFO): stop the Syncer (final write-behind
	// flush, loops joined) BEFORE the server, and both BEFORE the store closes,
	// so no background goroutine touches a closed store under -race.
	defer s.close()
	defer s.sy.Close()
	if err := s.sy.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	s.sy.Start() // background flush + reconcile loops running, exactly like production

	// Worker count: modest oversubscription of the scheduler so multiple
	// goroutines genuinely contend for the limiter/cost locks, without a
	// pathological scheduling tail that would make the p99 flaky under -race.
	workers := 2 * runtime.GOMAXPROCS(0)
	if workers < 16 {
		workers = 16
	}
	if workers > 64 {
		workers = 64
	}

	loadDur := 2 * time.Second
	if os.Getenv("AGENTGUARD_SOAK") == "1" {
		loadDur = 15 * time.Second
	}

	// A dedicated client with generous keep-alive so the sustained load reuses a
	// small pool of connections instead of churning ephemeral ports (matters on
	// Windows). Network cost is excluded from the enforced metric anyway; this
	// only keeps the reported throughput legible and the run stable.
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        workers * 2,
			MaxIdleConnsPerHost: workers * 2,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
	defer client.CloseIdleConnections()

	checkURL := s.ts.URL + "/v1/check"

	// do performs one POST /v1/check. It is goroutine-safe (never calls t.Fatalf,
	// which may only be used from the test goroutine): it returns the server's
	// self-reported hot-path milliseconds, the decision, and a non-empty failure
	// string on any transport error, non-200, decode error, missing header, or —
	// the cross-request guard — a decision that does not match the request shape.
	do := func(worker, seq int) (float64, string) {
		allow := seq%2 == 0
		cmd := "ls -la"
		want := policy.Allow
		if !allow {
			cmd = "rm -rf /tmp/soak" // no matching allow rule -> default deny
			want = policy.Deny
		}
		body := fmt.Sprintf(`{"scope":"shell","command":%q,"agent_id":"soak-w%d"}`, cmd, worker)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, strings.NewReader(body))
		if err != nil {
			return 0, "newrequest: " + err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, "do: " + err.Error()
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close() // drain+close so the keep-alive connection is reused
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		var res policy.CheckResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return 0, "decode: " + err.Error()
		}
		if res.Decision != want {
			return 0, fmt.Sprintf("wrong decision for %q: got %s want %s", cmd, res.Decision, want)
		}
		ms, err := strconv.ParseFloat(resp.Header.Get("X-AgentGuard-Total-Ms"), 64)
		if err != nil {
			return 0, "bad X-AgentGuard-Total-Ms header: " + resp.Header.Get("X-AgentGuard-Total-Ms")
		}
		return ms, ""
	}

	// Warm up: prime the per-agent buckets, the audit workers, and the
	// connection pool so the measured window is steady-state.
	for i := 0; i < 200; i++ {
		if _, e := do(0, i); e != "" {
			t.Fatalf("warm-up request %d failed: %s", i, e)
		}
	}

	// Each worker owns its own slice (no shared mutation, so the harness itself
	// adds no lock contention and stays -race clean); results merge after Wait.
	type workerResult struct {
		samples      []float64
		failures     int
		firstFailure string
	}
	results := make([]workerResult, workers)
	deadline := time.Now().Add(loadDur)

	var wg sync.WaitGroup
	wallStart := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			local := workerResult{samples: make([]float64, 0, 1<<16)}
			for seq := 0; time.Now().Before(deadline); seq++ {
				ms, e := do(w, seq)
				if e != "" {
					local.failures++
					if local.firstFailure == "" {
						local.firstFailure = e
					}
					continue
				}
				local.samples = append(local.samples, ms)
			}
			results[w] = local
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(wallStart)

	// Merge.
	all := make([]float64, 0, workers*4096)
	totalFailures := 0
	firstFailure := ""
	for _, r := range results {
		all = append(all, r.samples...)
		totalFailures += r.failures
		if firstFailure == "" {
			firstFailure = r.firstFailure
		}
	}

	// No errors / no cross-request leakage under load.
	if totalFailures > 0 {
		t.Errorf("%d request failures under %d-worker load (first: %q) — a transport error, non-200, decode failure, or a decision that did not match the request shape (state corruption / cross-request leak)",
			totalFailures, workers, firstFailure)
	}
	if len(all) < 2000 {
		t.Fatalf("collected only %d successful samples under load (want >=2000 for a meaningful p99); machine may be stalled", len(all))
	}

	sort.Float64s(all)
	p50 := all[len(all)*50/100]
	p99 := all[len(all)*99/100]
	max := all[len(all)-1]
	throughput := float64(len(all)) / elapsed.Seconds()
	// Mean per-op latency from one worker's perspective (network-INCLUDED): the
	// whole-run wall time divided by the ops a single worker completed. Robust on
	// coarse clocks because it is an aggregate, not a per-op reading.
	meanPerOpUs := elapsed.Seconds() * float64(workers) / float64(len(all)) * 1e6

	t.Logf("concurrent /v1/check hot-path (X-AgentGuard-Total-Ms, network-EXCLUDED) under %d workers x %s: p50=%.3fms p99=%.3fms max=%.3fms (samples=%d, failures=%d)",
		workers, elapsed.Round(time.Millisecond), p50, p99, max, len(all), totalFailures)
	t.Logf("aggregate client-observed (network-INCLUDED): throughput=%.0f req/s, mean per-op=%.1fµs",
		throughput, meanPerOpUs)

	// The <3ms p99 contract must hold UNDER sustained concurrent load, not just
	// for single requests. The store is write-behind and reconcile is
	// background, so neither may appear on this hot path.
	if p99 >= 3.0 {
		t.Errorf("concurrent hot-path p99 = %.3fms violates the <3ms budget under %d-worker sustained load with persistence on", p99, workers)
	}
}
