package persist

// End-to-end persistence integration: drive the REAL proxy.Server over HTTP
// with a store + syncer wired exactly as cmd/agentguard does, then prove that
// (1) approvals / costs / rate-limit buckets survive a full restart, and
// (2) enabling persistence does NOT push the /v1/check hot path over the <3ms
// budget (the store is write-behind, never inline).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

const itAPIKey = "it-key"

func itPolicy() *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Name:    "persist-it",
		Rules: []policy.RuleSet{
			{
				Scope:           "shell",
				Allow:           []policy.Rule{{Pattern: "ls *"}},
				RequireApproval: []policy.Rule{{Pattern: "sudo *"}},
				RateLimit:       &policy.RateLimitCfg{MaxRequests: 1000, Window: "1m"},
			},
			{
				Scope:  "cost",
				Limits: &policy.CostLimits{MaxPerSession: "$100.00"},
			},
		},
	}
}

// itServer builds a server + syncer over the given store, mirroring the
// cmd/agentguard wiring (store-backed audit behind the buffered async logger so
// the hot path only enqueues).
type itServer struct {
	srv    *proxy.Server
	eng    *policy.Engine
	sy     *Syncer
	ts     *httptest.Server
	disp   *notify.Dispatcher
	buflog *audit.BufferedAsyncLogger
}

func newITServer(t *testing.T, st store.Store, overflowDir string) *itServer {
	t.Helper()
	eng := policy.NewEngineFromPolicy(itPolicy())
	disp := notify.NewDispatcher(policy.NotificationCfg{})
	buflog, err := audit.NewBufferedAsyncLogger(store.NewAuditLogger(st), audit.BufferedAsyncOpts{
		QueueSize: 1024, Workers: 2, OverflowPath: filepath.Join(overflowDir, "overflow.jsonl"),
	})
	if err != nil {
		t.Fatalf("buffered logger: %v", err)
	}
	srv := proxy.NewServer(proxy.Config{
		Engine: eng, Logger: buflog, DashboardEnabled: true, Notifier: disp,
		APIKey: itAPIKey, BaseURL: "http://127.0.0.1:0", Version: "it",
	})
	// Reconciliation ARMED (v1.0): NodeID + a fast ReconcileInterval so the
	// background reconcile loop runs during the hot-path latency test and proves
	// it stays off the /v1/check path (the p99<3ms gate below). Single node =>
	// others=0 => behavioral no-op, but the loop still does its Snapshot-diff +
	// store round-trips on a background goroutine.
	sy := New(Config{
		Store: st, Engine: eng, Limiter: srv.Limiter(), Approvals: srv.ApprovalQueue(),
		NodeID: "it-node", ReconcileInterval: 100 * time.Millisecond, BucketTTL: time.Hour, CostTTL: time.Hour,
	})
	ts := httptest.NewServer(srv.Handler())
	return &itServer{srv: srv, eng: eng, sy: sy, ts: ts, disp: disp, buflog: buflog}
}

func (s *itServer) close() {
	s.ts.Close()
	_ = s.buflog.Close()
	s.disp.Close()
	s.srv.Shutdown()
}

func (s *itServer) postCheck(t *testing.T, body string) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, s.ts.URL+"/v1/check", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header
}

func TestIntegration_StateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agentguard.db")

	// --- lifecycle 1: create state, flush, shut down ---
	st1, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store #1: %v", err)
	}
	s1 := newITServer(t, st1, dir)
	if err := s1.sy.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate #1: %v", err)
	}

	// (a) an approval (require_approval rule)
	code, m, _ := s1.postCheck(t, `{"scope":"shell","command":"sudo apt update","agent_id":"smoke","session_id":"sess"}`)
	if code != http.StatusOK || m["decision"] != "REQUIRE_APPROVAL" {
		t.Fatalf("expected REQUIRE_APPROVAL, got code=%d body=%v", code, m)
	}
	apID, _ := m["approval_id"].(string)
	if apID == "" {
		t.Fatal("no approval_id returned")
	}
	// (b) a cost reservation
	if code, m, _ := s1.postCheck(t, `{"scope":"cost","est_cost":12.50,"session_id":"sess"}`); code != http.StatusOK || m["decision"] != "ALLOW" {
		t.Fatalf("cost reserve: code=%d body=%v", code, m)
	}
	// (c) a rate-limited allow (creates a bucket)
	if code, _, _ := s1.postCheck(t, `{"scope":"shell","command":"ls -la","agent_id":"smoke"}`); code != http.StatusOK {
		t.Fatalf("allow check: code=%d", code)
	}

	// Force a synchronous write-behind flush (what the 1s ticker / shutdown does).
	if err := s1.sy.Flush(ctx); err != nil {
		t.Fatalf("flush #1: %v", err)
	}
	s1.close()
	_ = st1.Close()

	// --- lifecycle 2: reopen the same DB, hydrate, verify survival ---
	st2, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store #2: %v", err)
	}
	defer st2.Close()
	s2 := newITServer(t, st2, dir)
	defer s2.close()
	if err := s2.sy.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate #2: %v", err)
	}

	// Approval survived: retrying the SAME approval_id must find the pending
	// entry (REQUIRE_APPROVAL with the same id), proving it was hydrated.
	code, m, _ = s2.postCheck(t, `{"scope":"shell","command":"sudo apt update","agent_id":"smoke","session_id":"sess","approval_id":"`+apID+`"}`)
	if code != http.StatusOK || m["decision"] != "REQUIRE_APPROVAL" || m["approval_id"] != apID {
		t.Errorf("approval did not survive restart: code=%d body=%v (want REQUIRE_APPROVAL id=%s)", code, m, apID)
	}

	// Cost survived: the local session already has $12.50 reserved, so a $90
	// reserve must DENY (12.50 + 90 > 100).
	if code, m, _ := s2.postCheck(t, `{"scope":"cost","est_cost":90.00,"session_id":"sess"}`); code != http.StatusOK || m["decision"] != "DENY" {
		t.Errorf("cost did not survive restart: code=%d body=%v (want DENY from carried-over $12.50)", code, m)
	}

	// Bucket survived: hydrated limiter has the consumed bucket.
	if got := s2.srv.Limiter().BucketCount(); got < 1 {
		t.Errorf("rate-limit bucket did not survive restart: count=%d", got)
	}
}

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

	// --- Signal 1: the SERVER's self-reported processing time -----------------
	// X-AgentGuard-Total-Ms over many requests — the hot path, excluding
	// httptest/network. This stays the ENFORCED budget guard (assertion below,
	// unchanged: p99 < 3ms).
	//
	// Caveat this test used to hide: the server derives that header from
	// duration.Microseconds() (truncated to whole µs) and, on a coarse monotonic
	// clock (Windows advances it only at the ~0.5ms system-timer tick), a ~µs
	// handler reads 0 — so p99 floored to "0.000ms". We now (a) sample many more
	// requests so the p99 is representative and (b) report in µs. On Linux CI the
	// header resolves to real µs; on a coarse clock it stays 0 (unmeasurable at
	// the source, since the server already truncated it), which is exactly why
	// Signal 2 below exists as the legible, cross-platform headline.
	const n = 1500
	samples := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		_, _, h := s.postCheck(t, `{"scope":"shell","command":"ls -la","agent_id":"lat"}`)
		ms, err := strconv.ParseFloat(h.Get("X-AgentGuard-Total-Ms"), 64)
		if err != nil {
			t.Fatalf("missing/invalid X-AgentGuard-Total-Ms header: %q", h.Get("X-AgentGuard-Total-Ms"))
		}
		samples = append(samples, ms)
	}
	sort.Float64s(samples)
	p50 := samples[len(samples)*50/100]
	p99 := samples[len(samples)*99/100]
	max := samples[len(samples)-1]
	t.Logf("server hot-path /v1/check (network-excluded, X-AgentGuard-Total-Ms): p50=%.1fµs p99=%.1fµs max=%.1fµs (n=%d)",
		p50*1000, p99*1000, max*1000, n)

	// Contract: <3ms p99. The store is write-behind, so it must not appear here.
	if p99 >= 3.0 {
		t.Errorf("hot-path p99 = %.3fms violates the <3ms budget with persistence on", p99)
	}

	// --- Signal 2: client-observed per-op latency, ns-precision, adaptive ------
	// The header above is µs-granular and floors to 0 on a coarse clock, so it is
	// not a legible headline. Here we measure the /v1/check round-trip latency at
	// nanosecond precision: on a fine clock each sample is one round-trip; on a
	// coarse clock the sampler groups enough round-trips for the monotonic clock
	// to advance and records the mean-per-op. The reported p99 is therefore always
	// non-zero and legible in µs, which makes this test load-bearing on every OS.
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
