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
	"testing"

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
	sy := New(Config{Store: st, Engine: eng, Limiter: srv.Limiter(), Approvals: srv.ApprovalQueue()})
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

// NOTE: TestIntegration_HotPathLatencyWithPersistence lives in
// integration_latency_test.go behind a `//go:build !race` tag — it is a
// wall-clock p99 budget gate that the race detector's timing distortion would
// flake. The shared itServer/newITServer/postCheck helpers above are compiled
// in all builds, so both files use them.
