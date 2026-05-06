package proxy

// Tests for the operator-grade /v1/health and /v1/t/{tenant}/health
// endpoints introduced in v0.5 Phase 2 (worker A10). The legacy /health
// endpoint stays unchanged and is covered by TestHandleHealth in
// server_test.go.
//
// We exercise the full handler chain via httptest.Server (not a raw
// httptest.ResponseRecorder) because the tenant-aware route uses Go
// 1.22+ ServeMux wildcard matching, which only fires through the
// configured mux — calling the handler function directly would skip
// the {tenant} pathvalue extraction.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// newHealthTestServer builds a Server wired to a real httptest.Server so
// the tenant-aware path /v1/t/{tenant}/health flows through the mux.
func newHealthTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	dir := t.TempDir()
	logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "health-test",
		Rules: []policy.RuleSet{{
			Scope: "shell",
			Allow: []policy.Rule{{Pattern: "ls *"}},
		}},
	}

	cfg := Config{
		Port:             0,
		Engine:           policy.NewEngineFromPolicy(pol),
		Logger:           logger,
		DashboardEnabled: false,
		Notifier:         notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:           "", // open-mode is fine; /v1/health is unauth anyway
		BaseURL:          "http://127.0.0.1:0",
		Version:          "test-v0.5",
	}

	srv := NewServer(cfg)
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)
	return srv, ts
}

// healthBody fetches /v1/health (or any URL) and decodes the JSON body.
// fatals on transport or parse errors.
func healthBody(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return resp.StatusCode, body
}

// TestHealthV1_NoTrafficYet — fetch /v1/health on a freshly-constructed
// server. The probe itself counts as traffic (withTraffic stamps before
// the handler runs), but the snapshot taken inside the handler reads the
// stamp set by *this* request, so last_request_at appears non-null. The
// invariant we assert is "no warnings yet" — the freshly-stamped
// timestamp is, by definition, not stale.
func TestHealthV1_NoTrafficYet(t *testing.T) {
	srv, ts := newHealthTestServer(t)
	_ = srv

	code, body := healthBody(t, ts.URL+"/v1/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["status"] != "ok" {
		t.Errorf("status: want ok, got %v", body["status"])
	}
	if body["tenant"] != "local" {
		t.Errorf("tenant: want local, got %v", body["tenant"])
	}
	if body["version"] != "test-v0.5" {
		t.Errorf("version: want test-v0.5, got %v", body["version"])
	}
	// uptime_seconds is JSON-decoded into a float64
	if _, ok := body["uptime_seconds"].(float64); !ok {
		t.Errorf("uptime_seconds missing or wrong type: %T", body["uptime_seconds"])
	}
	warnings, ok := body["warnings"].([]any)
	if !ok {
		t.Fatalf("warnings missing or wrong type: %T", body["warnings"])
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings on fresh server, got %v", warnings)
	}
	// last_policy_load_at must be set (NewEngine stamps on initial Get)
	if _, ok := body["last_policy_load_at"].(string); !ok {
		t.Errorf("last_policy_load_at missing on fresh server: %v", body)
	}
}

// TestHealthV1_AfterRequests — fire a /v1/check (which exercises
// withTraffic), then verify last_request_at advances close to now.
func TestHealthV1_AfterRequests(t *testing.T) {
	srv, ts := newHealthTestServer(t)

	before := time.Now()
	resp, err := http.Post(ts.URL+"/v1/check", "application/json",
		strings.NewReader(`{"scope":"shell","command":"ls /tmp","agent_id":"a"}`))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	resp.Body.Close()

	last := srv.LastRequestAt()
	if last.IsZero() {
		t.Fatalf("LastRequestAt is zero after a request")
	}
	if last.Before(before.Add(-1 * time.Second)) {
		t.Errorf("LastRequestAt %v is before the test start %v", last, before)
	}

	code, body := healthBody(t, ts.URL+"/v1/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	got, ok := body["last_request_at"].(string)
	if !ok || got == "" {
		t.Fatalf("last_request_at missing or empty: %v", body["last_request_at"])
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z07:00", got)
	if err != nil {
		t.Fatalf("parse last_request_at %q: %v", got, err)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("last_request_at %v is older than 5s", parsed)
	}
}

// TestHealthV1_PolicyReload — simulate a policy reload via the static
// provider's UpdatePolicy and verify last_policy_load_at advances.
func TestHealthV1_PolicyReload(t *testing.T) {
	dir := t.TempDir()
	logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	pol := &policy.Policy{Version: "1", Name: "reload-test"}
	prov := policy.NewStaticPolicyProvider(pol)
	t.Cleanup(func() { prov.Close() })
	eng, err := policy.NewEngine(prov)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	srv := NewServer(Config{
		Port:     0,
		Engine:   eng,
		Logger:   logger,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		Version:  "reload",
	})
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	first := eng.LastPolicyLoadAt()
	if first.IsZero() {
		t.Fatalf("LastPolicyLoadAt is zero on a fresh engine")
	}

	// Sleep just past the millisecond rounding boundary so the printed
	// timestamp is observably different. The test sleep is < 5ms; under
	// the 1-minute Go test default it is well within budget.
	time.Sleep(5 * time.Millisecond)

	prov.UpdatePolicy(&policy.Policy{Version: "1", Name: "reload-test-v2"})

	second := eng.LastPolicyLoadAt()
	if !second.After(first) {
		t.Fatalf("LastPolicyLoadAt did not advance: first=%v second=%v", first, second)
	}

	code, body := healthBody(t, ts.URL+"/v1/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	got, ok := body["last_policy_load_at"].(string)
	if !ok || got == "" {
		t.Fatalf("last_policy_load_at missing: %v", body)
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z07:00", got)
	if err != nil {
		t.Fatalf("parse last_policy_load_at: %v", err)
	}
	// JSON output is millisecond-truncated; compare with the same
	// truncation so the test does not flake on sub-millisecond drift.
	wantMs := second.UTC().Truncate(time.Millisecond)
	gotMs := parsed.UTC().Truncate(time.Millisecond)
	if !gotMs.Equal(wantMs) {
		t.Errorf("last_policy_load_at: got %v, want %v", gotMs, wantMs)
	}
}

// TestHealthV1_StaleTrafficWarning — backdate lastRequestAtNs to >5m
// ago via the atomic field directly and assert the warnings array
// includes the staleness string.
//
// We backdate lastRequestAtNs *after* the GET that triggers withTraffic,
// then perform a second request. But that second request would just
// re-stamp the field — defeating the test. Instead we use the
// httptest.Server's handler directly with a httptest.ResponseRecorder
// so the withTraffic middleware does not run. This is the only test
// that bypasses the full chain on purpose.
func TestHealthV1_StaleTrafficWarning(t *testing.T) {
	srv, _ := newHealthTestServer(t)

	// Stamp lastRequestAtNs to 6 minutes ago.
	stale := time.Now().Add(-6 * time.Minute).UnixNano()
	atomic.StoreInt64(&srv.lastRequestAtNs, stale)

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealthV1Local(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	warnings, ok := body["warnings"].([]any)
	if !ok {
		t.Fatalf("warnings wrong type: %T", body["warnings"])
	}
	found := false
	for _, w := range warnings {
		if s, _ := w.(string); s == "no traffic in 5m+" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warnings to include 'no traffic in 5m+', got %v", warnings)
	}
}

// TestHealthV1_StalePolicyWarning — same approach: backdate the
// engine's lastPolicyLoadAtNs and assert the corresponding warning.
//
// We can't poke the engine field directly from outside the policy
// package, so we backdate it via reflection-free trick: construct a
// StaticPolicyProvider, set the engine, and override the timestamp by
// calling the (test-only) hook below. Since no such hook exists, we
// instead temporarily shrink healthStalePolicyWindow so the 5ms-old
// stamp registers as stale. The assertion is the same: the warning
// must appear.
func TestHealthV1_StalePolicyWarning(t *testing.T) {
	srv, _ := newHealthTestServer(t)

	orig := healthStalePolicyWindow
	healthStalePolicyWindow = 1 * time.Nanosecond
	t.Cleanup(func() { healthStalePolicyWindow = orig })

	// Sleep past 1ns since the last load (NewEngine stamped during
	// newHealthTestServer construction, so any wall-clock movement is
	// enough).
	time.Sleep(2 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealthV1Local(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	warnings, _ := body["warnings"].([]any)
	found := false
	for _, w := range warnings {
		if s, _ := w.(string); s == "policy not reloaded in 24h+" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warnings to include 'policy not reloaded in 24h+', got %v", warnings)
	}
}

// TestHealthV1_TenantPath_Local — the tenant-aware route returns a
// well-formed body when tenant=local.
func TestHealthV1_TenantPath_Local(t *testing.T) {
	_, ts := newHealthTestServer(t)

	code, body := healthBody(t, ts.URL+"/v1/t/local/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["tenant"] != "local" {
		t.Errorf("tenant: want local, got %v", body["tenant"])
	}
	if body["status"] != "ok" {
		t.Errorf("status: want ok, got %v", body["status"])
	}
}

// TestHealthV1_TenantPath_UnknownTenant404 — tenants other than "local"
// return 404 with a structured error body.
func TestHealthV1_TenantPath_UnknownTenant404(t *testing.T) {
	_, ts := newHealthTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/t/nonexistent/health")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "tenant not found" {
		t.Errorf("error: want 'tenant not found', got %q", body["error"])
	}
}

// TestHealthV1_LegacyHealthUnchanged — confirm /health still returns
// the v0.4.x shape so existing operators do not see a behavior change.
func TestHealthV1_LegacyHealthUnchanged(t *testing.T) {
	_, ts := newHealthTestServer(t)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status: want ok, got %q", body["status"])
	}
	if body["version"] != "test-v0.5" {
		t.Errorf("version: want test-v0.5, got %q", body["version"])
	}
	// The legacy endpoint must NOT carry the new fields.
	if _, has := body["tenant"]; has {
		t.Errorf("legacy /health leaked tenant field")
	}
	if _, has := body["last_request_at"]; has {
		t.Errorf("legacy /health leaked last_request_at")
	}
}
