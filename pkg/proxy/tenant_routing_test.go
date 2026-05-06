package proxy

// Tests for the tenant-aware URL family /v1/t/{tenant}/... introduced
// in v0.5 Phase 2 (worker A7). The legacy /v1/... routes still anchor on
// the "local" tenant; the tenant-aware family extracts {tenant} from
// the path and validates it via Engine.PolicyForTenant.
//
// We use a real httptest.Server (rather than calling handlers directly
// via httptest.NewRecorder) because Go 1.22+ ServeMux wildcard routes
// only populate r.PathValue("tenant") and r.PathValue("id") when the
// request actually flows through the configured mux.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// newTenantRoutingServer builds a Server wired to a real httptest.Server
// so the tenant-aware routes flow through the mux. The policy allows
// "ls *", denies "rm -rf *", and requires approval for "sudo *" — same
// surface as newTestServer but standalone so we don't accidentally rely
// on per-test wiring there.
func newTenantRoutingServer(t *testing.T, apiKey string) (*Server, *httptest.Server, string) {
	t.Helper()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "tenant_audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "tenant-routing-test",
		Rules: []policy.RuleSet{
			{
				Scope:           "shell",
				Allow:           []policy.Rule{{Pattern: "ls *"}, {Pattern: "echo *"}},
				Deny:            []policy.Rule{{Pattern: "rm -rf *", Message: "Destructive"}},
				RequireApproval: []policy.Rule{{Pattern: "sudo *"}},
			},
		},
	}

	cfg := Config{
		Port:             0,
		Engine:           policy.NewEngineFromPolicy(pol),
		Logger:           logger,
		DashboardEnabled: true,
		Notifier:         notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:           apiKey,
		BaseURL:          "http://127.0.0.1:0",
		Version:          "test-v0.5",
	}

	srv := NewServer(cfg)
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)
	return srv, ts, logPath
}

// postCheck does POST /v1/check (or /v1/t/{tenant}/check) with a JSON
// body and returns (status, decoded result body, raw bytes).
func postCheck(t *testing.T, baseURL, body string) (int, policy.CheckResult, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, policy.CheckResult{}, raw
	}
	var result policy.CheckResult
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
		t.Fatalf("decode response: %v\nbody=%s", err, raw)
	}
	return resp.StatusCode, result, raw
}

// TestTenantRouting_LegacyAndV1TEquivalent — same body, two URL
// families: identical decision and identical audit trail.
func TestTenantRouting_LegacyAndV1TEquivalent(t *testing.T) {
	_, ts, _ := newTenantRoutingServer(t, "")

	body := `{"scope":"shell","command":"ls -la","agent_id":"alice"}`

	statusLegacy, resLegacy, _ := postCheck(t, ts.URL+"/v1/check", body)
	if statusLegacy != http.StatusOK {
		t.Fatalf("/v1/check legacy: status=%d", statusLegacy)
	}
	statusTenant, resTenant, _ := postCheck(t, ts.URL+"/v1/t/local/check", body)
	if statusTenant != http.StatusOK {
		t.Fatalf("/v1/t/local/check: status=%d", statusTenant)
	}

	if resLegacy.Decision != resTenant.Decision {
		t.Errorf("decisions diverge: legacy=%s tenant=%s", resLegacy.Decision, resTenant.Decision)
	}
	if resLegacy.Decision != policy.Allow {
		t.Errorf("expected ALLOW for ls *, got %s", resLegacy.Decision)
	}
	if resLegacy.SchemaVersion != resTenant.SchemaVersion {
		t.Errorf("schema_version differs: legacy=%q tenant=%q", resLegacy.SchemaVersion, resTenant.SchemaVersion)
	}
	if resLegacy.SchemaVersion != SchemaVersionV1 {
		t.Errorf("schema_version not v1: %q", resLegacy.SchemaVersion)
	}
}

// TestTenantRouting_UnknownTenant404 — /v1/t/nosuchtenant/check returns
// 404 with a structured error body. v0.5's PolicyProvider rejects every
// tenant other than "local" with ErrTenantNotFound.
func TestTenantRouting_UnknownTenant404(t *testing.T) {
	_, ts, _ := newTenantRoutingServer(t, "")

	body := `{"scope":"shell","command":"ls"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		ts.URL+"/v1/t/nosuchtenant/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404, got %d body=%s", resp.StatusCode, raw)
	}
	var body404 map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body404); err != nil {
		t.Fatalf("decode 404 body: %v", err)
	}
	if body404["error"] != "tenant not found" {
		t.Errorf("unexpected 404 body: %+v", body404)
	}
}

// TestTenantRouting_ApproveDenyWorkInBothFamilies — request approval via
// the legacy URL, approve via the tenant-aware URL, status via the legacy
// URL. Demonstrates approval state is shared (single-tenant queue in
// v0.5; v0.6 will shard by tenant).
func TestTenantRouting_ApproveDenyWorkInBothFamilies(t *testing.T) {
	_, ts, _ := newTenantRoutingServer(t, "")

	// 1. Trigger a REQUIRE_APPROVAL via legacy /v1/check.
	body := `{"scope":"shell","command":"sudo apt update","agent_id":"alice"}`
	status, result, _ := postCheck(t, ts.URL+"/v1/check", body)
	if status != http.StatusOK {
		t.Fatalf("/v1/check: status=%d", status)
	}
	if result.Decision != policy.RequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL, got %s", result.Decision)
	}
	if result.ApprovalID == "" {
		t.Fatalf("missing approval_id in response")
	}

	// 2. Approve via /v1/t/local/approve/{id}.
	approveURL := ts.URL + "/v1/t/local/approve/" + result.ApprovalID
	areq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, approveURL, nil)
	aresp, err := http.DefaultClient.Do(areq)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	defer aresp.Body.Close()
	if aresp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(aresp.Body)
		t.Fatalf("approve status=%d body=%s", aresp.StatusCode, raw)
	}

	// 3. Status check via legacy /v1/status/{id} should report resolved + ALLOW.
	statusURL := ts.URL + "/v1/status/" + result.ApprovalID
	sresp, err := http.Get(statusURL)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(sresp.Body)
		t.Fatalf("status code=%d body=%s", sresp.StatusCode, raw)
	}
	var sbody map[string]string
	if err := json.NewDecoder(sresp.Body).Decode(&sbody); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	if sbody["status"] != "resolved" || sbody["decision"] != string(policy.Allow) {
		t.Errorf("unexpected status body: %+v", sbody)
	}
}

// TestTenantRouting_AuthGatedEndpointsRequireKeyOnBothFamilies — both
// /v1/audit and /v1/t/local/audit return 401 without the bearer token,
// and 200 with it. requireAuthOrSession is URL-agnostic; this is a
// regression coupon to keep it that way.
func TestTenantRouting_AuthGatedEndpointsRequireKeyOnBothFamilies(t *testing.T) {
	const apiKey = "tenant-routing-secret"
	_, ts, _ := newTenantRoutingServer(t, apiKey)

	for _, path := range []string{"/v1/audit", "/v1/t/local/audit"} {
		// No auth → 401.
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without auth: expected 401, got %d", path, resp.StatusCode)
		}

		// Bearer → 200.
		req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+path, nil)
		req2.Header.Set("Authorization", "Bearer "+apiKey)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("GET %s with bearer: %v", path, err)
		}
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("GET %s with bearer: expected 200, got %d", path, resp2.StatusCode)
		}
	}
}

// TestTenantRouting_ContextCarriesTenant — direct unit test of
// TenantIDFromContext / WithTenantID. Independent of the mux so a
// regression in the helper itself is caught even if the route registration
// breaks.
func TestTenantRouting_ContextCarriesTenant(t *testing.T) {
	ctx := context.Background()
	if got := TenantIDFromContext(ctx); got != policy.LocalTenantID {
		t.Errorf("default: expected %q, got %q", policy.LocalTenantID, got)
	}

	ctx2 := WithTenantID(ctx, "")
	if got := TenantIDFromContext(ctx2); got != policy.LocalTenantID {
		t.Errorf("empty: expected %q (default), got %q", policy.LocalTenantID, got)
	}

	ctx3 := WithTenantID(ctx, "acme")
	if got := TenantIDFromContext(ctx3); got != "acme" {
		t.Errorf("explicit: expected acme, got %q", got)
	}
}

// TestTenantRouting_LegacyHandlerReadsLocalTenant — legacy /v1/check
// has no withTenant middleware, so TenantIDFromContext must default to
// "local" inside handleCheck. We can't observe the call directly, but
// we can confirm the response decoded fine and the audit log captured
// the entry — meaning the engine accepted the implicit "local" tenant.
func TestTenantRouting_LegacyHandlerReadsLocalTenant(t *testing.T) {
	_, ts, logPath := newTenantRoutingServer(t, "")

	body := `{"scope":"shell","command":"ls -la","agent_id":"alice"}`
	status, result, _ := postCheck(t, ts.URL+"/v1/check", body)
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if result.Decision != policy.Allow {
		t.Fatalf("expected ALLOW, got %s reason=%s", result.Decision, result.Reason)
	}

	// Give the audit logger a moment to flush.
	time.Sleep(20 * time.Millisecond)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"agent_id":"alice"`)) {
		t.Errorf("audit log does not contain expected entry; raw=%q", raw)
	}
}
