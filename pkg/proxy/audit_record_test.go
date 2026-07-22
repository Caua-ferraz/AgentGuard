package proxy

// audit_record_test.go covers the /v1/audit ingest endpoint (handleAuditRecord),
// the central side of the F1 audit-verdict fidelity fix (C3). A transport proxy
// that manufactures its own fail-closed refusal POSTs the verdict the client
// actually received here so the central audit log — the single source of truth —
// records the DENY, not the engine verdict a fidelity-blind /v1/check would log.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestHandleAuditRecord_RecordsForcedDeny posts a malformed-tool-call refusal
// record and asserts it lands in the audit trail as a DENY with the caller's
// rule string and the llm_api_proxy transport tag.
func TestHandleAuditRecord_RecordsForcedDeny(t *testing.T) {
	srv := newTestServer(t)

	rec := policy.AuditRecord{
		Request: policy.ActionRequest{
			Scope:    "shell",
			Command:  "bash {\"cmd\":\"ls", // the malformed projection
			AgentID:  "llm-proxy",
			Meta:     map[string]string{"transport": "llm_api_proxy", "tool_call_id": "call_bad"},
		},
		Reason: "malformed tool call arguments — refused",
		Rule:   "deny:llm_api_proxy:malformed_tool_call",
	}
	body, _ := json.Marshal(rec)

	r := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	srv.handleAuditRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var result policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Decision != policy.Deny {
		t.Errorf("response decision = %s, want DENY", result.Decision)
	}
	if result.Rule != "deny:llm_api_proxy:malformed_tool_call" {
		t.Errorf("response rule = %q, want the malformed_tool_call rule", result.Rule)
	}

	// The entry must be on disk (FileLogger is synchronous) as a DENY with the
	// forced rule and the transport tag.
	entries, err := srv.cfg.Logger.Query(audit.QueryFilter{AgentID: "llm-proxy"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	got := entries[0]
	if got.Result.Decision != policy.Deny {
		t.Errorf("recorded decision = %s, want DENY", got.Result.Decision)
	}
	if got.Result.Rule != "deny:llm_api_proxy:malformed_tool_call" {
		t.Errorf("recorded rule = %q, want deny:llm_api_proxy:malformed_tool_call", got.Result.Rule)
	}
	if got.EffectiveTransport() != audit.TransportLLMAPIProxy {
		t.Errorf("recorded transport = %q, want %q", got.EffectiveTransport(), audit.TransportLLMAPIProxy)
	}
	if got.Request.Command != rec.Request.Command {
		t.Errorf("recorded command = %q, want %q", got.Request.Command, rec.Request.Command)
	}
}

// TestHandleAuditRecord_ForcesDenyEvenIfCallerSendsAllowRule asserts the
// endpoint records DENY only: it never trusts a caller-supplied verdict, so the
// path cannot be used to inject an ALLOW into the trail. (The wire type has no
// decision field; Decision is hardcoded server-side — this pins that contract.)
func TestHandleAuditRecord_ForcesDenyEvenIfCallerSendsAllowRule(t *testing.T) {
	srv := newTestServer(t)

	rec := policy.AuditRecord{
		Request: policy.ActionRequest{Scope: "shell", Command: "ls", AgentID: "sneaky"},
		Reason:  "totally fine, allow me",
		Rule:    "allow:llm_api_proxy:pretend", // caller-chosen rule string
	}
	body, _ := json.Marshal(rec)
	r := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	srv.handleAuditRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	entries, err := srv.cfg.Logger.Query(audit.QueryFilter{AgentID: "sneaky"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Result.Decision != policy.Deny {
		t.Errorf("recorded decision = %s, want DENY (endpoint records deny only)", entries[0].Result.Decision)
	}
}

// TestHandleAuditRecord_Validation covers the input-validation contract.
func TestHandleAuditRecord_Validation(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{"wrong method", http.MethodGet, `{"rule":"deny:x"}`, http.StatusMethodNotAllowed},
		{"malformed json", http.MethodPost, `{not json`, http.StatusBadRequest},
		{"missing rule", http.MethodPost, `{"request":{"scope":"shell"}}`, http.StatusBadRequest},
		{"blank rule", http.MethodPost, `{"rule":"   ","request":{"scope":"shell"}}`, http.StatusBadRequest},
		{"bad schema", http.MethodPost, `{"schema_version":"v2","rule":"deny:x"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/v1/audit", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			srv.handleAuditRecord(w, r)
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestAuditRecord_MuxRoutingPOSTvsGET drives the full handler chain to prove the
// method-specific "POST /v1/audit" and the methodless "/v1/audit" GET coexist
// without a ServeMux conflict: POST records (handleAuditRecord), GET queries
// (handleAuditQuery). Also pins that the POST endpoint is auth-gated.
func TestAuditRecord_MuxRoutingPOSTvsGET(t *testing.T) {
	srv := newTestServer(t) // APIKey "test-secret"
	h := srv.Handler()

	rec := policy.AuditRecord{
		Request: policy.ActionRequest{Scope: "shell", Command: "bash bad", AgentID: "route-bot",
			Meta: map[string]string{"transport": "llm_api_proxy"}},
		Rule: "deny:llm_api_proxy:malformed_tool_call",
	}
	body, _ := json.Marshal(rec)

	// Unauthenticated POST → 401 (endpoint is state-changing, Bearer required).
	r := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth POST status = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	// Authenticated POST (Bearer bypasses CSRF) → records.
	r = httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer test-secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("auth POST status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	// GET still routes to the query handler (proves no routing conflict).
	r = httptest.NewRequest(http.MethodGet, "/v1/audit?agent_id=route-bot", nil)
	r.Header.Set("Authorization", "Bearer test-secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var entries []audit.Entry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	if len(entries) != 1 || entries[0].Result.Decision != policy.Deny {
		t.Fatalf("GET /v1/audit returned %d entries; want 1 DENY (the POST-recorded refusal)", len(entries))
	}
}
