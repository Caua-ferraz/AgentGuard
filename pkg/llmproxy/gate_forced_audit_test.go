package llmproxy

// gate_forced_audit_test.go pins the F1 forced-audit FAILURE-PATH fallback.
//
// RecordForcedAudit POSTs the client-visible DENY to the central /v1/audit
// endpoint so the audit trail carries the exact verdict the agent received.
// That POST can fail — the canonical case is a central server started with
// --api-key while this proxy has none: the (open) /v1/check still works but
// the (auth-gated) POST /v1/audit returns 401. Before the fallback, that
// refusal left NO audit entry at all — strictly worse than the pre-F1
// behavior, which at least logged a low-fidelity entry via /v1/check.
//
// The fix: on a /v1/audit failure, best-effort replay the same ActionRequest
// through /v1/check so the trail never goes dark (fidelity degrades to the
// engine verdict; coverage does not). This test proves the fallback /v1/check
// fires and that the failure never surfaces to the client (RecordForcedAudit
// is fire-and-forget by contract).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestRecordForcedAudit_AuditFailureFallsBackToCheck stands up a central
// server whose /v1/audit returns 401 (the keyed-server / unkeyed-proxy case)
// while /v1/check answers 200. It asserts the fallback /v1/check call fires so
// the audit trail is not left empty for a forced refusal.
func TestRecordForcedAudit_AuditFailureFallsBackToCheck(t *testing.T) {
	var auditHits, checkHits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/audit"):
			// Keyed server, unkeyed proxy: /v1/audit is auth-gated → 401.
			auditHits.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case strings.HasSuffix(r.URL.Path, "/check"):
			// /v1/check is open and answers normally — this is the fallback
			// audit-driving path we expect the gate to reach.
			checkHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"ALLOW","reason":"engine allow","matched_rule":"allow:mock"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		// APIKey intentionally empty: the proxy is unkeyed while the server
		// (modeled above) gates /v1/audit.
		TenantID: "local",
		FailMode: "deny",
	}, nil)

	// A proxy-manufactured malformed_tool_call DENY, exactly as the streaming
	// malformed path emits.
	decision := malformedToolCallDecision()
	req := toolCall("openai", "bash", map[string]interface{}{"command": "ls"})

	// RecordForcedAudit is fire-and-forget: it returns nothing and must never
	// panic or block the caller regardless of the /v1/audit outcome.
	gate.RecordForcedAudit(context.Background(), req, decision)

	if got := auditHits.Load(); got != 1 {
		t.Errorf("expected exactly 1 /v1/audit attempt, got %d", got)
	}
	if got := checkHits.Load(); got != 1 {
		t.Fatalf("expected the fallback to drive exactly 1 /v1/check call after /v1/audit 401, got %d "+
			"(audit trail would be dark for this refusal)", got)
	}
}

// TestRecordForcedAudit_AuditSuccessDoesNotFallBack is the negative control:
// when /v1/audit succeeds, the gate must NOT also hit /v1/check — the
// high-fidelity path already recorded the DENY, and a second call would
// double-log (and re-evaluate the engine verdict).
func TestRecordForcedAudit_AuditSuccessDoesNotFallBack(t *testing.T) {
	var auditHits, checkHits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/audit"):
			auditHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"DENY","reason":"recorded verbatim","matched_rule":"deny:llm_api_proxy:malformed_tool_call"}`))
		case strings.HasSuffix(r.URL.Path, "/check"):
			checkHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"v1","decision":"ALLOW"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		APIKey:   "matched-key",
		TenantID: "local",
		FailMode: "deny",
	}, nil)

	gate.RecordForcedAudit(context.Background(),
		toolCall("openai", "bash", map[string]interface{}{"command": "ls"}),
		malformedToolCallDecision())

	if got := auditHits.Load(); got != 1 {
		t.Errorf("expected 1 /v1/audit call, got %d", got)
	}
	if got := checkHits.Load(); got != 0 {
		t.Errorf("expected NO /v1/check fallback on audit success, got %d", got)
	}
}
