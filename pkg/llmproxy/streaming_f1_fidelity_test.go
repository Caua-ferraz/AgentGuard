package llmproxy

// streaming_f1_fidelity_test.go pins the F1 audit-verdict FIDELITY fix (C3),
// the follow-up to the F1 fail-closed fix in streaming_f1_test.go.
//
// Before this fix, a malformed-completion tool_call was refused to the client
// (a forced malformed_tool_call DENY) but its AUDIT entry was written by the
// normal /v1/check path, which records the POLICY engine's verdict — often
// ALLOW. So the audit trail could read ALLOW while the agent got DENY: a
// compliance hazard for a firewall. With Server.RecordForcedAudit wired, the
// malformed call's audit entry now carries the DENY the client actually
// received, and the policy gate is NOT consulted for that call (no fidelity-
// blind /v1/check), while a LATER valid call in the same stream still gates
// normally.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// forcedAuditSpy captures the decisions passed to Server.RecordForcedAudit. It
// stands in for the central /v1/audit ingest, so a captured entry is the
// observable proxy for "what verdict the audit trail recorded for this call".
type forcedAuditSpy struct {
	mu    sync.Mutex
	calls []forcedAuditCall
}

type forcedAuditCall struct {
	toolCallID string
	decision   Decision
}

func (f *forcedAuditSpy) record(_ context.Context, tc *ToolCallCheck, d Decision) {
	f.mu.Lock()
	f.calls = append(f.calls, forcedAuditCall{toolCallID: tc.ToolCallID, decision: d})
	f.mu.Unlock()
}

func (f *forcedAuditSpy) recorded() []forcedAuditCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]forcedAuditCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// TestStreaming_OpenAI_MalformedCompletion_AuditRecordsMalformedDeny drives an
// OpenAI stream whose first tool_call finalizes with invalid JSON, followed by a
// valid tool_call. PolicyCheck is wired to ALLOW (the fidelity-gap scenario).
// The audit record for the malformed call must carry the malformed_tool_call
// DENY, and PolicyCheck must NOT fire for it — only for the later valid call.
func TestStreaming_OpenAI_MalformedCompletion_AuditRecordsMalformedDeny(t *testing.T) {
	malformedDelta := `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_bad","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls"}}]},"finish_reason":null}]}` + "\n\n"
	finish := `data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"
	validDelta := `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_good","type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":null}]}` + "\n\n"
	done := "data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, malformedDelta+finish+validDelta+finish+done)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	spy := &gateSpy{decision: Decision{Allow: true, Rule: "allow:test"}} // engine WOULD allow
	auditSpy := &forcedAuditSpy{}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = spy.check
		s.RecordForcedAudit = auditSpy.record
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	// Client still refused; malformed tool_call did not leak.
	if !strings.Contains(string(got), "malformed tool call arguments") {
		t.Errorf("expected malformed refusal to client; got %q", string(got))
	}
	if strings.Contains(string(got), "call_bad") {
		t.Errorf("malformed tool_call leaked into client output: %q", string(got))
	}

	// Fidelity: the audit record for the malformed call carries the DENY, NOT
	// the policy verdict.
	rec := auditSpy.recorded()
	if len(rec) != 1 || rec[0].toolCallID != "call_bad" {
		t.Fatalf("forced-audit records = %+v, want exactly one for call_bad", rec)
	}
	if rec[0].decision.Allow {
		t.Errorf("audit recorded an ALLOW for the malformed call; want DENY")
	}
	if rec[0].decision.Rule != "deny:llm_api_proxy:malformed_tool_call" {
		t.Errorf("audit recorded rule = %q, want deny:llm_api_proxy:malformed_tool_call (not the policy verdict)", rec[0].decision.Rule)
	}

	// The policy gate must NOT be consulted for the malformed call (no
	// fidelity-blind /v1/check), but MUST still gate the later valid call.
	if ids := spy.ids(); len(ids) != 1 || ids[0] != "call_good" {
		t.Fatalf("PolicyCheck ids = %v, want [call_good] only (malformed call audited via forced path; valid call gated normally)", ids)
	}
}

// TestStreaming_Anthropic_MalformedCompletion_AuditRecordsMalformedDeny is the
// Anthropic sibling.
func TestStreaming_Anthropic_MalformedCompletion_AuditRecordsMalformedDeny(t *testing.T) {
	badStart := `event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_bad","name":"bash","input":{}}}` + "\n\n"
	badDelta := `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls"}}` + "\n\n"
	badStop := `event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n"
	goodStart := `event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_good","name":"bash","input":{}}}` + "\n\n"
	goodDelta := `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{}"}}` + "\n\n"
	goodStop := `event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":1}` + "\n\n"
	msgStop := `event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, badStart+badDelta+badStop+goodStart+goodDelta+goodStop+msgStop)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	spy := &gateSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	auditSpy := &forcedAuditSpy{}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = spy.check
		s.RecordForcedAudit = auditSpy.record
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(got), "malformed tool call arguments") {
		t.Errorf("expected malformed refusal to client; got %q", string(got))
	}
	if strings.Contains(string(got), "toolu_bad") {
		t.Errorf("malformed tool_use leaked into client output: %q", string(got))
	}

	rec := auditSpy.recorded()
	if len(rec) != 1 || rec[0].toolCallID != "toolu_bad" {
		t.Fatalf("forced-audit records = %+v, want exactly one for toolu_bad", rec)
	}
	if rec[0].decision.Allow || rec[0].decision.Rule != "deny:llm_api_proxy:malformed_tool_call" {
		t.Errorf("audit recorded decision = %+v, want malformed_tool_call DENY (not the policy verdict)", rec[0].decision)
	}
	if ids := spy.ids(); len(ids) != 1 || ids[0] != "toolu_good" {
		t.Fatalf("PolicyCheck ids = %v, want [toolu_good] only", ids)
	}
}

// TestStreaming_MalformedCompletion_NilHook_FallsBackToPolicyAudit pins the
// nil-hook fallback: with RecordForcedAudit unwired, the malformed call is still
// audited via the normal /v1/check path (lower fidelity, but no silent gap) —
// exactly the pre-C3 behavior the existing F1 tests rely on.
func TestStreaming_MalformedCompletion_NilHook_FallsBackToPolicyAudit(t *testing.T) {
	malformedDelta := `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_bad","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls"}}]},"finish_reason":null}]}` + "\n\n"
	finish := `data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"
	done := "data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, malformedDelta+finish+done)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	spy := &gateSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = spy.check
		// RecordForcedAudit intentionally left nil.
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(got), "malformed tool call arguments") {
		t.Errorf("expected malformed refusal to client; got %q", string(got))
	}
	// Fallback: the policy gate IS consulted for the malformed call (that is the
	// audit mechanism when the forced-audit hook is not wired).
	if ids := spy.ids(); len(ids) != 1 || ids[0] != "call_bad" {
		t.Fatalf("PolicyCheck ids = %v, want [call_bad] (nil-hook fallback audits via /v1/check)", ids)
	}
}
