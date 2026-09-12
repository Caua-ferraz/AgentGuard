package llmproxy

// stream_refusal_audit_test.go pins that every proxy-manufactured streaming
// refusal reaches the central audit trail.
//
// Two refusal families never wrote an entry: the structural ones (a stream the
// accumulator cannot bind to a gateable call) and the buffer-cap ones. In both
// the gate never runs, so the /v1/check path that normally writes the entry is
// never taken, and the only signal was a counter in the proxy's process-local
// registry — which has no scrape endpoint. The client got a refusal and the
// operator got silence: no tenant, no agent, no rule, no idea it happened.
//
// Container-verified before the fix: driving an orphaned-tool-input stream and
// a multi-choice stream through the real cluster produced correct refusals and
// `null` from /v1/audit, while the neighbouring EOF and whitespace-seed
// scenarios both produced entries.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SSE framing, named so the oversized-event fixtures below read as framing
// rather than as escape soup.
const (
	sseLine       = "\n"
	sseTerminator = "\n\n"
)

// runStreamWithAudit drives one streaming request against an upstream that
// writes body verbatim, with the forced-audit hook wired as production wires
// it. maxBuffer <= 0 leaves the default cap.
func runStreamWithAudit(t *testing.T, provider, body string, maxBuffer int) (string, *forcedAuditSpy) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, body)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	spy := &forcedAuditSpy{}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.RecordForcedAudit = spy.record
		if maxBuffer > 0 {
			s.cfg.MaxBufferBytes = maxBuffer
		}
	})
	defer teardown()

	path, reqBody := "/v1/chat/completions", `{"model":"gpt-4","messages":[],"stream":true}`
	if provider == "anthropic" {
		path, reqBody = "/v1/messages", `{"model":"claude-3-5-sonnet","messages":[],"stream":true}`
	}
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(reqBody))
	req.Header.Set("X-Agent-ID", "audit-probe")
	req.Header.Set("X-Session-ID", "sess-42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw), spy
}

// assertAudited checks the single expected entry: the rule the client saw, and
// the identity fields an operator needs to act on it.
func assertAudited(t *testing.T, spy *forcedAuditSpy, wantRule, wantProvider string) ToolCallCheck {
	t.Helper()
	rec := spy.recorded()
	if len(rec) != 1 {
		t.Fatalf("RecordForcedAudit fired %d times, want 1 — the refusal left no audit trail", len(rec))
	}
	if rec[0].decision.Rule != wantRule {
		t.Errorf("audited rule = %q, want %q", rec[0].decision.Rule, wantRule)
	}
	if rec[0].decision.Allow {
		t.Errorf("audited an ALLOW for a refusal: %+v", rec[0].decision)
	}
	c := rec[0].call
	if c.Provider != wantProvider {
		t.Errorf("audited provider = %q, want %q", c.Provider, wantProvider)
	}
	if c.TenantID != "test" {
		t.Errorf("audited tenant = %q, want the server's configured tenant", c.TenantID)
	}
	if c.AgentID != "audit-probe" {
		t.Errorf("audited agent = %q, want the request's X-Agent-ID", c.AgentID)
	}
	if c.SessionID != "sess-42" {
		t.Errorf("audited session = %q, want the request's X-Session-ID", c.SessionID)
	}
	if !c.Stream {
		t.Error("audited entry is not marked as a streaming call")
	}
	return c
}

// TestAudit_OrphanedToolInput_IsRecorded — Anthropic tool input with no block
// open. Nothing assembled, so there is no tool name to carry; the entry still
// has to exist.
func TestAudit_OrphanedToolInput_IsRecorded(t *testing.T) {
	stream := pvAnthropicTextStart(0) +
		pvAnthropicTextDelta(0, "sure") +
		pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`)

	got, spy := runStreamWithAudit(t, "anthropic", stream, 0)
	if !strings.Contains(got, "deny:llm_api_proxy:orphaned_tool_input") {
		t.Fatalf("client did not receive the expected refusal: %q", got)
	}
	assertAudited(t, spy, "deny:llm_api_proxy:orphaned_tool_input", "anthropic")
}

// TestAudit_MultiChoiceToolCalls_IsRecorded — OpenAI tool calls on two
// choices. Here the accumulator DID see a name before refusing, so the entry
// must carry it: that is the difference between "something was refused" and
// "a bash call was refused".
func TestAudit_MultiChoiceToolCalls_IsRecorded(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_a", "bash", `{"command":"ls"}`) +
		pvOpenAIToolDelta(1, 0, "call_b", "bash", `{"command":"rm -rf /"}`)

	got, spy := runStreamWithAudit(t, "openai", stream, 0)
	if !strings.Contains(got, "deny:llm_api_proxy:multi_choice_tool_calls") {
		t.Fatalf("client did not receive the expected refusal: %q", got)
	}
	c := assertAudited(t, spy, "deny:llm_api_proxy:multi_choice_tool_calls", "openai")
	if c.ToolName != "bash" {
		t.Errorf("audited tool name = %q, want bash — the parser saw it before refusing", c.ToolName)
	}
	if c.ToolCallID != "call_a" {
		t.Errorf("audited tool_call id = %q, want call_a (the lowest-indexed named call)", c.ToolCallID)
	}
}

// TestAudit_InterleavedToolUse_IsRecorded — the refusal that has existed since
// 1.0 and has never been audited.
func TestAudit_InterleavedToolUse_IsRecorded(t *testing.T) {
	stream := pvAnthropicToolStart(0, "toolu_first", "bash", `{}`) +
		pvAnthropicInputDelta(0, `{"command":"ls"}`) +
		pvAnthropicToolStart(1, "toolu_second", "bash", `{}`)

	got, spy := runStreamWithAudit(t, "anthropic", stream, 0)
	if !strings.Contains(got, "deny:llm_api_proxy:tool_use_interleaved") {
		t.Fatalf("client did not receive the expected refusal: %q", got)
	}
	c := assertAudited(t, spy, "deny:llm_api_proxy:tool_use_interleaved", "anthropic")
	if c.ToolName != "bash" || c.ToolCallID != "toolu_first" {
		t.Errorf("audited identity = (%q,%q), want the open block (bash, toolu_first)", c.ToolName, c.ToolCallID)
	}
}

// TestAudit_CumulativeBufferOverflow_IsRecorded — arguments that cross
// --max-buffer-bytes only when ADDED UP. Each individual event stays well
// under the per-event ceiling, so this is the accumulator's own overflow
// branch, not the oversized-single-event one below. They are separate code
// paths with separate refusals, and both were silent.
func TestAudit_CumulativeBufferOverflow_IsRecorded(t *testing.T) {
	frag := strings.Repeat("A", 200) // 4 of these blow a 512-byte cap

	t.Run("openai", func(t *testing.T) {
		stream := pvOpenAIToolDelta(0, 0, "call_big", "bash", `{"command":"`)
		for i := 0; i < 4; i++ {
			stream += pvOpenAIToolDelta(0, 0, "", "", frag)
		}
		got, spy := runStreamWithAudit(t, "openai", stream, 512)
		if !strings.Contains(got, "deny:llm_api_proxy:buffer_overflow") {
			t.Fatalf("client did not receive the overflow refusal: %q", got)
		}
		c := assertAudited(t, spy, "deny:llm_api_proxy:buffer_overflow", "openai")
		if c.ToolName != "bash" {
			t.Errorf("audited tool name = %q, want bash — the name arrived before the cap was hit", c.ToolName)
		}
	})

	t.Run("anthropic", func(t *testing.T) {
		stream := pvAnthropicToolStart(0, "toolu_big", "bash", `{}`)
		for i := 0; i < 4; i++ {
			stream += pvAnthropicInputDelta(0, frag)
		}
		got, spy := runStreamWithAudit(t, "anthropic", stream, 512)
		if !strings.Contains(got, "deny:llm_api_proxy:buffer_overflow") {
			t.Fatalf("client did not receive the overflow refusal: %q", got)
		}
		c := assertAudited(t, spy, "deny:llm_api_proxy:buffer_overflow", "anthropic")
		if c.ToolName != "bash" {
			t.Errorf("audited tool name = %q, want bash", c.ToolName)
		}
	})
}

// TestAudit_OversizedSingleEvent_IsRecorded — ONE event past twice the cap.
// This trips in readSSEEvent, before the parser sees anything, so it is the
// path least likely to carry identity — which is exactly why it must still
// leave an entry naming the tenant, agent and rule.
func TestAudit_OversizedSingleEvent_IsRecorded(t *testing.T) {
	huge := strings.Repeat("B", 8192)

	t.Run("openai", func(t *testing.T) {
		stream := fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":"%s"},"finish_reason":null}]}`, huge) + sseTerminator
		got, spy := runStreamWithAudit(t, "openai", stream, 512)
		if !strings.Contains(got, "deny:llm_api_proxy:buffer_overflow") {
			t.Fatalf("client did not receive the overflow refusal: %q", got)
		}
		assertAudited(t, spy, "deny:llm_api_proxy:buffer_overflow", "openai")
	})

	t.Run("anthropic", func(t *testing.T) {
		stream := "event: content_block_delta" + sseLine +
			fmt.Sprintf(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"%s"}}`, huge) + sseTerminator
		got, spy := runStreamWithAudit(t, "anthropic", stream, 512)
		if !strings.Contains(got, "deny:llm_api_proxy:buffer_overflow") {
			t.Fatalf("client did not receive the overflow refusal: %q", got)
		}
		assertAudited(t, spy, "deny:llm_api_proxy:buffer_overflow", "anthropic")
	})
}

// TestAudit_HappyStreamIsNotDoubleAudited is the counterweight. A normal gated
// call is audited by the gate itself; the refusal path must not add a second
// entry, or every allowed tool call would appear twice in the trail.
func TestAudit_HappyStreamIsNotDoubleAudited(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_ok", "bash", `{"command":"ls"}`) +
		pvOpenAIFinish(0, "tool_calls") +
		"data: [DONE]\n\n"

	got, spy := runStreamWithAudit(t, "openai", stream, 0)
	if strings.Contains(got, "AgentGuard denied") {
		t.Fatalf("a healthy stream was refused: %q", got)
	}
	if rec := spy.recorded(); len(rec) != 0 {
		t.Errorf("RecordForcedAudit fired %d times on a healthy stream; the gate owns that entry", len(rec))
	}
}
