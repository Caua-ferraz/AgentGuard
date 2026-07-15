package llmproxy

// streaming_f1_test.go pins v1.0 review finding F1: a streaming
// completion that carries a parse error (a finalized tool_use cycle
// whose assembled arguments are not valid JSON — e.g. a max_tokens-
// truncated tool call, routine OR attacker-inducible) must be treated
// as a fail-closed DENY, never silently dropped.
//
// Pre-fix, the streaming loop did `if ferr != nil && !isEOF { continue }`
// which discarded the completion: the gate never ran (no refusal, no
// audit entry) and the accumulator was left stuck so every subsequent
// event buffered and was dropped at EOF — the firewall went dark with
// no trail. These tests prove the completion now (a) refuses the client,
// (b) still drives the audit path (PolicyCheck is invoked — the sole
// audit mechanism; the proxy never emits audit directly, see server.go),
// and (c) resets the accumulator so a LATER valid tool call in the same
// stream is still gated (the "stuck accumulator" is fixed).

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// gateSpy is a thread-safe PolicyCheck stub that records the tool-call
// ids it was asked to gate. A recorded id is the observable proxy for
// "an audit entry was produced for this action" (the wired PolicyCheck
// POSTs to /v1/check, which writes the audit entry — server.go). The
// decision it returns is configurable so a test can prove fail-closed
// behaviour EVEN WHEN the policy would ALLOW.
type gateSpy struct {
	mu       sync.Mutex
	seenIDs  []string
	decision Decision
}

func (g *gateSpy) check(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
	g.mu.Lock()
	g.seenIDs = append(g.seenIDs, tc.ToolCallID)
	g.mu.Unlock()
	return g.decision, nil
}

func (g *gateSpy) ids() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, len(g.seenIDs))
	copy(out, g.seenIDs)
	return out
}

// TestStreaming_OpenAI_MalformedCompletion_FailsClosedAuditsAndResets
// drives an OpenAI stream whose FIRST tool_call finalizes with truncated
// (invalid) JSON arguments, immediately followed by a SECOND, well-formed
// tool_call in the same stream. The gate spy is wired to ALLOW so the
// test proves the malformed cycle is refused regardless of policy verdict.
func TestStreaming_OpenAI_MalformedCompletion_FailsClosedAuditsAndResets(t *testing.T) {
	// arguments concatenate to `{"cmd":"ls` — unterminated, invalid JSON.
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

	spy := &gateSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = spy.check
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	got := string(raw)

	// (a) A refusal reached the client, carrying the malformed reason.
	if !strings.Contains(got, "AgentGuard denied") || !strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("expected fail-closed malformed refusal; got %q", got)
	}
	// Fail-closed proof: the buffered malformed tool_call MUST NOT leak,
	// even though PolicyCheck was wired to ALLOW.
	if strings.Contains(got, "call_bad") {
		t.Errorf("malformed tool_call id leaked into client output (not fail-closed): %q", got)
	}

	// (b) audit + (c) reset/resume: PolicyCheck must have been invoked for
	// the malformed call (audit gap closed) AND for the subsequent valid
	// call (accumulator reset — gating resumed; the stuck-accumulator bug
	// is fixed).
	ids := spy.ids()
	if len(ids) != 2 || ids[0] != "call_bad" || ids[1] != "call_good" {
		t.Fatalf("PolicyCheck ids = %v, want [call_bad call_good] (audit for malformed + gating resumed for the later valid call)", ids)
	}
}

// TestStreaming_Anthropic_MalformedCompletion_FailsClosedAuditsAndResets
// is the Anthropic sibling: a tool_use whose input_json_delta is
// truncated at content_block_stop, followed by a well-formed tool_use.
func TestStreaming_Anthropic_MalformedCompletion_FailsClosedAuditsAndResets(t *testing.T) {
	badStart := `event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_bad","name":"bash","input":{}}}` + "\n\n"
	// partial_json concatenates to `{"cmd":"ls` — invalid JSON.
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
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = spy.check
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	got := string(raw)

	// (a) refusal reached the client with the malformed reason + the
	// Anthropic stop_reason rewrite.
	if !strings.Contains(got, "AgentGuard denied") || !strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("expected fail-closed malformed refusal; got %q", got)
	}
	if !strings.Contains(got, "stop_reason") {
		t.Errorf("expected Anthropic stop_reason rewrite in refusal; got %q", got)
	}
	// Fail-closed proof: buffered malformed tool_use MUST NOT leak.
	if strings.Contains(got, "toolu_bad") {
		t.Errorf("malformed tool_use id leaked into client output (not fail-closed): %q", got)
	}

	// (b) audit + (c) reset/resume.
	ids := spy.ids()
	if len(ids) != 2 || ids[0] != "toolu_bad" || ids[1] != "toolu_good" {
		t.Fatalf("PolicyCheck ids = %v, want [toolu_bad toolu_good] (audit for malformed + gating resumed for the later valid call)", ids)
	}
}

// TestStreaming_MalformedNonCompletionDelta_NoSpuriousRefusal is the
// regression guard for the PRESERVED behaviour: a malformed event that
// is NOT a completion (garbage mid-stream JSON) is still dropped
// silently — no crash, no spurious refusal, no gate call — and valid
// events that follow pass through byte-for-byte.
func TestStreaming_MalformedNonCompletionDelta_NoSpuriousRefusal(t *testing.T) {
	garbage := "data: {totally not valid json}\n\n"
	content := `data: {"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}` + "\n\n"
	done := "data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, garbage+content+done)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	spy := &gateSpy{decision: Decision{Allow: true}}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = spy.check
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	got := string(raw)

	if strings.Contains(got, "AgentGuard denied") || strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("malformed NON-completion delta spuriously refused: %q", got)
	}
	if !strings.Contains(got, "hello") {
		t.Errorf("valid content after the garbage event did not pass through: %q", got)
	}
	if !strings.Contains(got, "[DONE]") {
		t.Errorf("expected [DONE] to pass through: %q", got)
	}
	if ids := spy.ids(); len(ids) != 0 {
		t.Errorf("PolicyCheck must not fire on a non-completion malformed delta; saw %v", ids)
	}
}

// TestStreaming_OpenAI_ValidToolCall_HappyPathUnchanged is the happy-path
// regression: a well-formed tool_call still gates exactly once and, on
// ALLOW, replays upstream bytes byte-identical. Pins that the F1 change
// added a branch only for the malformed-completion case and left the
// ALLOW path untouched.
func TestStreaming_OpenAI_ValidToolCall_HappyPathUnchanged(t *testing.T) {
	fixture := `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_ok","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, fixture)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	var mu sync.Mutex
	var seenArgs string
	spy := &gateSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			mu.Lock()
			seenArgs = strings.TrimSpace(string(tc.RawArguments))
			mu.Unlock()
			return spy.check(ctx, tc)
		}
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(raw, []byte(fixture)) {
		t.Errorf("ALLOW-path byte-identity violated:\n got=%q\nwant=%q", string(raw), fixture)
	}
	if ids := spy.ids(); len(ids) != 1 || ids[0] != "call_ok" {
		t.Fatalf("PolicyCheck ids = %v, want [call_ok] (gate must fire exactly once)", ids)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenArgs != `{"cmd":"ls"}` {
		t.Errorf("gate saw RawArguments=%q, want {\"cmd\":\"ls\"}", seenArgs)
	}
}
