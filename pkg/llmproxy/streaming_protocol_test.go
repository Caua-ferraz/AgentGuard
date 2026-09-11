package llmproxy

// streaming_protocol_test.go pins two v1.0 audit findings in the
// Anthropic SSE accumulator and the stream loop that drives it. Both share
// one theme: a stream the firewall cannot gate must end in a refusal,
// never in ungated bytes and never in silence.
//
//	B7  Anthropic: an input_json_delta arriving while NO tool_use block
//	    is open was forwarded verbatim. Those are tool-call argument
//	    bytes belonging to a call the gate never saw start.
//	B21 Anthropic: `{ }` as content_block_start.input was compared with
//	    bytes.Equal against "{}", so an empty seed carrying insignificant
//	    whitespace was mistaken for real arguments and the next
//	    (conformant) input_json_delta tripped the H2 conflict refusal.
//
// Each finding gets both a parser-level test (exact FeedResult and
// violation kind) and an end-to-end test through the real stream loop
// (what the CLIENT receives), plus a counterweight test proving the fix
// did not over-refuse traffic that must still flow.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------
// event builders. Named with a pv* prefix so they never collide with the
// fixture helpers other test files define.
// ---------------------------------------------------------------------

func pvAnthropicToolStart(index int, id, name, input string) string {
	return "event: content_block_start\n" + fmt.Sprintf(
		`data: {"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%q,"name":%q,"input":%s}}`+"\n\n",
		index, id, name, input,
	)
}

func pvAnthropicTextStart(index int) string {
	return "event: content_block_start\n" + fmt.Sprintf(
		`data: {"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`+"\n\n",
		index,
	)
}

func pvAnthropicInputDelta(index int, partial string) string {
	return "event: content_block_delta\n" + fmt.Sprintf(
		`data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%q}}`+"\n\n",
		index, partial,
	)
}

func pvAnthropicTextDelta(index int, text string) string {
	return "event: content_block_delta\n" + fmt.Sprintf(
		`data: {"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%q}}`+"\n\n",
		index, text,
	)
}

func pvAnthropicStop(index int) string {
	return "event: content_block_stop\n" + fmt.Sprintf(
		`data: {"type":"content_block_stop","index":%d}`+"\n\n", index,
	)
}

// pvCallSpy is a PolicyCheck stub that records the FULL tool calls it was
// asked to gate — the id proves an audit entry was driven, the raw
// arguments prove WHAT the gate actually evaluated (which is the whole
// question in B18 and B21).
type pvCallSpy struct {
	mu       sync.Mutex
	calls    []ToolCallCheck
	decision Decision
	err      error
}

func (g *pvCallSpy) check(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
	g.mu.Lock()
	g.calls = append(g.calls, *tc)
	g.mu.Unlock()
	return g.decision, g.err
}

func (g *pvCallSpy) seen() []ToolCallCheck {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ToolCallCheck, len(g.calls))
	copy(out, g.calls)
	return out
}

// pvRunStream drives one streaming request through the real proxy loop
// against an upstream that writes `body` verbatim and then closes. The
// close is what makes these tests meaningful for B17: the upstream never
// lingers, so EOF is reached deterministically.
func pvRunStream(t *testing.T, provider, body string, spy *pvCallSpy) string {
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

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		// Rich refusals render the Rule string, which is the stable
		// operator-facing contract each of these tests asserts on.
		s.BuildRefusal = BuildRefusalRich
		if spy != nil {
			s.PolicyCheck = spy.check
		}
	})
	defer teardown()

	path := "/v1/chat/completions"
	reqBody := `{"model":"gpt-4","messages":[],"stream":true}`
	if provider == "anthropic" {
		path = "/v1/messages"
		reqBody = `{"model":"claude-3-5-sonnet","messages":[],"stream":true}`
	}
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(reqBody))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// ---------------------------------------------------------------------
// B7 — orphaned input_json_delta
// ---------------------------------------------------------------------

// TestB7_AnthropicIdleInputJSONDelta_FailsClosed pins that tool-input
// fragments arriving with no tool_use block open are refused, not
// forwarded. Pre-fix the idle branch returned PassThrough for every
// delta type, so the fragments reached the client verbatim: a client
// that reconstructs tool input from deltas alone would assemble and
// execute arguments the firewall never inspected, and no gate cycle
// existed that could ever have caught them.
func TestB7_AnthropicIdleInputJSONDelta_FailsClosed(t *testing.T) {
	acc := NewAnthropicAccumulator(0)

	// An idle text block first — this must still pass through.
	if res, err := acc.FeedEvent([]byte(pvAnthropicTextStart(0))); err != nil || !res.PassThrough {
		t.Fatalf("text start: res=%+v err=%v, want PassThrough", res, err)
	}

	res, err := acc.FeedEvent([]byte(pvAnthropicInputDelta(0, `{"command":"rm -rf /"}`)))
	if err != nil {
		t.Fatalf("orphaned input_json_delta: %v", err)
	}
	if !res.ProtocolViolation {
		t.Fatalf("orphaned input_json_delta returned %+v, want ProtocolViolation (B7 regression: tool input forwarded ungated)", res)
	}
	if res.PassThrough {
		t.Errorf("orphaned input_json_delta must not also be PassThrough: %+v", res)
	}
	if res.violation != violationOrphanedToolInput {
		t.Errorf("violation kind = %d, want violationOrphanedToolInput (%d) — the refusal would name the wrong defect",
			res.violation, violationOrphanedToolInput)
	}
}

// TestB7_AnthropicIdleNonToolDeltas_StillPassThrough is the
// counterweight: the B7 fix must refuse ONLY input_json_delta. Text
// deltas are the overwhelming majority of idle events on this branch and
// are not gated at all — refusing them would break every streaming text
// response.
func TestB7_AnthropicIdleNonToolDeltas_StillPassThrough(t *testing.T) {
	cases := []struct {
		name  string
		event string
	}{
		{"text_delta", pvAnthropicTextDelta(0, "hello")},
		{"unknown_delta_type", "event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}` + "\n\n"},
		{"no_delta_field", "event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0}` + "\n\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			res, err := acc.FeedEvent([]byte(c.event))
			if err != nil {
				t.Fatalf("feed: %v", err)
			}
			if res.ProtocolViolation {
				t.Fatalf("idle %s was refused as a protocol violation — B7 over-refused: %+v", c.name, res)
			}
			if !res.PassThrough {
				t.Errorf("idle %s: res=%+v, want PassThrough", c.name, res)
			}
		})
	}
}

// TestB7_AnthropicOrphanedToolInput_RefusesEndToEnd proves the client
// receives a refusal naming the defect, and — the security property —
// that the orphaned arguments never appear in the response body.
func TestB7_AnthropicOrphanedToolInput_RefusesEndToEnd(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_b7","type":"message"}}` + "\n\n" +
		pvAnthropicTextStart(0) +
		pvAnthropicTextDelta(0, "sure, running that") +
		// No content_block_start for a tool_use — the gate never saw a
		// block open, yet tool input streams anyway.
		pvAnthropicInputDelta(1, `{"command":"rm -rf /"}`) +
		pvAnthropicStop(1)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	if strings.Contains(got, "rm -rf /") {
		t.Errorf("orphaned tool input reached the client (B7 bypass): %q", got)
	}
	if !strings.Contains(got, "deny:llm_api_proxy:orphaned_tool_input") {
		t.Errorf("expected the orphaned_tool_input refusal rule; got %q", got)
	}
	// The leading text block was legitimate and already flushed.
	if !strings.Contains(got, "sure, running that") {
		t.Errorf("pre-violation text was dropped; got %q", got)
	}
	// Nothing was gateable, so the gate correctly never ran — the
	// refusal is unconditional, not policy-derived.
	if n := len(spy.seen()); n != 0 {
		t.Errorf("PolicyCheck ran %d times for an orphaned delta; want 0 (there is no assembled call to gate)", n)
	}
}

// ---------------------------------------------------------------------
// B21 — whitespace-only empty seed
// ---------------------------------------------------------------------

// TestB21_EmptyObjectSeedVariants_DoNotBlockStreamedArgs drives the
// conformant Anthropic shape — `input` empty at content_block_start,
// real arguments via input_json_delta — with every spelling of "empty
// object". Pre-fix only the exact bytes `{}` were recognised, so `{ }`
// set startSeeded and the very next delta tripped the H2 conflict
// refusal: a legitimate stream refused.
func TestB21_EmptyObjectSeedVariants_DoNotBlockStreamedArgs(t *testing.T) {
	// Space and tab only: a raw newline cannot appear inside a
	// single-line SSE `data:` field, so it is not a shape this branch
	// can receive on the wire. The newline spellings are covered
	// directly in TestB21_IsEmptyJSONObject.
	seeds := []string{`{}`, `{ }`, "{\t}", "{ \t  }"}
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed=%q", seed), func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			if res, err := acc.FeedEvent([]byte(pvAnthropicToolStart(0, "toolu_b21", "bash", seed))); err != nil || !res.Accumulating {
				t.Fatalf("tool start: res=%+v err=%v", res, err)
			}
			res, err := acc.FeedEvent([]byte(pvAnthropicInputDelta(0, `{"cmd":"ls"}`)))
			if err != nil {
				t.Fatalf("input delta: %v", err)
			}
			if res.ProtocolViolation {
				t.Fatalf("a conformant stream seeded with %q was refused (B21 regression)", seed)
			}
			res, err = acc.FeedEvent([]byte(pvAnthropicStop(0)))
			if err != nil {
				t.Fatalf("stop: %v", err)
			}
			if !res.Completed || len(res.CompletedToolCalls) != 1 {
				t.Fatalf("stop: res=%+v, want one completed call", res)
			}
			// The gate must see the STREAMED arguments, not an empty
			// object and not a concatenation of both.
			if got := strings.TrimSpace(string(res.CompletedToolCalls[0].RawArguments)); got != `{"cmd":"ls"}` {
				t.Errorf("gated arguments = %q, want %q", got, `{"cmd":"ls"}`)
			}
		})
	}
}

// TestB21_NonEmptySeedStillConflictsWithDeltas is the counterweight: the
// H2 defence must survive. A start block carrying REAL arguments plus
// streamed deltas is the conflicting-sources shape, and it stays refused
// — including when the real arguments are padded with whitespace, which
// is exactly where a byte-equality check would be fooled in the other
// direction.
func TestB21_NonEmptySeedStillConflictsWithDeltas(t *testing.T) {
	for _, seed := range []string{`{"cmd":"x"}`, `{ "cmd":"x" }`} {
		t.Run(seed, func(t *testing.T) {
			acc := NewAnthropicAccumulator(0)
			if _, err := acc.FeedEvent([]byte(pvAnthropicToolStart(0, "toolu_h2", "bash", seed))); err != nil {
				t.Fatalf("tool start: %v", err)
			}
			res, err := acc.FeedEvent([]byte(pvAnthropicInputDelta(0, `{"cmd":"ls"}`)))
			if err != nil {
				t.Fatalf("input delta: %v", err)
			}
			if !res.ProtocolViolation {
				t.Fatalf("seeded arguments + streamed deltas must fail closed (H2); got %+v", res)
			}
			if res.violation != violationInterleavedToolUse {
				t.Errorf("violation kind = %d, want violationInterleavedToolUse (%d)", res.violation, violationInterleavedToolUse)
			}
		})
	}
}

// TestB21_IsEmptyJSONObject pins the predicate directly, including the
// shapes that must NOT be treated as empty. A false positive here would
// silently discard real start-block arguments — the H2 bypass.
func TestB21_IsEmptyJSONObject(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`{}`, true},
		{`{ }`, true},
		{"{\n}", true},
		{"{\t}", true},
		{"{\r\n  \t}", true},
		{`{"a":1}`, false},
		{`{ "a":1 }`, false},
		{`{""}`, false},
		{`null`, false},
		{`[]`, false},
		{`{`, false},
		{`}`, false},
		{``, false},
		{`{}}`, false},
		{`{{}}`, false},
	}
	for _, c := range cases {
		if got := isEmptyJSONObject([]byte(c.in)); got != c.want {
			t.Errorf("isEmptyJSONObject(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestB21_WhitespaceSeedStreamGatesEndToEnd drives the `{ }` shape
// through the real loop: the gate must see the streamed arguments and,
// on ALLOW, the client must receive the upstream bytes rather than a
// spurious refusal.
func TestB21_WhitespaceSeedStreamGatesEndToEnd(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_b21","type":"message"}}` + "\n\n" +
		pvAnthropicToolStart(0, "toolu_ws", "bash", `{ }`) +
		pvAnthropicInputDelta(0, `{"cmd":"ls -la"}`) +
		pvAnthropicStop(0) +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	if strings.Contains(got, "AgentGuard denied") {
		t.Fatalf("a conformant `{ }`-seeded stream was refused (B21 regression): %q", got)
	}
	calls := spy.seen()
	if len(calls) != 1 {
		t.Fatalf("PolicyCheck ran %d times, want 1", len(calls))
	}
	if args := strings.TrimSpace(string(calls[0].RawArguments)); args != `{"cmd":"ls -la"}` {
		t.Errorf("gate evaluated %q, want %q", args, `{"cmd":"ls -la"}`)
	}
	if !strings.Contains(got, "toolu_ws") {
		t.Errorf("ALLOWed tool_use block did not reach the client: %q", got)
	}
}
