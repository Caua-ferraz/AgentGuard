package llmproxy

// streaming_protocol_test.go pins four v1.0 audit findings in the two
// SSE accumulators and the stream loops that drive them. All four share
// one theme: a stream the firewall cannot gate must end in a refusal,
// never in ungated bytes and never in silence.
//
//	B7  Anthropic: an input_json_delta arriving while NO tool_use block
//	    is open was forwarded verbatim. Those are tool-call argument
//	    bytes belonging to a call the gate never saw start.
//	B17 Both: buffered (ungated) events were DROPPED when upstream hit
//	    EOF, or when `[DONE]` arrived while a cycle was still open. The
//	    client got an empty response, the gate never ran and nothing was
//	    audited. Note the fix is NOT to flush them — that would be the
//	    bypass — but to run the completion path: gate, or refuse.
//	B18 OpenAI: tool_call state is keyed by tool_calls[i].index, which is
//	    unique only WITHIN a choice. With n>1, two choices' fragments
//	    merged into one argument string nobody executes, and a sibling
//	    choice's finish_reason could close the cycle early.
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
	"time"
)

// ---------------------------------------------------------------------
// event builders. Named with a pv* prefix so they never collide with the
// fixture helpers other test files define.
// ---------------------------------------------------------------------

// pvOpenAIToolDelta emits one OpenAI tool_call delta on a given CHOICE
// index (the axis audit B18 is about) and tool_calls index.
func pvOpenAIToolDelta(choice, toolIdx int, id, name, args string) string {
	idPart := ""
	if id != "" {
		idPart = fmt.Sprintf(`"id":%q,"type":"function",`, id)
	}
	namePart := ""
	if name != "" {
		namePart = fmt.Sprintf(`"name":%q,`, name)
	}
	return fmt.Sprintf(
		`data: {"choices":[{"index":%d,"delta":{"tool_calls":[{"index":%d,%s"function":{%s"arguments":%q}}]},"finish_reason":null}]}`+"\n\n",
		choice, toolIdx, idPart, namePart, args,
	)
}

// pvOpenAIFinish emits a finish_reason on a given choice index.
func pvOpenAIFinish(choice int, reason string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":%d,"delta":{},"finish_reason":%q}]}`+"\n\n",
		choice, reason,
	)
}

// pvOpenAIContent emits a plain content delta on a given choice index.
func pvOpenAIContent(choice int, text string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":%d,"delta":{"content":%q},"finish_reason":null}]}`+"\n\n",
		choice, text,
	)
}

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

// ---------------------------------------------------------------------
// B18 — tool calls across multiple choices
// ---------------------------------------------------------------------

// TestB18_ToolCallsOnSecondChoice_FailClosed pins the collision. With
// n>1 both choices number their tool calls from 0, so the accumulator's
// tool_calls[i].index key merged them: the gate evaluated a splice of
// two different calls' arguments — a string no client ever executes —
// while the two real calls went unexamined.
func TestB18_ToolCallsOnSecondChoice_FailClosed(t *testing.T) {
	t.Run("separate-events", func(t *testing.T) {
		acc := NewOpenAIToolCallAccumulator(0)
		if res, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "call_a", "bash", `{"cmd":"ls"}`))); err != nil || !res.Accumulating {
			t.Fatalf("choice 0 delta: res=%+v err=%v", res, err)
		}
		res, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(1, 0, "call_b", "bash", `{"cmd":"rm -rf /"}`)))
		if err != nil {
			t.Fatalf("choice 1 delta: %v", err)
		}
		if !res.ProtocolViolation {
			t.Fatalf("tool_calls on a second choice returned %+v, want ProtocolViolation (B18: the two calls would merge)", res)
		}
		if res.violation != violationMultiChoiceToolCalls {
			t.Errorf("violation kind = %d, want violationMultiChoiceToolCalls (%d)", res.violation, violationMultiChoiceToolCalls)
		}
	})

	t.Run("same-event", func(t *testing.T) {
		acc := NewOpenAIToolCallAccumulator(0)
		ev := `data: {"choices":[` +
			`{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls\"}"}}]},"finish_reason":null},` +
			`{"index":1,"delta":{"tool_calls":[{"index":0,"id":"call_b","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"rm -rf /\"}"}}]},"finish_reason":null}` +
			`]}` + "\n\n"
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			t.Fatalf("two-choice event: %v", err)
		}
		if !res.ProtocolViolation {
			t.Fatalf("two choices with tool_calls in ONE event returned %+v, want ProtocolViolation", res)
		}
	})
}

// TestB18_SingleChoiceStreamUnaffected is the counterweight that matters
// most: n=1 is what every mainstream agent framework sends, and the B18
// guard must be invisible to it.
func TestB18_SingleChoiceStreamUnaffected(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)
	events := []string{
		pvOpenAIContent(0, "thinking"),
		pvOpenAIToolDelta(0, 0, "call_1", "bash", `{"cmd":`),
		pvOpenAIToolDelta(0, 0, "", "", `"ls"}`),
		// A second tool call on the SAME choice — legal, and must not
		// be confused with a second CHOICE.
		pvOpenAIToolDelta(0, 1, "call_2", "cat", `{"path":"/etc/hosts"}`),
		pvOpenAIFinish(0, "tool_calls"),
	}
	var last FeedResult
	for i, ev := range events {
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if res.ProtocolViolation {
			t.Fatalf("event %d on a single-choice stream was refused (B18 over-refused): %s", i, ev)
		}
		last = res
	}
	if !last.Completed || len(last.CompletedToolCalls) != 2 {
		t.Fatalf("final res=%+v, want Completed with 2 calls", last)
	}
	if got := strings.TrimSpace(string(last.CompletedToolCalls[0].RawArguments)); got != `{"cmd":"ls"}` {
		t.Errorf("call 0 arguments = %q, want %q", got, `{"cmd":"ls"}`)
	}
	if got := strings.TrimSpace(string(last.CompletedToolCalls[1].RawArguments)); got != `{"path":"/etc/hosts"}` {
		t.Errorf("call 1 arguments = %q, want %q", got, `{"path":"/etc/hosts"}`)
	}
}

// TestB18_SiblingChoiceFinishDoesNotCloseCycle pins the second half of
// B18. hasFinishReason accepted a finish_reason from ANY choice, so with
// n>1 a sibling choice finishing first closed the tool-call cycle while
// its arguments were still streaming: the gate saw `{"cmd":"l`, which
// does not parse, and a healthy stream was refused as malformed.
func TestB18_SiblingChoiceFinishDoesNotCloseCycle(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)

	if res, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "call_1", "bash", `{"cmd":"l`))); err != nil || !res.Accumulating {
		t.Fatalf("partial args: res=%+v err=%v", res, err)
	}
	// Sibling choice 1 finishes while choice 0 is mid-arguments.
	res, err := acc.FeedEvent([]byte(pvOpenAIFinish(1, "stop")))
	if err != nil {
		t.Fatalf("sibling finish: %v", err)
	}
	if res.Completed {
		t.Fatalf("a sibling choice's finish_reason closed the cycle early (B18): res=%+v", res)
	}
	if !res.Accumulating {
		t.Errorf("sibling finish: res=%+v, want Accumulating", res)
	}
	// The owning choice streams the rest and closes.
	if _, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "", "", `s"}`))); err != nil {
		t.Fatalf("rest of args: %v", err)
	}
	res, err = acc.FeedEvent([]byte(pvOpenAIFinish(0, "tool_calls")))
	if err != nil {
		t.Fatalf("owning finish: %v", err)
	}
	if !res.Completed || len(res.CompletedToolCalls) != 1 {
		t.Fatalf("owning finish: res=%+v, want Completed with 1 call", res)
	}
	if got := strings.TrimSpace(string(res.CompletedToolCalls[0].RawArguments)); got != `{"cmd":"ls"}` {
		t.Errorf("gated arguments = %q, want the COMPLETE %q", got, `{"cmd":"ls"}`)
	}
}

// TestB18_MultiChoiceToolCalls_RefusesEndToEnd proves neither call's
// bytes reach the client and the refusal names the defect.
func TestB18_MultiChoiceToolCalls_RefusesEndToEnd(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_first", "bash", `{"cmd":"ls"}`) +
		pvOpenAIToolDelta(1, 0, "call_second", "bash", `{"cmd":"rm -rf /"}`) +
		pvOpenAIFinish(0, "tool_calls") +
		"data: [DONE]\n\n"

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	if strings.Contains(got, "call_first") || strings.Contains(got, "call_second") {
		t.Errorf("a tool_call leaked from an ungateable multi-choice stream: %q", got)
	}
	if strings.Contains(got, "rm -rf /") {
		t.Errorf("tool arguments leaked from an ungateable multi-choice stream: %q", got)
	}
	if !strings.Contains(got, "deny:llm_api_proxy:multi_choice_tool_calls") {
		t.Errorf("expected the multi_choice_tool_calls refusal rule; got %q", got)
	}
}

// ---------------------------------------------------------------------
// B17 — end of stream while a cycle is open
// ---------------------------------------------------------------------

// TestB17_OpenAI_EOFMidToolCall_GatesInsteadOfDropping drives a stream
// that ends with NO finish_reason and NO [DONE] — a dropped upstream
// connection. Pre-fix the loop returned and the buffered events went on
// the floor: the client got an empty 200, the gate never ran, nothing
// was audited. The fix runs the completion path, so the call is gated
// and (on ALLOW) delivered.
func TestB17_OpenAI_EOFMidToolCall_GatesInsteadOfDropping(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_eof", "bash", `{"cmd":"ls"}`)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	calls := spy.seen()
	if len(calls) != 1 {
		t.Fatalf("PolicyCheck ran %d times, want 1 — the cycle was dropped at EOF without gating (B17)", len(calls))
	}
	if args := strings.TrimSpace(string(calls[0].RawArguments)); args != `{"cmd":"ls"}` {
		t.Errorf("gate evaluated %q, want %q", args, `{"cmd":"ls"}`)
	}
	if !strings.Contains(got, "call_eof") {
		t.Errorf("ALLOWed tool_call was not delivered after the EOF close: %q", got)
	}
}

// TestB17_OpenAI_EOFMidToolCall_DenyDoesNotLeak is the security half:
// the EOF closer must route through the gate, so a DENY still refuses.
// A "flush whatever's buffered" reading of the same finding would have
// handed these bytes to the client ungated.
func TestB17_OpenAI_EOFMidToolCall_DenyDoesNotLeak(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_eof_deny", "bash", `{"cmd":"rm -rf /"}`)

	spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "blocked by policy", Rule: "deny:test:rule"}}
	got := pvRunStream(t, "openai", stream, spy)

	if strings.Contains(got, "call_eof_deny") || strings.Contains(got, "rm -rf /") {
		t.Fatalf("a DENIED tool_call leaked to the client at EOF (B17 fail-open): %q", got)
	}
	if !strings.Contains(got, "deny:test:rule") {
		t.Errorf("expected the policy refusal to reach the client; got %q", got)
	}
	if len(spy.seen()) != 1 {
		t.Errorf("PolicyCheck ran %d times, want 1", len(spy.seen()))
	}
}

// TestB17_OpenAI_EOFTruncatedArgs_FailsClosed covers the routine case: a
// max_tokens cutoff mid-arguments. The assembled JSON cannot parse, so
// the cycle lands on the F1 malformed refusal — denied AND audited,
// rather than dropped in silence.
func TestB17_OpenAI_EOFTruncatedArgs_FailsClosed(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_trunc", "bash", `{"cmd":"rm -rf `)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	if !strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("expected the malformed fail-closed refusal; got %q", got)
	}
	if strings.Contains(got, "call_trunc") {
		t.Errorf("truncated tool_call leaked to the client: %q", got)
	}
	// The audit path still runs even though the verdict is forced.
	if len(spy.seen()) != 1 {
		t.Errorf("PolicyCheck ran %d times, want 1 (the audit trail for the forced deny)", len(spy.seen()))
	}
}

// TestB17_OpenAI_DoneWhileActive_ClosesTheCycle covers `[DONE]` arriving
// while a tool_call is still open. `[DONE]` IS the end of stream, so the
// cycle closes there rather than waiting for the transport EOF — and it
// closes through the gate, both directions.
func TestB17_OpenAI_DoneWhileActive_ClosesTheCycle(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_done", "bash", `{"cmd":"ls"}`) + "data: [DONE]\n\n"

	t.Run("allow-flushes", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
		got := pvRunStream(t, "openai", stream, spy)
		if len(spy.seen()) != 1 {
			t.Fatalf("PolicyCheck ran %d times, want 1", len(spy.seen()))
		}
		if !strings.Contains(got, "call_done") {
			t.Errorf("ALLOWed tool_call was not delivered: %q", got)
		}
		if !strings.Contains(got, "[DONE]") {
			t.Errorf("terminator missing from the flushed stream: %q", got)
		}
	})

	t.Run("deny-does-not-leak", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "no", Rule: "deny:test:rule"}}
		got := pvRunStream(t, "openai", stream, spy)
		if strings.Contains(got, "call_done") {
			t.Fatalf("a DENIED tool_call leaked via the [DONE] path: %q", got)
		}
		if !strings.Contains(got, "deny:test:rule") {
			t.Errorf("expected the policy refusal; got %q", got)
		}
	})
}

// TestB17_OpenAI_DoneWithoutEOF_DoesNotWaitForTheConnectionToClose
// isolates the `[DONE]` closer from the EOF closer. When upstream closes
// right after `[DONE]` the two are indistinguishable — EOF arrives
// immediately and finalizes the cycle either way. An upstream that holds
// the connection open after `[DONE]` (keep-alive behaviour some gateways
// have) is the case that separates them: without the `[DONE]` close the
// client waits on a stream that is already over.
func TestB17_OpenAI_DoneWithoutEOF_DoesNotWaitForTheConnectionToClose(t *testing.T) {
	released := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, pvOpenAIToolDelta(0, 0, "call_keepalive", "bash", `{"cmd":"rm -rf /"}`))
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
		// Hold the connection open. The proxy must NOT need this to end.
		select {
		case <-released:
		case <-r.Context().Done():
		case <-time.After(15 * time.Second):
		}
	}))
	defer upstream.Close()
	defer close(released)

	spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "no", Rule: "deny:test:rule"}}
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = spy.check
	})
	defer teardown()

	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4","messages":[],"stream":true}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		done <- result{body: string(raw)}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("request: %v", got.err)
		}
		if strings.Contains(got.body, "call_keepalive") || strings.Contains(got.body, "rm -rf /") {
			t.Fatalf("a DENIED tool_call leaked via the [DONE] path: %q", got.body)
		}
		if !strings.Contains(got.body, "deny:test:rule") {
			t.Errorf("expected the policy refusal; got %q", got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client was still waiting 5s after [DONE]: the cycle is not closed until the connection drops (B17)")
	}
}

// TestB17_Anthropic_EOFMidToolUse_GatesInsteadOfDropping is the
// Anthropic sibling: a tool_use block still open when upstream vanishes.
func TestB17_Anthropic_EOFMidToolUse_GatesInsteadOfDropping(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_b17","type":"message"}}` + "\n\n" +
		pvAnthropicToolStart(0, "toolu_eof", "bash", `{}`) +
		pvAnthropicInputDelta(0, `{"cmd":"rm -rf /"}`)
	// No content_block_stop, no message_stop — the connection dies here.

	t.Run("deny-does-not-leak", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: false, Reason: "no", Rule: "deny:test:rule"}}
		got := pvRunStream(t, "anthropic", stream, spy)
		if len(spy.seen()) != 1 {
			t.Fatalf("PolicyCheck ran %d times, want 1 — the tool_use was dropped at EOF without gating (B17)", len(spy.seen()))
		}
		if strings.Contains(got, "rm -rf /") {
			t.Fatalf("a DENIED tool_use leaked to the client at EOF: %q", got)
		}
		if !strings.Contains(got, "deny:test:rule") {
			t.Errorf("expected the policy refusal; got %q", got)
		}
	})

	t.Run("allow-delivers", func(t *testing.T) {
		spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
		got := pvRunStream(t, "anthropic", stream, spy)
		if len(spy.seen()) != 1 {
			t.Fatalf("PolicyCheck ran %d times, want 1", len(spy.seen()))
		}
		if !strings.Contains(got, "toolu_eof") {
			t.Errorf("ALLOWed tool_use was not delivered after the EOF close: %q", got)
		}
	})
}

// TestB17_Anthropic_EOFTruncatedInput_FailsClosed: the arguments were
// cut mid-JSON, so the EOF close lands on the malformed refusal.
func TestB17_Anthropic_EOFTruncatedInput_FailsClosed(t *testing.T) {
	stream := pvAnthropicToolStart(0, "toolu_trunc", "bash", `{}`) +
		pvAnthropicInputDelta(0, `{"cmd":"rm -rf `)

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "anthropic", stream, spy)

	if !strings.Contains(got, "malformed tool call arguments") {
		t.Errorf("expected the malformed fail-closed refusal; got %q", got)
	}
	if strings.Contains(got, "rm -rf") {
		t.Errorf("truncated tool input leaked to the client: %q", got)
	}
}

// TestB17_CompletionSignalledExactlyOnce guards the latch the two new
// closers required. A stream that ends properly must gate its call ONCE:
// if `[DONE]` or EOF could re-close an already-completed cycle, every
// well-formed tool call would be gated (and audited) twice.
func TestB17_CompletionSignalledExactlyOnce(t *testing.T) {
	stream := pvOpenAIToolDelta(0, 0, "call_once", "bash", `{"cmd":"ls"}`) +
		pvOpenAIFinish(0, "tool_calls") +
		"data: [DONE]\n\n"

	spy := &pvCallSpy{decision: Decision{Allow: true, Rule: "allow:test"}}
	got := pvRunStream(t, "openai", stream, spy)

	if n := len(spy.seen()); n != 1 {
		t.Fatalf("PolicyCheck ran %d times for one tool call, want exactly 1", n)
	}
	if !strings.Contains(got, "call_once") || !strings.Contains(got, "[DONE]") {
		t.Errorf("normal ALLOW stream was altered: %q", got)
	}
	if strings.Count(got, "call_once") != 1 {
		t.Errorf("tool_call delivered %d times, want once: %q", strings.Count(got, "call_once"), got)
	}
}

// TestB17_CloseAtEOF_IsInertAfterACleanClose pins the same latch at the
// parser boundary, where the orchestrator's Reset is not in the picture.
func TestB17_CloseAtEOF_IsInertAfterACleanClose(t *testing.T) {
	t.Run("openai", func(t *testing.T) {
		acc := NewOpenAIToolCallAccumulator(0)
		if _, err := acc.FeedEvent([]byte(pvOpenAIToolDelta(0, 0, "call_x", "bash", `{}`))); err != nil {
			t.Fatalf("delta: %v", err)
		}
		res, err := acc.FeedEvent([]byte(pvOpenAIFinish(0, "tool_calls")))
		if err != nil || !res.Completed {
			t.Fatalf("finish: res=%+v err=%v", res, err)
		}
		if res, _ := acc.CloseAtEOF(); res.Completed {
			t.Errorf("CloseAtEOF re-completed an already-closed cycle: %+v", res)
		}
	})

	t.Run("anthropic", func(t *testing.T) {
		acc := NewAnthropicAccumulator(0)
		if _, err := acc.FeedEvent([]byte(pvAnthropicToolStart(0, "toolu_x", "bash", `{}`))); err != nil {
			t.Fatalf("start: %v", err)
		}
		res, err := acc.FeedEvent([]byte(pvAnthropicStop(0)))
		if err != nil || !res.Completed {
			t.Fatalf("stop: res=%+v err=%v", res, err)
		}
		if res, _ := acc.CloseAtEOF(); res.Completed {
			t.Errorf("CloseAtEOF re-completed an already-closed cycle: %+v", res)
		}
	})

	t.Run("idle-stream-is-untouched", func(t *testing.T) {
		// No tool call ever started: EOF must do nothing at all.
		acc := NewOpenAIToolCallAccumulator(0)
		if _, err := acc.FeedEvent([]byte(pvOpenAIContent(0, "hi"))); err != nil {
			t.Fatalf("content: %v", err)
		}
		res, err := acc.CloseAtEOF()
		if err != nil || res.Completed || res.PassThrough || res.Accumulating {
			t.Errorf("CloseAtEOF on an idle stream = %+v (err=%v), want the zero result", res, err)
		}
	})
}
