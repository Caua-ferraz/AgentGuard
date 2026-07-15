package llmproxy

// at_sse_realism_test.go hardens the SYNTHESIZED streaming fixtures'
// realism (see the v1.0 AT brief, item 2a). Real captured traces need
// live provider API traffic we can't generate here, so instead of
// weakening the coverage we synthesize fixtures that reproduce the
// real-world SSE quirks the original spec-derived fixtures under-cover:
//
//   - SSE framing: `event:` lines, bare `:` comment/ping keep-alives,
//     blank-line event boundaries, multi-line `data:` values, and the
//     OpenAI `data: [DONE]` sentinel.
//   - Anthropic: message_start -> content_block_start (text AND
//     tool_use) -> many small input_json_delta fragments that assemble
//     into valid JSON -> content_block_stop -> message_delta
//     (stop_reason + usage) -> message_stop, with ping events
//     interleaved; a multi-tool_use stream; and an empty-arguments
//     ({}) tool_use.
//   - OpenAI: role delta (content:null), content deltas, tool_calls
//     deltas whose arguments stream across MANY small fragments,
//     finish_reason, a usage-only chunk, then [DONE]; plus a
//     multiple-tool-call stream and an empty-arguments ({}) call.
//   - Fragmentation realism: JSON split across delta boundaries at
//     awkward points (mid-key, mid-string, mid-token) with interleaved
//     whitespace.
//
// These tests are TEST-ONLY: they never touch production parsers or
// streaming code, only add fixtures + assertions. They replay each
// fixture through the real accumulators exactly as the streaming
// orchestrator does -- including calling Reset() on every Completed to
// mirror the ALLOW-path flush -- and assert the fully-assembled tool
// name(s), RawArguments/Arguments, and Completed signalling.
//
// The testdata/captured/ auto-detect seam (at_captured_fixtures_test.go)
// is intentionally left intact so real captures can drop in later.

import (
	"reflect"
	"strings"
	"testing"
)

// wantTool is the expected fully-assembled shape of one tool call.
type wantTool struct {
	provider string
	name     string
	id       string
	rawArgs  string                 // exact assembled RawArguments (TrimSpace'd)
	args     map[string]interface{} // parsed Arguments (numbers are float64)
}

// replayResult captures what a full fixture replay produced.
type replayResult struct {
	completed    []ToolCallCheck
	passThrough  int
	accumulating int
	completions  int // number of events that returned Completed=true
}

// replayOpenAIFixture feeds every event of the named fixture through a
// fresh OpenAIToolCallAccumulator, mirroring the orchestrator: on each
// Completed it collects the calls and Reset()s (as gateAndFlushOpenAI
// does on ALLOW). Comment/ping and provenance events are fed as-is (NOT
// stripped) so their pass-through / buffering behavior is exercised.
func replayOpenAIFixture(t *testing.T, name string) replayResult {
	t.Helper()
	events := readFixtureEvents(t, name)
	if len(events) == 0 {
		t.Fatalf("%s: fixture produced 0 events", name)
	}
	acc := NewOpenAIToolCallAccumulator(0)
	var rr replayResult
	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("%s: event %d (%q): unexpected err: %v", name, i, ev, err)
		}
		switch {
		case res.OverflowBufferBytes:
			t.Fatalf("%s: event %d: unexpected OverflowBufferBytes", name, i)
		case res.Completed:
			rr.completions++
			rr.completed = append(rr.completed, res.CompletedToolCalls...)
			acc.Reset()
		case res.Accumulating:
			rr.accumulating++
		case res.PassThrough:
			rr.passThrough++
		}
	}
	return rr
}

// replayAnthropicFixture is the Anthropic analogue. Anthropic gates ONE
// tool_use per content_block_stop and the orchestrator Reset()s between
// gates, so a multi-tool_use stream only surfaces both calls if we
// Reset() on each Completed -- exactly what gateAndFlushAnthropic does.
func replayAnthropicFixture(t *testing.T, name string) replayResult {
	t.Helper()
	events := readFixtureEvents(t, name)
	if len(events) == 0 {
		t.Fatalf("%s: fixture produced 0 events", name)
	}
	acc := NewAnthropicAccumulator(0)
	var rr replayResult
	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("%s: event %d (%q): unexpected err: %v", name, i, ev, err)
		}
		switch {
		case res.OverflowBufferBytes:
			t.Fatalf("%s: event %d: unexpected OverflowBufferBytes", name, i)
		case res.Completed:
			rr.completions++
			rr.completed = append(rr.completed, res.CompletedToolCalls...)
			acc.Reset()
		case res.Accumulating:
			rr.accumulating++
		case res.PassThrough:
			rr.passThrough++
		}
	}
	return rr
}

// assertToolMatches checks one assembled ToolCallCheck against want.
func assertToolMatches(t *testing.T, ctx string, got ToolCallCheck, want wantTool) {
	t.Helper()
	if got.Provider != want.provider {
		t.Errorf("%s: Provider = %q, want %q", ctx, got.Provider, want.provider)
	}
	if got.ToolName != want.name {
		t.Errorf("%s: ToolName = %q, want %q", ctx, got.ToolName, want.name)
	}
	if got.ToolCallID != want.id {
		t.Errorf("%s: ToolCallID = %q, want %q", ctx, got.ToolCallID, want.id)
	}
	if raw := strings.TrimSpace(string(got.RawArguments)); raw != want.rawArgs {
		t.Errorf("%s: RawArguments = %q, want %q", ctx, raw, want.rawArgs)
	}
	if !reflect.DeepEqual(got.Arguments, want.args) {
		t.Errorf("%s: Arguments = %#v, want %#v", ctx, got.Arguments, want.args)
	}
}

// --- OpenAI realism fixtures -------------------------------------------------

func TestSSERealism_OpenAI_ToolCallFragmented(t *testing.T) {
	rr := replayOpenAIFixture(t, "openai_streaming_tool_call_fragmented.txt")
	if rr.completions != 1 {
		t.Fatalf("Completed fired %d times, want 1", rr.completions)
	}
	if len(rr.completed) != 1 {
		t.Fatalf("len(completed) = %d, want 1", len(rr.completed))
	}
	assertToolMatches(t, "openai frag", rr.completed[0], wantTool{
		provider: "openai",
		name:     "get_current_weather",
		id:       "call_abc123XYZ",
		rawArgs:  `{"location": "Boston, MA", "unit": "fahrenheit"}`,
		args: map[string]interface{}{
			"location": "Boston, MA",
			"unit":     "fahrenheit",
		},
	})
	// Non-tool content is handled: the role delta + two content deltas +
	// the provenance comment event all pass through BEFORE the tool_call,
	// and the trailing usage chunk + [DONE] pass through AFTER the gate.
	if rr.passThrough < 4 {
		t.Errorf("PassThrough = %d, want >= 4 (pre-tool content/comment + trailing usage/[DONE])", rr.passThrough)
	}
	// The name delta + the many argument fragments (plus an interleaved
	// keep-alive comment) buffer rather than leak to the client.
	if rr.accumulating < 10 {
		t.Errorf("Accumulating = %d, want >= 10 (heavily fragmented arguments buffered)", rr.accumulating)
	}
}

func TestSSERealism_OpenAI_MultiToolCallFragmented(t *testing.T) {
	rr := replayOpenAIFixture(t, "openai_streaming_multi_tool_call_fragmented.txt")
	if rr.completions != 1 {
		t.Fatalf("Completed fired %d times, want 1 (both calls close at one finish_reason)", rr.completions)
	}
	if len(rr.completed) != 2 {
		t.Fatalf("len(completed) = %d, want 2", len(rr.completed))
	}
	assertToolMatches(t, "openai multi[0]", rr.completed[0], wantTool{
		provider: "openai",
		name:     "search",
		id:       "call_s0",
		rawArgs:  `{"query": "climate", "limit": 5}`,
		args: map[string]interface{}{
			"query": "climate",
			"limit": float64(5),
		},
	})
	assertToolMatches(t, "openai multi[1]", rr.completed[1], wantTool{
		provider: "openai",
		name:     "send_email",
		id:       "call_e1",
		rawArgs:  `{"to": "a@b.com", "body": "hi"}`,
		args: map[string]interface{}{
			"to":   "a@b.com",
			"body": "hi",
		},
	})
}

func TestSSERealism_OpenAI_EmptyArgsToolCall(t *testing.T) {
	rr := replayOpenAIFixture(t, "openai_streaming_empty_args_tool_call.txt")
	if rr.completions != 1 || len(rr.completed) != 1 {
		t.Fatalf("completions=%d len(completed)=%d, want 1/1", rr.completions, len(rr.completed))
	}
	assertToolMatches(t, "openai empty", rr.completed[0], wantTool{
		provider: "openai",
		name:     "get_time",
		id:       "call_time0",
		rawArgs:  `{}`,
		args:     map[string]interface{}{},
	})
}

func TestSSERealism_OpenAI_MultilineDataFraming(t *testing.T) {
	// A single event whose JSON payload is split across two `data:` lines
	// (SSE spec joins them with '\n'). extractOpenAIDataLine must rejoin
	// them into valid JSON and still assemble the tool_call.
	rr := replayOpenAIFixture(t, "openai_streaming_multiline_data.txt")
	if rr.completions != 1 || len(rr.completed) != 1 {
		t.Fatalf("completions=%d len(completed)=%d, want 1/1", rr.completions, len(rr.completed))
	}
	assertToolMatches(t, "openai multiline", rr.completed[0], wantTool{
		provider: "openai",
		name:     "noop",
		id:       "call_ml",
		rawArgs:  `{}`,
		args:     map[string]interface{}{},
	})
}

// --- Anthropic realism fixtures ----------------------------------------------

func TestSSERealism_Anthropic_ToolUseFragmented(t *testing.T) {
	rr := replayAnthropicFixture(t, "anthropic_streaming_tool_use_fragmented.txt")
	if rr.completions != 1 {
		t.Fatalf("Completed fired %d times, want 1", rr.completions)
	}
	if len(rr.completed) != 1 {
		t.Fatalf("len(completed) = %d, want 1", len(rr.completed))
	}
	assertToolMatches(t, "anthropic frag", rr.completed[0], wantTool{
		provider: "anthropic",
		name:     "get_weather",
		id:       "toolu_01A09q90qw90lkfsdf",
		rawArgs:  `{"location": "San Francisco, CA", "unit": "celsius", "days": 3}`,
		args: map[string]interface{}{
			"location": "San Francisco, CA",
			"unit":     "celsius",
			"days":     float64(3),
		},
	})
	// The text preamble block (message_start, content_block_start(text),
	// two text_deltas, content_block_stop) and the leading ping all pass
	// through before the tool_use buffer opens.
	if rr.passThrough < 5 {
		t.Errorf("PassThrough = %d, want >= 5 (text preamble + leading ping)", rr.passThrough)
	}
	// The tool_use start + many input_json_delta fragments + interleaved
	// ping/keep-alive all buffer.
	if rr.accumulating < 10 {
		t.Errorf("Accumulating = %d, want >= 10 (fragmented tool_use input buffered)", rr.accumulating)
	}
}

func TestSSERealism_Anthropic_MultiToolUse(t *testing.T) {
	rr := replayAnthropicFixture(t, "anthropic_streaming_multi_tool_use.txt")
	// Two serial tool_use blocks, each gated at its own content_block_stop
	// with a Reset() between -> two separate Completed signals.
	if rr.completions != 2 {
		t.Fatalf("Completed fired %d times, want 2", rr.completions)
	}
	if len(rr.completed) != 2 {
		t.Fatalf("len(completed) = %d, want 2", len(rr.completed))
	}
	assertToolMatches(t, "anthropic multi[0]", rr.completed[0], wantTool{
		provider: "anthropic",
		name:     "get_weather",
		id:       "toolu_multi_1",
		rawArgs:  `{"city": "Paris"}`,
		args:     map[string]interface{}{"city": "Paris"},
	})
	assertToolMatches(t, "anthropic multi[1]", rr.completed[1], wantTool{
		provider: "anthropic",
		name:     "list_files",
		id:       "toolu_multi_2",
		rawArgs:  `{"path": "/var/log", "recursive": true}`,
		args: map[string]interface{}{
			"path":      "/var/log",
			"recursive": true,
		},
	})
}

func TestSSERealism_Anthropic_EmptyArgsToolUse(t *testing.T) {
	rr := replayAnthropicFixture(t, "anthropic_streaming_empty_args_tool_use.txt")
	if rr.completions != 1 || len(rr.completed) != 1 {
		t.Fatalf("completions=%d len(completed)=%d, want 1/1", rr.completions, len(rr.completed))
	}
	assertToolMatches(t, "anthropic empty", rr.completed[0], wantTool{
		provider: "anthropic",
		name:     "get_current_time",
		id:       "toolu_empty_0",
		rawArgs:  `{}`,
		args:     map[string]interface{}{},
	})
}

// --- Line-ending framing robustness (inline bytes; immune to git
// autocrlf normalization of the fixture files) --------------------------------

// TestSSERealism_OpenAI_LineEndingRobustness feeds the SAME tool_call as
// both LF- and CRLF-framed SSE and asserts identical assembly. Real
// provider streams are LF; some proxies/CDNs rewrite to CRLF.
func TestSSERealism_OpenAI_LineEndingRobustness(t *testing.T) {
	for _, tc := range []struct {
		name string
		eol  string
	}{
		{"lf", "\n"},
		{"crlf", "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eol := tc.eol
			start := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_eol","type":"function","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}` + eol + eol)
			arg1 := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\":\"l"}}]},"finish_reason":null}]}` + eol + eol)
			arg2 := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"s -la\"}"}}]},"finish_reason":"tool_calls"}]}` + eol + eol)

			acc := NewOpenAIToolCallAccumulator(0)
			var completed []ToolCallCheck
			for i, ev := range [][]byte{start, arg1, arg2} {
				res, err := acc.FeedEvent(ev)
				if err != nil {
					t.Fatalf("event %d: %v", i, err)
				}
				if res.Completed {
					completed = res.CompletedToolCalls
				}
			}
			if len(completed) != 1 {
				t.Fatalf("len(completed) = %d, want 1", len(completed))
			}
			assertToolMatches(t, "openai "+tc.name, completed[0], wantTool{
				provider: "openai",
				name:     "bash",
				id:       "call_eol",
				rawArgs:  `{"cmd":"ls -la"}`,
				args:     map[string]interface{}{"cmd": "ls -la"},
			})
		})
	}
}

// TestSSERealism_Anthropic_LineEndingRobustness mirrors the above for the
// Anthropic two-line event shape (`event:` + `data:`).
func TestSSERealism_Anthropic_LineEndingRobustness(t *testing.T) {
	for _, tc := range []struct {
		name string
		eol  string
	}{
		{"lf", "\n"},
		{"crlf", "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eol := tc.eol
			start := []byte("event: content_block_start" + eol + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_eol","name":"bash","input":{}}}` + eol + eol)
			d1 := []byte("event: content_block_delta" + eol + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"l"}}` + eol + eol)
			d2 := []byte("event: content_block_delta" + eol + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"s -la\"}"}}` + eol + eol)
			stop := []byte("event: content_block_stop" + eol + `data: {"type":"content_block_stop","index":0}` + eol + eol)

			acc := NewAnthropicAccumulator(0)
			var completed []ToolCallCheck
			for i, ev := range [][]byte{start, d1, d2, stop} {
				res, err := acc.FeedEvent(ev)
				if err != nil {
					t.Fatalf("event %d: %v", i, err)
				}
				if res.Completed {
					completed = res.CompletedToolCalls
				}
			}
			if len(completed) != 1 {
				t.Fatalf("len(completed) = %d, want 1", len(completed))
			}
			assertToolMatches(t, "anthropic "+tc.name, completed[0], wantTool{
				provider: "anthropic",
				name:     "bash",
				id:       "toolu_eol",
				rawArgs:  `{"cmd":"ls -la"}`,
				args:     map[string]interface{}{"cmd": "ls -la"},
			})
		})
	}
}
