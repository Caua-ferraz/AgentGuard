package llmproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFixtureEvents reads an SSE fixture file and returns one byte
// slice per complete event (each entry ends with the blank-line
// terminator "\n"). Mirrors how the streaming orchestrator chunks the
// stream so parser tests exercise the same input shape as production.
func readFixtureEvents(t *testing.T, name string) [][]byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	defer f.Close()
	br := bufio.NewReader(f)

	var events [][]byte
	for {
		ev, err := readSSEEvent(br, 0)
		if len(ev) > 0 {
			cp := make([]byte, len(ev))
			copy(cp, ev)
			events = append(events, cp)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return events
		}
		t.Fatalf("read fixture event: %v", err)
	}
}

// stripCommentEvents drops SSE events that are pure ":..." comment
// lines (used to embed provenance metadata in fixtures).
func stripCommentEvents(events [][]byte) [][]byte {
	out := make([][]byte, 0, len(events))
	for _, ev := range events {
		if isCommentOnlyEvent(ev) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func isCommentOnlyEvent(ev []byte) bool {
	for _, line := range bytes.Split(ev, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if !bytes.HasPrefix(line, []byte(":")) {
			return false
		}
	}
	return true
}

// TestOpenAIParser_NoToolCallsPassThrough — pure-content stream:
// every non-comment event is PassThrough.
func TestOpenAIParser_NoToolCallsPassThrough(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "openai_streaming_text_only.txt"))
	if len(events) == 0 {
		t.Fatalf("fixture produced 0 events after comment-strip")
	}
	acc := NewOpenAIToolCallAccumulator(0)
	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("event %d: unexpected err: %v", i, err)
		}
		if !res.PassThrough {
			t.Errorf("event %d: want PassThrough, got %+v\nev=%q", i, res, ev)
		}
	}
}

// TestOpenAIParser_SingleToolCallAccumulates — captured fixture with
// one tool_call; assert exactly one CompletedToolCalls with the right
// name and parsed arguments.
func TestOpenAIParser_SingleToolCallAccumulates(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "openai_streaming_single_tool_call.txt"))
	acc := NewOpenAIToolCallAccumulator(0)

	var completed []ToolCallCheck
	for i, ev := range events {
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
	if completed[0].ToolName != "bash" {
		t.Errorf("name = %q, want bash", completed[0].ToolName)
	}
	if completed[0].ToolCallID != "call_abc123" {
		t.Errorf("id = %q, want call_abc123", completed[0].ToolCallID)
	}
	if cmd, _ := completed[0].Arguments["cmd"].(string); cmd != "ls -la" {
		t.Errorf("args.cmd = %v, want ls -la", completed[0].Arguments["cmd"])
	}
	// Buffered events should include the role-set event at the start
	// (which arrived BEFORE the first tool_call delta) — wait, it
	// doesn't: the role event is content-only and passes through. Only
	// from the first tool_call delta do events buffer.
	if len(acc.BufferedEvents()) == 0 {
		t.Errorf("BufferedEvents = 0, want > 0 (tool_call deltas + finish_reason)")
	}
}

// TestOpenAIParser_MultipleToolCallsByIndex — multi-tool response;
// both indices accumulate independently and surface in completed
// order.
func TestOpenAIParser_MultipleToolCallsByIndex(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "openai_streaming_multi_tool_call.txt"))
	acc := NewOpenAIToolCallAccumulator(0)

	var completed []ToolCallCheck
	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if res.Completed {
			completed = res.CompletedToolCalls
		}
	}
	if len(completed) != 2 {
		t.Fatalf("len(completed) = %d, want 2", len(completed))
	}
	if completed[0].ToolName != "read_file" {
		t.Errorf("[0].name = %q, want read_file", completed[0].ToolName)
	}
	if completed[1].ToolName != "bash" {
		t.Errorf("[1].name = %q, want bash", completed[1].ToolName)
	}
	if path, _ := completed[0].Arguments["path"].(string); path != "/tmp/x" {
		t.Errorf("[0].args.path = %v, want /tmp/x", completed[0].Arguments["path"])
	}
	if cmd, _ := completed[1].Arguments["cmd"].(string); cmd != "ls" {
		t.Errorf("[1].args.cmd = %v, want ls", completed[1].Arguments["cmd"])
	}
}

// TestOpenAIParser_BufferOverflow — feed huge arguments; assert
// OverflowBufferBytes fires at the right cumulative size.
func TestOpenAIParser_BufferOverflow(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(256)

	startEvent := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_x","type":"function","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}` + "\n\n")
	if res, err := acc.FeedEvent(startEvent); err != nil || !res.Accumulating {
		t.Fatalf("start event: res=%+v err=%v", res, err)
	}

	// Compose a single delta whose arguments fragment alone exceeds the cap.
	huge := strings.Repeat("a", 1024)
	overflowEvent := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"` + huge + `"}}]},"finish_reason":null}]}` + "\n\n")
	res, err := acc.FeedEvent(overflowEvent)
	if err != nil {
		t.Fatalf("overflow event: %v", err)
	}
	if !res.OverflowBufferBytes {
		t.Errorf("expected OverflowBufferBytes, got %+v", res)
	}
}

// TestOpenAIParser_MalformedDelta — feed garbage; assert error
// returned and parser doesn't panic.
func TestOpenAIParser_MalformedDelta(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)
	bad := []byte("data: {\"choices\":[{not valid json}]}\n\n")
	res, err := acc.FeedEvent(bad)
	if err == nil {
		t.Errorf("expected error on malformed delta, got nil; res=%+v", res)
	}
}

// TestOpenAIParser_ContentBeforeToolCall — content deltas pass
// through immediately, then tool_call deltas buffer.
func TestOpenAIParser_ContentBeforeToolCall(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "openai_streaming_mixed_text_and_tool.txt"))
	acc := NewOpenAIToolCallAccumulator(0)

	passThroughCount := 0
	accumulatingCount := 0
	completedCount := 0
	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		switch {
		case res.PassThrough:
			passThroughCount++
		case res.Accumulating:
			accumulatingCount++
		case res.Completed:
			completedCount++
		}
	}
	// Two text deltas + final [DONE] = 3 pass-through (note: [DONE]
	// after a tool_call buffer flush is technically passthrough only
	// when not active; the orchestrator flushes the buffer on
	// Completed and resets, so [DONE] then passes through).
	// Two tool_call deltas (first carries the name, second carries
	// finish_reason) = 1 accumulating + 1 completed.
	if passThroughCount < 2 {
		t.Errorf("PassThrough count = %d, want >= 2", passThroughCount)
	}
	if accumulatingCount < 1 {
		t.Errorf("Accumulating count = %d, want >= 1", accumulatingCount)
	}
	if completedCount != 1 {
		t.Errorf("Completed count = %d, want 1", completedCount)
	}
}

// TestOpenAIParser_DoneTerminatorWhileIdle — [DONE] outside any
// tool_call cycle passes through.
func TestOpenAIParser_DoneTerminatorWhileIdle(t *testing.T) {
	acc := NewOpenAIToolCallAccumulator(0)
	res, err := acc.FeedEvent([]byte("data: [DONE]\n\n"))
	if err != nil {
		t.Fatalf("[DONE]: %v", err)
	}
	if !res.PassThrough {
		t.Errorf("expected PassThrough for [DONE], got %+v", res)
	}
}

// TestOpenAIParser_ExtractDataLine_SpaceTolerant — both `data: <json>`
// and `data:<json>` (no space) shapes are recognised.
func TestOpenAIParser_ExtractDataLine_SpaceTolerant(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"with-space", "data: {\"a\":1}\n\n", `{"a":1}`},
		{"no-space", "data:{\"a\":1}\n\n", `{"a":1}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line, _, ok := extractOpenAIDataLine([]byte(c.raw))
			if !ok {
				t.Fatalf("extractOpenAIDataLine: ok=false")
			}
			if string(line) != c.want {
				t.Errorf("got %q, want %q", string(line), c.want)
			}
		})
	}
}
