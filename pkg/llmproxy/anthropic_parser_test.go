package llmproxy

import (
	"strings"
	"testing"
)

// TestAnthropicParser_TextOnlyPassThrough — pure text-block stream:
// every non-comment event is PassThrough.
func TestAnthropicParser_TextOnlyPassThrough(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "anthropic_streaming_text_only.txt"))
	if len(events) == 0 {
		t.Fatalf("fixture produced 0 events")
	}
	acc := NewAnthropicAccumulator(0)
	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if !res.PassThrough {
			t.Errorf("event %d: want PassThrough, got %+v", i, res)
		}
	}
}

// TestAnthropicParser_SingleToolUseAccumulates — captured fixture
// with one tool_use; assert exactly one CompletedToolCalls with the
// right name and parsed arguments.
func TestAnthropicParser_SingleToolUseAccumulates(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "anthropic_streaming_single_tool_use.txt"))
	acc := NewAnthropicAccumulator(0)

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
	if completed[0].ToolCallID != "toolu_xyz" {
		t.Errorf("id = %q, want toolu_xyz", completed[0].ToolCallID)
	}
	if cmd, _ := completed[0].Arguments["cmd"].(string); cmd != "ls -la" {
		t.Errorf("args.cmd = %v, want ls -la", completed[0].Arguments["cmd"])
	}
	if completed[0].Provider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", completed[0].Provider)
	}
}

// TestAnthropicParser_MixedTextAndToolUse — text block at index 0
// passes through; then tool_use at index 1 buffers and gates.
func TestAnthropicParser_MixedTextAndToolUse(t *testing.T) {
	events := stripCommentEvents(readFixtureEvents(t, "anthropic_streaming_text_then_tool.txt"))
	acc := NewAnthropicAccumulator(0)

	passThroughBeforeTool := 0
	startedBuffering := false
	completed := 0

	for i, ev := range events {
		res, err := acc.FeedEvent(ev)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		switch {
		case res.PassThrough && !startedBuffering:
			passThroughBeforeTool++
		case res.Accumulating:
			startedBuffering = true
		case res.Completed:
			completed++
		}
	}
	if passThroughBeforeTool < 4 {
		// message_start, content_block_start (text), content_block_delta,
		// content_block_stop = 4 events before the tool_use buffer begins.
		t.Errorf("PassThrough-before-tool = %d, want >= 4", passThroughBeforeTool)
	}
	if completed != 1 {
		t.Errorf("Completed count = %d, want 1", completed)
	}
}

// TestAnthropicParser_BufferOverflow — feed huge partial_json
// fragments; assert OverflowBufferBytes fires.
func TestAnthropicParser_BufferOverflow(t *testing.T) {
	acc := NewAnthropicAccumulator(256)

	startEvent := []byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_x\",\"name\":\"bash\",\"input\":{}}}\n\n")
	if res, err := acc.FeedEvent(startEvent); err != nil || !res.Accumulating {
		t.Fatalf("start event: res=%+v err=%v", res, err)
	}

	huge := strings.Repeat("a", 1024)
	overflowEvent := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"" + huge + "\"}}\n\n")
	res, err := acc.FeedEvent(overflowEvent)
	if err != nil {
		t.Fatalf("overflow event: %v", err)
	}
	if !res.OverflowBufferBytes {
		t.Errorf("expected OverflowBufferBytes, got %+v", res)
	}
}

// TestAnthropicParser_PartialEventLine — feed the same fixture but
// re-segmented so a single event's two lines arrive in separate
// FeedEvent calls. Anthropic events are normally read as one unit by
// readSSEEvent; this tests defensive behavior when the orchestrator's
// reader hands us a partial.
func TestAnthropicParser_PartialEventLine(t *testing.T) {
	// Construct a "broken" event: only the `event:` line, no `data:`.
	// The parser should treat it as no-data and pass through (since
	// we're idle).
	acc := NewAnthropicAccumulator(0)
	res, err := acc.FeedEvent([]byte("event: ping\n\n"))
	if err != nil {
		t.Fatalf("partial event: %v", err)
	}
	if !res.PassThrough {
		t.Errorf("partial event with no data line should pass through, got %+v", res)
	}
}

// TestAnthropicParser_MalformedJSON — bad data line; expect error
// without panic.
func TestAnthropicParser_MalformedJSON(t *testing.T) {
	acc := NewAnthropicAccumulator(0)
	bad := []byte("event: content_block_delta\ndata: {not valid}\n\n")
	res, err := acc.FeedEvent(bad)
	if err == nil {
		t.Errorf("expected error on malformed JSON, got nil; res=%+v", res)
	}
}

// TestAnthropicParser_MissingEventLineToleratedViaJSONType — Anthropic
// protocol allows event events without `event:` because the JSON
// payload also carries the discriminator. Confirm we read the type
// from JSON.
func TestAnthropicParser_MissingEventLineToleratedViaJSONType(t *testing.T) {
	acc := NewAnthropicAccumulator(0)
	// content_block_start arrives without the `event:` line.
	startEvent := []byte("data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_y\",\"name\":\"bash\",\"input\":{}}}\n\n")
	res, err := acc.FeedEvent(startEvent)
	if err != nil {
		t.Fatalf("start event: %v", err)
	}
	if !res.Accumulating {
		t.Errorf("want Accumulating (tool_use start), got %+v", res)
	}
	if acc.ActiveToolUseIndex() != 0 {
		t.Errorf("active index = %d, want 0", acc.ActiveToolUseIndex())
	}
}

// TestAnthropicParser_ActiveToolUseIndex — index is correctly tracked
// for synthesizing refusal context.
func TestAnthropicParser_ActiveToolUseIndex(t *testing.T) {
	acc := NewAnthropicAccumulator(0)
	if got := acc.ActiveToolUseIndex(); got != -1 {
		t.Errorf("idle: ActiveToolUseIndex = %d, want -1", got)
	}
	startEvent := []byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":3,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_z\",\"name\":\"bash\",\"input\":{}}}\n\n")
	if _, err := acc.FeedEvent(startEvent); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := acc.ActiveToolUseIndex(); got != 3 {
		t.Errorf("after tool_use start at index 3, ActiveToolUseIndex = %d, want 3", got)
	}
}
