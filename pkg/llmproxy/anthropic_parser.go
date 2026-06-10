package llmproxy

// anthropic_parser.go owns the Anthropic Messages streaming-event
// parser and tool_use accumulator. Anthropic's streaming format
// differs from OpenAI's in three structural ways the parser must
// handle:
//
//   1. Two-line events: each event is `event: <name>\n data: <json>\n\n`.
//      The `event:` line is informational; the type discriminator is
//      also inside the JSON payload (`type: "content_block_delta"`),
//      so the parser drives off the JSON to be tolerant of the
//      `event:` line being missing.
//   2. Block-indexed content: the response body is a heterogeneous
//      `content` array; tool_use lives at `content[i]` for some i.
//      The streaming wire reflects this with `index: i` on every
//      `content_block_*` event.
//   3. JSON-fragment input: tool_use input arrives as a stream of
//      `input_json_delta.partial_json` strings. We concatenate them
//      verbatim and json.Unmarshal at content_block_stop (the close
//      boundary).
//
// The orchestrator buffers raw event bytes from the moment a tool_use
// content_block_start arrives until content_block_stop closes that
// block. On ALLOW we replay the buffered bytes byte-identical; on
// DENY we discard them and emit a synthetic refusal text-block at
// the buffered tool_use's index.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// anthropicEventEnvelope is the parsed shape of one event's `data:`
// payload. Only fields the parser needs are typed.
type anthropicEventEnvelope struct {
	Type         string                       `json:"type"`
	Index        int                          `json:"index,omitempty"`
	ContentBlock *anthropicContentBlockShape  `json:"content_block,omitempty"`
	Delta        *anthropicEventDeltaShape    `json:"delta,omitempty"`
}

// anthropicContentBlockShape is the start-of-block descriptor
// (content_block_start). For tool_use it carries id+name; for text
// it carries an initial empty `text`.
type anthropicContentBlockShape struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	Text  string          `json:"text,omitempty"`
}

// anthropicEventDeltaShape carries the per-delta payload. Two
// discriminated forms in practice:
//   - text_delta: text fragment for a text content block
//   - input_json_delta: partial JSON fragment for a tool_use input
//
// message_delta also lands here when stop_reason rewrites are needed
// in a synthetic refusal — the parser only reads the two block-delta
// forms; message_delta passes through.
type anthropicEventDeltaShape struct {
	Type        string `json:"type,omitempty"`
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
	StopReason  string `json:"stop_reason,omitempty"`
}

// anthropicBlockState tracks one in-flight content block. Only
// tool_use blocks gate; text blocks pass through immediately.
type anthropicBlockState struct {
	Index     int
	Type      string // "text" | "tool_use"
	ID        string
	Name      string
	InputJSON bytes.Buffer
	Closed    bool
	// startSeeded is true when the tool_use's arguments were seeded from a
	// non-empty content_block_start.input (audit H2). A conformant Anthropic
	// stream never does this (start input is always `{}` and the real
	// arguments stream via input_json_delta), so if startSeeded is true AND
	// an input_json_delta later arrives for the same block the two argument
	// sources conflict — the parser fails closed in that case.
	startSeeded bool
}

// AnthropicAccumulator stitches Anthropic streaming events into
// gating-ready ToolCallCheck records and holds the raw SSE bytes for
// byte-identical ALLOW-path replay. Mirrors OpenAIToolCallAccumulator's
// contract; the orchestrator branches on FeedResult identically.
//
// Note Anthropic's stream is not strictly serial: in principle there
// can be a text content block at index 0, a tool_use at index 1,
// another text at index 2, and they may interleave during streaming.
// We buffer ALL events from the first tool_use content_block_start
// onward — even text deltas to other indices — until the tool_use's
// content_block_stop closes it. Reasoning: emitting text deltas while
// holding back a tool_use would deliver an out-of-order stream that
// some clients don't tolerate. (In practice Anthropic emits content
// blocks serially: each block fully closes before the next begins.)
type AnthropicAccumulator struct {
	maxBufferBytes int

	blocks map[int]*anthropicBlockState

	// activeToolUseIndex is the content-block index of the in-flight
	// tool_use we're buffering for, or -1 if none.
	activeToolUseIndex int

	bufferedEvents [][]byte
	bufferedBytes  int
}

// NewAnthropicAccumulator constructs a fresh accumulator with the
// given per-stream buffer cap. maxBufferBytes <= 0 means "no cap".
func NewAnthropicAccumulator(maxBufferBytes int) *AnthropicAccumulator {
	return &AnthropicAccumulator{
		maxBufferBytes:     maxBufferBytes,
		blocks:             map[int]*anthropicBlockState{},
		activeToolUseIndex: -1,
	}
}

// BufferedEvents returns raw event byte slices held back since the
// active tool_use's start. Caller treats them as read-only.
func (a *AnthropicAccumulator) BufferedEvents() [][]byte {
	return a.bufferedEvents
}

// ActiveToolUseIndex returns the content-block index of the
// currently-buffering tool_use, or -1 if none. The orchestrator uses
// this to populate RefusalContext.AnthropicToolUseIndex so a refusal
// rewrites the right block.
func (a *AnthropicAccumulator) ActiveToolUseIndex() int {
	return a.activeToolUseIndex
}

// Reset clears accumulator state. Called after a successful flush so
// subsequent tool_use blocks in the same message get a fresh state.
func (a *AnthropicAccumulator) Reset() {
	a.blocks = map[int]*anthropicBlockState{}
	a.activeToolUseIndex = -1
	a.bufferedEvents = nil
	a.bufferedBytes = 0
}

// FeedEvent ingests one complete Anthropic SSE event. Returns
// FeedResult per the same contract as OpenAIToolCallAccumulator.
//
// Errors are returned for malformed JSON in the data line; the
// orchestrator's policy is log + drop without injecting bytes.
func (a *AnthropicAccumulator) FeedEvent(rawEvent []byte) (FeedResult, error) {
	dataLine, hasData := extractAnthropicDataLine(rawEvent)
	if !hasData {
		// `event:` line only, comment, or empty — keep buffering if
		// active, else pass through.
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}

	var env anthropicEventEnvelope
	if err := json.Unmarshal(dataLine, &env); err != nil {
		return FeedResult{}, fmt.Errorf("anthropic parser: malformed event JSON: %w", err)
	}

	switch env.Type {
	case "content_block_start":
		// New block. If it's a tool_use, this is the START signal —
		// begin buffering. If it's a text block (and we're idle),
		// pass through. If it's a text block while a tool_use is
		// already buffering, keep buffering (preserve order).
		if env.ContentBlock != nil && env.ContentBlock.Type == "tool_use" {
			// SECURITY (audit H1): a second tool_use content block must
			// never open while one is still buffering. Anthropic emits
			// content blocks serially — each block's content_block_stop
			// (which gates it and Resets the accumulator) lands before the
			// next block's start. An interleaved second tool_use would be
			// buffered here, flushed to the client when the FIRST block's
			// gate cycle Resets us, and then its remaining deltas/stop would
			// pass through UNGATED. We cannot gate two blocks in one cycle,
			// so we fail closed: signal a protocol violation and let the
			// orchestrator refuse the whole stream.
			if a.activeToolUseIndex >= 0 {
				return FeedResult{ProtocolViolation: true}, nil
			}
			st := &anthropicBlockState{
				Index: env.Index,
				Type:  "tool_use",
				ID:    env.ContentBlock.ID,
				Name:  env.ContentBlock.Name,
			}
			// Seed arguments from content_block.input when present
			// (audit H2): a conformant Anthropic stream sends `input:{}` at
			// start and streams the real arguments via input_json_delta, but
			// a non-conformant/adversarial upstream can put the real
			// arguments in the start event and emit no delta. If we ignored
			// `input` here the gate would evaluate an empty `{}` while the
			// client SDK, which seeds tool input from the start block,
			// executes the real arguments. Seed the buffer so the gate sees
			// what the client will.
			if seed := bytes.TrimSpace(env.ContentBlock.Input); len(seed) > 0 && !bytes.Equal(seed, []byte("{}")) {
				st.InputJSON.Write(seed)
				st.startSeeded = true
			}
			a.blocks[env.Index] = st
			if a.activeToolUseIndex < 0 {
				a.activeToolUseIndex = env.Index
			}
			return a.appendBuffered(rawEvent)
		}
		// Non-tool_use block-start.
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		// Track text block for completeness (not strictly required
		// for gating — we don't surface text blocks to PolicyCheck).
		if env.ContentBlock != nil {
			a.blocks[env.Index] = &anthropicBlockState{
				Index: env.Index,
				Type:  env.ContentBlock.Type,
			}
		}
		return FeedResult{PassThrough: true}, nil

	case "content_block_delta":
		// While a tool_use block is buffering, ALL block deltas (even
		// for other indices) join the buffer to preserve order.
		if a.activeToolUseIndex >= 0 {
			// If this delta is for the active tool_use index, ALSO
			// accumulate the partial_json fragment so we can parse it
			// at content_block_stop.
			if env.Index == a.activeToolUseIndex && env.Delta != nil &&
				env.Delta.Type == "input_json_delta" && env.Delta.PartialJSON != "" {
				st := a.blocks[env.Index]
				if st == nil {
					// Should never happen — content_block_start must
					// precede content_block_delta — but defensive.
					st = &anthropicBlockState{Index: env.Index, Type: "tool_use"}
					a.blocks[env.Index] = st
				}
				// SECURITY (audit H2): arguments seeded from a non-empty
				// content_block_start.input must not also be streamed via
				// input_json_delta — the two sources would concatenate into
				// invalid JSON and the gate could end up evaluating a
				// truncated/empty view. A conformant stream never does both;
				// fail closed.
				if st.startSeeded {
					return FeedResult{ProtocolViolation: true}, nil
				}
				projected := totalAnthropicArgsLen(a.blocks) + len(env.Delta.PartialJSON)
				if a.maxBufferBytes > 0 && projected > a.maxBufferBytes {
					return FeedResult{OverflowBufferBytes: true}, nil
				}
				st.InputJSON.WriteString(env.Delta.PartialJSON)
			}
			return a.appendBuffered(rawEvent)
		}
		// Idle: text deltas (and unexpected input_json_deltas)
		// pass through. We don't gate text blocks.
		return FeedResult{PassThrough: true}, nil

	case "content_block_stop":
		if a.activeToolUseIndex >= 0 {
			res, err := a.appendBuffered(rawEvent)
			if err != nil {
				return res, err
			}
			// Only the active tool_use's content_block_stop closes
			// the gating cycle. Other block-stops (interleaved text
			// blocks closing while tool_use buffers) just keep the
			// buffer growing.
			if env.Index == a.activeToolUseIndex {
				st := a.blocks[env.Index]
				if st != nil {
					st.Closed = true
				}
				calls, parseErr := a.assembleCompletedCalls()
				return FeedResult{
					Completed:          true,
					CompletedToolCalls: calls,
				}, parseErr
			}
			return res, nil
		}
		// Idle text-block close: pass through.
		return FeedResult{PassThrough: true}, nil

	case "message_start", "message_delta", "message_stop", "ping":
		// Message-level events. Always pass through when idle; buffer
		// when active so they don't leak ahead of the tool_use cycle.
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil

	default:
		// Unknown event type. Same buffer-or-passthrough rule.
		if a.activeToolUseIndex >= 0 {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}
}

// appendBuffered records rawEvent in bufferedEvents enforcing the cap.
func (a *AnthropicAccumulator) appendBuffered(rawEvent []byte) (FeedResult, error) {
	if a.maxBufferBytes > 0 && a.bufferedBytes+len(rawEvent) > a.maxBufferBytes {
		return FeedResult{OverflowBufferBytes: true}, nil
	}
	copied := make([]byte, len(rawEvent))
	copy(copied, rawEvent)
	a.bufferedEvents = append(a.bufferedEvents, copied)
	a.bufferedBytes += len(copied)
	return FeedResult{Accumulating: true}, nil
}

// assembleCompletedCalls converts the closed tool_use blocks into
// ToolCallCheck records. Only the active block is gated this cycle;
// any non-active tool_use blocks (rare in practice — Anthropic emits
// blocks serially) remain in `blocks` for a future cycle.
func (a *AnthropicAccumulator) assembleCompletedCalls() ([]ToolCallCheck, error) {
	st, ok := a.blocks[a.activeToolUseIndex]
	if !ok || st.Type != "tool_use" {
		return nil, nil
	}
	args := bytes.TrimSpace(st.InputJSON.Bytes())
	if len(args) == 0 {
		// Some tool calls have no arguments. Use "{}" so RawArguments
		// is parseable downstream.
		args = []byte("{}")
	}
	var parsed map[string]interface{}
	var firstErr error
	if err := json.Unmarshal(args, &parsed); err != nil {
		firstErr = fmt.Errorf("anthropic parser: tool_use[%d] input is not valid JSON: %w", st.Index, err)
		parsed = nil
	}
	tc := ToolCallCheck{
		Provider:     "anthropic",
		ToolName:     st.Name,
		ToolCallID:   st.ID,
		Arguments:    parsed,
		RawArguments: json.RawMessage(args),
	}
	return []ToolCallCheck{tc}, firstErr
}

// totalAnthropicArgsLen sums InputJSON bytes across all tool_use
// blocks tracked so far. Used for the overflow precheck.
func totalAnthropicArgsLen(blocks map[int]*anthropicBlockState) int {
	n := 0
	for _, st := range blocks {
		if st.Type == "tool_use" {
			n += st.InputJSON.Len()
		}
	}
	return n
}

// extractAnthropicDataLine returns the JSON payload of an event's
// `data:` line(s). Anthropic always sends single-line `data:` events,
// but the SSE spec allows multi-line `data:` (joined by '\n'); we
// support both.
//
// The `event:` line is informational only — we discriminate on the
// JSON `type` field — so we don't return it.
func extractAnthropicDataLine(rawEvent []byte) (dataLine []byte, hasData bool) {
	const dataPrefix = "data: "
	const dataPrefixShort = "data:"
	var buf bytes.Buffer
	for _, line := range bytes.Split(rawEvent, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var payload []byte
		switch {
		case bytes.HasPrefix(line, []byte(dataPrefix)):
			payload = line[len(dataPrefix):]
		case bytes.HasPrefix(line, []byte(dataPrefixShort)):
			payload = line[len(dataPrefixShort):]
		default:
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(payload)
		hasData = true
	}
	if !hasData {
		return nil, false
	}
	return buf.Bytes(), true
}
