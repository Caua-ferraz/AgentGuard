package llmproxy

// openai_parser.go owns the OpenAI Chat Completions streaming-delta
// parser and tool_call accumulator. The parser is fed one SSE event
// at a time by the streaming orchestrator (streaming.go) and decides:
//
//   1. Pass-through: this event is a normal content delta and can be
//      forwarded to the client byte-identical to upstream right now.
//   2. Accumulating: this event participates in an in-flight tool_call;
//      buffer it (the orchestrator holds the raw bytes for ALLOW-path
//      replay) and do not flush.
//   3. Completed: tool_calls finished assembling (signalled by
//      finish_reason: "tool_calls"). The orchestrator gates each
//      completed call through PolicyCheck.
//   4. OverflowBufferBytes: cumulative buffered bytes exceeded the
//      configured cap (--max-buffer-bytes). The orchestrator emits a
//      synthetic refusal and stops reading upstream.
//
// Per docs/LLM_API_PROXY.md § 5.1 the wire format is `data: <json>\n\n`
// SSE events with a `data: [DONE]` sentinel. Tool_calls arrive across
// multiple deltas keyed by `tool_calls[i].index` (NOT by id; ids may
// be omitted on later fragments). `arguments` is a string of partial
// JSON that we concatenate verbatim and parse only at gating time.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// openAIDeltaEnvelope is the minimal shape of an OpenAI streaming
// chunk's `data:` JSON payload. Only fields we need are typed; unknown
// fields round-trip via the raw event bytes (which the orchestrator
// holds for byte-identical ALLOW-path replay).
type openAIDeltaEnvelope struct {
	Choices []openAIDeltaChoice `json:"choices"`
}

type openAIDeltaChoice struct {
	Index        int                  `json:"index"`
	Delta        openAIDeltaMessage   `json:"delta"`
	FinishReason string               `json:"finish_reason,omitempty"`
}

type openAIDeltaMessage struct {
	Role      string                  `json:"role,omitempty"`
	Content   string                  `json:"content,omitempty"`
	ToolCalls []openAIToolCallDelta   `json:"tool_calls,omitempty"`
}

type openAIToolCallDelta struct {
	Index    int                       `json:"index"`
	ID       string                    `json:"id,omitempty"`
	Type     string                    `json:"type,omitempty"`
	Function *openAIToolCallFuncDelta  `json:"function,omitempty"`
}

type openAIToolCallFuncDelta struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// openAIToolCallState aggregates fragments for one tool_call (keyed by
// its `tool_calls[i].index`). The Arguments builder accumulates the
// partial-JSON string fragments verbatim.
type openAIToolCallState struct {
	Index        int
	ID           string
	Name         string
	Arguments    strings.Builder
	HasFunction  bool // we observed at least one function delta
}

// FeedResult is what FeedEvent returns to the streaming orchestrator.
// Exactly one of {PassThrough, Accumulating, Completed,
// OverflowBufferBytes} should be true; the orchestrator branches on it.
type FeedResult struct {
	// PassThrough: forward the raw event bytes to the client now,
	// byte-identical. (No tool_call in flight; or this is a [DONE]
	// terminator after the whole stream completes without tool_calls.)
	PassThrough bool

	// Accumulating: buffer the raw event bytes; do NOT flush to client
	// yet. A tool_call is in flight.
	Accumulating bool

	// Completed: a tool_call finish boundary was observed. The
	// orchestrator should now gate each tool call in CompletedToolCalls
	// through PolicyCheck. On ALLOW it flushes the buffered events
	// (BufferedEvents()); on DENY it discards them and emits a
	// synthetic refusal.
	Completed bool

	// CompletedToolCalls is the list of fully-assembled tool calls,
	// in tool_calls[i].index order. Populated only when Completed=true.
	CompletedToolCalls []ToolCallCheck

	// OverflowBufferBytes signals that the cumulative buffered byte
	// count exceeded the cap. The orchestrator emits the canonical
	// "tool call arguments exceed gating buffer" refusal.
	OverflowBufferBytes bool
}

// OpenAIToolCallAccumulator stitches streaming tool_call fragments
// back into complete ToolCallCheck records and holds the raw SSE
// event bytes for byte-identical ALLOW-path replay.
//
// One accumulator per stream — never share between requests. The
// streaming orchestrator constructs a fresh one in each request
// goroutine (per-request goroutine isolation is the Phase 4A rule).
type OpenAIToolCallAccumulator struct {
	maxBufferBytes int

	// byIndex tracks pending tool_call state keyed by
	// tool_calls[i].index. We use a map (not a slice) because indices
	// are not guaranteed to be densely 0..N — though in practice they
	// are; the map handles the spec-allowed case cleanly.
	byIndex map[int]*openAIToolCallState

	// bufferedEvents holds raw SSE event bytes (each entry is one
	// complete event including the trailing blank line) collected
	// since the FIRST tool_call delta arrived. On ALLOW the
	// orchestrator flushes them in order; on DENY it discards them.
	bufferedEvents [][]byte
	bufferedBytes  int

	// active is true once we've started accumulating a tool_call and
	// haven't yet flushed/refused.
	active bool
}

// NewOpenAIToolCallAccumulator constructs a fresh accumulator with
// the given per-stream buffer cap. maxBufferBytes <= 0 means "no cap"
// (used in unit tests; production wires --max-buffer-bytes from
// Config).
func NewOpenAIToolCallAccumulator(maxBufferBytes int) *OpenAIToolCallAccumulator {
	return &OpenAIToolCallAccumulator{
		maxBufferBytes: maxBufferBytes,
		byIndex:        map[int]*openAIToolCallState{},
	}
}

// BufferedEvents returns the raw SSE event byte slices held back
// since the first tool_call delta. Caller MUST treat the returned
// slices as read-only; the accumulator retains them until Reset().
func (a *OpenAIToolCallAccumulator) BufferedEvents() [][]byte {
	return a.bufferedEvents
}

// Reset clears accumulator state for a new gating cycle. Called by
// the orchestrator after a successful flush so subsequent tool_calls
// in the same stream get a fresh accumulator.
func (a *OpenAIToolCallAccumulator) Reset() {
	a.byIndex = map[int]*openAIToolCallState{}
	a.bufferedEvents = nil
	a.bufferedBytes = 0
	a.active = false
}

// FeedEvent ingests one complete SSE event (raw bytes including the
// final blank-line terminator). Returns a FeedResult describing what
// the orchestrator should do with the event.
//
// Errors are returned for malformed JSON in the data line; the
// orchestrator's policy is to log + drop (do NOT inject our own bytes
// into the byte-identity stream) and continue.
func (a *OpenAIToolCallAccumulator) FeedEvent(rawEvent []byte) (FeedResult, error) {
	dataLine, isDone, hasData := extractOpenAIDataLine(rawEvent)
	if !hasData {
		// Comment, retry, event-name, or empty line — treat as
		// metadata. If we're in the middle of buffering a tool_call
		// we keep buffering (no client-visible effect); else
		// pass-through verbatim.
		if a.active {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}

	// `data: [DONE]` terminator. Always pass through directly: even
	// if we were buffering a tool_call (which would normally close
	// via finish_reason: "tool_calls" first), [DONE] forces the
	// stream to end and we have to surface it.
	if isDone {
		// If still active (i.e. tool_calls never finished cleanly)
		// we treat this as an end-of-stream and let the orchestrator
		// flush whatever's buffered as-is. This is a degenerate
		// path — most providers always emit finish_reason first.
		if a.active {
			return a.appendBuffered(rawEvent)
		}
		return FeedResult{PassThrough: true}, nil
	}

	var env openAIDeltaEnvelope
	if err := json.Unmarshal(dataLine, &env); err != nil {
		return FeedResult{}, fmt.Errorf("openai parser: malformed delta JSON: %w", err)
	}

	// Look across all choices: tool_call deltas and finish_reason can
	// land on any choice index. In practice OpenAI sends one choice at
	// a time for a streaming response, but we don't rely on it.
	hasToolCallDelta := false
	finishReasonToolCalls := false
	for _, ch := range env.Choices {
		if len(ch.Delta.ToolCalls) > 0 {
			hasToolCallDelta = true
		}
		if ch.FinishReason == "tool_calls" {
			finishReasonToolCalls = true
		}
	}

	// State machine:
	//   1. Tool_call delta arrives → become active, accumulate, buffer.
	//   2. While active, every event is buffered.
	//   3. finish_reason: "tool_calls" closes the active cycle →
	//      Completed result with assembled tool calls.
	//   4. Pure content delta with no active cycle → pass through.

	if hasToolCallDelta {
		a.active = true
		// Accumulate fragments before deciding to buffer (cheaper to
		// abort on overflow without storing the event).
		for _, ch := range env.Choices {
			for _, tc := range ch.Delta.ToolCalls {
				st, ok := a.byIndex[tc.Index]
				if !ok {
					st = &openAIToolCallState{Index: tc.Index}
					a.byIndex[tc.Index] = st
				}
				if tc.ID != "" {
					st.ID = tc.ID
				}
				if tc.Function != nil {
					st.HasFunction = true
					if tc.Function.Name != "" {
						st.Name = tc.Function.Name
					}
					if tc.Function.Arguments != "" {
						// Length-cap check uses the cumulative
						// arguments string size — that's the input
						// to PolicyCheck and the spec's overflow
						// semantic ("tool call arguments exceed
						// gating buffer").
						projected := totalArgsLen(a.byIndex) + len(tc.Function.Arguments)
						if a.maxBufferBytes > 0 && projected > a.maxBufferBytes {
							return FeedResult{OverflowBufferBytes: true}, nil
						}
						st.Arguments.WriteString(tc.Function.Arguments)
					}
				}
			}
		}
		return a.appendBuffered(rawEvent)
	}

	if a.active {
		// Continue buffering until finish_reason terminates the cycle.
		// finish_reason: "tool_calls" is the close signal; other
		// finish_reasons (e.g. "stop") that arrive while a tool_call
		// is in-flight also force closure — we cannot leave a half-
		// assembled accumulator dangling.
		appendRes, err := a.appendBuffered(rawEvent)
		if err != nil {
			return appendRes, err
		}

		if finishReasonToolCalls || hasFinishReason(env) {
			calls, parseErr := a.assembleCompletedCalls()
			// parseErr surfaces invalid-JSON-arguments cases to the
			// caller. The caller (orchestrator) still proceeds with
			// gating using RawArguments — A24's policy hook decides
			// how to handle malformed args.
			res := FeedResult{
				Completed:          true,
				CompletedToolCalls: calls,
			}
			return res, parseErr
		}

		return appendRes, nil
	}

	// Idle (no active tool_call) and not a tool_call event: forward
	// byte-identical to client.
	return FeedResult{PassThrough: true}, nil
}

// appendBuffered records rawEvent in bufferedEvents while enforcing
// the byte cap. Returns Accumulating=true on the success path.
func (a *OpenAIToolCallAccumulator) appendBuffered(rawEvent []byte) (FeedResult, error) {
	if a.maxBufferBytes > 0 && a.bufferedBytes+len(rawEvent) > a.maxBufferBytes {
		// The sum of arguments bytes plus envelope bytes blew the cap.
		// Same overflow semantic as the args-only check.
		return FeedResult{OverflowBufferBytes: true}, nil
	}
	// Copy: rawEvent is a Bytes() slice from a bufio.Reader-like
	// source whose backing array is reused on the next read. Without
	// a copy our buffered events would silently mutate.
	copied := make([]byte, len(rawEvent))
	copy(copied, rawEvent)
	a.bufferedEvents = append(a.bufferedEvents, copied)
	a.bufferedBytes += len(copied)
	return FeedResult{Accumulating: true}, nil
}

// assembleCompletedCalls converts the accumulated by-index map into
// a sorted slice of ToolCallCheck records. Returns a non-nil error
// if any tool call's Arguments could not be JSON-parsed; the slice
// is still populated (with Arguments=nil, RawArguments preserved) so
// the orchestrator can surface raw bytes to PolicyCheck even on
// malformed input.
func (a *OpenAIToolCallAccumulator) assembleCompletedCalls() ([]ToolCallCheck, error) {
	if len(a.byIndex) == 0 {
		return nil, nil
	}
	// Stable order by tool_calls[i].index so audit entries are
	// deterministic.
	indices := make([]int, 0, len(a.byIndex))
	for i := range a.byIndex {
		indices = append(indices, i)
	}
	// Insertion sort is fine — N is at most a handful in practice.
	for i := 1; i < len(indices); i++ {
		for j := i; j > 0 && indices[j-1] > indices[j]; j-- {
			indices[j-1], indices[j] = indices[j], indices[j-1]
		}
	}

	var firstErr error
	out := make([]ToolCallCheck, 0, len(indices))
	for _, idx := range indices {
		st := a.byIndex[idx]
		args := strings.TrimSpace(st.Arguments.String())
		raw := json.RawMessage(args)
		var parsed map[string]interface{}
		if args != "" {
			if err := json.Unmarshal([]byte(args), &parsed); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("openai parser: tool_call[%d] arguments are not valid JSON: %w", idx, err)
				}
				parsed = nil
			}
		}
		out = append(out, ToolCallCheck{
			Provider:     "openai",
			ToolName:     st.Name,
			ToolCallID:   st.ID,
			Arguments:    parsed,
			RawArguments: raw,
		})
	}
	return out, firstErr
}

// hasFinishReason returns true if any choice has a non-empty
// finish_reason. Used to detect end-of-cycle when finish_reason isn't
// "tool_calls" but is still terminal (e.g. "stop") — we must close
// the buffered cycle to avoid hanging the stream.
func hasFinishReason(env openAIDeltaEnvelope) bool {
	for _, ch := range env.Choices {
		if ch.FinishReason != "" {
			return true
		}
	}
	return false
}

// totalArgsLen returns the cumulative bytes already accumulated across
// all tool_call states. Used for the overflow check before allocating.
func totalArgsLen(byIndex map[int]*openAIToolCallState) int {
	n := 0
	for _, st := range byIndex {
		n += st.Arguments.Len()
	}
	return n
}

// extractOpenAIDataLine inspects a raw SSE event (lines separated by
// '\n', terminated by a blank line) and returns:
//
//   - dataLine: the JSON payload after `data: ` (multiple `data:` lines
//     are concatenated with '\n' per the SSE spec, but OpenAI Chat
//     Completions emits exactly one).
//   - isDone: true if the data line is the literal `[DONE]` sentinel.
//   - hasData: false for events with no `data:` line at all (e.g.
//     comments starting with ':', event-name only, blank).
func extractOpenAIDataLine(rawEvent []byte) (dataLine []byte, isDone bool, hasData bool) {
	const dataPrefix = "data: "
	const dataPrefixShort = "data:" // some servers omit the space
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
		return nil, false, false
	}
	bb := buf.Bytes()
	if bytes.Equal(bytes.TrimSpace(bb), []byte("[DONE]")) {
		return bb, true, true
	}
	return bb, false, true
}

