package llmproxy

// fuzz_streaming_test.go adds Go native fuzz targets for the two SSE
// streaming tool-call accumulators (v1.0 item 2, sub-task 2b). These
// complement the testing/quick property tests in
// at_openai_property_test.go and at_anthropic_property_test.go, which
// feed structurally-valid events; the fuzzers instead pound FeedEvent
// with arbitrary bytes to prove the single robustness invariant that
// matters on the hot path:
//
//	FeedEvent must never panic and must always return (no hang) on ANY
//	input.
//
// A fresh accumulator is constructed per iteration. The fuzzed []byte
// is split on the SSE event boundary ("\n\n") so a single seed/mutation
// exercises a multi-event sequence, then each event is fed in turn. The
// seed corpus is drawn from the real fixtures under testdata/ plus a
// handful of hand-written edge cases (empty, [DONE], malformed JSON,
// bare comment/event lines).
//
// NOTE: these are TEST-ONLY additions. If a fuzzer discovers a crash in
// the parsers (hot-path production code) the crasher is left in place
// and reported for separate human review — the parsers are NOT patched
// here.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// feedTimeout bounds a single FeedEvent call. json.Unmarshal over
// arbitrary bytes is bounded (stdlib caps nesting depth), so this is a
// generous ceiling that only trips on a genuine hang.
const feedTimeout = 5 * time.Second

// maxFuzzEventBytes bounds a single event handed to FeedEvent so a
// pathological seed/mutation cannot make one iteration allocate
// unreasonable memory. Real SSE events are far smaller.
const maxFuzzEventBytes = 1 << 20 // 1 MiB

// callWithinTimeout runs fn on a watchdog goroutine. A panic raised by
// fn is recovered and re-raised on the test goroutine so Go's fuzzing
// engine records the reproducing input as a crasher; if fn does not
// return within d the test fails (reported as a hang crasher).
func callWithinTimeout(t *testing.T, d time.Duration, desc string, fn func()) {
	t.Helper()
	done := make(chan interface{}, 1) // carries the recovered panic value, or nil
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	select {
	case rec := <-done:
		if rec != nil {
			// Re-raise on the fuzz-worker goroutine so the engine
			// captures it and writes the crasher to testdata/fuzz/.
			panic(rec)
		}
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (possible hang / infinite loop)", desc, d)
	}
}

// splitSSEEvents splits a raw SSE stream into per-event byte slices on
// the blank-line ("\n\n") boundary and re-appends the terminator so the
// framing each event sees matches what the streaming orchestrator feeds.
// Empty trailing segments are dropped. If there is no boundary the whole
// input is returned as one event (exercises the single-event path).
func splitSSEEvents(data []byte) [][]byte {
	segs := bytes.Split(data, []byte("\n\n"))
	out := make([][]byte, 0, len(segs))
	for _, s := range segs {
		if len(s) == 0 {
			continue
		}
		ev := make([]byte, 0, len(s)+2)
		ev = append(ev, s...)
		ev = append(ev, '\n', '\n')
		out = append(out, ev)
	}
	if len(out) == 0 {
		// All-empty input: still feed one empty event so FeedEvent's
		// no-data path is exercised.
		return [][]byte{[]byte("\n\n")}
	}
	return out
}

// readSeedFixture returns the bytes of a testdata fixture, or nil if it
// cannot be read (seeds are best-effort — the hand-written seeds below
// keep the corpus non-empty regardless). Named distinctly from the
// existing testing.T-based readFixture helper in streaming_test.go.
func readSeedFixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		return nil
	}
	return b
}

// handWrittenStreamSeeds are provider-agnostic edge cases every SSE
// accumulator should survive.
var handWrittenStreamSeeds = [][]byte{
	[]byte(""),
	[]byte("\n\n"),
	[]byte("data: [DONE]\n\n"),
	[]byte(": a bare comment line\n\n"),
	[]byte("event: ping\n\n"),
	[]byte("data:\n\n"),                        // data prefix, empty payload
	[]byte("data: {\n\n"),                      // truncated / malformed JSON
	[]byte("data: {}\n\n"),                     // valid-JSON, no fields
	[]byte("data: not json at all\n\n"),        // non-JSON payload
	[]byte("data: {\"type\":\"unknown\"}\n\n"), // unknown event type
	[]byte("data: [1,2,3]\n\n"),                // JSON array where object expected
	[]byte("data: \"a string\"\n\n"),           // JSON scalar
	[]byte("data: 12345\n\n"),                  // JSON number
	[]byte("data: null\n\n"),                   // JSON null
	// Multi-line data: SSE-spec continuation (payload joined by '\n').
	[]byte("data: {\"type\":\n data: \"ping\"}\n\n"),
}

// FuzzAnthropicFeedEvent feeds arbitrary bytes (split into events) to a
// fresh AnthropicAccumulator. Property: FeedEvent never panics and
// always returns.
func FuzzAnthropicFeedEvent(f *testing.F) {
	for _, name := range []string{
		"anthropic_streaming_single_tool_use.txt",
		"anthropic_streaming_text_only.txt",
		"anthropic_streaming_text_then_tool.txt",
	} {
		if b := readSeedFixture(name); b != nil {
			f.Add(b)
		}
	}
	// A couple of representative single events pulled from the format.
	f.Add([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_x\",\"name\":\"bash\",\"input\":{}}}\n\n"))
	f.Add([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n\n"))
	f.Add([]byte("data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"))
	for _, s := range handWrittenStreamSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		acc := NewAnthropicAccumulator(0)
		for _, ev := range splitSSEEvents(data) {
			if len(ev) > maxFuzzEventBytes {
				ev = ev[:maxFuzzEventBytes]
			}
			ev := ev // capture for closure
			callWithinTimeout(t, feedTimeout, "AnthropicAccumulator.FeedEvent", func() {
				// Return value and error are both acceptable outcomes;
				// only a panic or hang is a failure.
				_, _ = acc.FeedEvent(ev)
			})
		}
	})
}

// FuzzOpenAIFeedEvent feeds arbitrary bytes (split into events) to a
// fresh OpenAIToolCallAccumulator. Property: FeedEvent never panics and
// always returns.
func FuzzOpenAIFeedEvent(f *testing.F) {
	for _, name := range []string{
		"openai_streaming_single_tool_call.txt",
		"openai_streaming_multi_tool_call.txt",
		"openai_streaming_mixed_text_and_tool.txt",
		"openai_streaming_args_and_finish_in_one_event.txt",
		"openai_streaming_text_only.txt",
	} {
		if b := readSeedFixture(name); b != nil {
			f.Add(b)
		}
	}
	// Representative single events.
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n"))
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n"))
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"))
	for _, s := range handWrittenStreamSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		acc := NewOpenAIToolCallAccumulator(0)
		for _, ev := range splitSSEEvents(data) {
			if len(ev) > maxFuzzEventBytes {
				ev = ev[:maxFuzzEventBytes]
			}
			ev := ev // capture for closure
			callWithinTimeout(t, feedTimeout, "OpenAIToolCallAccumulator.FeedEvent", func() {
				_, _ = acc.FeedEvent(ev)
			})
		}
	})
}
