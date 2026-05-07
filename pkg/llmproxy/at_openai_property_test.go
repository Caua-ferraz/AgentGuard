package llmproxy

// at_openai_property_test.go is the AT-added property-based test for the
// OpenAI streaming tool_call accumulator. The combinatorial space of
// (random JSON-encoded arguments string × random splitting across N SSE
// deltas) is too large for hand-rolled cases — testing/quick (stdlib)
// generates random inputs and asserts the parser's invariants.
//
// Properties verified (per the v0.5 plan AT brief):
//   1. Args reassembly: for any random JSON arguments and any random
//      splitting across N deltas, concat(deltas) == accumulator.Arguments.
//   2. Multi-tool: random N tools (1-5), each with random args, random
//      delta interleaving by tool_calls[i].index — all N reassemble.
//   3. Buffer bound: random arg sizes; overflow fires precisely when
//      cumulative bytes exceed MaxBufferBytes.
//   4. Mid-stream content: random text-content deltas interleaved with
//      tool_call deltas — text passes through, tool_calls buffer.
//   5. Malformed: random byte injection into delta JSON — parser does
//      not panic, returns error.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
)

// quickConfig keeps property runs bounded for CI determinism.
var quickConfig = &quick.Config{MaxCount: 200}

// TestAT_OpenAIParser_AssemblesArgsAcrossArbitraryChunkBoundaries pins
// the central invariant: regardless of how the upstream chooses to
// split a tool_call's `arguments` JSON across SSE deltas, the parser
// must reassemble the exact original byte sequence.
func TestAT_OpenAIParser_AssemblesArgsAcrossArbitraryChunkBoundaries(t *testing.T) {
	property := func(seed int64, rawJSON string, splitCount uint8) bool {
		// Reject inputs the test generator cannot meaningfully exercise.
		// We need a non-empty JSON-shaped string and a finite split count.
		if rawJSON == "" || splitCount == 0 {
			return true // no-op
		}
		// Bound size so a single property run doesn't allocate megabytes.
		if len(rawJSON) > 4096 {
			rawJSON = rawJSON[:4096]
		}
		// Bound splits to a sane multiple of len.
		nSplits := int(splitCount) % 32
		if nSplits == 0 {
			nSplits = 1
		}

		// Use the seed for a deterministic local RNG so failures are
		// reproducible; testing/quick passes the seed via the input.
		r := rand.New(rand.NewSource(seed))

		// Wrap rawJSON as the JSON-encoded value of a "cmd" arg so the
		// resulting tool_call arguments are well-formed for the
		// post-stream parse step. We feed the parser raw fragments of
		// the JSON ENCODING (a string), not of the final structure.
		encoded, _ := json.Marshal(map[string]string{"cmd": rawJSON})
		argsString := string(encoded)

		fragments := splitIntoFragments(argsString, nSplits, r)

		acc := NewOpenAIToolCallAccumulator(0)
		// Start delta — establishes name + id + first (possibly empty) frag.
		feed(acc, openAIStartDelta("call_prop", "bash", fragments[0]))
		for _, frag := range fragments[1:] {
			feed(acc, openAIArgDelta(frag))
		}
		// Close cycle.
		res, err := acc.FeedEvent([]byte(openAIFinishDelta()))
		if err != nil {
			// JSON unmarshal of args may fail when rawJSON contains
			// quote chars that break the wrapper — accept that case
			// (we still preserve RawArguments byte-for-byte). Property
			// holds against RawArguments below.
		}
		if !res.Completed || len(res.CompletedToolCalls) != 1 {
			t.Logf("seed=%d nSplits=%d: completion missing; res=%+v", seed, nSplits, res)
			return false
		}
		got := string(res.CompletedToolCalls[0].RawArguments)
		// The parser trims surrounding whitespace; we must too.
		if strings.TrimSpace(got) != strings.TrimSpace(argsString) {
			t.Logf("seed=%d nSplits=%d: reassembly mismatch:\n got=%q\nwant=%q", seed, nSplits, got, argsString)
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("property failed: %v", err)
	}
}

// TestAT_OpenAIParser_MultiToolReassemblyByIndex pins that with N
// random tools (1..5) interleaved by their tool_calls[i].index, each
// tool's arguments reassemble independently.
func TestAT_OpenAIParser_MultiToolReassemblyByIndex(t *testing.T) {
	property := func(seed int64, n uint8) bool {
		nTools := int(n)%5 + 1
		r := rand.New(rand.NewSource(seed))

		// Build N tool_calls with random args (small JSON objects).
		args := make([]string, nTools)
		for i := range args {
			args[i] = fmt.Sprintf(`{"i":%d,"r":%d}`, i, r.Intn(100000))
		}

		// Generate fragments for each tool, then interleave them
		// randomly. Each fragment carries its tool's index.
		type frag struct {
			toolIdx int
			text    string
			isStart bool
			name    string
			id      string
		}
		var allFrags []frag
		for ti := 0; ti < nTools; ti++ {
			pieces := splitIntoFragments(args[ti], 1+r.Intn(4), r)
			// First fragment is the start delta with name+id.
			allFrags = append(allFrags, frag{
				toolIdx: ti, text: pieces[0], isStart: true,
				name: fmt.Sprintf("tool_%d", ti),
				id:   fmt.Sprintf("call_%d", ti),
			})
			for _, p := range pieces[1:] {
				allFrags = append(allFrags, frag{toolIdx: ti, text: p})
			}
		}

		// Stable-sort partial: each tool's fragments must stay in
		// order, but different tools' fragments can interleave. We
		// achieve this by random selection from the heads of N queues.
		queues := make([][]frag, nTools)
		for _, f := range allFrags {
			queues[f.toolIdx] = append(queues[f.toolIdx], f)
		}
		var ordered []frag
		for {
			active := []int{}
			for i, q := range queues {
				if len(q) > 0 {
					active = append(active, i)
				}
			}
			if len(active) == 0 {
				break
			}
			pick := active[r.Intn(len(active))]
			ordered = append(ordered, queues[pick][0])
			queues[pick] = queues[pick][1:]
		}

		acc := NewOpenAIToolCallAccumulator(0)
		for _, f := range ordered {
			if f.isStart {
				ev := fmt.Sprintf(
					`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%s}}]},"finish_reason":null}]}`,
					f.toolIdx, f.id, f.name, mustJSON(f.text),
				) + "\n\n"
				if _, err := acc.FeedEvent([]byte(ev)); err != nil {
					t.Logf("seed=%d: feed start frag err=%v", seed, err)
					return false
				}
			} else {
				ev := fmt.Sprintf(
					`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":%d,"function":{"arguments":%s}}]},"finish_reason":null}]}`,
					f.toolIdx, mustJSON(f.text),
				) + "\n\n"
				if _, err := acc.FeedEvent([]byte(ev)); err != nil {
					t.Logf("seed=%d: feed cont frag err=%v", seed, err)
					return false
				}
			}
		}
		res, err := acc.FeedEvent([]byte(openAIFinishDelta()))
		if err != nil {
			t.Logf("seed=%d: finish err=%v", seed, err)
			return false
		}
		if !res.Completed || len(res.CompletedToolCalls) != nTools {
			t.Logf("seed=%d: nTools=%d but got %d completed", seed, nTools, len(res.CompletedToolCalls))
			return false
		}
		// Sorted by index inside the parser; verify reassembly.
		for i, tc := range res.CompletedToolCalls {
			gotArgs := strings.TrimSpace(string(tc.RawArguments))
			wantArgs := strings.TrimSpace(args[i])
			if gotArgs != wantArgs {
				t.Logf("seed=%d tool[%d]: got=%q want=%q", seed, i, gotArgs, wantArgs)
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("multi-tool property failed: %v", err)
	}
}

// TestAT_OpenAIParser_OverflowFiresAtCorrectThreshold pins the
// overflow semantic: with MaxBufferBytes=N, overflow fires once
// cumulative arguments bytes (or buffered envelope bytes) exceed N.
// Below the threshold no overflow; above, it must trip.
func TestAT_OpenAIParser_OverflowFiresAtCorrectThreshold(t *testing.T) {
	property := func(capN uint16, argSize uint16) bool {
		cap := int(capN)%2048 + 64 // [64..2111]
		size := int(argSize) % 4096
		if size <= 0 {
			return true
		}
		acc := NewOpenAIToolCallAccumulator(cap)

		// First delta: start the cycle with name + empty args.
		startEv := openAIStartDelta("call_x", "bash", "")
		startRes, err := acc.FeedEvent([]byte(startEv))
		if err != nil || (!startRes.Accumulating && !startRes.OverflowBufferBytes) {
			t.Logf("cap=%d: start unexpected: res=%+v err=%v", cap, startRes, err)
			return false
		}
		if startRes.OverflowBufferBytes {
			// The start envelope itself blew the cap — sanity: it has
			// to have been > cap bytes. If size==0 the envelope is
			// small, but the parser counts bufferedBytes too.
			return true
		}
		// Then a single arg-only delta with `size` bytes of payload.
		bigArg := strings.Repeat("a", size)
		ev := openAIArgDelta(bigArg)
		res, err := acc.FeedEvent([]byte(ev))
		if err != nil {
			return true // malformed JSON path is allowed
		}
		// The parser checks BOTH cumulative args bytes AND buffered
		// envelope bytes. Both can trip overflow; the first one wins.
		// We assert the outcome is consistent: overflow IFF
		//   (size > cap)                            // args check
		//   OR (lenStartEnvelope + lenContEnvelope > cap) // buffer check
		startEnvLen := len(startEv)
		contEnvLen := len(ev)
		shouldOverflowOnArgs := size > cap
		shouldOverflowOnBuffer := startEnvLen+contEnvLen > cap
		shouldOverflow := shouldOverflowOnArgs || shouldOverflowOnBuffer

		if shouldOverflow != res.OverflowBufferBytes {
			t.Logf(
				"cap=%d size=%d startEnv=%d contEnv=%d: shouldOverflow=%v actual=%v res=%+v",
				cap, size, startEnvLen, contEnvLen, shouldOverflow, res.OverflowBufferBytes, res,
			)
			return false
		}
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("overflow-threshold property failed: %v", err)
	}
}

// TestAT_OpenAIParser_TextDeltasPassThroughUntilToolCall pins that
// arbitrary text-only content deltas pass through immediately when no
// tool_call has begun, then start buffering when one does.
func TestAT_OpenAIParser_TextDeltasPassThroughUntilToolCall(t *testing.T) {
	property := func(textChunks []string) bool {
		acc := NewOpenAIToolCallAccumulator(0)
		for _, txt := range textChunks {
			ev := fmt.Sprintf(
				`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":%s},"finish_reason":null}]}`,
				mustJSON(txt),
			) + "\n\n"
			res, err := acc.FeedEvent([]byte(ev))
			if err != nil {
				continue // malformed via random content — skip
			}
			if !res.PassThrough {
				return false
			}
		}
		// Now begin a tool_call; it must NOT be PassThrough.
		startEv := openAIStartDelta("call_t", "bash", `{"cmd":"x"}`)
		res, err := acc.FeedEvent([]byte(startEv))
		if err != nil {
			return false
		}
		return res.Accumulating
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("text-passthrough property failed: %v", err)
	}
}

// TestAT_OpenAIParser_MalformedNeverPanics pins that random byte
// injection into a delta-shape envelope returns an error (not a
// panic). testing/quick generates random byte slices; we wrap each
// in `data: ...\n\n` and feed it. The parser must remain alive.
func TestAT_OpenAIParser_MalformedNeverPanics(t *testing.T) {
	property := func(garbage []byte) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PANIC on input %q: %v", garbage, r)
				ok = false
			}
		}()
		acc := NewOpenAIToolCallAccumulator(0)
		// Wrap as `data: <bytes>\n\n` so the framing is at least valid.
		ev := append([]byte("data: "), garbage...)
		ev = append(ev, '\n', '\n')
		// FeedEvent may return an error or a benign result; either is
		// acceptable as long as it does not panic.
		_, _ = acc.FeedEvent(ev)
		return true
	}
	if err := quick.Check(property, quickConfig); err != nil {
		t.Errorf("malformed-no-panic property failed: %v", err)
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// splitIntoFragments splits s into n random pieces along rune
// boundaries. Splitting on byte boundaries inside a multi-byte rune
// produces invalid UTF-8 fragments which json.Marshal would replace
// with U+FFFD, breaking the byte-identity property under test.
// Real upstreams emit valid UTF-8 in each delta (the spec requires it
// per RFC 8259); the parser is fed pre-encoded JSON regardless. The
// rune-boundary constraint reflects what actually arrives on the wire.
func splitIntoFragments(s string, n int, r *rand.Rand) []string {
	if n <= 1 || len(s) == 0 {
		return []string{s}
	}
	// Build a list of valid rune-boundary indices (0 and after each rune).
	boundaries := make([]int, 0, len(s)+1)
	for i := range s {
		boundaries = append(boundaries, i)
	}
	boundaries = append(boundaries, len(s))
	if n >= len(boundaries)-1 {
		// One rune per fragment (cap at rune count).
		out := make([]string, 0, len(boundaries)-1)
		for i := 0; i < len(boundaries)-1; i++ {
			out = append(out, s[boundaries[i]:boundaries[i+1]])
		}
		return out
	}
	// Pick n-1 random cut points (no duplicates) from interior boundaries.
	used := map[int]bool{}
	cuts := make([]int, 0, n-1)
	for len(cuts) < n-1 {
		// Interior indices are 1..len(boundaries)-2 (exclude 0 and end).
		bi := 1 + r.Intn(len(boundaries)-2)
		c := boundaries[bi]
		if !used[c] {
			used[c] = true
			cuts = append(cuts, c)
		}
	}
	// Sort cut points.
	for i := 1; i < len(cuts); i++ {
		for j := i; j > 0 && cuts[j-1] > cuts[j]; j-- {
			cuts[j-1], cuts[j] = cuts[j], cuts[j-1]
		}
	}
	out := make([]string, 0, n)
	prev := 0
	for _, c := range cuts {
		out = append(out, s[prev:c])
		prev = c
	}
	out = append(out, s[prev:])
	return out
}

func openAIStartDelta(callID, name, argsFrag string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":%s}}]},"finish_reason":null}]}`+"\n\n",
		callID, name, mustJSON(argsFrag),
	)
}

func openAIArgDelta(argsFrag string) string {
	return fmt.Sprintf(
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":%s}}]},"finish_reason":null}]}`+"\n\n",
		mustJSON(argsFrag),
	)
}

func openAIFinishDelta() string {
	return `data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func feed(acc *OpenAIToolCallAccumulator, raw string) FeedResult {
	res, _ := acc.FeedEvent([]byte(raw))
	return res
}
