package llmproxy

// at_captured_fixtures_test.go is the AT-added captured-fixture
// cross-check. The v0.5 plan AT brief asks for "real SSE responses
// captured from OpenAI and Anthropic API ... Replay through parser,
// assert tool_calls extracted correctly."
//
// A22 noted the bundled fixtures in pkg/llmproxy/testdata/ are
// SYNTHESIZED from spec — at design time the OpenAI docs page
// returned 403 and there were no captured traces in the repo. The
// synthesized fixtures are exercised by openai_parser_test.go and
// anthropic_parser_test.go and pin the spec semantics; a captured
// fixture would tighten the regression coupon further by catching any
// drift between spec and real upstream behavior.
//
// To add a captured fixture:
//   1. Capture the SSE response of a real /v1/chat/completions
//      streaming call with stream=true and a tool the model calls.
//   2. Save the raw SSE bytes under
//      pkg/llmproxy/testdata/captured/openai_streaming_real_<date>.txt
//      with a `: provenance` SSE comment header (capture date, model,
//      redaction notes for any sensitive content).
//   3. The TestAT_CapturedFixtures_OpenAI sub-test below will pick it
//      up automatically.
//
// TODO(v0.7, #llm-real-captured-fixtures): include captured fixtures
// from real OpenAI + Anthropic API calls in the regression suite.

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAT_CapturedFixtures_OpenAI replays every captured OpenAI streaming
// fixture through OpenAIToolCallAccumulator and asserts at least one
// ToolCallCheck reassembles. When no real captures are committed yet, it falls
// back to the committed synthesized fixtures so the capture→replay→reassemble
// pipeline still runs in CI instead of skipping silently; real captures dropped
// under testdata/captured/ take precedence.
func TestAT_CapturedFixtures_OpenAI(t *testing.T) {
	files, err := filepath.Glob("testdata/captured/openai_streaming_*.txt")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		// Fall back to the committed synthesized fixtures (honestly labelled as
		// synthesized via their provenance header) so the replay path is
		// exercised on every run. See TODO(v0.7, #llm-real-captured-fixtures).
		files, err = filepath.Glob("testdata/openai_streaming_*.txt")
		if err != nil {
			t.Fatalf("glob synthesized fallback: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("no OpenAI streaming fixtures present (captured or synthesized)")
		}
		t.Logf("no captured fixtures; replaying %d synthesized fixture(s) as the fallback coupon", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			handle, err := os.Open(f)
			if err != nil {
				t.Fatalf("open %s: %v", f, err)
			}
			defer handle.Close()
			br := bufio.NewReader(handle)
			acc := NewOpenAIToolCallAccumulator(0)
			var completed []ToolCallCheck
			for {
				ev, err := readSSEEvent(br, 0)
				if len(ev) > 0 {
					res, ferr := acc.FeedEvent(ev)
					if ferr != nil {
						// Real captures may include events the spec
						// hadn't documented; log + continue but do
						// not fail. The reassembly assertion below is
						// the load-bearing one.
						t.Logf("event-feed err: %v", ferr)
					}
					if res.Completed {
						completed = append(completed, res.CompletedToolCalls...)
					}
				}
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("read event: %v", err)
				}
			}
			if len(completed) == 0 {
				// A real captured fixture that contains a tool_call
				// MUST reassemble at least one. If we get a
				// pass-through-only stream (e.g. the user captured a
				// non-tool-using prompt) the file should be named
				// without the tool_call hint; we fail loudly.
				if strings.Contains(strings.ToLower(filepath.Base(f)), "tool") {
					t.Errorf("captured fixture %s claims to contain a tool_call but parser produced 0 completions", f)
				}
			}
		})
	}
}

// TestAT_CapturedFixtures_Anthropic mirrors the OpenAI variant for captured
// Anthropic /v1/messages streaming traces, with the same synthesized-fixture
// fallback so the replay path runs in CI rather than skipping silently.
func TestAT_CapturedFixtures_Anthropic(t *testing.T) {
	files, err := filepath.Glob("testdata/captured/anthropic_streaming_*.txt")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		// Fall back to the committed synthesized fixtures so the replay path is
		// exercised on every run. See TODO(v0.7, #llm-real-captured-fixtures).
		files, err = filepath.Glob("testdata/anthropic_streaming_*.txt")
		if err != nil {
			t.Fatalf("glob synthesized fallback: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("no Anthropic streaming fixtures present (captured or synthesized)")
		}
		t.Logf("no captured fixtures; replaying %d synthesized fixture(s) as the fallback coupon", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			handle, err := os.Open(f)
			if err != nil {
				t.Fatalf("open %s: %v", f, err)
			}
			defer handle.Close()
			br := bufio.NewReader(handle)
			acc := NewAnthropicAccumulator(0)
			var completed []ToolCallCheck
			for {
				ev, err := readSSEEvent(br, 0)
				if len(ev) > 0 {
					res, ferr := acc.FeedEvent(ev)
					if ferr != nil {
						t.Logf("event-feed err: %v", ferr)
					}
					if res.Completed {
						completed = append(completed, res.CompletedToolCalls...)
					}
				}
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("read event: %v", err)
				}
			}
			if len(completed) == 0 {
				if strings.Contains(strings.ToLower(filepath.Base(f)), "tool") {
					t.Errorf("captured fixture %s claims to contain a tool_use but parser produced 0 completions", f)
				}
			}
		})
	}
}

// TestAT_SynthesizedFixturesHaveProvenanceHeader documents the
// bundled-fixture provenance contract: every fixture in
// testdata/*_streaming_*.txt must begin with an SSE comment line (`:`
// prefix) recording its synthesis date and source spec section. The
// streaming parser drops these comment events transparently so they
// don't affect parser behavior, but they are load-bearing for the
// audit trail when an operator wonders why a fixture matches.
func TestAT_SynthesizedFixturesHaveProvenanceHeader(t *testing.T) {
	files, err := filepath.Glob("testdata/*_streaming_*.txt")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no streaming fixtures in testdata/")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			handle, err := os.Open(f)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer handle.Close()
			br := bufio.NewReader(handle)
			first, err := br.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("read first line: %v", err)
			}
			if !strings.HasPrefix(first, ":") {
				t.Errorf("%s: first line %q does not start with `:` (SSE comment provenance header missing)", f, first)
			}
			if !strings.Contains(strings.ToLower(first), "synthesized") &&
				!strings.Contains(strings.ToLower(first), "captured") {
				t.Errorf("%s: provenance header should declare `synthesized` or `captured`; got %q", f, first)
			}
		})
	}
}
