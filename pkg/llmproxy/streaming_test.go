package llmproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// readFixture loads the SSE bytes for a fixture as one byte slice
// (suitable for serving from an httptest server).
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// newStreamingTestServer builds a streaming-aware proxy in front of
// the given upstream. The upstream's handler emits whatever fixture
// bytes you want.
func newStreamingTestServer(
	t *testing.T,
	upstream *httptest.Server,
	mutators ...func(*Server),
) (string, func()) {
	t.Helper()
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    upstream.URL,
		UpstreamAnthropic: upstream.URL,
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	for _, m := range mutators {
		m(srv)
	}
	srv.startTime = time.Now()
	httpSrv := httptest.NewServer(srv.routes())
	teardown := func() { httpSrv.Close() }
	return httpSrv.URL, teardown
}

// TestStreamingAllowPath_ByteIdentity is the headline correctness
// test: when PolicyCheck returns ALLOW for every tool_call (the
// default with no hook), the bytes the client receives must be
// byte-identical to the upstream output (modulo provenance comment
// events which the parser keeps verbatim).
func TestStreamingAllowPath_ByteIdentity(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write(fixture)
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream)
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, fixture) {
		t.Errorf("byte-identity violated: client received %d bytes, upstream sent %d bytes", len(got), len(fixture))
		t.Errorf("got=%q\nwant=%q", string(got), string(fixture))
	}
}

// TestStreaming_ArgsAndFinishInSameEvent_GateRunsAndFlushes pins the
// full-orchestrator behaviour for audit blocker B3. The fixture packs
// the closing tool_call argument fragment and finish_reason: tool_calls
// into a single SSE event. With PolicyCheck stubbed to ALLOW, the
// orchestrator must:
//   - Run the gate (observed via the policyHookSeen counter)
//   - Receive the FULL assembled arguments {"cmd":"ls"} (not the
//     truncated {"cmd":"l"} that the pre-fix parser would have produced)
//   - Replay the upstream bytes byte-identical to the client.
//
// Without the fix the gate would never fire (Completed never returned)
// and the buffered events would be silently dropped at EOF.
func TestStreaming_ArgsAndFinishInSameEvent_GateRunsAndFlushes(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_args_and_finish_in_one_event.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	var policyHookSeen atomic.Int64
	var seenArgs atomic.Value // string
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			policyHookSeen.Add(1)
			seenArgs.Store(strings.TrimSpace(string(tc.RawArguments)))
			return Decision{Allow: true, Rule: "allow:test"}, nil
		}
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)

	// 1. The gate must have fired (1 tool_call assembled).
	if got := policyHookSeen.Load(); got != 1 {
		t.Errorf("PolicyCheck called %d times, want 1 (B3 regression: gate did not fire)", got)
	}
	// 2. PolicyCheck must have seen the FULL args (closing fragment present).
	if v := seenArgs.Load(); v == nil || v.(string) != `{"cmd":"ls"}` {
		t.Errorf("PolicyCheck saw RawArguments=%v, want {\"cmd\":\"ls\"} (closing fragment dropped — B3 regression)", v)
	}
	// 3. ALLOW path must replay upstream bytes byte-identical.
	if !bytes.Equal(got, fixture) {
		t.Errorf("byte-identity violated on bundling fixture: client received %d bytes, upstream sent %d bytes\ngot=%q\nwant=%q",
			len(got), len(fixture), string(got), string(fixture))
	}
}

// TestStreamingDenyPath_RefusesAndCloses — when PolicyCheck DENYs the
// tool_call, the client receives a synthetic refusal and the upstream
// tool_call deltas never reach it.
func TestStreamingDenyPath_RefusesAndCloses(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: false, Reason: "test deny", Rule: "deny:test"}, nil
		}
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// The upstream tool_call's id MUST NOT leak through.
	if strings.Contains(gotStr, "call_abc123") {
		t.Errorf("buffered tool_call id leaked into client output: %q", gotStr)
	}
	// The synthetic refusal must mention "denied" (default builder text).
	if !strings.Contains(gotStr, "AgentGuard denied") {
		t.Errorf("expected refusal text; got %q", gotStr)
	}
	if !strings.Contains(gotStr, "[DONE]") {
		t.Errorf("expected [DONE] terminator; got %q", gotStr)
	}
}

// TestStreamingApprovalPath — REQUIRE_APPROVAL behaves like DENY
// (the stream is interrupted with a synthetic refusal carrying the
// approval URL). The default fallback builder doesn't include an
// approval URL but a custom BuildRefusal does — this test wires one
// to confirm the hook receives the decision verbatim.
func TestStreamingApprovalPath(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	var seenDecision Decision
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{
				Allow:            false,
				RequiresApproval: true,
				Reason:           "needs approval",
				ApprovalID:       "ap_xyz",
				ApprovalURL:      "http://localhost:8080/approve/ap_xyz",
			}, nil
		}
		s.BuildRefusal = func(provider string, decision Decision, ctx *RefusalContext) []byte {
			seenDecision = decision
			return []byte("data: {\"refusal\":\"approval\"}\n\ndata: [DONE]\n\n")
		}
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "approval") {
		t.Errorf("expected approval refusal payload; got %q", string(got))
	}
	if seenDecision.ApprovalID != "ap_xyz" {
		t.Errorf("BuildRefusal received approval_id=%q, want ap_xyz", seenDecision.ApprovalID)
	}
}

// TestStreamingMixedTextAndToolCall — text deltas pass through
// immediately; the tool_call's deltas buffer and either flush on
// ALLOW or get refused on DENY. We test the ALLOW variant; bytes
// must match (modulo strict byte-identity which we already cover
// in the dedicated test).
func TestStreamingMixedTextAndToolCall(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_mixed_text_and_tool.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream)
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, fixture) {
		t.Errorf("ALLOW-path mixed stream not byte-identical")
	}
}

// TestStreamingOverflowBufferBytes — set MaxBufferBytes to 256; emit
// a tool_call with 1 KiB arguments; assert the proxy denies with the
// canonical buffer-overflow refusal.
func TestStreamingOverflowBufferBytes(t *testing.T) {
	huge := strings.Repeat("a", 1024)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_x\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n")
		_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"%s\"}}]},\"finish_reason\":null}]}\n\n", huge)
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.cfg.MaxBufferBytes = 256
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "exceed gating buffer") {
		t.Errorf("expected buffer-overflow refusal; got %q", string(got))
	}
}

// TestReadSSEEvent_NewlineFreeFloodRefused — a giant blob with no
// newline at all must still trip the per-event cap. The pre-fix
// ReadBytes implementation buffered the entire "line" before the cap
// check ever ran, so a newline-free upstream flood grew memory
// unboundedly even with --max-buffer-bytes at its default.
func TestReadSSEEvent_NewlineFreeFloodRefused(t *testing.T) {
	src := strings.NewReader(strings.Repeat("x", 5000)) // no '\n' anywhere
	r := bufio.NewReaderSize(src, 16)                   // small buffer => deterministic ReadSlice chunks

	got, err := readSSEEvent(r, 1024)
	if !errors.Is(err, errSSEEventTooLarge) {
		t.Fatalf("err = %v, want errSSEEventTooLarge", err)
	}
	// The cap check runs once per <=16-byte chunk, so accumulation must
	// stop within one chunk of the cap — not after the full 5000 bytes.
	if len(got) > 1024+16 {
		t.Errorf("accumulated %d bytes; cap enforcement lagged past one chunk over 1024", len(got))
	}
}

// TestReadSSEEvent_LongLineFragmentNotMistakenForBlankLine — when a
// line is longer than the reader's buffer, ReadSlice hands it back in
// fragments and the FINAL fragment can be exactly "\n" (or "\r\n").
// That fragment must not be mistaken for the blank-line event
// terminator; the event must come back whole and byte-identical.
func TestReadSSEEvent_LongLineFragmentNotMistakenForBlankLine(t *testing.T) {
	for _, nl := range []string{"\n", "\r\n"} {
		// 16 data bytes fill the buffer exactly, leaving the newline
		// sequence alone in the next fragment.
		line := "data: 0123456789" + nl // len("data: 0123456789") == 16
		event := line + "\n"            // blank line terminates the event
		r := bufio.NewReaderSize(strings.NewReader(event+"data: next\n\n"), 16)

		got, err := readSSEEvent(r, 0)
		if err != nil {
			t.Fatalf("nl=%q: err = %v, want nil", nl, err)
		}
		if string(got) != event {
			t.Errorf("nl=%q: event = %q, want %q (fragment %q wrongly treated as blank line?)", nl, got, event, nl)
		}
	}
}

// TestReadSSEEvent_PartialTrailingEventEOF pins the documented EOF
// contract: a stream ending mid-event returns the accumulated bytes
// with err == io.EOF so callers can still attempt to dispatch it.
func TestReadSSEEvent_PartialTrailingEventEOF(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("data: partial\n"), 16)
	got, err := readSSEEvent(r, 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if string(got) != "data: partial\n" {
		t.Errorf("partial event = %q, want %q", got, "data: partial\n")
	}
}

// TestStreamingNewlineFreeBlobRefusedAtDefaultCap is the loop-level
// regression guard for the ReadBytes hole: with the DEFAULT
// --max-buffer-bytes (1 MiB), a newline-free upstream blob must be
// refused fail-closed at the 2x per-event read cap instead of being
// buffered in its entirety.
func TestStreamingNewlineFreeBlobRefusedAtDefaultCap(t *testing.T) {
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    "https://api.openai.com",
		UpstreamAnthropic: "https://api.anthropic.com",
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// 3 MiB of 'a' with not a single newline — over the 2 MiB event cap.
	chunk := strings.Repeat("a", 1<<20)
	readers := []io.Reader{
		strings.NewReader(chunk), strings.NewReader(chunk), strings.NewReader(chunk),
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	srv.runOpenAIStreamLoop(w, w, req, io.MultiReader(readers...))

	got := w.Body.String()
	if !strings.Contains(got, "exceed gating buffer") {
		t.Errorf("expected buffer-overflow refusal for newline-free blob; got %d bytes: %.200q", len(got), got)
	}
}

// TestHardCappedBufferBytes pins the cap-resolution contract: any
// positive computed cap passes through untouched (operator-configured
// behaviour is unchanged), and <= 0 falls back to the absolute ceiling.
func TestHardCappedBufferBytes(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, absoluteMaxBufferBytes},
		{-1, absoluteMaxBufferBytes},
		{256, 256},
		{DefaultMaxBufferBytes, DefaultMaxBufferBytes},
		{MaxConfigurableBufferBytes * 2, MaxConfigurableBufferBytes * 2}, // 2x event cap at max config
	}
	for _, c := range cases {
		if got := hardCappedBufferBytes(c.in); got != c.want {
			t.Errorf("hardCappedBufferBytes(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestStreamingHardCeilingAppliesWhenCapDisabled — audit L1: with
// MaxBufferBytes = 0 ("no operator-configured cap", only reachable by
// building the Config directly; ParseConfig rejects 0) an upstream that
// never terminates an SSE event previously grew the read buffer without
// bound. The absolute hard ceiling must refuse the stream fail-closed
// with the canonical buffer-overflow refusal instead.
//
// Drives runOpenAIStreamLoop directly rather than through a full HTTP
// hop: with the cap at 0 readRequestBody rejects any request body
// before streaming starts, and pushing 64 MiB through two loopback
// servers buys no extra coverage over feeding the reader in-process.
func TestStreamingHardCeilingAppliesWhenCapDisabled(t *testing.T) {
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    "https://api.openai.com",
		UpstreamAnthropic: "https://api.anthropic.com",
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.cfg.MaxBufferBytes = 0 // bypasses Validate, as a direct Config build can

	// One SSE event that never sees a blank-line terminator: 1 MiB data
	// lines repeated until just past the absolute ceiling. If the
	// ceiling regressed, the loop would swallow all of it and finish at
	// EOF without a refusal (clean failure, no hang).
	line := "data: " + strings.Repeat("a", 1<<20) + "\n"
	nLines := absoluteMaxBufferBytes/len(line) + 2
	readers := make([]io.Reader, nLines)
	for i := range readers {
		readers[i] = strings.NewReader(line)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	srv.runOpenAIStreamLoop(w, w, req, io.MultiReader(readers...))

	got := w.Body.String()
	if !strings.Contains(got, "exceed gating buffer") {
		t.Errorf("expected buffer-overflow refusal with cap disabled; got %d bytes: %.200q", len(got), got)
	}
}

// TestStreamingMalformedUpstream — upstream emits garbage; proxy must
// not panic. The bad event is dropped (we don't inject our own bytes
// into the stream); valid events that follow continue to work.
func TestStreamingMalformedUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {totally not valid json}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream)
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	// [DONE] should still get through (since it's after the bad event).
	if !strings.Contains(string(got), "[DONE]") {
		t.Errorf("expected [DONE] to pass through after malformed event; got %q", string(got))
	}
}

// TestStreamingConcurrent_NoCrossLeak — 10 concurrent streaming
// requests, each tagged with a distinct tool_call id. Assert each
// client receives its own id and never another request's. This
// exercises the per-request goroutine isolation invariant.
func TestStreamingConcurrent_NoCrossLeak(t *testing.T) {
	const concurrency = 10
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The client puts the desired call id in a custom header so
		// the upstream emits a fixture with that id.
		callID := r.Header.Get("X-Test-Call-ID")
		if callID == "" {
			callID = "default"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		// Emit a tool_call with the requested id, then [DONE].
		fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n")
		fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":%q,\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n\n", callID)
		fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		fmt.Fprintf(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	var observedIDs sync.Map
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		// PolicyCheck observes the call id and records it under the
		// caller's tag so a leak (one request's id flowing through
		// another's accumulator) would show up.
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			// Pull the test tag from the request via meta — we can't
			// do that without plumbing context, so we instead just
			// record the seen ToolCallID. Cross-leak would manifest
			// as duplicate IDs in `observedIDs`.
			observedIDs.LoadOrStore(tc.ToolCallID, true)
			return Decision{Allow: true}, nil
		}
	})
	defer teardown()

	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			callID := fmt.Sprintf("call_concurrent_%d", i)
			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("X-Test-Call-ID", callID)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("client %d: post: %v", i, err)
				failures.Add(1)
				return
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(got), callID) {
				t.Errorf("client %d: expected %q in response, got %q", i, callID, string(got))
				failures.Add(1)
			}
			// Other clients' ids must not leak in.
			for j := 0; j < concurrency; j++ {
				if j == i {
					continue
				}
				other := fmt.Sprintf("call_concurrent_%d", j)
				if strings.Contains(string(got), other) {
					t.Errorf("client %d: leaked %q from another request: got %q", i, other, string(got))
					failures.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if failures.Load() > 0 {
		t.Fatalf("%d concurrent failures", failures.Load())
	}
}

// TestStreamingAnthropicAllowPath — ALLOW path on Anthropic should
// also be byte-identical.
func TestStreamingAnthropicAllowPath(t *testing.T) {
	fixture := readFixture(t, "anthropic_streaming_single_tool_use.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream)
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, fixture) {
		t.Errorf("Anthropic ALLOW-path not byte-identical: got %q", string(got))
	}
}

// TestStreamingAnthropicDenyPath — Anthropic DENY produces a refusal
// with stop_reason rewrite to end_turn.
func TestStreamingAnthropicDenyPath(t *testing.T) {
	fixture := readFixture(t, "anthropic_streaming_single_tool_use.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: false, Reason: "shell denied", Rule: "deny:shell"}, nil
		}
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)
	if strings.Contains(gotStr, "toolu_xyz") {
		t.Errorf("buffered tool_use id leaked into Anthropic deny path: %q", gotStr)
	}
	if !strings.Contains(gotStr, "AgentGuard denied") {
		t.Errorf("expected refusal text; got %q", gotStr)
	}
	if !strings.Contains(gotStr, "stop_reason") {
		t.Errorf("expected stop_reason rewrite in Anthropic refusal; got %q", gotStr)
	}
}

// TestStreaming_FailMode_DenyVsClosedAudit_DistinctRules pins B4 closed.
//
// Drives a streaming OpenAI request twice with the central /v1/check
// unreachable: once with --fail-mode deny, once with
// --fail-mode fail-closed-with-audit. The two synthetic refusals MUST
// emit distinct rule strings so operators who alert on
// `deny:llm_api_proxy:fail_closed_audit` can differentiate central-server
// outage events from plain fail-closed denials. The fix wires the gate's
// failModeDecision Decision through the streaming orchestrator (or, when
// the test shim returns a bare error without a Rule, falls back to the
// per-fail-mode rule string via fallbackFailModeRule).
//
// Pre-fix: streaming.go hardcoded `deny:llm_api_proxy:policy_unreachable`
// regardless of FailMode, making `fail-closed-with-audit` observationally
// indistinguishable from `deny`.
func TestStreaming_FailMode_DenyVsClosedAudit_DistinctRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_fm","type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":null}]}`+"\n\n")
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	// Test runs against the production gate so the Rule string is
	// constructed by HTTPPolicyClient.failModeDecision (not the streaming
	// fallback). Use an unreachable guard URL so the gate's HTTP call
	// fails and failModeDecision fires.
	unreachableGuard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer unreachableGuard.Close()

	driveOnce := func(t *testing.T, failMode string) string {
		t.Helper()
		base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
			s.cfg.FailMode = failMode
			// Wire the rich refusal builder so the rule string lands in
			// the client-visible refusal payload. (The default refusal
			// builder only renders Reason; only the rich builder
			// includes Rule.)
			s.BuildRefusal = BuildRefusalRich
			// Wire the production HTTPPolicyClient against an
			// unreachable guard so failModeDecision fires with the
			// gate-shaped Decision (not a test-shim bare error).
			gateCfg := &Config{
				GuardURL: unreachableGuard.URL,
				TenantID: "test",
				FailMode: failMode,
			}
			gate := NewHTTPPolicyClient(gateCfg, nil)
			gate.HTTPClient = &http.Client{Timeout: 250 * time.Millisecond}
			s.PolicyCheck = gate.Check
		})
		defer teardown()

		body := `{"model":"gpt-4","messages":[],"stream":true}`
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("fail-mode %s: post: %v", failMode, err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		return string(got)
	}

	t.Run("deny", func(t *testing.T) {
		got := driveOnce(t, "deny")
		if !strings.Contains(got, FailModeRuleClosed) {
			t.Errorf("fail-mode=deny: expected refusal to contain %q; got %q", FailModeRuleClosed, got)
		}
		// MUST NOT carry the audit variant — that's a different mode.
		if strings.Contains(got, FailModeRuleClosedAudit) {
			t.Errorf("fail-mode=deny: refusal must not contain audit-variant rule; got %q", got)
		}
		// Refusal must replace the buffered tool_call (no leak).
		if strings.Contains(got, `"call_fm"`) {
			t.Errorf("fail-mode=deny: buffered tool_call leaked: %q", got)
		}
	})

	t.Run("fail-closed-with-audit", func(t *testing.T) {
		got := driveOnce(t, "fail-closed-with-audit")
		if !strings.Contains(got, FailModeRuleClosedAudit) {
			t.Errorf("fail-mode=fail-closed-with-audit: expected refusal to contain %q; got %q", FailModeRuleClosedAudit, got)
		}
		if strings.Contains(got, `"call_fm"`) {
			t.Errorf("fail-mode=fail-closed-with-audit: buffered tool_call leaked: %q", got)
		}
	})
}

// TestStreaming_FailMode_BareErrorFallback_DistinctRules covers the
// test-shim path where PolicyCheck returns a bare error without a
// fail-mode-shaped Decision. The streaming orchestrator's
// fallbackFailModeRule must still emit the right rule per --fail-mode
// so dashboards stay consistent regardless of which path constructed
// the Decision.
func TestStreaming_FailMode_BareErrorFallback_DistinctRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_fb","type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":null}]}`+"\n\n")
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	driveOnce := func(t *testing.T, failMode string) string {
		t.Helper()
		base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
			s.cfg.FailMode = failMode
			s.BuildRefusal = BuildRefusalRich
			s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
				return Decision{}, fmt.Errorf("simulated /v1/check unreachable")
			}
		})
		defer teardown()

		body := `{"model":"gpt-4","messages":[],"stream":true}`
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("fail-mode %s: post: %v", failMode, err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		return string(got)
	}

	t.Run("deny", func(t *testing.T) {
		got := driveOnce(t, "deny")
		if !strings.Contains(got, FailModeRuleClosed) {
			t.Errorf("fail-mode=deny fallback: expected %q; got %q", FailModeRuleClosed, got)
		}
		if strings.Contains(got, FailModeRuleClosedAudit) {
			t.Errorf("fail-mode=deny fallback: must not contain audit variant; got %q", got)
		}
	})

	t.Run("fail-closed-with-audit", func(t *testing.T) {
		got := driveOnce(t, "fail-closed-with-audit")
		if !strings.Contains(got, FailModeRuleClosedAudit) {
			t.Errorf("fail-mode=fail-closed-with-audit fallback: expected %q; got %q", FailModeRuleClosedAudit, got)
		}
	})
}
