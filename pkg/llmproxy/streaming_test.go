package llmproxy

import (
	"bytes"
	"context"
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
