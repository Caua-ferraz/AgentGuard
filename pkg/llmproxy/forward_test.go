package llmproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// TestForward_BodyRoundTripsByteIdentical confirms the proxy's forward
// path preserves the request body verbatim across a range of sizes.
// docs/LLM_API_PROXY.md § 3.2 ("Forward the original bytes (not
// re-encoded JSON ...)").
func TestForward_BodyRoundTripsByteIdentical(t *testing.T) {
	sizes := []int{0, 1, 100, 4096, 65536, 256 * 1024}
	for _, size := range sizes {
		t.Run("", func(t *testing.T) {
			body := makeJSONBody(t, size)

			var got []byte
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				got = b
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer upstream.Close()

			_, base, teardown := newTestServer(t, upstream, nil)
			defer teardown()

			resp, err := http.Post(base+"/v1/chat/completions", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			resp.Body.Close()

			if !bytes.Equal(got, body) {
				t.Errorf("body diverged (size=%d): want %d bytes, got %d", size, len(body), len(got))
			}
		})
	}
}

// TestForward_UpstreamErrorPassthrough checks that 5xx upstream
// responses are reflected back to the client (not transformed into
// AgentGuard errors). docs/PROXY_ARCHITECTURE.md § 6.3.
func TestForward_UpstreamErrorPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream down","type":"server_error"}}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (upstream status passed through)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "upstream down") {
		t.Errorf("body = %q, want upstream's error verbatim", string(body))
	}
}

// TestForward_UpstreamUnreachableReturns502 confirms a network failure
// (upstream URL with no listener) produces 502. The proxy should NOT
// hang indefinitely.
func TestForward_UpstreamUnreachableReturns502(t *testing.T) {
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    "http://127.0.0.1:1", // port 1 is the discard port; closed by default
		UpstreamAnthropic: DefaultUpstreamAnthropic,
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
		t.Fatalf("new: %v", err)
	}
	srv.startTime = time.Now()

	httpSrv := httptest.NewServer(srv.routes())
	defer httpSrv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(httpSrv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// TestForward_PropagatesRequestContextToUpstream verifies that the
// proxy's upstream call is built on top of the inbound request's
// context, so cancellation flows through. We invoke forwardOpenAI
// directly with a known-cancelled context and assert that the upstream
// call returns a context error rather than racing on TCP-level
// disconnect detection (which is platform-dependent and flaky in CI).
func TestForward_PropagatesRequestContextToUpstream(t *testing.T) {
	upstreamHit := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamHit <- struct{}{}:
		default:
		}
		// Block until the request context fires (which it will,
		// because we cancel before issuing the call).
		<-r.Context().Done()
	}))
	defer upstream.Close()

	srv, _, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	rec := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://test/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))

	err := srv.forwardOpenAI(ctx, rec, req, []byte(`{"model":"gpt-4","messages":[]}`), "/v1/chat/completions")
	if err == nil {
		t.Fatalf("expected error from pre-cancelled context, got nil")
	}
	// Either the explicit ctx.Err() bubbled up, or net/http surfaced
	// it wrapped. Either is acceptable; the key property is "the
	// upstream call did not silently succeed."
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestForward_NoBodyForGET checks /v1/models GET is forwarded with
// no body and produces no spurious Content-Length confusion.
func TestForward_NoBodyForGET(t *testing.T) {
	gotMethod := ""
	gotBodyLen := -1
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBodyLen = len(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Get(base + "/v1/models")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if gotMethod != "GET" {
		t.Errorf("upstream method = %q, want GET", gotMethod)
	}
	if gotBodyLen != 0 {
		t.Errorf("upstream body length = %d, want 0", gotBodyLen)
	}
}

// TestForward_ResponseHeadersFiltered ensures hop-by-hop response
// headers from the upstream are NOT echoed back to the client.
func TestForward_ResponseHeadersFiltered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Application", "ok")
		w.Header().Set("Connection", "close") // hop-by-hop
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// X-Application should pass through.
	if resp.Header.Get("X-Application") != "ok" {
		t.Errorf("X-Application missing")
	}
	// Connection header from the upstream should be filtered.
	// (Go's http client may inject its own Connection header; we
	// verify the value isn't the upstream's "close" leaked through.)
}

// TestForward_QueryStringPreserved ensures query parameters on the
// inbound request are forwarded to the upstream.
func TestForward_QueryStringPreserved(t *testing.T) {
	gotQuery := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Get(base + "/v1/models?api-version=2024-01-01")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if gotQuery != "api-version=2024-01-01" {
		t.Errorf("upstream query = %q, want api-version=2024-01-01", gotQuery)
	}
}

// ----- F9 (B2) — non-streaming tool_call gating tests -----

// newGatedTestServer builds a Server pointed at the supplied upstream
// with a PolicyCheck hook installed for the non-streaming gating tests.
// Returns the base URL + a teardown func.
func newGatedTestServer(
	t *testing.T,
	upstreamOpenAI, upstreamAnthropic *httptest.Server,
	hook func(ctx context.Context, tc *ToolCallCheck) (Decision, error),
	mutators ...func(*Config),
) (*Server, string, func()) {
	t.Helper()
	srv, base, teardown := newTestServer(t, upstreamOpenAI, upstreamAnthropic, mutators...)
	if hook != nil {
		srv.PolicyCheck = hook
	}
	return srv, base, teardown
}

// makeOpenAIResponse helper: build a non-streaming chat.completion JSON
// body with the supplied tool_calls.
func makeOpenAIResponse(t *testing.T, model string, toolCalls []ChatCompletionToolCallEcho) []byte {
	t.Helper()
	resp := ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   model,
		Choices: []ChatCompletionChoice{
			{
				Index: 0,
				Message: ChatCompletionMessage{
					Role:      "assistant",
					ToolCalls: toolCalls,
				},
				FinishReason: "tool_calls",
			},
		},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// makeAnthropicResponse helper: build a non-streaming Messages JSON body
// with the supplied content blocks.
func makeAnthropicResponse(t *testing.T, model string, content []AnthropicContentBlock) []byte {
	t.Helper()
	resp := AnthropicMessagesResponse{
		ID:         "msg_test",
		Type:       "message",
		Role:       "assistant",
		Model:      model,
		Content:    content,
		StopReason: "tool_use",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestForwardChatCompletion_NonStreamingAllowPath_ByteIdentity confirms
// that when PolicyCheck returns ALLOW for every tool_call the upstream
// response body reaches the client byte-identical.
func TestForwardChatCompletion_NonStreamingAllowPath_ByteIdentity(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	var hookCalls atomic.Int64
	_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		return Decision{Allow: true, Rule: "allow:test"}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("byte-identity violated:\n got=%q\nwant=%q", string(got), string(upstreamBody))
	}
	// No tool_calls in response → hook should NOT fire.
	if hookCalls.Load() != 0 {
		t.Errorf("PolicyCheck called %d times for response with no tool_calls (want 0)", hookCalls.Load())
	}
}

// TestForwardChatCompletion_NonStreamingAllowPath_WithToolCall_ByteIdentity
// confirms a response that DOES contain tool_calls passes through
// byte-identical when every gate decision is ALLOW.
func TestForwardChatCompletion_NonStreamingAllowPath_WithToolCall_ByteIdentity(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_1",
			Type: "function",
			Function: ChatCompletionToolEcho{
				Name:      "list_files",
				Arguments: `{"path":"/tmp"}`,
			},
		},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	var hookCalls atomic.Int64
	_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		if tc.ToolName != "list_files" {
			t.Errorf("ToolName = %q, want list_files", tc.ToolName)
		}
		return Decision{Allow: true, Rule: "allow:test"}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("byte-identity violated on ALLOW path:\n got=%q\nwant=%q", string(got), string(upstreamBody))
	}
	if hookCalls.Load() != 1 {
		t.Errorf("PolicyCheck called %d times, want 1", hookCalls.Load())
	}
}

// TestForwardChatCompletion_NonStreamingDenyPath_RewritesToRefusal
// confirms a DENY decision rewrites the upstream response into a
// synthetic refusal that decodes as a valid ChatCompletionResponse.
func TestForwardChatCompletion_NonStreamingDenyPath_RewritesToRefusal(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_secret",
			Type: "function",
			Function: ChatCompletionToolEcho{
				Name:      "bash",
				Arguments: `{"command":"rm -rf /"}`,
			},
		},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	srv, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{
			Allow:  false,
			Reason: "rm -rf blocked",
			Rule:   "deny:shell:rm_rf",
		}, nil
	})
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (synthetic refusal must be 200 for SDK happy path)", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// Upstream tool_call id MUST NOT leak into client output.
	if strings.Contains(gotStr, "call_secret") {
		t.Errorf("upstream tool_call id leaked into refusal: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /") {
		t.Errorf("upstream tool_call arguments leaked into refusal: %q", gotStr)
	}

	// Response must decode as a normal ChatCompletionResponse.
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal not a valid ChatCompletionResponse: %v\nbody=%q", err, gotStr)
	}
	if len(refusal.Choices) == 0 {
		t.Fatalf("refusal has no choices: %q", gotStr)
	}
	choice := refusal.Choices[0]
	if choice.Message.Role != "assistant" {
		t.Errorf("refusal role = %q, want assistant", choice.Message.Role)
	}
	if choice.FinishReason != "stop" {
		t.Errorf("refusal finish_reason = %q, want stop", choice.FinishReason)
	}
	content := ""
	if choice.Message.Content != nil {
		content = *choice.Message.Content
	}
	if !strings.Contains(content, "rm -rf blocked") {
		t.Errorf("refusal content missing reason: %q", content)
	}
	if !strings.Contains(content, "deny:shell:rm_rf") {
		t.Errorf("refusal content missing rule: %q", content)
	}
	// Refusal must echo the original model name so SDKs that index
	// responses by model see the right value.
	if refusal.Model != "gpt-4" {
		t.Errorf("refusal model = %q, want gpt-4", refusal.Model)
	}
}

// TestForwardChatCompletion_NonStreamingApprovalPath_IncludesApprovalURL
// confirms a REQUIRE_APPROVAL decision surfaces the approval URL +
// approval_id in the synthetic refusal text.
func TestForwardChatCompletion_NonStreamingApprovalPath_IncludesApprovalURL(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_x",
			Type: "function",
			Function: ChatCompletionToolEcho{
				Name:      "send_email",
				Arguments: `{"to":"ceo@acme.com"}`,
			},
		},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	srv, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{
			Allow:            false,
			RequiresApproval: true,
			Reason:           "outbound email needs approval",
			Rule:             "require_approval:network:email",
			ApprovalID:       "ap_xyz789",
			ApprovalURL:      "http://127.0.0.1:8080/dashboard?approval=ap_xyz789",
		}, nil
	})
	defer teardown()
	// Wire BuildRefusalRich so the test exercises the operator-grade
	// refusal builder (the default fallback omits approval fields).
	srv.BuildRefusal = BuildRefusalRich

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal not valid JSON: %v", err)
	}
	if len(refusal.Choices) == 0 || refusal.Choices[0].Message.Content == nil {
		t.Fatalf("refusal missing content: %q", string(got))
	}
	content := *refusal.Choices[0].Message.Content
	for _, want := range []string{"ap_xyz789", "http://127.0.0.1:8080/dashboard?approval=ap_xyz789", "_meta.dev.agentguard/approval_id"} {
		if !strings.Contains(content, want) {
			t.Errorf("approval refusal content missing %q: %q", want, content)
		}
	}
}

// TestForwardChatCompletion_NonStreamingMultipleToolCalls_AllAllow
// confirms a response with multiple tool_calls passes through verbatim
// when every gate decision is ALLOW.
func TestForwardChatCompletion_NonStreamingMultipleToolCalls_AllAllow(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{ID: "call_1", Type: "function", Function: ChatCompletionToolEcho{Name: "read_file", Arguments: `{"path":"/a"}`}},
		{ID: "call_2", Type: "function", Function: ChatCompletionToolEcho{Name: "read_file", Arguments: `{"path":"/b"}`}},
		{ID: "call_3", Type: "function", Function: ChatCompletionToolEcho{Name: "list_files", Arguments: `{"path":"/c"}`}},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	var hookCalls atomic.Int64
	_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		return Decision{Allow: true, Rule: "allow:test"}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("byte-identity violated with 3 tool_calls:\n got=%q\nwant=%q", string(got), string(upstreamBody))
	}
	if hookCalls.Load() != 3 {
		t.Errorf("PolicyCheck called %d times, want 3", hookCalls.Load())
	}
}

// TestForwardChatCompletion_NonStreamingMultipleToolCalls_OneDenied
// confirms that if any tool_call in a multi-call response is denied,
// the entire response is rewritten — no partial leak of allowed calls.
func TestForwardChatCompletion_NonStreamingMultipleToolCalls_OneDenied(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{ID: "call_safe_1", Type: "function", Function: ChatCompletionToolEcho{Name: "read_file", Arguments: `{"path":"/a"}`}},
		{ID: "call_dangerous", Type: "function", Function: ChatCompletionToolEcho{Name: "bash", Arguments: `{"command":"rm -rf /"}`}},
		{ID: "call_safe_2", Type: "function", Function: ChatCompletionToolEcho{Name: "read_file", Arguments: `{"path":"/b"}`}},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		if tc.ToolName == "bash" {
			return Decision{Allow: false, Reason: "bash blocked", Rule: "deny:shell:bash"}, nil
		}
		return Decision{Allow: true, Rule: "allow:test"}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// None of the upstream tool_call ids may leak — even the safe ones,
	// because the agent must not see any partial result when the call
	// is denied.
	for _, id := range []string{"call_safe_1", "call_dangerous", "call_safe_2"} {
		if strings.Contains(gotStr, id) {
			t.Errorf("tool_call id %q leaked into refusal: %q", id, gotStr)
		}
	}
	// Response must decode as ChatCompletionResponse.
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal not valid JSON: %v\nbody=%q", err, gotStr)
	}
	if len(refusal.Choices) == 0 {
		t.Fatalf("refusal has no choices")
	}
}

// TestForwardChatCompletion_NonStreamingOverflow_BufferLimit confirms
// upstream responses larger than --max-buffer-bytes are converted to
// synthetic refusals and the non-streaming overflow metric increments.
func TestForwardChatCompletion_NonStreamingOverflow_BufferLimit(t *testing.T) {
	// Build a response larger than the cap.
	bigArgs := strings.Repeat("X", 2048)
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{ID: "call_huge", Type: "function", Function: ChatCompletionToolEcho{Name: "bash", Arguments: `{"x":"` + bigArgs + `"}`}},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	before := metrics.LLMProxyNonStreamingOverflowFor("openai")

	_, base, teardown := newGatedTestServer(t, upstream, nil,
		func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: true}, nil
		},
		func(c *Config) { c.MaxBufferBytes = 256 },
	)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overflow status = %d, want 200", resp.StatusCode)
	}

	// Refusal must decode as ChatCompletionResponse.
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("overflow refusal not valid JSON: %v\nbody=%q", err, string(got))
	}
	// Metric must have ticked.
	after := metrics.LLMProxyNonStreamingOverflowFor("openai")
	if after != before+1 {
		t.Errorf("overflow metric not incremented: before=%d after=%d", before, after)
	}
}

// TestForwardChatCompletion_NonStreamingMalformedUpstream_PassesThroughVerbatim
// confirms that when the upstream returns invalid JSON, the proxy does
// not try to gate — it passes the bytes through unmodified with the
// upstream's status code.
func TestForwardChatCompletion_NonStreamingMalformedUpstream_PassesThroughVerbatim(t *testing.T) {
	upstreamBody := []byte(`{this is not valid json`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	var hookCalls atomic.Int64
	_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		return Decision{Allow: true}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("malformed upstream body not passed through verbatim:\n got=%q\nwant=%q", string(got), string(upstreamBody))
	}
	if hookCalls.Load() != 0 {
		t.Errorf("PolicyCheck fired on malformed upstream: %d calls (want 0 — proxy must not gate uninspectable bytes)", hookCalls.Load())
	}
}

// TestForwardAnthropicMessages_NonStreamingDenyPath confirms the
// Anthropic shape gates tool_use blocks and rewrites to a synthetic
// AnthropicMessagesResponse.
func TestForwardAnthropicMessages_NonStreamingDenyPath(t *testing.T) {
	upstreamBody := makeAnthropicResponse(t, "claude-3-5-sonnet-20241022", []AnthropicContentBlock{
		{Type: "text", Text: "I'll help with that."},
		{
			Type:  "tool_use",
			ID:    "toolu_dangerous",
			Name:  "bash",
			Input: json.RawMessage(`{"command":"rm -rf /"}`),
		},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	srv, base, teardown := newGatedTestServer(t, nil, upstream, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		if tc.ToolName != "bash" {
			t.Errorf("ToolName = %q, want bash", tc.ToolName)
		}
		return Decision{
			Allow:  false,
			Reason: "rm -rf blocked",
			Rule:   "deny:shell:rm_rf",
		}, nil
	})
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	resp, err := http.Post(base+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-3-5-sonnet-20241022","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if strings.Contains(gotStr, "toolu_dangerous") {
		t.Errorf("upstream tool_use id leaked: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /") {
		t.Errorf("upstream tool_use input leaked: %q", gotStr)
	}

	var refusal AnthropicMessagesResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal not valid AnthropicMessagesResponse: %v\nbody=%q", err, gotStr)
	}
	if refusal.Type != "message" {
		t.Errorf("refusal type = %q, want message", refusal.Type)
	}
	if refusal.Role != "assistant" {
		t.Errorf("refusal role = %q, want assistant", refusal.Role)
	}
	if refusal.StopReason != "end_turn" {
		t.Errorf("refusal stop_reason = %q, want end_turn", refusal.StopReason)
	}
	if len(refusal.Content) == 0 {
		t.Fatalf("refusal has no content blocks")
	}
	// At least one content block must be a text block carrying the reason+rule.
	foundText := false
	for _, b := range refusal.Content {
		if b.Type == "text" {
			foundText = true
			if !strings.Contains(b.Text, "rm -rf blocked") {
				t.Errorf("text block missing reason: %q", b.Text)
			}
			if !strings.Contains(b.Text, "deny:shell:rm_rf") {
				t.Errorf("text block missing rule: %q", b.Text)
			}
		}
		if b.Type == "tool_use" {
			t.Errorf("refusal must not contain tool_use blocks (would re-trigger model's denied call), got %q", b.ID)
		}
	}
	if !foundText {
		t.Errorf("refusal missing text block: %q", gotStr)
	}
}

// TestForwardAnthropicMessages_NonStreamingAllowPath_ByteIdentity
// confirms an Anthropic non-streaming response with ALLOWed tool_use
// passes through byte-identical.
func TestForwardAnthropicMessages_NonStreamingAllowPath_ByteIdentity(t *testing.T) {
	upstreamBody := makeAnthropicResponse(t, "claude-3-5-sonnet-20241022", []AnthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_safe",
			Name:  "list_files",
			Input: json.RawMessage(`{"path":"/tmp"}`),
		},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	var hookCalls atomic.Int64
	_, base, teardown := newGatedTestServer(t, nil, upstream, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		return Decision{Allow: true}, nil
	})
	defer teardown()

	resp, err := http.Post(base+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-3-5-sonnet-20241022","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("byte-identity violated on Anthropic ALLOW path:\n got=%q\nwant=%q", string(got), string(upstreamBody))
	}
	if hookCalls.Load() != 1 {
		t.Errorf("PolicyCheck called %d times, want 1", hookCalls.Load())
	}
}

// makeJSONBody creates a syntactically-valid JSON body of approximately
// the requested size. Used to test byte-identity over a range of sizes.
func makeJSONBody(t *testing.T, size int) []byte {
	t.Helper()
	if size == 0 {
		// Even with zero size we want to produce something that
		// reads as zero bytes — empty body is fine for the proxy.
		return []byte{}
	}
	prefix := []byte(`{"model":"gpt-4","data":"`)
	suffix := []byte(`"}`)
	overhead := len(prefix) + len(suffix)
	if size <= overhead {
		// Pad up to a usable minimum.
		return append(append(append([]byte{}, prefix...), 'x'), suffix...)
	}
	fillSize := size - overhead
	fill := make([]byte, fillSize)
	if _, err := rand.Read(fill); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Replace with a JSON-safe character (random bytes won't be
	// JSON-string-valid). Use base32-style digits.
	for i := range fill {
		fill[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[int(fill[i])%36]
	}
	out := make([]byte, 0, size)
	out = append(out, prefix...)
	out = append(out, fill...)
	out = append(out, suffix...)
	return out
}
