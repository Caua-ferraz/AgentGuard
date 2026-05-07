package llmproxy

// at_integration_test.go — AT (Test Wrangler) audit-fixup verification.
//
// The audit-fixup workers' fixes touch interconnected code paths. AT
// adds two cross-fix integration tests that exercise multiple closed
// blockers together to confirm they compose correctly:
//
//   1. Streaming DENY path (B3/B4-adjacent) + transport-tagged audit
//      — the central server records `transport: "llm_api_proxy"` AND
//      the rule string is the gate's rule (NOT the streaming
//      orchestrator's pre-F5 hardcoded `policy_unreachable`).
//   2. Non-streaming DENY path (F9/B2) + transport-tagged audit —
//      F9's gating + the same transport-tag plumbing agree.
//
// Both tests use a real HTTPPolicyClient against a mock central
// recorder (see at_b2_e2e_test.go) so the /v1/check wire shape, the
// transport meta tag, and the rule construction all flow through
// production code.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestAT_FullStack_StreamingDenyPath_TransportTaggedAudit drives a
// streaming OpenAI request through the full proxy → gate → mock
// central. The model emits a tool_call; the central returns DENY
// with a specific rule. The test asserts:
//
//   1. The client sees a synthetic refusal with the central's rule
//      string (not a hardcoded streaming-side rule).
//   2. The central recorder shows exactly one /v1/check request,
//      tagged with `transport: "llm_api_proxy"`.
//   3. The central recorder's recorded request uses the gate's
//      build path (provider=openai, mapped_scope set).
func TestAT_FullStack_StreamingDenyPath_TransportTaggedAudit(t *testing.T) {
	// Upstream emits a streaming response with a complete tool_call.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_at_stream_deny","type":"function","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":\"rm -rf /\"}"}}]},"finish_reason":null}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-at1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	central := newATCentralRecorder(t, func(ar policy.ActionRequest) policy.CheckResult {
		return policy.CheckResult{
			Decision: policy.Deny,
			Rule:     "deny:shell:rm_rf_at_integration",
			Reason:   "AT integration: rm -rf blocked",
		}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"clean root"}],"stream":true}`
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// 1. Refusal must carry the gate's central-server rule, NOT the
	//    streaming orchestrator's old hardcoded `policy_unreachable`
	//    rule (pre-F5 bug shape that B4 closed).
	if !strings.Contains(gotStr, "deny:shell:rm_rf_at_integration") {
		t.Errorf("refusal missing central-server rule: %q", gotStr)
	}
	if strings.Contains(gotStr, "policy_unreachable") {
		t.Errorf("refusal contains pre-F5 hardcoded rule `policy_unreachable`; B4 regression: %q", gotStr)
	}

	// Upstream tool_call ids / args must NOT leak.
	if strings.Contains(gotStr, "call_at_stream_deny") {
		t.Errorf("upstream tool_call id leaked into streaming refusal: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /") {
		t.Errorf("upstream tool_call args leaked into streaming refusal: %q", gotStr)
	}

	// 2. Central recorder must show exactly one /v1/check, transport-tagged.
	if got := central.calls.Load(); got != 1 {
		t.Errorf("central /v1/check calls = %d, want 1 (one tool_call → one gate hit)", got)
	}
	reqs := central.Requests()
	if len(reqs) != 1 {
		t.Fatalf("central recorded %d requests, want 1", len(reqs))
	}
	ar := reqs[0]

	// 3. Transport tag must be `llm_api_proxy` (not blank, not `sdk`,
	//    not `mcp_gateway`). This is the dashboard-chip discriminator.
	if got := ar.Meta["transport"]; got != "llm_api_proxy" {
		t.Errorf("transport meta tag = %q, want llm_api_proxy", got)
	}
	if got := ar.Meta["provider"]; got != "openai" {
		t.Errorf("provider meta tag = %q, want openai", got)
	}
	// Streaming requests have `stream: "true"` in meta per
	// buildLLMMeta — pin the meta-tag plumbing as well.
	if got := ar.Meta["stream"]; got != "true" {
		t.Errorf("stream meta tag = %q, want \"true\" (streaming path indicator)", got)
	}
}

// TestAT_FullStack_NonStreamingDenyPath_TransportTaggedAudit is the
// non-streaming twin of the above — verifies F9's non-streaming gating
// path emits the same transport tag and rule-string contract as the
// streaming path. Closes the integration of B2 (non-streaming gating)
// + the transport-tag plumbing.
func TestAT_FullStack_NonStreamingDenyPath_TransportTaggedAudit(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_at_nonstream_deny",
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

	central := newATCentralRecorder(t, func(ar policy.ActionRequest) policy.CheckResult {
		return policy.CheckResult{
			Decision: policy.Deny,
			Rule:     "deny:shell:rm_rf_at_nonstream",
			Reason:   "AT non-streaming integration: rm -rf blocked",
		}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"clean root"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// Refusal must decode as a normal chat.completion JSON (not SSE).
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("non-streaming refusal not valid ChatCompletionResponse: %v\nbody=%q", err, gotStr)
	}
	if !strings.Contains(gotStr, "deny:shell:rm_rf_at_nonstream") {
		t.Errorf("refusal missing central-server rule: %q", gotStr)
	}
	if strings.Contains(gotStr, "call_at_nonstream_deny") {
		t.Errorf("upstream tool_call id leaked into non-streaming refusal: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /") {
		t.Errorf("upstream tool_call args leaked into non-streaming refusal: %q", gotStr)
	}

	// Verify the refusal echoes the original model name (B2 invariant).
	if refusal.Model != "gpt-4" {
		t.Errorf("refusal model = %q, want gpt-4", refusal.Model)
	}

	// Central recorder must show one /v1/check call with the same
	// transport tag as the streaming path. F9's non-streaming code
	// path goes through the same HTTPPolicyClient.Check entry point
	// → buildLLMMeta → identical transport tag.
	if got := central.calls.Load(); got != 1 {
		t.Errorf("central /v1/check calls = %d, want 1", got)
	}
	reqs := central.Requests()
	if len(reqs) != 1 {
		t.Fatalf("central recorded %d requests, want 1", len(reqs))
	}
	ar := reqs[0]
	if got := ar.Meta["transport"]; got != "llm_api_proxy" {
		t.Errorf("transport meta tag = %q, want llm_api_proxy (non-streaming F9 path must agree with streaming)", got)
	}
	if got := ar.Meta["provider"]; got != "openai" {
		t.Errorf("provider meta tag = %q, want openai", got)
	}
	// Non-streaming has stream != "true". Pin so a future regression
	// where someone forces stream:"true" everywhere is caught.
	if got := ar.Meta["stream"]; got == "true" {
		t.Errorf("stream meta tag = %q on non-streaming path; must NOT be \"true\"", got)
	}

	// Belt-and-braces: refusal body must NOT contain the streaming
	// SSE marker `data:` — F9's non-streaming refusal is pure JSON.
	if bytes.Contains(got, []byte("\ndata:")) {
		t.Errorf("non-streaming refusal contains SSE markers: %q", gotStr)
	}
}
