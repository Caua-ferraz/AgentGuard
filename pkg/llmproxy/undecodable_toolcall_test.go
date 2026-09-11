package llmproxy

// Audit B6: a non-streaming upstream body that fails strict decode but
// still carries a tool call must be refused, not forwarded ungated.
//
// The gap being closed: encoding/json aborts on a type-mismatched field
// the target struct declares, while a lenient client SDK ignores that
// field and executes the tool_calls sitting beside it. So the proxy's
// "I can't decode this, pass it through untouched" rule handed the agent
// a call the firewall never evaluated.
//
// The pre-existing contract is deliberately preserved and re-asserted
// here: a body with NO tool call still passes through verbatim with the
// policy hook untouched. This change narrows the passthrough, it does not
// reverse it — which is why
// TestForwardChatCompletion_NonStreamingMalformedUpstream_PassesThroughVerbatim
// still passes unmodified.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// upstreamServing returns a test upstream that answers 200 with body.
func upstreamServing(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A real OpenAI-compatible-shim response: every field is spec-shaped
// EXCEPT `created`, which is a string instead of an int. Go's decoder
// rejects the whole body; a Python or TypeScript SDK ignores the odd
// field and runs the tool call.
const shimBodyOpenAI = `{
  "id": "chatcmpl-shim",
  "object": "chat.completion",
  "created": "1730000000",
  "model": "gpt-4",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "tool_calls": [{
        "id": "call_ungated",
        "type": "function",
        "function": {"name": "bash", "arguments": "{\"command\":\"rm -rf /\"}"}
      }]
    },
    "finish_reason": "tool_calls"
  }]
}`

// Same idea for Anthropic: stop_reason arrives as a number instead of a
// string, tool_use block intact.
//
// Note it must be a genuine TYPE MISMATCH, not null. encoding/json treats
// a JSON null as a no-op for a non-pointer field — it leaves the zero
// value in place and returns no error — so a nulled field decodes fine
// and does not reproduce B6 at all. Only a value of the wrong type aborts
// the decode. TestProbeSucceedsWhereStrictDecodeFails guards this
// distinction, and caught exactly this mistake in an earlier draft of
// this fixture.
const shimBodyAnthropic = `{
  "id": "msg_shim",
  "type": "message",
  "role": "assistant",
  "model": "claude-3-5-sonnet",
  "stop_reason": 5,
  "content": [{
    "type": "tool_use",
    "id": "toolu_ungated",
    "name": "bash",
    "input": {"command": "rm -rf /"}
  }]
}`

func TestNonStreaming_UndecodableBodyWithToolCall_IsRefused(t *testing.T) {
	upstream := upstreamServing(t, shimBodyOpenAI)
	var hookCalls atomic.Int64
	srv, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		return Decision{Allow: true}, nil
	})
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	before := metrics.LLMProxyUndecodableToolCallFor("openai")
	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if bytes.Contains(got, []byte("call_ungated")) {
		t.Errorf("upstream tool_call reached the client — the whole point of B6:\n%s", gotStr)
	}
	if bytes.Contains(got, []byte("rm -rf /")) {
		t.Errorf("upstream tool_call arguments reached the client:\n%s", gotStr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (synthetic refusal keeps the SDK happy path)", resp.StatusCode)
	}

	// The refusal must be a well-formed response the SDK can read.
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal is not a valid ChatCompletionResponse: %v\nbody=%q", err, gotStr)
	}
	if len(refusal.Choices) == 0 || refusal.Choices[0].Message.Content == nil {
		t.Fatalf("refusal carries no message content: %q", gotStr)
	}
	if len(refusal.Choices[0].Message.ToolCalls) != 0 {
		t.Errorf("refusal must not carry tool calls, got %d", len(refusal.Choices[0].Message.ToolCalls))
	}

	if got := metrics.LLMProxyUndecodableToolCallFor("openai") - before; got != 1 {
		t.Errorf("undecodable-tool-call counter moved by %d, want 1 (operators must be able to see these)", got)
	}
	// The hook fires exactly once, and NOT to decide anything — the body
	// did not decode, so there is no tool call to evaluate. It runs to
	// drive the audit trail, the nil-RecordForcedAudit fallback that
	// auditDeniedToolCalls documents. Its verdict is ignored, which
	// TestNonStreaming_UndecodableToolCall_RefusedEvenWhenPolicyWouldAllow
	// proves: this hook returns Allow and the response is still a refusal.
	if hookCalls.Load() != 1 {
		t.Errorf("PolicyCheck fired %d times; want 1 (the audit-trail fallback)", hookCalls.Load())
	}
}

// A B6 refusal must never be silent. The llmproxy's metrics registry has
// no scrape endpoint, so the audit trail is the only place an operator
// can see that a call was refused — the same reasoning that made F1 wire
// RecordForcedAudit for malformed streaming completions.
func TestNonStreaming_UndecodableToolCall_IsAudited(t *testing.T) {
	upstream := upstreamServing(t, shimBodyOpenAI)
	srv, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{Allow: true}, nil
	})
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	var recorded []Decision
	var recordedChecks []ToolCallCheck
	srv.RecordForcedAudit = func(ctx context.Context, req *ToolCallCheck, d Decision) {
		recorded = append(recorded, d)
		recordedChecks = append(recordedChecks, *req)
	}

	req, _ := http.NewRequest(http.MethodPost, base+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "agent-7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if len(recorded) != 1 {
		t.Fatalf("RecordForcedAudit called %d times, want 1 — a refusal with no audit entry is invisible", len(recorded))
	}
	// The entry must carry the DENY the client received, not a policy
	// verdict (the F1/C3 fidelity rule).
	if recorded[0].Allow {
		t.Error("audited decision must be the forced DENY")
	}
	if recorded[0].Rule != "deny:llm_api_proxy:undecodable_tool_call" {
		t.Errorf("audited rule = %q, want the stable undecodable rule", recorded[0].Rule)
	}
	if recordedChecks[0].AgentID != "agent-7" {
		t.Errorf("audited agent = %q, want the request's X-Agent-ID", recordedChecks[0].AgentID)
	}
	if recordedChecks[0].Provider != "openai" {
		t.Errorf("audited provider = %q, want openai", recordedChecks[0].Provider)
	}
	if recordedChecks[0].Stream {
		t.Error("this is the non-streaming path; Stream must be false")
	}
}

func TestNonStreaming_UndecodableBodyWithToolUse_IsRefused_Anthropic(t *testing.T) {
	upstream := upstreamServing(t, shimBodyAnthropic)
	srv, base, teardown := newGatedTestServer(t, nil, upstream, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{Allow: true}, nil
	})
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	before := metrics.LLMProxyUndecodableToolCallFor("anthropic")
	resp, err := http.Post(base+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-3-5-sonnet","max_tokens":100,"messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if bytes.Contains(got, []byte("toolu_ungated")) || bytes.Contains(got, []byte("rm -rf /")) {
		t.Errorf("upstream tool_use reached the client:\n%s", got)
	}
	var refusal AnthropicMessagesResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal is not a valid AnthropicMessagesResponse: %v\nbody=%q", err, got)
	}
	for _, b := range refusal.Content {
		if b.Type == "tool_use" {
			t.Errorf("refusal still carries a tool_use block: %s", got)
		}
	}
	if got := metrics.LLMProxyUndecodableToolCallFor("anthropic") - before; got != 1 {
		t.Errorf("counter moved by %d, want 1", got)
	}
}

// The refusal is unconditional: --fail-mode allow governs "the guard is
// unreachable", not "the guard cannot see what the client will execute".
// Honouring it here would reopen the bypass, so it must not apply —
// matching the duplicate-JSON-key hard deny in streaming.go.
func TestNonStreaming_UndecodableToolCall_IgnoresFailModeAllow(t *testing.T) {
	upstream := upstreamServing(t, shimBodyOpenAI)
	srv, base, teardown := newGatedTestServer(t, upstream, nil,
		func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: true}, nil
		},
		func(c *Config) { c.FailMode = "allow" })
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if bytes.Contains(got, []byte("call_ungated")) {
		t.Errorf("--fail-mode allow let an ungated tool call through:\n%s", got)
	}
}

// A tool call the policy WOULD have allowed is still refused. The
// refusal is about not being able to gate reliably, not about the
// verdict — a body we cannot parse is a body whose arguments we cannot
// trust ourselves to have read the same way the client will.
func TestNonStreaming_UndecodableToolCall_RefusedEvenWhenPolicyWouldAllow(t *testing.T) {
	body := strings.Replace(shimBodyOpenAI, `{\"command\":\"rm -rf /\"}`, `{\"command\":\"ls -la\"}`, 1)
	upstream := upstreamServing(t, body)
	srv, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{Allow: true}, nil
	})
	defer teardown()
	srv.BuildRefusal = BuildRefusalRich

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if bytes.Contains(got, []byte("call_ungated")) {
		t.Errorf("benign-looking undecodable tool call was forwarded ungated:\n%s", got)
	}
}

// The counterweight, and the reason this change is a narrowing rather
// than a reversal: an undecodable body with NO tool call keeps its
// verbatim passthrough, the policy hook stays untouched, and the counter
// does not move.
func TestNonStreaming_UndecodableBodyWithoutToolCall_StillPassesThrough(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"type mismatch, no tool call", `{"id":"x","object":"chat.completion","created":"nope","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`},
		{"not json at all", `{this is not valid json`},
		{"empty body", ``},
		{"json array", `[1,2,3]`},
		{"tool_calls only mentioned in prose", `{"created":"x","choices":[{"message":{"role":"assistant","content":"I could use tool_calls here"}}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := upstreamServing(t, tc.body)
			var hookCalls atomic.Int64
			_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, c *ToolCallCheck) (Decision, error) {
				hookCalls.Add(1)
				return Decision{Allow: true}, nil
			})
			defer teardown()

			before := metrics.LLMProxyUndecodableToolCallFor("openai")
			resp, err := http.Post(base+"/v1/chat/completions", "application/json",
				strings.NewReader(`{"model":"gpt-4","messages":[]}`))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)

			if string(got) != tc.body {
				t.Errorf("body not passed through verbatim:\n got=%q\nwant=%q", got, tc.body)
			}
			if hookCalls.Load() != 0 {
				t.Errorf("PolicyCheck fired on uninspectable bytes: %d", hookCalls.Load())
			}
			if got := metrics.LLMProxyUndecodableToolCallFor("openai") - before; got != 0 {
				t.Errorf("counter moved by %d on a body with no tool call", got)
			}
		})
	}
}

// A body that decodes cleanly must never reach the probe. This is the
// latency guarantee in test form: the success path is untouched.
func TestNonStreaming_WellFormedBodyIsUnaffected(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{{
		ID: "call_ok", Type: "function",
		Function: ChatCompletionToolEcho{Name: "bash", Arguments: `{"command":"ls -la"}`},
	}})
	upstream := upstreamServing(t, string(upstreamBody))
	var hookCalls atomic.Int64
	_, base, teardown := newGatedTestServer(t, upstream, nil, func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		hookCalls.Add(1)
		return Decision{Allow: true}, nil
	})
	defer teardown()

	before := metrics.LLMProxyUndecodableToolCallFor("openai")
	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("allowed tool call must round-trip byte-identical:\n got=%q\nwant=%q", got, upstreamBody)
	}
	if hookCalls.Load() != 1 {
		t.Errorf("PolicyCheck fired %d times, want 1 (the normal gated path)", hookCalls.Load())
	}
	if got := metrics.LLMProxyUndecodableToolCallFor("openai") - before; got != 0 {
		t.Errorf("undecodable counter moved on a well-formed body: %d", got)
	}
}

// --- probe unit tests -------------------------------------------------

func TestHasLenientToolCall(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		body     string
		want     bool
	}{
		{"openai: shim body with tool call", "openai", shimBodyOpenAI, true},
		{"openai: text only", "openai", `{"created":"x","choices":[{"message":{"role":"assistant","content":"hi"}}]}`, false},
		{"openai: empty tool_calls array", "openai", `{"choices":[{"message":{"tool_calls":[]}}]}`, false},
		{"openai: tool call in a later choice", "openai", `{"choices":[{"message":{"content":"a"}},{"message":{"tool_calls":[{"id":"x"}]}}]}`, true},
		{"openai: unparseable", "openai", `{nope`, false},
		{"openai: null choices", "openai", `{"choices":null}`, false},
		{"anthropic: tool_use block", "anthropic", shimBodyAnthropic, true},
		{"anthropic: text block only", "anthropic", `{"stop_reason":null,"content":[{"type":"text","text":"hi"}]}`, false},
		{"anthropic: tool_use after text", "anthropic", `{"content":[{"type":"text"},{"type":"tool_use"}]}`, true},
		{"anthropic: unparseable", "anthropic", `not json`, false},
		{"unknown provider never refuses", "gemini", shimBodyOpenAI, false},
		{"empty body", "openai", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasLenientToolCall([]byte(tc.body), tc.provider); got != tc.want {
				t.Errorf("hasLenientToolCall(%s) = %v, want %v", tc.provider, got, tc.want)
			}
		})
	}
}

// The probe must succeed on exactly the bodies the strict decoder
// rejects — that divergence is the entire bug. If both agreed there
// would be nothing to fix, so pin it.
func TestProbeSucceedsWhereStrictDecodeFails(t *testing.T) {
	var strict ChatCompletionResponse
	if err := json.Unmarshal([]byte(shimBodyOpenAI), &strict); err == nil {
		t.Fatal("the shim body now decodes strictly; this fixture no longer reproduces B6")
	}
	if !hasLenientToolCall([]byte(shimBodyOpenAI), "openai") {
		t.Error("probe failed on a body a lenient client SDK would execute")
	}

	var strictA AnthropicMessagesResponse
	if err := json.Unmarshal([]byte(shimBodyAnthropic), &strictA); err == nil {
		t.Fatal("the Anthropic shim body now decodes strictly; fixture no longer reproduces B6")
	}
	if !hasLenientToolCall([]byte(shimBodyAnthropic), "anthropic") {
		t.Error("probe failed on an Anthropic body a lenient client would execute")
	}
}
