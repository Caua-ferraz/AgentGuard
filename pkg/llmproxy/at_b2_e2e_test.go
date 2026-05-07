package llmproxy

// at_b2_e2e_test.go — AT (Test Wrangler) audit-fixup verification.
//
// F9 closed audit blocker B2 by wiring non-streaming /v1/chat/completions
// and /v1/messages to inspect responses for tool_calls/tool_use, gate
// each through the policy hook, and replace the response with a synthetic
// refusal on non-ALLOW. F9's tests use a direct PolicyCheck stub. AT
// adds full-stack E2E that drives the proxy server with the production
// HTTPPolicyClient pointed at a mock central server (so every layer of
// /v1/check wire shape, transport tag, and audit instrumentation flows
// through the seam where the bug originally lived). Only the central
// server itself is mocked at the /v1/check seam (the only allowed mock,
// since the central server is not the SUT here).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// atCentralRecorder is a minimal mock of the AgentGuard central server's
// /v1/check endpoint used by AT's full-stack tests. It records every
// ActionRequest the proxy POSTs and lets the test pick a CheckResult to
// return per request.
type atCentralRecorder struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []policy.ActionRequest
	calls    atomic.Int64
	respond  func(ar policy.ActionRequest) policy.CheckResult
}

func newATCentralRecorder(t *testing.T, respond func(policy.ActionRequest) policy.CheckResult) *atCentralRecorder {
	t.Helper()
	rec := &atCentralRecorder{respond: respond}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.calls.Add(1)
		// Accept both legacy /v1/check and tenant-aware /v1/t/{tenant}/check
		// shapes the proxy might emit (HTTPPolicyClient uses the tenant-
		// aware shape per A24).
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var ar policy.ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&ar); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.mu.Lock()
		rec.requests = append(rec.requests, ar)
		rec.mu.Unlock()
		result := rec.respond(ar)
		if result.SchemaVersion == "" {
			result.SchemaVersion = "v1"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func (r *atCentralRecorder) Requests() []policy.ActionRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]policy.ActionRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

// newATFullStackProxy stands up a real LLM proxy Server (via
// newTestServer) wired to the production HTTPPolicyClient pointed at
// the supplied central recorder. This exercises the full stack:
// upstream → forwardChatCompletion / forwardWithToolCallGating →
// HTTPPolicyClient.Check → mock central → refusal builder → client.
func newATFullStackProxy(
	t *testing.T,
	upstreamOpenAI *httptest.Server,
	central *atCentralRecorder,
	mutators ...func(*Config),
) (string, func()) {
	t.Helper()
	combined := append([]func(*Config){
		func(c *Config) {
			c.GuardURL = central.srv.URL
			c.TenantID = "local"
		},
	}, mutators...)
	srv, base, teardown := newTestServer(t, upstreamOpenAI, nil, combined...)
	gate := NewHTTPPolicyClient(srv.cfg, nil)
	srv.PolicyCheck = gate.Check
	srv.BuildRefusal = BuildRefusalRich
	return base, teardown
}

// TestAT_B2_NonStreamingFullServer_AllowPath drives a non-streaming
// /v1/chat/completions through the full proxy. Upstream returns a
// tool_call response; central returns ALLOW. The client must receive
// the byte-identical upstream body (B2's invariant: ALLOW path is a
// pass-through). The central recorder must show exactly one /v1/check
// request with transport=llm_api_proxy.
func TestAT_B2_NonStreamingFullServer_AllowPath(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_at_allow",
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

	central := newATCentralRecorder(t, func(ar policy.ActionRequest) policy.CheckResult {
		return policy.CheckResult{Decision: policy.Allow, Rule: "allow:test:filesystem", Reason: "AT central allow"}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"list /tmp"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, upstreamBody) {
		t.Errorf("byte-identity violated on full-stack ALLOW:\n got=%q\nwant=%q", string(got), string(upstreamBody))
	}

	// Central must have been hit exactly once with the gated tool_call.
	if got := central.calls.Load(); got != 1 {
		t.Errorf("central /v1/check calls = %d, want 1", got)
	}
	reqs := central.Requests()
	if len(reqs) != 1 {
		t.Fatalf("central recorded %d requests, want 1", len(reqs))
	}
	ar := reqs[0]
	if ar.Meta["transport"] != "llm_api_proxy" {
		t.Errorf("transport tag = %q, want llm_api_proxy", ar.Meta["transport"])
	}
	if ar.Meta["provider"] != "openai" {
		t.Errorf("provider tag = %q, want openai", ar.Meta["provider"])
	}
	if ar.Meta["tool_name"] != "list_files" {
		t.Errorf("tool_name tag = %q, want list_files", ar.Meta["tool_name"])
	}
}

// TestAT_B2_NonStreamingFullServer_DenyPath drives a non-streaming
// chat completion through the full proxy with the central returning
// DENY. The client must receive a synthetic refusal whose
// chat.completion shape decodes correctly and whose content carries
// the rule string. No upstream tool_call id or arguments may leak.
func TestAT_B2_NonStreamingFullServer_DenyPath(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_at_deny_secret",
			Type: "function",
			Function: ChatCompletionToolEcho{
				Name:      "bash",
				Arguments: `{"command":"rm -rf /etc/at_secret"}`,
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
			Rule:     "deny:shell:rm_rf_at",
			Reason:   "AT central blocked rm -rf",
		}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"clean /etc"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (synthetic refusal must be 200 for SDK happy path)", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	// Upstream tool_call identifiers / args MUST NOT leak.
	if strings.Contains(gotStr, "call_at_deny_secret") {
		t.Errorf("upstream tool_call id leaked into refusal: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf /etc/at_secret") {
		t.Errorf("upstream tool_call arguments leaked into refusal: %q", gotStr)
	}

	// Refusal must decode as a normal chat.completion response.
	var refusal ChatCompletionResponse
	if err := json.Unmarshal(got, &refusal); err != nil {
		t.Fatalf("refusal not a valid ChatCompletionResponse: %v\nbody=%q", err, gotStr)
	}
	if len(refusal.Choices) == 0 {
		t.Fatalf("refusal has no choices")
	}
	choice := refusal.Choices[0]
	if choice.FinishReason != "stop" {
		t.Errorf("refusal finish_reason = %q, want stop", choice.FinishReason)
	}
	content := ""
	if choice.Message.Content != nil {
		content = *choice.Message.Content
	}
	if !strings.Contains(content, "deny:shell:rm_rf_at") {
		t.Errorf("refusal content missing rule: %q", content)
	}
	if !strings.Contains(content, "AT central blocked") {
		t.Errorf("refusal content missing reason: %q", content)
	}
}

// TestAT_B2_NonStreamingFullServer_ApprovalPath drives a non-streaming
// chat completion through the full proxy with the central returning
// REQUIRE_APPROVAL. The client refusal must include the approval URL
// and approval id so an SDK observing the response can prompt the
// human to approve.
func TestAT_B2_NonStreamingFullServer_ApprovalPath(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", []ChatCompletionToolCallEcho{
		{
			ID:   "call_at_approval",
			Type: "function",
			Function: ChatCompletionToolEcho{
				Name:      "send_email",
				Arguments: `{"to":"ceo@acme.com"}`,
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
			Decision:    policy.RequireApproval,
			Rule:        "require_approval:network:email",
			Reason:      "AT central wants human approval",
			ApprovalID:  "ap_at_e2e_xyz",
			ApprovalURL: "http://127.0.0.1:8080/dashboard?approval=ap_at_e2e_xyz",
		}
	})

	base, teardown := newATFullStackProxy(t, upstream, central)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if !strings.Contains(gotStr, "ap_at_e2e_xyz") {
		t.Errorf("approval_id missing from refusal: %q", gotStr)
	}
	if !strings.Contains(gotStr, "/dashboard?approval=ap_at_e2e_xyz") {
		t.Errorf("approval_url missing from refusal: %q", gotStr)
	}
	if !strings.Contains(gotStr, "require_approval:network:email") {
		t.Errorf("rule missing from refusal: %q", gotStr)
	}
}

// TestAT_B2_NonStreamingFullServer_MaxConcurrentStreams_DoesNotLimitNonStreaming
// asserts that F6's --max-concurrent-streams cap (R-Sec H3) does NOT
// apply to the non-streaming path. The non-streaming code path
// (forwardChatCompletion → forwardWithToolCallGating) does not call
// admitStream / releaseStream. Setting the cap to 2 and firing 25
// concurrent non-streaming requests must let all 25 succeed.
//
// This guards against a future regression where someone adds the
// admission gate to the non-streaming forwarder by mistake (it would
// fix nothing — non-streaming buffer ceilings are bounded per request
// — and would silently throttle batch-eval workloads).
func TestAT_B2_NonStreamingFullServer_MaxConcurrentStreams_DoesNotLimitNonStreaming(t *testing.T) {
	upstreamBody := makeOpenAIResponse(t, "gpt-4", nil) // No tool_calls; ALLOW shouldn't even fire central
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	central := newATCentralRecorder(t, func(ar policy.ActionRequest) policy.CheckResult {
		return policy.CheckResult{Decision: policy.Allow, Rule: "allow:test"}
	})

	base, teardown := newATFullStackProxy(t, upstream, central, func(c *Config) {
		// Set a tiny cap; non-streaming must NOT obey it.
		c.MaxConcurrentStreams = 2
	})
	defer teardown()

	const N = 25
	var wg sync.WaitGroup
	statuses := make([]int, N)
	bodies := make([][]byte, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/chat/completions",
				strings.NewReader(fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"hi-%d"}]}`, idx)))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs[idx] = err
				return
			}
			defer resp.Body.Close()
			statuses[idx] = resp.StatusCode
			bodies[idx], _ = io.ReadAll(resp.Body)
		}(i)
	}
	wg.Wait()

	for i := 0; i < N; i++ {
		if errs[i] != nil {
			t.Errorf("request %d errored: %v", i, errs[i])
			continue
		}
		if statuses[i] != http.StatusOK {
			t.Errorf("request %d status = %d, want 200 (non-streaming must not be throttled by --max-concurrent-streams=2)",
				i, statuses[i])
		}
		if !bytes.Equal(bodies[i], upstreamBody) {
			t.Errorf("request %d byte-identity violated", i)
		}
	}
}
