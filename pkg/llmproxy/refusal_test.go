package llmproxy

// refusal_test.go covers BuildRefusalRich: the operator-grade synthetic
// refusal text and provider-specific SSE shape wired into
// Server.BuildRefusal. Cross-checks:
//
//   - OpenAI shape: assistant-text content delta + finish_reason: "stop"
//                   followed by [DONE].
//   - Anthropic shape: content_block_start (text) at the buffered
//                     tool_use's index, content_block_delta (text_delta),
//                     content_block_stop, message_delta with
//                     stop_reason: "end_turn", message_stop.
//   - Reason + Rule + ApprovalID/URL all surface in the human-readable
//     message body.
//
// SSE parsing uses bufio to match the streaming tests' assertion style.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// parseSSEEvents splits raw SSE bytes into discrete events. Each event
// is a map of header lines (e.g. "event") plus a single "data" payload
// (the stripped JSON or "[DONE]" string).
type sseEvent struct {
	Event string
	Data  string
}

func parseSSEEvents(t *testing.T, raw []byte) []sseEvent {
	t.Helper()
	var out []sseEvent
	cur := sseEvent{}
	hasContent := false

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if hasContent {
				out = append(out, cur)
			}
			cur = sseEvent{}
			hasContent = false
			continue
		}
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.Event = strings.TrimPrefix(line, "event: ")
			hasContent = true
		case strings.HasPrefix(line, "data: "):
			cur.Data = strings.TrimPrefix(line, "data: ")
			hasContent = true
		}
	}
	if hasContent {
		out = append(out, cur)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	return out
}

// --- OpenAI shape ---

func TestBuildRefusalRich_OpenAIDeny(t *testing.T) {
	dec := Decision{
		Allow:  false,
		Reason: "system path blocked",
		Rule:   "deny:filesystem:/etc/**",
	}
	raw := BuildRefusalRich("openai", dec, &RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
	events := parseSSEEvents(t, raw)

	if len(events) != 2 {
		t.Fatalf("expected 2 SSE events (chunk + [DONE]), got %d: %s", len(events), string(raw))
	}
	if events[1].Data != "[DONE]" {
		t.Errorf("expected [DONE] sentinel, got %q", events[1].Data)
	}

	var payload struct {
		Choices []struct {
			Delta struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(events[0].Data), &payload); err != nil {
		t.Fatalf("decode chunk: %v", err)
	}
	if len(payload.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(payload.Choices))
	}
	c := payload.Choices[0]
	if c.Delta.Role != "assistant" {
		t.Errorf("delta.role = %q, want assistant", c.Delta.Role)
	}
	if c.FinishReason != "stop" {
		t.Errorf("finish_reason = %q, want stop", c.FinishReason)
	}
	if !strings.Contains(c.Delta.Content, "system path blocked") {
		t.Errorf("content missing reason: %q", c.Delta.Content)
	}
	if !strings.Contains(c.Delta.Content, "deny:filesystem:/etc/**") {
		t.Errorf("content missing rule: %q", c.Delta.Content)
	}
}

func TestBuildRefusalRich_OpenAIApproval(t *testing.T) {
	dec := Decision{
		Allow:            false,
		RequiresApproval: true,
		Reason:           "human approval required",
		Rule:             "require_approval:network:*",
		ApprovalID:       "ap_abc",
		ApprovalURL:      "http://127.0.0.1:8080/dashboard?approval=ap_abc",
	}
	raw := BuildRefusalRich("openai", dec, &RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
	events := parseSSEEvents(t, raw)

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[1].Data != "[DONE]" {
		t.Errorf("expected [DONE], got %q", events[1].Data)
	}

	var payload struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(events[0].Data), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	content := payload.Choices[0].Delta.Content
	if !strings.Contains(content, "approval") {
		t.Errorf("content missing approval mention: %q", content)
	}
	if !strings.Contains(content, "http://127.0.0.1:8080/dashboard?approval=ap_abc") {
		t.Errorf("content missing approval URL: %q", content)
	}
	if !strings.Contains(content, "ap_abc") {
		t.Errorf("content missing approval id: %q", content)
	}
	if !strings.Contains(content, "_meta.dev.agentguard/approval_id") {
		t.Errorf("content missing round-trip hint: %q", content)
	}
}

// --- Anthropic shape ---

func TestBuildRefusalRich_AnthropicDeny(t *testing.T) {
	dec := Decision{
		Allow:  false,
		Reason: "shell rm -rf blocked",
		Rule:   "deny:shell:rm_rf",
	}
	raw := BuildRefusalRich("anthropic", dec, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: 1})
	events := parseSSEEvents(t, raw)

	want := []string{"content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d: %s", len(want), len(events), string(raw))
	}
	for i, w := range want {
		if events[i].Event != w {
			t.Errorf("event[%d].Event = %q, want %q", i, events[i].Event, w)
		}
	}

	// Validate content_block_delta carries the message + rule.
	var delta struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Delta struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(events[1].Data), &delta); err != nil {
		t.Fatalf("decode delta: %v", err)
	}
	if delta.Delta.Type != "text_delta" {
		t.Errorf("delta.type = %q, want text_delta", delta.Delta.Type)
	}
	if !strings.Contains(delta.Delta.Text, "deny:shell:rm_rf") {
		t.Errorf("delta.text missing rule: %q", delta.Delta.Text)
	}
	if !strings.Contains(delta.Delta.Text, "shell rm -rf blocked") {
		t.Errorf("delta.text missing reason: %q", delta.Delta.Text)
	}

	// message_delta must rewrite stop_reason → end_turn.
	var msgDelta struct {
		Type  string `json:"type"`
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(events[3].Data), &msgDelta); err != nil {
		t.Fatalf("decode message_delta: %v", err)
	}
	if msgDelta.Delta.StopReason != "end_turn" {
		t.Errorf("stop_reason = %q, want end_turn", msgDelta.Delta.StopReason)
	}
}

func TestBuildRefusalRich_AnthropicApproval(t *testing.T) {
	dec := Decision{
		RequiresApproval: true,
		Reason:           "needs approval",
		Rule:             "require_approval:browser:*",
		ApprovalID:       "ap_xyz",
		ApprovalURL:      "http://127.0.0.1:8080/dashboard?approval=ap_xyz",
	}
	raw := BuildRefusalRich("anthropic", dec, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: 0})
	events := parseSSEEvents(t, raw)
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}

	var delta struct {
		Delta struct {
			Text string `json:"text"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(events[1].Data), &delta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(delta.Delta.Text, "ap_xyz") {
		t.Errorf("approval id missing from text: %q", delta.Delta.Text)
	}
	if !strings.Contains(delta.Delta.Text, "http://127.0.0.1:8080/dashboard?approval=ap_xyz") {
		t.Errorf("approval URL missing from text: %q", delta.Delta.Text)
	}
}

func TestBuildRefusalRich_AnthropicReplacesAtCorrectIndex(t *testing.T) {
	dec := Decision{Allow: false, Reason: "blocked", Rule: "deny:shell:x"}
	raw := BuildRefusalRich("anthropic", dec, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: 3})
	events := parseSSEEvents(t, raw)

	indexed := []sseEvent{events[0], events[1], events[2]} // start/delta/stop
	for i, e := range indexed {
		var v struct {
			Index int `json:"index"`
		}
		if err := json.Unmarshal([]byte(e.Data), &v); err != nil {
			t.Fatalf("decode event %d: %v", i, err)
		}
		if v.Index != 3 {
			t.Errorf("event %d (%s): index = %d, want 3", i, e.Event, v.Index)
		}
	}
}

func TestBuildRefusalRich_AnthropicNegativeIndexFallsBackToZero(t *testing.T) {
	dec := Decision{Allow: false, Reason: "blocked", Rule: "deny:shell:x"}
	raw := BuildRefusalRich("anthropic", dec, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: -1})
	events := parseSSEEvents(t, raw)
	var v struct {
		Index int `json:"index"`
	}
	if err := json.Unmarshal([]byte(events[0].Data), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Index != 0 {
		t.Errorf("negative index should fall back to 0, got %d", v.Index)
	}
}

// --- Buffer overflow message ---

func TestBuildRefusalRich_OverflowMessage(t *testing.T) {
	dec := Decision{
		Allow:  false,
		Reason: "tool call arguments exceed gating buffer",
		Rule:   "deny:llm_api_proxy:buffer_overflow",
	}
	raw := BuildRefusalRich("openai", dec, &RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
	events := parseSSEEvents(t, raw)
	if len(events) < 1 {
		t.Fatalf("no SSE events emitted")
	}
	var payload struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(events[0].Data), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	content := payload.Choices[0].Delta.Content
	for _, want := range []string{"buffer", "max-buffer-bytes", "deny:llm_api_proxy:buffer_overflow"} {
		if !strings.Contains(content, want) {
			t.Errorf("overflow message missing %q substring: %q", want, content)
		}
	}
}

// --- Direct tests of buildRefusalMessage helper ---

func TestBuildRefusalMessage_IncludesRule(t *testing.T) {
	got := buildRefusalMessage(Decision{
		Allow:  false,
		Reason: "blocked",
		Rule:   "deny:network:*.evil.com",
	})
	if !strings.Contains(got, "deny:network:*.evil.com") {
		t.Errorf("message missing rule: %q", got)
	}
	if !strings.Contains(got, "blocked") {
		t.Errorf("message missing reason: %q", got)
	}
}

func TestBuildRefusalMessage_NoRuleFallback(t *testing.T) {
	got := buildRefusalMessage(Decision{Allow: false})
	if got == "" {
		t.Errorf("empty refusal message")
	}
	// Should still mention denial / AgentGuard regardless of empty fields.
	if !strings.Contains(got, "AgentGuard") {
		t.Errorf("message missing AgentGuard prefix: %q", got)
	}
	if !strings.Contains(got, "denied") {
		t.Errorf("message should say denied: %q", got)
	}
}

func TestBuildRefusalMessage_ApprovalIncludesAllFields(t *testing.T) {
	got := buildRefusalMessage(Decision{
		RequiresApproval: true,
		Reason:           "human gate",
		Rule:             "require_approval:shell:*",
		ApprovalID:       "ap_1",
		ApprovalURL:      "https://x.example/dashboard?id=ap_1",
	})
	for _, want := range []string{"paused", "human gate", "require_approval:shell:*", "ap_1", "https://x.example/dashboard?id=ap_1", "_meta.dev.agentguard/approval_id"} {
		if !strings.Contains(got, want) {
			t.Errorf("approval message missing %q: %q", want, got)
		}
	}
}

func TestBuildRefusalRich_UnknownProviderFallsBackToOpenAI(t *testing.T) {
	raw := BuildRefusalRich("mystery", Decision{Allow: false, Reason: "x"}, &RefusalContext{})
	if !bytes.Contains(raw, []byte("[DONE]")) {
		t.Errorf("unknown-provider fallback should produce OpenAI shape with [DONE], got: %s", string(raw))
	}
}

func TestBuildRefusalRich_NilContextSafe(t *testing.T) {
	// Streaming.go always passes a non-nil ctx, but defensive: nil ctx
	// must not panic.
	raw := BuildRefusalRich("anthropic", Decision{Allow: false, Reason: "x"}, nil)
	if len(raw) == 0 {
		t.Errorf("nil ctx produced empty output")
	}
	events := parseSSEEvents(t, raw)
	if len(events) == 0 {
		t.Errorf("nil ctx produced no events")
	}
}

// --- F9 (B2) — non-streaming JSON-object refusals ---

// TestBuildRefusalRich_OpenAINonStreaming_ValidJSON confirms that
// passing NonStreaming=true on the context yields a single decodable
// ChatCompletionResponse JSON object (not SSE bytes) with the reason +
// rule embedded in choices[0].message.content.
func TestBuildRefusalRich_OpenAINonStreaming_ValidJSON(t *testing.T) {
	dec := Decision{
		Allow:  false,
		Reason: "shell rm -rf blocked",
		Rule:   "deny:shell:rm_rf",
	}
	raw := BuildRefusalRich("openai", dec, &RefusalContext{
		Provider:     "openai",
		NonStreaming: true,
		Model:        "gpt-4",
	})

	// Must NOT contain SSE markers.
	if bytes.Contains(raw, []byte("data: ")) {
		t.Errorf("non-streaming refusal contains SSE marker: %q", string(raw))
	}
	if bytes.Contains(raw, []byte("[DONE]")) {
		t.Errorf("non-streaming refusal contains [DONE] sentinel: %q", string(raw))
	}

	var resp ChatCompletionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("non-streaming refusal not a valid ChatCompletionResponse: %v\nbody=%q", err, string(raw))
	}
	if resp.Object != "chat.completion" {
		t.Errorf("object = %q, want chat.completion", resp.Object)
	}
	if resp.Model != "gpt-4" {
		t.Errorf("model = %q, want gpt-4", resp.Model)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(resp.Choices))
	}
	c := resp.Choices[0]
	if c.Message.Role != "assistant" {
		t.Errorf("role = %q, want assistant", c.Message.Role)
	}
	if c.FinishReason != "stop" {
		t.Errorf("finish_reason = %q, want stop", c.FinishReason)
	}
	content := ""
	if c.Message.Content != nil {
		content = *c.Message.Content
	}
	if !strings.Contains(content, "shell rm -rf blocked") {
		t.Errorf("content missing reason: %q", content)
	}
	if !strings.Contains(content, "deny:shell:rm_rf") {
		t.Errorf("content missing rule: %q", content)
	}
}

// TestBuildRefusalRich_AnthropicNonStreaming_ValidJSON confirms the
// Anthropic non-streaming refusal decodes as a valid Messages response.
func TestBuildRefusalRich_AnthropicNonStreaming_ValidJSON(t *testing.T) {
	dec := Decision{
		Allow:  false,
		Reason: "browser navigation blocked",
		Rule:   "deny:browser:bad_domain",
	}
	raw := BuildRefusalRich("anthropic", dec, &RefusalContext{
		Provider:     "anthropic",
		NonStreaming: true,
		Model:        "claude-3-5-sonnet-20241022",
	})

	if bytes.Contains(raw, []byte("event: ")) {
		t.Errorf("non-streaming refusal contains SSE event marker: %q", string(raw))
	}

	var resp AnthropicMessagesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("non-streaming refusal not a valid AnthropicMessagesResponse: %v\nbody=%q", err, string(raw))
	}
	if resp.Type != "message" {
		t.Errorf("type = %q, want message", resp.Type)
	}
	if resp.Role != "assistant" {
		t.Errorf("role = %q, want assistant", resp.Role)
	}
	if resp.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q, want claude-3-5-sonnet-20241022", resp.Model)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("stop_reason = %q, want end_turn", resp.StopReason)
	}
	if len(resp.Content) == 0 {
		t.Fatalf("content array empty: %q", string(raw))
	}
	for _, b := range resp.Content {
		if b.Type == "tool_use" {
			t.Errorf("non-streaming refusal must not contain tool_use blocks: %+v", b)
		}
	}
	if resp.Content[0].Type != "text" {
		t.Errorf("first block type = %q, want text", resp.Content[0].Type)
	}
	if !strings.Contains(resp.Content[0].Text, "browser navigation blocked") {
		t.Errorf("text missing reason: %q", resp.Content[0].Text)
	}
	if !strings.Contains(resp.Content[0].Text, "deny:browser:bad_domain") {
		t.Errorf("text missing rule: %q", resp.Content[0].Text)
	}
}

// TestBuildRefusalRich_StreamingFlagDistinguishesFormat confirms calling
// the builder with NonStreaming=false vs NonStreaming=true produces
// distinctly-shaped byte sequences (SSE vs JSON object).
func TestBuildRefusalRich_StreamingFlagDistinguishesFormat(t *testing.T) {
	dec := Decision{Allow: false, Reason: "test", Rule: "deny:test"}

	streaming := BuildRefusalRich("openai", dec, &RefusalContext{
		Provider:     "openai",
		NonStreaming: false,
	})
	nonStreaming := BuildRefusalRich("openai", dec, &RefusalContext{
		Provider:     "openai",
		NonStreaming: true,
	})

	if bytes.Equal(streaming, nonStreaming) {
		t.Fatalf("streaming and non-streaming refusal bytes are identical (flag has no effect)")
	}
	// Streaming must carry SSE markers; non-streaming must not.
	if !bytes.Contains(streaming, []byte("data: ")) {
		t.Errorf("streaming output missing SSE 'data: ' prefix: %q", string(streaming))
	}
	if !bytes.Contains(streaming, []byte("[DONE]")) {
		t.Errorf("streaming output missing [DONE] sentinel: %q", string(streaming))
	}
	if bytes.Contains(nonStreaming, []byte("data: ")) {
		t.Errorf("non-streaming output unexpectedly contains SSE marker: %q", string(nonStreaming))
	}
	// Non-streaming must decode as valid JSON.
	var resp ChatCompletionResponse
	if err := json.Unmarshal(nonStreaming, &resp); err != nil {
		t.Errorf("non-streaming output is not a valid JSON object: %v", err)
	}

	// Same exercise on Anthropic provider.
	streamingA := BuildRefusalRich("anthropic", dec, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: 0})
	nonStreamingA := BuildRefusalRich("anthropic", dec, &RefusalContext{Provider: "anthropic", NonStreaming: true})
	if bytes.Equal(streamingA, nonStreamingA) {
		t.Fatalf("Anthropic streaming and non-streaming refusal bytes are identical")
	}
	if !bytes.Contains(streamingA, []byte("event: ")) {
		t.Errorf("Anthropic streaming output missing SSE event marker: %q", string(streamingA))
	}
	if bytes.Contains(nonStreamingA, []byte("event: ")) {
		t.Errorf("Anthropic non-streaming output contains SSE event marker: %q", string(nonStreamingA))
	}
	var anth AnthropicMessagesResponse
	if err := json.Unmarshal(nonStreamingA, &anth); err != nil {
		t.Errorf("Anthropic non-streaming output is not a valid JSON object: %v", err)
	}
}

// TestBuildRefusalRich_NonStreaming_EmptyModelFallback confirms an empty
// Model field on the RefusalContext yields a synthetic model name (so
// the output remains decodable) rather than emitting an empty string.
func TestBuildRefusalRich_NonStreaming_EmptyModelFallback(t *testing.T) {
	dec := Decision{Allow: false, Reason: "x", Rule: "deny:y"}
	raw := BuildRefusalRich("openai", dec, &RefusalContext{Provider: "openai", NonStreaming: true})

	var resp ChatCompletionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Model == "" {
		t.Errorf("empty model field on non-streaming refusal — SDKs may error on missing model")
	}
}
