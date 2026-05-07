package llmproxy

// refusal.go ships the operator-grade synthetic refusal builder A24
// wires into Server.BuildRefusal — replacing A22's minimal default
// (defaultRefusalBytes in streaming.go) with text the agent reads,
// the human reviewer reads, and the audit log preserves.
//
// Differences vs the default:
//
//   - Includes the rule that fired ("deny:shell:rm_rf", ...) so the
//     agent's logs explain the verdict without operators having to
//     cross-reference the audit JSONL by approval id.
//   - On REQUIRE_APPROVAL, embeds BOTH the approval URL the human
//     visits AND the approval_id with a hint to round-trip it through
//     `_meta.dev.agentguard/approval_id` on retry. Closes the
//     "approve once, model proceeds" loop with Phase 4B A19b's
//     central-server approval_id round-trip.
//   - Provider-specific shape (per Phase 4A locked decisions):
//       OpenAI:   assistant-text content delta + finish_reason: "stop"
//                 + [DONE]. NOT role: "tool" (rejected at Phase 4A
//                 § 5.3 because the OpenAI SDKs hang on missing
//                 `tool_call_id` when role: "tool" is synthesized).
//       Anthropic: text content_block at the buffered tool_use's index
//                  + message_delta with stop_reason: end_turn +
//                  message_stop. The buffered content_block_start was
//                  discarded on the DENY path (streaming.go drops it
//                  with the rest of the buffered events) so the
//                  synthetic emits a fresh content_block_start at the
//                  same index.
//
// The buffer-overflow refusal (Rule="deny:llm_api_proxy:buffer_overflow")
// gets a tailored message that names the operator-tunable cap so
// recovery is mechanical rather than mysterious.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BuildRefusalRich is the function A24 wires into Server.BuildRefusal.
// Called by streaming.go's gateAndFlush* on DENY/REQUIRE_APPROVAL or
// by the overflow path with a synthetic Decision (see streaming.go's
// runOpenAIStreamLoop / runAnthropicStreamLoop). Also called by F9
// (B2) for non-streaming refusals via the same hook — the
// ctx.NonStreaming flag picks the shape.
//
// Always returns a non-nil byte slice: an empty refusal would leave
// the SSE stream open (or yield a zero-length response on the
// non-streaming path) and SDK clients would hang.
func BuildRefusalRich(provider string, decision Decision, ctx *RefusalContext) []byte {
	msg := buildRefusalMessage(decision)
	nonStreaming := ctx != nil && ctx.NonStreaming
	model := ""
	if ctx != nil {
		model = ctx.Model
	}

	switch provider {
	case "openai":
		if nonStreaming {
			return buildOpenAIRefusalNonStreaming(msg, model)
		}
		return buildOpenAIRefusalSSE(msg)
	case "anthropic":
		if nonStreaming {
			return buildAnthropicRefusalNonStreaming(msg, model)
		}
		idx := 0
		if ctx != nil && ctx.AnthropicToolUseIndex >= 0 {
			idx = ctx.AnthropicToolUseIndex
		}
		return buildAnthropicRefusalSSE(msg, idx)
	default:
		// Defensive: A22 always passes "openai" or "anthropic". If a
		// new provider lands without updating this switch, fall back
		// to the OpenAI shape — most upstreams accept it as a
		// degenerate text-completion (or chat.completion) response.
		if nonStreaming {
			return buildOpenAIRefusalNonStreaming(msg, model)
		}
		return buildOpenAIRefusalSSE(msg)
	}
}

// buildRefusalMessage assembles the human-readable text that goes
// inside the synthetic SSE event. The exact string is asserted on by
// the refusal tests so the operator-facing copy is reviewable in
// version control rather than buried in test fixtures.
func buildRefusalMessage(d Decision) string {
	if d.Rule == "deny:llm_api_proxy:buffer_overflow" {
		return buildOverflowMessage(d)
	}

	var b strings.Builder
	b.WriteString("AgentGuard ")

	if d.RequiresApproval || d.ApprovalURL != "" || d.ApprovalID != "" {
		b.WriteString("paused this action pending human approval.")
		b.WriteString("\n\nReason: ")
		b.WriteString(refusalReasonOrDefault(d, "policy required human approval"))
		if d.Rule != "" {
			b.WriteString("\nRule: ")
			b.WriteString(d.Rule)
		}
		if d.ApprovalURL != "" {
			b.WriteString("\n\nApproval URL: ")
			b.WriteString(d.ApprovalURL)
		}
		if d.ApprovalID != "" {
			b.WriteString("\nApproval ID: ")
			b.WriteString(d.ApprovalID)
			b.WriteString(" (preserve in _meta.dev.agentguard/approval_id on retry to resume after approval)")
		}
		b.WriteString("\n\nWait for human approval, then retry the same call.")
		return b.String()
	}

	b.WriteString("denied this action.")
	b.WriteString("\n\nReason: ")
	b.WriteString(refusalReasonOrDefault(d, "tool call denied by AgentGuard policy"))
	if d.Rule != "" {
		b.WriteString("\nRule: ")
		b.WriteString(d.Rule)
	}
	return b.String()
}

// buildOverflowMessage renders the dedicated copy for the
// buffer-overflow refusal. Includes the operator-tunable knob name so
// recovery is mechanical.
func buildOverflowMessage(d Decision) string {
	var b strings.Builder
	b.WriteString("AgentGuard refused this tool call: its accumulated arguments exceeded the gating buffer cap.")
	b.WriteString("\n\nReason: ")
	b.WriteString(refusalReasonOrDefault(d, "tool call arguments exceed gating buffer"))
	b.WriteString("\nRule: ")
	if d.Rule != "" {
		b.WriteString(d.Rule)
	} else {
		b.WriteString("deny:llm_api_proxy:buffer_overflow")
	}
	b.WriteString("\n\nThe per-stream buffer is bounded by the proxy's --max-buffer-bytes flag (default 1 MiB).")
	b.WriteString(" Operators who legitimately need larger tool-call arguments can raise the cap, ")
	b.WriteString("but the more common cause is a model emitting runaway JSON; consider asking the agent to summarise.")
	return b.String()
}

// refusalReasonOrDefault returns d.Reason when non-empty, else fallback.
// Keeps copy uniform when the central server returns a deny without a
// human-readable reason (rare; defensive).
func refusalReasonOrDefault(d Decision, fallback string) string {
	if d.Reason != "" {
		return d.Reason
	}
	return fallback
}

// buildOpenAIRefusalSSE emits the OpenAI-shape synthetic refusal: one
// assistant-role content delta carrying the message, a finish_reason of
// "stop", followed by the canonical [DONE] sentinel. SDKs treat this
// as a normal stream termination — no client-side hang because the
// finish_reason resets any in-flight tool_call accumulation state in
// SDK clients that observe one.
func buildOpenAIRefusalSSE(message string) []byte {
	payload := map[string]interface{}{
		// Synthetic id; SDKs accept any non-empty string.
		"id":      "agentguard-refusal",
		"object":  "chat.completion.chunk",
		"created": 0,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"delta": map[string]interface{}{
					"role":    "assistant",
					"content": message,
				},
				"finish_reason": "stop",
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Marshal of a known-shape map cannot fail in practice; the
		// fallback keeps the stream well-formed if it ever does.
		fallback, _ := json.Marshal(map[string]string{"error": "agentguard refusal marshal failed"})
		return []byte("data: " + string(fallback) + "\n\ndata: [DONE]\n\n")
	}
	return []byte("data: " + string(b) + "\n\ndata: [DONE]\n\n")
}

// buildOpenAIRefusalNonStreaming emits the synthetic refusal as a
// single non-streaming OpenAI ChatCompletionResponse JSON object — the
// shape SDK clients decode when they POST with stream=false. F9 (B2)
// wires this path; the streaming path stays on buildOpenAIRefusalSSE.
//
// The response intentionally omits tool_calls (the model's tool_call is
// dropped on the deny path) and sets finish_reason="stop" so SDK
// clients treat the synthetic message as a normal assistant turn that
// completes the conversation cleanly.
//
// model is the original request's model name when available; empty
// falls back to "agentguard-refusal" so the response is still a valid
// JSON object the SDK can decode without errors on the model field.
func buildOpenAIRefusalNonStreaming(message, model string) []byte {
	if model == "" {
		model = "agentguard-refusal"
	}
	payload := map[string]interface{}{
		"id":      "agentguard-refusal",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": message,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     0,
			"completion_tokens": 0,
			"total_tokens":      0,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Marshal of a known-shape map cannot fail in practice; the
		// fallback keeps the response decodable as a minimal JSON
		// object.
		return []byte(`{"id":"agentguard-refusal","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"AgentGuard refusal"},"finish_reason":"stop"}]}`)
	}
	return b
}

// buildAnthropicRefusalNonStreaming emits the synthetic refusal as a
// single non-streaming AnthropicMessagesResponse JSON object. Mirrors
// buildOpenAIRefusalNonStreaming for the Anthropic shape: the
// content array carries one text block (no tool_use, since the
// upstream's tool_use is dropped on the deny path) and stop_reason is
// "end_turn" so the SDK does not expect a tool result to follow.
func buildAnthropicRefusalNonStreaming(message, model string) []byte {
	if model == "" {
		model = "agentguard-refusal"
	}
	payload := map[string]interface{}{
		"id":    "agentguard-refusal",
		"type":  "message",
		"role":  "assistant",
		"model": model,
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": message,
			},
		},
		"stop_reason": "end_turn",
		"usage": map[string]interface{}{
			"input_tokens":  0,
			"output_tokens": 0,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return []byte(`{"id":"agentguard-refusal","type":"message","role":"assistant","content":[{"type":"text","text":"AgentGuard refusal"}],"stop_reason":"end_turn"}`)
	}
	return b
}

// buildAnthropicRefusalSSE emits the Anthropic-shape synthetic refusal:
//
//   1. content_block_start (text) at toolUseIndex — the buffered
//      tool_use's content_block_start was discarded on the DENY path,
//      so this is the first start event the client sees at this index.
//   2. content_block_delta (text_delta) carrying the message body.
//   3. content_block_stop closing the text block.
//   4. message_delta with stop_reason: end_turn — overrides any
//      tool_use stop_reason that would have otherwise come from
//      upstream and tells the SDK no tool result is needed.
//   5. message_stop terminating the message.
//
// Each event is `event: <name>\ndata: <json>\n\n` per the Anthropic
// streaming wire format (docs/LLM_API_PROXY.md § 5.2).
func buildAnthropicRefusalSSE(message string, toolUseIndex int) []byte {
	var buf bytes.Buffer

	emit := func(eventName string, payload map[string]interface{}) {
		body, err := json.Marshal(payload)
		if err != nil {
			// Defensive fallback (see buildOpenAIRefusalSSE rationale).
			body = []byte(`{"error":"agentguard refusal marshal failed"}`)
		}
		fmt.Fprintf(&buf, "event: %s\ndata: %s\n\n", eventName, string(body))
	}

	emit("content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": toolUseIndex,
		"content_block": map[string]interface{}{
			"type": "text",
			"text": "",
		},
	})

	emit("content_block_delta", map[string]interface{}{
		"type":  "content_block_delta",
		"index": toolUseIndex,
		"delta": map[string]interface{}{
			"type": "text_delta",
			"text": message,
		},
	})

	emit("content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": toolUseIndex,
	})

	emit("message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason": "end_turn",
		},
	})

	emit("message_stop", map[string]interface{}{
		"type": "message_stop",
	})

	return buf.Bytes()
}
