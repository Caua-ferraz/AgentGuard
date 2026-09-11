package llmproxy

// Lenient tool-call detection for bodies the typed decoders reject.
//
// The non-streaming gated path decodes an upstream response into
// ChatCompletionResponse / AnthropicMessagesResponse and gates whatever
// tool calls it finds. When that decode fails the body is forwarded
// verbatim, on the deliberate principle that AgentGuard never rewrites an
// already-corrupt wire.
//
// The gap is that "fails Go's strict decode" is a NARROWER condition than
// "the client cannot use it". encoding/json aborts on a type-mismatched
// field the target struct declares — `"created":"1730000000"` where
// Created is an int64, `"stop_reason":5` where it is a string — while a
// Python or TypeScript SDK parsing the same bytes ignores the odd field
// and happily executes the tool_calls sitting next to it. The result is
// a tool call the firewall never evaluates. No attacker is required: an
// OpenAI-compatible shim (vLLM, Ollama, LiteLLM, a cloud gateway) that
// stringifies one numeric field is enough, and pointing the proxy at one
// is a supported configuration via --upstream-openai.
//
// Worth knowing precisely which bodies this covers: a JSON null is NOT a
// type error. encoding/json treats null as a no-op for a non-pointer
// field, leaving the zero value and returning no error, so a nulled field
// still decodes and reaches the normal gate. Only a wrong-typed value
// diverts flow here. An unknown extra field is likewise ignored, so a
// provider ADDING fields never trips this path.
//
// So before falling back to passthrough, ask a narrower question: does
// this body carry a tool call at all? The probe types below declare ONLY
// the path down to the tool-call array. Every sibling field is
// undeclared, and encoding/json ignores undeclared fields, so nothing
// outside that path can impose a type constraint or fail the decode.
// That is precisely why the probe succeeds where the full struct fails,
// and why it cannot disagree with a lenient client about what is
// executable: it constrains nothing the client would ignore either.
//
// A substring search for `"tool_calls"` would be cheaper and wrong — it
// fires on any model reply that merely mentions the phrase in its prose,
// turning ordinary answers into refusals.
//
// Cost: this runs ONLY on the decode-failure branch. A body that decodes
// normally never reaches it, so the success path pays nothing — no extra
// parse, no extra allocation.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// openAIToolCallProbe mirrors just choices[].message.tool_calls from the
// OpenAI chat-completion response. json.RawMessage keeps each entry
// unparsed: presence is the only question being asked.
type openAIToolCallProbe struct {
	Choices []struct {
		Message struct {
			ToolCalls []json.RawMessage `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// anthropicToolUseProbe mirrors just content[].type from the Anthropic
// messages response. Only the discriminator is needed; the block body is
// irrelevant to the presence question.
type anthropicToolUseProbe struct {
	Content []struct {
		Type string `json:"type"`
	} `json:"content"`
}

// hasLenientToolCall reports whether body carries at least one tool call
// under a permissive decode, for a body the strict decoder already
// rejected.
//
// False means one of two things, and both are handled the same way by the
// caller (forward verbatim, as before): the body has no tool call, or it
// is so malformed that even the probe cannot read it — in which case a
// client SDK cannot reliably execute a tool call from it either.
//
// An unknown provider returns false, keeping the pre-existing passthrough
// for any transport this function has not been taught about.
func hasLenientToolCall(body []byte, provider string) bool {
	switch provider {
	case "openai":
		var p openAIToolCallProbe
		if err := json.Unmarshal(body, &p); err != nil {
			return false
		}
		for i := range p.Choices {
			if len(p.Choices[i].Message.ToolCalls) > 0 {
				return true
			}
		}
		return false

	case "anthropic":
		var p anthropicToolUseProbe
		if err := json.Unmarshal(body, &p); err != nil {
			return false
		}
		for i := range p.Content {
			if p.Content[i].Type == "tool_use" {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// undecodableToolCallDecision is the refusal returned when a body that
// failed strict decode turns out to carry a tool call.
//
// Deliberately NOT subject to --fail-mode allow, matching the
// duplicate-JSON-key refusal in streaming.go. --fail-mode answers "what
// should happen when the guard is unreachable"; here the guard is healthy
// and the problem is that it cannot see what the client will execute.
// Letting `allow` through would reopen exactly the bypass this closes.
func undecodableToolCallDecision(provider string) Decision {
	return Decision{
		Allow: false,
		Reason: "upstream response carries a tool call but does not decode as a valid " +
			provider + " response; refused rather than forwarded ungated",
		Rule: "deny:llm_api_proxy:undecodable_tool_call",
	}
}

// auditUndecodableToolCall records the refusal in the central audit trail,
// mirroring auditMalformedToolCalls (the F1/C3 fidelity fix) for the
// non-streaming undecodable case.
//
// Without this the refusal would be invisible from every angle: the
// llmproxy's process-local metrics registry has no scrape endpoint (see
// docs/OBSERVABILITY.md), so the counter alone tells an operator nothing,
// and a refused call that leaves no trace is exactly the "firewall goes
// dark when it manufactures its own refusal" gap F1 closed for streams.
//
// The recorded ToolCallCheck is deliberately thin — the body did not
// decode, so there is no tool name or arguments to report. What matters
// is that a refusal happened, under which rule, for which tenant and
// agent. When RecordForcedAudit is wired (both shipped binaries do) the
// entry carries the forced DENY the client actually received. When it is
// not (tests, embedders), it falls back to the normal PolicyCheck path,
// which still writes a transport-tagged entry — lower fidelity, as
// auditDeniedToolCalls documents, but not silence. The fallback's verdict
// is ignored: the refusal is unconditional either way.
//
// Runs only on this rare branch, never on a body that decodes.
func (s *Server) auditUndecodableToolCall(r *http.Request, provider, model string) {
	check := ToolCallCheck{
		Provider:  provider,
		Model:     model,
		TenantID:  s.cfg.TenantID,
		AgentID:   strings.TrimSpace(r.Header.Get("X-Agent-ID")),
		SessionID: strings.TrimSpace(r.Header.Get("X-Session-ID")),
		Stream:    false,
	}
	if check.AgentID == "" {
		check.AgentID = "llm-proxy"
	}
	if s.RecordForcedAudit != nil {
		s.RecordForcedAudit(r.Context(), &check, undecodableToolCallDecision(provider))
		return
	}
	_, _ = s.runPolicyCheck(r.Context(), check)
}
