package llmproxy

// streaming.go is the SSE pause/resume/rewrite orchestrator:
//
//   - Pure content deltas pass through to the client byte-identical
//     to upstream (the byte-identity invariant on the ALLOW path).
//   - Tool_call deltas are accumulated; the orchestrator pauses
//     forwarding from the first tool_call delta until the call is
//     fully assembled.
//   - The assembled tool_call is gated through Server.PolicyCheck.
//     On ALLOW, the buffered SSE event bytes are replayed to the
//     client byte-identical and forwarding resumes. On DENY /
//     REQUIRE_APPROVAL, buffered events are discarded and a synthetic
//     refusal is emitted via Server.BuildRefusal (this file ships a
//     default fallback for tests).
//   - Per-stream buffer cap (--max-buffer-bytes) bounds memory; if
//     accumulated tool_call arguments exceed the cap, a synthetic
//     refusal with reason "tool call arguments exceed gating buffer"
//     fires and the metric agentguard_llmproxy_buffer_overflow_total
//     increments.
//
// Per-request goroutine isolation is the hard rule: each request
// constructs its own accumulator and never shares it. The orchestrator
// holds no global state.
//
// Per docs/LLM_API_PROXY.md § 6 we use a hand-rolled bufio.Reader
// loop (not bufio.Scanner) because SSE events have no hard line
// bound and the scanner's default cap (64 KiB) is awkward to raise.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// RefusalContext is the input to Server.BuildRefusal. Carries
// everything the builder needs to construct a provider-specific
// synthetic refusal payload.
type RefusalContext struct {
	// Provider is "openai" or "anthropic". Used to pick the right
	// SSE event shape.
	Provider string

	// OriginalToolCall is the parsed tool call that was denied. May
	// be a zero-value when the refusal fires for a non-tool-call
	// cause (buffer overflow before any complete tool_call landed).
	OriginalToolCall ToolCallCheck

	// AnthropicToolUseIndex is the content_block index of the
	// in-flight tool_use the refusal is replacing. -1 when not
	// applicable (overflow before any content_block_start arrived,
	// or OpenAI provider).
	AnthropicToolUseIndex int

	// NonStreaming flips the refusal builder from "SSE event bytes"
	// (the streaming path's shape — assistant-text content delta +
	// [DONE] for OpenAI; content_block_* events for Anthropic) to a
	// single non-streaming JSON object the SDK decodes as a normal
	// chat.completion / message response. The non-streaming
	// /v1/chat/completions and /v1/messages forwarders set this; the
	// streaming orchestrator never does (zero-value preserves SSE).
	//
	// Model is the original request's model string, surfaced into the
	// synthetic non-streaming response so SDKs that index by model
	// don't see "" / unknown-model errors. Optional; empty falls back
	// to "agentguard-refusal" in the builder.
	NonStreaming bool
	Model        string
}

// dispatchStreamingUpstream POSTs the request body to the upstream
// and returns the live response. On success the caller is responsible
// for closing resp.Body. On context cancel or network failure an
// error is returned (no response).
func (s *Server) dispatchStreamingUpstream(
	ctx context.Context,
	upstream *url.URL,
	path string,
	srcHeader http.Header,
	body []byte,
) (*http.Response, error) {
	if upstream == nil {
		return nil, errors.New("upstream URL not configured")
	}
	target := *upstream
	target.Path = joinPath(upstream.Path, path)

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build streaming upstream request: %w", err)
	}
	copyForwardableHeaders(srcHeader, req.Header)
	rewriteUserAgent(req.Header, srcHeader.Get("User-Agent"))
	req.Host = upstream.Host

	// Streaming responses must NOT carry a request-level timeout —
	// the http.Client's Timeout is 0 by construction (see NewServer).
	// Cancellation rides through ctx.
	resp, err := s.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("streaming upstream %s: %w", target.String(), err)
	}
	return resp, nil
}

// copyStreamingResponseHeaders copies upstream headers (filtered for
// hop-by-hop) into the client response. Must be called before any
// w.Write — once headers flush they freeze.
//
// Sets X-Accel-Buffering: no defensively in case anything in the
// proxy chain (e.g. nginx) would otherwise buffer SSE.
func (s *Server) copyStreamingResponseHeaders(w http.ResponseWriter, upstream *http.Response) {
	copyForwardableHeaders(upstream.Header, w.Header())
	if w.Header().Get("X-Accel-Buffering") == "" {
		w.Header().Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(upstream.StatusCode)
}

// streamingForwardError writes a JSON error envelope when streaming
// setup fails BEFORE we've sent any bytes downstream. After the first
// flush it's too late — we'd corrupt the SSE stream — so the
// orchestrator never calls this past the headers boundary.
func (s *Server) streamingForwardError(w http.ResponseWriter, err error) {
	writeJSONError(w, http.StatusBadGateway, fmt.Errorf("streaming proxy: %w", err))
}

// readSSEEvent reads one complete Server-Sent Event from r — every
// line up to (and including) the blank-line terminator. Returns the
// raw event bytes (joined with '\n', trailing "\n\n").
//
// We do NOT use bufio.Scanner per docs/LLM_API_PROXY.md § 6 — events
// can be larger than the scanner's default 64 KiB and multiline data
// fields require more state than a tokenizer.
//
// Returns io.EOF at end of stream. A partial trailing event (file
// ended before blank line) is returned with err=io.EOF and the
// accumulated bytes; callers should still attempt to dispatch it.
func readSSEEvent(r *bufio.Reader, maxEventBytes int) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			buf.Write(line)
			if maxEventBytes > 0 && buf.Len() > maxEventBytes {
				return buf.Bytes(), errSSEEventTooLarge
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && buf.Len() > 0 {
				return buf.Bytes(), io.EOF
			}
			return buf.Bytes(), err
		}
		// Blank line terminates the event. SSE spec: a blank line is
		// just "\n" or "\r\n".
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			return buf.Bytes(), nil
		}
	}
}

var errSSEEventTooLarge = errors.New("sse event exceeded buffer cap")

// runPolicyCheck invokes Server.PolicyCheck. Default behaviour when
// nil: ALLOW. This makes the streaming pipe testable without the gate
// wired and matches the rest of the package's nil-safety pattern.
func (s *Server) runPolicyCheck(ctx context.Context, tc ToolCallCheck) (Decision, error) {
	// SECURITY (audit H3): reject tool-call arguments that contain duplicate
	// JSON keys before evaluating policy. The gate projects from a Go map
	// (last-wins on duplicates) while the ALLOW path replays the raw argument
	// bytes; a first-wins downstream executor would then act on a different
	// value than the one gated — a parser-differential bypass. Fail closed
	// regardless of the wired PolicyCheck (this is a hard deny, nil error, so
	// it is not subject to --fail-mode allow).
	if hasDuplicateJSONKeys(tc.RawArguments) {
		return Decision{
			Allow:  false,
			Reason: "tool call arguments contain duplicate JSON keys (ambiguous to gate; refused)",
			Rule:   "deny:llm_api_proxy:duplicate_argument_key",
		}, nil
	}
	if s.PolicyCheck == nil {
		return Decision{Allow: true, Rule: "allow:llm_api_proxy:no_hook"}, nil
	}
	return s.PolicyCheck(ctx, &tc)
}

// buildRefusal calls Server.BuildRefusal with a sane default fallback.
// The default emits a minimal SSE refusal so unit tests can exercise
// the deny path without the rich builder wired.
func (s *Server) buildRefusal(provider string, decision Decision, ctx *RefusalContext) []byte {
	if s.BuildRefusal != nil {
		return s.BuildRefusal(provider, decision, ctx)
	}
	return defaultRefusalBytes(provider, decision, ctx)
}

// defaultRefusalBytes is the test-only fallback used when
// Server.BuildRefusal is nil. Emits a minimal payload that closes the
// stream cleanly so SDK clients don't hang. The production refusal
// builder lives in refusal.go and is wired by main.go.
//
// Important: the OpenAI shape is assistant-text + [DONE]. The
// `role: "tool"` shape was rejected because the response schema only
// emits assistant role and SDKs hang on missing `tool_call_id`.
//
// Honours ctx.NonStreaming for the non-streaming forwarders. Non-
// streaming refusals are single JSON objects shaped like a normal
// upstream response — SDKs decode them without going through SSE
// parsing.
func defaultRefusalBytes(provider string, decision Decision, ctx *RefusalContext) []byte {
	msg := decision.Reason
	if msg == "" {
		msg = "tool call denied by AgentGuard policy"
	}
	full := "AgentGuard denied this action: " + msg

	if ctx != nil && ctx.NonStreaming {
		return defaultRefusalNonStreamingBytes(provider, full, ctx.Model)
	}

	switch provider {
	case "openai":
		// Build a single content-delta event followed by [DONE]. The
		// content string is JSON-escaped via json.Marshal so the
		// payload is always valid even if `full` contains quotes.
		quoted, _ := json.Marshal(full)
		event := fmt.Sprintf(
			`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":%s},"finish_reason":"stop"}]}`,
			string(quoted),
		)
		return []byte(event + "\n\n" + "data: [DONE]\n\n")

	case "anthropic":
		idx := 0
		if ctx != nil && ctx.AnthropicToolUseIndex >= 0 {
			idx = ctx.AnthropicToolUseIndex
		}
		quoted, _ := json.Marshal(full)
		// Replace the tool_use at idx with a text content_block, then
		// rewrite stop_reason to "end_turn" so the SDK doesn't expect
		// a tool result to follow.
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n", idx)
		fmt.Fprintf(&buf, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", idx, string(quoted))
		fmt.Fprintf(&buf, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)
		fmt.Fprintf(&buf, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n")
		fmt.Fprintf(&buf, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		return buf.Bytes()

	default:
		return []byte("data: {\"error\":\"agentguard refusal\"}\n\n")
	}
}

// defaultRefusalNonStreamingBytes is the non-streaming sibling of
// defaultRefusalBytes. F9 (B2) wires it for the early-bring-up path
// when Server.BuildRefusal is nil and the non-streaming forwarder
// needs to emit a refusal. Mirrors BuildRefusalRich's non-streaming
// shape but with the bare reason — refusal.go's BuildRefusalRich
// produces the operator-grade copy with rule + approval URL.
//
// model carries the original request's model name when available;
// empty falls back to "agentguard-refusal" so the JSON object remains
// decodable by SDK clients without nil-model errors.
func defaultRefusalNonStreamingBytes(provider, full, model string) []byte {
	if model == "" {
		model = "agentguard-refusal"
	}
	switch provider {
	case "openai":
		payload := map[string]interface{}{
			"id":      "agentguard-refusal",
			"object":  "chat.completion",
			"created": 0,
			"model":   model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": full,
					},
					"finish_reason": "stop",
				},
			},
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return []byte(`{"id":"agentguard-refusal","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"AgentGuard refusal"},"finish_reason":"stop"}]}`)
		}
		return b
	case "anthropic":
		payload := map[string]interface{}{
			"id":    "agentguard-refusal",
			"type":  "message",
			"role":  "assistant",
			"model": model,
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": full,
				},
			},
			"stop_reason": "end_turn",
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return []byte(`{"id":"agentguard-refusal","type":"message","role":"assistant","content":[{"type":"text","text":"AgentGuard refusal"}],"stop_reason":"end_turn"}`)
		}
		return b
	default:
		return []byte(`{"error":{"message":"agentguard refusal","type":"agentguard_error"}}`)
	}
}

// handleStreamingChatCompletion implements OpenAI streaming with the
// byte-identity invariant: bytes delivered to the client MUST be
// byte-identical to upstream output on the ALLOW path. No JSON re-
// encoding; no whitespace normalization; no header rewriting beyond
// hop-by-hop filtering.
//
// Streaming admission control: admitStream gates entry against
// cfg.MaxConcurrentStreams. Refused requests get 503 + Retry-After: 5
// before any body bytes touch upstream — protects the proxy from
// self-DoS via fan-out.
func (s *Server) handleStreamingChatCompletion(w http.ResponseWriter, r *http.Request, body []byte, _ *ChatCompletionRequest) {
	if !s.admitStream(w) {
		return
	}
	defer s.releaseStream()

	upstreamResp, err := s.dispatchStreamingUpstream(r.Context(), s.openaiURL, "/v1/chat/completions", r.Header, body)
	if err != nil {
		s.streamingForwardError(w, err)
		return
	}
	defer upstreamResp.Body.Close()

	// Non-2xx upstream: pass through as-is. The body is small enough
	// that a copy is fine; the client gets the upstream's error
	// envelope verbatim.
	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		s.copyStreamingResponseHeaders(w, upstreamResp)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.streamingForwardError(w, errors.New("response writer does not support flushing"))
		return
	}

	s.copyStreamingResponseHeaders(w, upstreamResp)
	flusher.Flush() // EventSource.onopen fires immediately

	s.runOpenAIStreamLoop(w, flusher, r, upstreamResp.Body)
}

// handleStreamingAnthropicMessages mirrors handleStreamingChatCompletion
// for Anthropic Messages. Same MaxConcurrentStreams admission gate.
func (s *Server) handleStreamingAnthropicMessages(w http.ResponseWriter, r *http.Request, body []byte, _ *AnthropicMessagesRequest) {
	if !s.admitStream(w) {
		return
	}
	defer s.releaseStream()

	upstreamResp, err := s.dispatchStreamingUpstream(r.Context(), s.anthropicURL, "/v1/messages", r.Header, body)
	if err != nil {
		s.streamingForwardError(w, err)
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		s.copyStreamingResponseHeaders(w, upstreamResp)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.streamingForwardError(w, errors.New("response writer does not support flushing"))
		return
	}

	s.copyStreamingResponseHeaders(w, upstreamResp)
	flusher.Flush()

	s.runAnthropicStreamLoop(w, flusher, r, upstreamResp.Body)
}

// runOpenAIStreamLoop is the per-request streaming loop. Constructs
// a fresh accumulator (per-request goroutine isolation), reads SSE
// events from upstream, branches on FeedResult, and either flushes
// (PassThrough or ALLOW-path replay) or refuses (DENY / overflow).
func (s *Server) runOpenAIStreamLoop(w http.ResponseWriter, flusher http.Flusher, r *http.Request, body io.Reader) {
	acc := NewOpenAIToolCallAccumulator(s.cfg.MaxBufferBytes)
	reader := bufio.NewReader(body)

	for {
		event, err := readSSEEvent(reader, s.cfg.MaxBufferBytes*2)
		isEOF := errors.Is(err, io.EOF)
		isTooLarge := errors.Is(err, errSSEEventTooLarge)

		if isTooLarge {
			// One single SSE event blew past 2x the buffer cap. This
			// is pathological; treat it as an upstream protocol error
			// and emit a minimal refusal.
			metrics.IncLLMProxyBufferOverflow("openai")
			refusal := s.buildRefusal("openai", Decision{
				Allow:  false,
				Reason: "tool call arguments exceed gating buffer",
				Rule:   "deny:llm_api_proxy:buffer_overflow",
			}, &RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return
		}

		if len(event) > 0 {
			result, ferr := acc.FeedEvent(event)
			if ferr != nil && !result.Completed && !isEOF {
				// Malformed NON-completion delta — drop the event and
				// continue. We do NOT inject our own bytes into the
				// stream (would violate byte-identity for following
				// events). Corruption that affects a decision surfaces
				// at completion (handled fail-closed below), not here.
				continue
			}
			switch {
			case ferr != nil && result.Completed:
				// F1 (fail-closed): a finalized tool_call cycle whose
				// assembled arguments are not valid JSON (truncated /
				// malformed — routine on a max_tokens cutoff, or
				// attacker-inducible). Such a completion MUST deny, never
				// be silently dropped: dropping leaves the gate un-run,
				// writes no audit entry, and strands the accumulator so
				// every later event is buffered then dropped at EOF (the
				// firewall goes dark with no trail). See denyMalformedOpenAI.
				s.denyMalformedOpenAI(w, flusher, r, acc, result.CompletedToolCalls)

			case result.ProtocolViolation:
				// Defensive: the OpenAI accumulator does not currently emit
				// this (its tool_calls all close together at finish_reason, so
				// there is no interleave window). Handled here so a future
				// parser change can never silently drop the signal and leak an
				// ungated call. Fail closed with a synthetic refusal.
				metrics.IncLLMProxyProtocolViolation("openai")
				refusal := s.buildRefusal("openai", Decision{
					Allow:  false,
					Reason: "upstream tool_call stream is malformed; refused",
					Rule:   "deny:llm_api_proxy:tool_use_interleaved",
				}, &RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
				_, _ = w.Write(refusal)
				flusher.Flush()
				return

			case result.OverflowBufferBytes:
				metrics.IncLLMProxyBufferOverflow("openai")
				refusal := s.buildRefusal("openai", Decision{
					Allow:  false,
					Reason: "tool call arguments exceed gating buffer",
					Rule:   "deny:llm_api_proxy:buffer_overflow",
				}, &RefusalContext{Provider: "openai", AnthropicToolUseIndex: -1})
				_, _ = w.Write(refusal)
				flusher.Flush()
				return

			case result.Completed:
				if !s.gateAndFlushOpenAI(w, flusher, r, acc, result.CompletedToolCalls) {
					return // refused; orchestrator stops reading
				}

			case result.PassThrough:
				_, _ = w.Write(event)
				flusher.Flush()

			case result.Accumulating:
				// Held in acc.bufferedEvents; do not flush.
			}
		}

		if isEOF {
			return
		}
		if err != nil {
			// Upstream read error mid-stream. The client may have
			// already received some bytes; we can't safely emit a
			// JSON error envelope here. Just close — clients react
			// to EOF as end-of-stream.
			return
		}
		// Cancellation: client disconnected.
		if r.Context().Err() != nil {
			return
		}
	}
}

// gateAndFlushOpenAI gates each completed tool_call through PolicyCheck.
// Returns true when ALLOW (orchestrator continues reading); false when
// DENY (orchestrator emits a refusal and stops).
func (s *Server) gateAndFlushOpenAI(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *OpenAIToolCallAccumulator, calls []ToolCallCheck) bool {
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].Stream = true
		decision, err := s.runPolicyCheck(r.Context(), calls[i])
		if err != nil {
			// PolicyCheck failed (network error, malformed response).
			// Honour fail-mode: when the gate (gate.go::failModeDecision)
			// is wired (production), it returns a fully-shaped Decision
			// alongside the err — `deny` → FailModeRuleClosed,
			// `fail-closed-with-audit` → FailModeRuleClosedAudit,
			// `allow` → FailModeRuleOpen. We propagate that Decision
			// VERBATIM rather than synthesising a local one so the
			// operator's chosen --fail-mode value reaches the
			// client-visible refusal rule string. Tests that wire a
			// PolicyCheck returning a bare error get the safe fallback.
			if s.cfg.FailMode == "allow" {
				continue
			}
			refusalDecision := decision
			if refusalDecision.Rule == "" {
				// Test-shim or non-gate PolicyCheck returned a bare
				// error without a fail-mode-shaped Decision. Synthesise
				// a fallback that still distinguishes the two closed
				// modes so the dashboard rule-string contract holds.
				refusalDecision = Decision{
					Allow:  false,
					Reason: fmt.Sprintf("policy check unavailable: %v", err),
					Rule:   fallbackFailModeRule(s.cfg.FailMode),
				}
			}
			refusal := s.buildRefusal("openai", refusalDecision, &RefusalContext{Provider: "openai", OriginalToolCall: calls[i], AnthropicToolUseIndex: -1})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
		if !decision.Allow {
			refusal := s.buildRefusal("openai", decision, &RefusalContext{
				Provider:              "openai",
				OriginalToolCall:      calls[i],
				AnthropicToolUseIndex: -1,
			})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
	}
	// All tool_calls in this batch ALLOWed. Flush buffered events
	// byte-identical and reset the accumulator for the next cycle.
	for _, ev := range acc.BufferedEvents() {
		_, _ = w.Write(ev)
	}
	flusher.Flush()
	acc.Reset()
	return true
}

// malformedToolCallDecision is the fail-closed verdict the streaming
// orchestrator stamps when a finalized tool_call/tool_use cycle carries
// a parse error (its assembled arguments are not valid JSON — e.g. a
// max_tokens-truncated tool call, routine OR attacker-inducible). F1:
// such a completion must DENY, never be silently dropped. The Rule is a
// stable, tenant-agnostic string operators can alert on.
func malformedToolCallDecision() Decision {
	return Decision{
		Allow:  false,
		Reason: "malformed tool call arguments — refused",
		Rule:   "deny:llm_api_proxy:malformed_tool_call",
	}
}

// auditDeniedToolCalls runs the SAME PolicyCheck the normal gate runs
// for each supplied tool call, purely to drive the audit trail: the
// wired PolicyCheck POSTs to /v1/check, which writes the transport-
// tagged audit entry (the proxy never emits audit entries directly —
// single source of truth, see server.go). The returned decision and any
// error are intentionally ignored — the F1 malformed-completion path
// that calls this forces an unconditional fail-closed refusal — but the
// call still closes the audit gap the pre-fix silent drop left open.
//
// It sets the same tenant/agent/session identity fields gateAndFlush*
// sets so the audit entry is attributed identically to a normal deny.
// Runs only on the (rare) malformed-completion path, never the happy
// path, so it adds no per-event work to the hot loop.
func (s *Server) auditDeniedToolCalls(r *http.Request, calls []ToolCallCheck) {
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].Stream = true
		_, _ = s.runPolicyCheck(r.Context(), calls[i])
	}
}

// denyMalformedOpenAI is the F1 fail-closed path for the OpenAI loop: a
// finalized tool_call cycle whose assembled arguments are not valid
// JSON. It (1) audits each malformed call through the normal PolicyCheck
// path (auditDeniedToolCalls), (2) emits a fail-closed refusal with the
// fixed malformed_tool_call Decision regardless of the check's verdict,
// (3) flushes, and (4) resets the accumulator. Unlike the overflow /
// normal-deny branches it does NOT stop reading upstream: a later valid
// tool_call in the same response must still be gated (the reset is what
// un-sticks the accumulator). Buffered events (the malformed cycle's raw
// bytes) are discarded, not flushed — the refusal replaces them.
func (s *Server) denyMalformedOpenAI(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *OpenAIToolCallAccumulator, calls []ToolCallCheck) {
	s.auditDeniedToolCalls(r, calls)
	var original ToolCallCheck
	if len(calls) > 0 {
		original = calls[0]
	}
	refusal := s.buildRefusal("openai", malformedToolCallDecision(), &RefusalContext{
		Provider:              "openai",
		OriginalToolCall:      original,
		AnthropicToolUseIndex: -1,
	})
	_, _ = w.Write(refusal)
	flusher.Flush()
	acc.Reset()
}

// fallbackFailModeRule returns the rule string the streaming
// orchestrator uses when the wired PolicyCheck returns an error WITHOUT
// a populated Decision (e.g. test shims). Production code paths get
// the Decision shaped by gate.go::failModeDecision and never hit this
// fallback. Kept in sync with FailModeRule* constants in gate.go so
// the dashboard rule-string contract is identical regardless of which
// path constructed the refusal.
func fallbackFailModeRule(failMode string) string {
	switch strings.ToLower(failMode) {
	case "fail-closed-with-audit":
		return FailModeRuleClosedAudit
	default:
		return FailModeRuleClosed
	}
}

// runAnthropicStreamLoop mirrors runOpenAIStreamLoop for Anthropic.
// The shape difference is captured inside the accumulator; the loop
// itself is structurally identical.
func (s *Server) runAnthropicStreamLoop(w http.ResponseWriter, flusher http.Flusher, r *http.Request, body io.Reader) {
	acc := NewAnthropicAccumulator(s.cfg.MaxBufferBytes)
	reader := bufio.NewReader(body)

	for {
		event, err := readSSEEvent(reader, s.cfg.MaxBufferBytes*2)
		isEOF := errors.Is(err, io.EOF)
		isTooLarge := errors.Is(err, errSSEEventTooLarge)

		if isTooLarge {
			metrics.IncLLMProxyBufferOverflow("anthropic")
			refusal := s.buildRefusal("anthropic", Decision{
				Allow:  false,
				Reason: "tool call arguments exceed gating buffer",
				Rule:   "deny:llm_api_proxy:buffer_overflow",
			}, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return
		}

		if len(event) > 0 {
			result, ferr := acc.FeedEvent(event)
			if ferr != nil && !result.Completed && !isEOF {
				// Malformed NON-completion delta — drop and continue
				// (mirrors the OpenAI loop). A malformed COMPLETION is
				// handled fail-closed below, never dropped.
				continue
			}
			switch {
			case ferr != nil && result.Completed:
				// F1 (fail-closed): a finalized tool_use cycle with
				// unparseable input JSON. Deny + audit + reset, then keep
				// gating the rest of the stream — see denyMalformedAnthropic.
				s.denyMalformedAnthropic(w, flusher, r, acc, result.CompletedToolCalls)

			case result.ProtocolViolation:
				// SECURITY (audit H1/H2): the upstream emitted a structurally
				// unsafe tool_use stream (interleaved second tool_use, or
				// start-input conflicting with streamed deltas). We cannot
				// gate it without risking an ungated call, so we fail closed:
				// discard the buffered bytes and emit a synthetic refusal.
				metrics.IncLLMProxyProtocolViolation("anthropic")
				refusal := s.buildRefusal("anthropic", Decision{
					Allow:  false,
					Reason: "upstream tool_use stream is malformed (interleaved or conflicting tool_use blocks); refused",
					Rule:   "deny:llm_api_proxy:tool_use_interleaved",
				}, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
				_, _ = w.Write(refusal)
				flusher.Flush()
				return

			case result.OverflowBufferBytes:
				metrics.IncLLMProxyBufferOverflow("anthropic")
				refusal := s.buildRefusal("anthropic", Decision{
					Allow:  false,
					Reason: "tool call arguments exceed gating buffer",
					Rule:   "deny:llm_api_proxy:buffer_overflow",
				}, &RefusalContext{Provider: "anthropic", AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
				_, _ = w.Write(refusal)
				flusher.Flush()
				return

			case result.Completed:
				if !s.gateAndFlushAnthropic(w, flusher, r, acc, result.CompletedToolCalls) {
					return
				}

			case result.PassThrough:
				_, _ = w.Write(event)
				flusher.Flush()

			case result.Accumulating:
				// Held in acc.bufferedEvents.
			}
		}

		if isEOF {
			return
		}
		if err != nil {
			return
		}
		if r.Context().Err() != nil {
			return
		}
	}
}

// gateAndFlushAnthropic mirrors gateAndFlushOpenAI for Anthropic.
func (s *Server) gateAndFlushAnthropic(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *AnthropicAccumulator, calls []ToolCallCheck) bool {
	for i := range calls {
		calls[i].TenantID = s.cfg.TenantID
		calls[i].AgentID = strings.TrimSpace(r.Header.Get("X-Agent-ID"))
		if calls[i].AgentID == "" {
			calls[i].AgentID = "llm-proxy"
		}
		calls[i].SessionID = strings.TrimSpace(r.Header.Get("X-Session-ID"))
		calls[i].Stream = true
		decision, err := s.runPolicyCheck(r.Context(), calls[i])
		if err != nil {
			// See the OpenAI sibling above for the fail-mode propagation
			// rationale; we propagate the gate's Decision verbatim and
			// fall back to a synthesised one only when the test shim
			// returned a bare error without a Rule-shaped Decision.
			if s.cfg.FailMode == "allow" {
				continue
			}
			refusalDecision := decision
			if refusalDecision.Rule == "" {
				refusalDecision = Decision{
					Allow:  false,
					Reason: fmt.Sprintf("policy check unavailable: %v", err),
					Rule:   fallbackFailModeRule(s.cfg.FailMode),
				}
			}
			refusal := s.buildRefusal("anthropic", refusalDecision, &RefusalContext{Provider: "anthropic", OriginalToolCall: calls[i], AnthropicToolUseIndex: acc.ActiveToolUseIndex()})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
		if !decision.Allow {
			refusal := s.buildRefusal("anthropic", decision, &RefusalContext{
				Provider:              "anthropic",
				OriginalToolCall:      calls[i],
				AnthropicToolUseIndex: acc.ActiveToolUseIndex(),
			})
			_, _ = w.Write(refusal)
			flusher.Flush()
			return false
		}
	}
	for _, ev := range acc.BufferedEvents() {
		_, _ = w.Write(ev)
	}
	flusher.Flush()
	acc.Reset()
	return true
}

// denyMalformedAnthropic is the Anthropic sibling of denyMalformedOpenAI
// (see it for the full rationale). It audits the malformed tool_use
// through the normal PolicyCheck path, emits a fail-closed refusal that
// rewrites the buffered tool_use's content-block index (captured via
// acc.ActiveToolUseIndex() BEFORE the reset), flushes, then resets so a
// later valid tool_use in the same stream is still gated. It does NOT
// stop reading upstream.
func (s *Server) denyMalformedAnthropic(w http.ResponseWriter, flusher http.Flusher, r *http.Request, acc *AnthropicAccumulator, calls []ToolCallCheck) {
	s.auditDeniedToolCalls(r, calls)
	var original ToolCallCheck
	if len(calls) > 0 {
		original = calls[0]
	}
	refusal := s.buildRefusal("anthropic", malformedToolCallDecision(), &RefusalContext{
		Provider:              "anthropic",
		OriginalToolCall:      original,
		AnthropicToolUseIndex: acc.ActiveToolUseIndex(),
	})
	_, _ = w.Write(refusal)
	flusher.Flush()
	acc.Reset()
}
