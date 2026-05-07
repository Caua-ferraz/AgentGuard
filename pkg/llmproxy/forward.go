package llmproxy

// forward.go is the non-streaming forward path. F9 (B2) closed the
// gating gap: until v0.5 fixup, the non-streaming forwarder was a
// verbatim pass-through (the streaming path A22 was the only place
// tool_calls were inspected). Many production agents use stream=false
// — batch evals, non-interactive workflows, frameworks that don't
// enable streaming by default — so the "wire-level firewall" claim
// required this path to gate too.
//
// Algorithm (mirrors streaming.go's pause/resume/rewrite, synchronous):
//
//   1. POST the request body to upstream verbatim.
//   2. Read the upstream response into memory bounded by
//      --max-buffer-bytes (an extra byte is read so overflow is
//      unambiguous; the streaming path uses the same +1 trick).
//   3. If the body overflows the cap → IncLLMProxyNonStreamingOverflow,
//      synthesize a refusal with Rule="deny:llm_api_proxy:non_streaming_buffer_overflow",
//      respond 200 with the refusal bytes (SDKs expect 200 + a
//      decodable response shape; non-200 short-circuits SDK-side error
//      paths).
//   4. Parse the body as the provider's non-streaming response shape.
//      Malformed JSON → pass through verbatim with the upstream's
//      original status (we never inject our own bytes onto an
//      already-corrupt wire).
//   5. Walk the response for tool_calls (OpenAI choices[*].message.tool_calls)
//      or tool_use blocks (Anthropic content[i].type == "tool_use").
//      Run each through Server.PolicyCheck. First non-ALLOW (DENY,
//      REQUIRE_APPROVAL, or PolicyCheck error under fail-closed) →
//      synthesize a refusal that replaces the entire response. We
//      do NOT preserve any other content — partial leaks would let
//      the agent see the model's reasoning behind the denied call.
//   6. If every tool_call ALLOWed → forward the upstream body
//      byte-identical with the upstream's status code. The byte
//      identity invariant from the streaming path applies here too:
//      no JSON re-encoding, no whitespace normalisation.

import (
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

// hopByHopHeaders are the HTTP/1.1 headers that MUST NOT be forwarded
// across a proxy per RFC 7230 § 6.1. Everything else passes through.
//
// "Host" is also stripped because Go's http.Request honours the URL
// authority; an explicit Host header would break upstream routing.
//
// Content-Length is stripped because the upstream client computes
// its own from the io.Reader body length — emitting both can cause
// chunked-vs-fixed-length negotiation confusion on some intermediaries.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Host":                {},
	"Content-Length":      {},
}

// forwardOpenAI forwards a request to the OpenAI upstream, copying
// the response back to the client. path is the upstream URL path
// (e.g. "/v1/chat/completions"). body is the original request bytes
// (preserved verbatim — re-encoding would break byte-identity).
//
// This is the pass-through forwarder used by endpoints that never
// emit tool_calls (/v1/embeddings, /v1/models, /v1/completions). For
// non-streaming /v1/chat/completions use forwardChatCompletion which
// adds tool_call gating per F9 (B2).
func (s *Server) forwardOpenAI(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, path string) error {
	return s.forwardTo(ctx, w, r, body, s.openaiURL, path)
}

// forwardAnthropic mirrors forwardOpenAI for the Anthropic upstream.
// Pass-through only — used by routes that never emit tool_use. For
// /v1/messages use forwardAnthropicMessages which gates tool_use blocks.
func (s *Server) forwardAnthropic(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, path string) error {
	return s.forwardTo(ctx, w, r, body, s.anthropicURL, path)
}

// forwardChatCompletion is the non-streaming /v1/chat/completions
// forwarder with tool_call gating. It POSTs the request to OpenAI,
// reads the response into memory bounded by --max-buffer-bytes,
// extracts any tool_calls, runs each through PolicyCheck, and either
// forwards the original bytes verbatim (all ALLOW) or rewrites the
// response to a synthetic refusal (any DENY/REQUIRE_APPROVAL or
// overflow). req carries the original request's model name so the
// synthetic refusal can echo it.
func (s *Server) forwardChatCompletion(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, req *ChatCompletionRequest) error {
	return s.forwardWithToolCallGating(ctx, w, r, body, s.openaiURL, "/v1/chat/completions", "openai", req.Model)
}

// forwardAnthropicMessages is the non-streaming /v1/messages forwarder
// with tool_use gating. Mirrors forwardChatCompletion for the
// Anthropic shape.
func (s *Server) forwardAnthropicMessages(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, req *AnthropicMessagesRequest) error {
	return s.forwardWithToolCallGating(ctx, w, r, body, s.anthropicURL, "/v1/messages", "anthropic", req.Model)
}

// forwardWithToolCallGating is the shared implementation for the
// non-streaming gated forwarders. provider is "openai" or "anthropic"
// — picks the response-shape parser and the synthetic-refusal builder.
// reqModel is the model name from the parsed request body, surfaced
// into the synthetic refusal when the proxy rewrites the response.
//
// On any error before the response status is written (upstream POST
// failure, body read failure other than overflow), an error is returned
// for the caller to translate into a 502. Once the proxy has decided
// to write a 200 + synthetic refusal or pass through verbatim, errors
// are swallowed (we cannot retract a response that's already on the
// wire).
func (s *Server) forwardWithToolCallGating(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	upstream *url.URL,
	path string,
	provider string,
	reqModel string,
) error {
	if upstream == nil {
		return errors.New("upstream URL not configured")
	}

	target := *upstream
	target.Path = joinPath(upstream.Path, path)
	target.RawQuery = r.URL.RawQuery

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("build upstream request: %w", err)
	}
	copyForwardableHeaders(r.Header, upstreamReq.Header)
	rewriteUserAgent(upstreamReq.Header, r.Header.Get("User-Agent"))
	upstreamReq.Host = upstream.Host

	resp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("upstream %s: %w", target.String(), err)
	}
	defer resp.Body.Close()

	// Non-2xx responses pass through verbatim. SDK clients rely on
	// receiving the upstream's error envelope unchanged so retry/
	// rate-limit logic kicks in.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		copyForwardableHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		if _, copyErr := io.Copy(w, resp.Body); copyErr != nil {
			return fmt.Errorf("copy upstream error body: %w", copyErr)
		}
		return nil
	}

	// Read upstream body bounded by --max-buffer-bytes. Read one extra
	// byte so we can tell "exactly cap bytes" from "overflowed". The
	// streaming path uses the same +1 trick (readRequestBody in
	// server.go).
	cap := s.cfg.MaxBufferBytes
	if cap <= 0 {
		cap = DefaultMaxBufferBytes
	}
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(cap)+1))
	if readErr != nil {
		return fmt.Errorf("read upstream body: %w", readErr)
	}

	if len(bodyBytes) > cap {
		// Overflow: the response body is too large to safely inspect
		// for tool_calls. Refuse with a synthetic JSON object so the
		// SDK doesn't see partial bytes (which would race with the
		// reader we already consumed). The metric distinguishes this
		// from the streaming-path overflow.
		metrics.IncLLMProxyNonStreamingOverflow(provider)
		decision := Decision{
			Allow:  false,
			Reason: fmt.Sprintf("upstream non-streaming response exceeds gating buffer (--max-buffer-bytes=%d)", cap),
			Rule:   "deny:llm_api_proxy:non_streaming_buffer_overflow",
		}
		writeNonStreamingRefusal(s, w, resp.Header, provider, decision, ToolCallCheck{Provider: provider}, reqModel)
		return nil
	}

	// Parse the response. Malformed JSON passes through verbatim — we
	// never inject our own bytes into an already-corrupt wire. If the
	// model wasn't going to call a tool the parser still works (empty
	// tool_calls / tool_use slice).
	switch provider {
	case "openai":
		var parsed ChatCompletionResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			passThroughResponse(w, resp.Header, resp.StatusCode, bodyBytes)
			return nil
		}
		decision, denied, denyCall := s.gateOpenAINonStreaming(ctx, r, &parsed)
		if denied {
			writeNonStreamingRefusal(s, w, resp.Header, "openai", decision, denyCall, reqModel)
			return nil
		}
	case "anthropic":
		var parsed AnthropicMessagesResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			passThroughResponse(w, resp.Header, resp.StatusCode, bodyBytes)
			return nil
		}
		decision, denied, denyCall := s.gateAnthropicNonStreaming(ctx, r, &parsed)
		if denied {
			writeNonStreamingRefusal(s, w, resp.Header, "anthropic", decision, denyCall, reqModel)
			return nil
		}
	}

	// All tool_calls (if any) ALLOWed → forward upstream bytes verbatim.
	passThroughResponse(w, resp.Header, resp.StatusCode, bodyBytes)
	return nil
}

// passThroughResponse copies upstream headers (filtered for hop-by-hop)
// + the upstream status + body to the client byte-identical. The
// Content-Length header is filtered (hop-by-hop set already drops it)
// so Go's http stack computes its own.
func passThroughResponse(w http.ResponseWriter, srcHeader http.Header, status int, body []byte) {
	copyForwardableHeaders(srcHeader, w.Header())
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeNonStreamingRefusal writes a synthetic refusal JSON object to
// the client with HTTP 200. Provider-specific shape (OpenAI
// ChatCompletionResponse, Anthropic Messages response) is picked by
// Server.buildRefusal via the NonStreaming flag on RefusalContext.
//
// Status 200 (not 4xx/5xx) is intentional: SDKs expect a normal
// chat.completion shape and short-circuit on non-2xx into client-side
// error paths that wouldn't surface the refusal text to the agent.
// The refusal payload itself signals the deny via assistant content
// + finish_reason=stop / stop_reason=end_turn.
func writeNonStreamingRefusal(
	s *Server,
	w http.ResponseWriter,
	srcHeader http.Header,
	provider string,
	decision Decision,
	originalCall ToolCallCheck,
	model string,
) {
	// Copy upstream headers (filtered) so Content-Type and other
	// metadata flow through, then drop Content-Length explicitly —
	// the refusal is a different length than the upstream body.
	copyForwardableHeaders(srcHeader, w.Header())
	w.Header().Del("Content-Length")
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}

	refusal := s.buildRefusal(provider, decision, &RefusalContext{
		Provider:              provider,
		OriginalToolCall:      originalCall,
		AnthropicToolUseIndex: -1,
		NonStreaming:          true,
		Model:                 model,
	})

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(refusal)
}

// gateOpenAINonStreaming walks the response choices[*].message.tool_calls
// and runs each through PolicyCheck. Returns (decision, denied, deniedCall).
// On the first non-ALLOW result, denied=true and the loop exits — partial
// allow is not safe (the agent must not see the assistant's tool_call
// arguments for any subsequent ALLOWed call when an earlier one was
// denied; the entire response is replaced).
func (s *Server) gateOpenAINonStreaming(
	ctx context.Context,
	r *http.Request,
	resp *ChatCompletionResponse,
) (Decision, bool, ToolCallCheck) {
	for _, choice := range resp.Choices {
		for i := range choice.Message.ToolCalls {
			tc := &choice.Message.ToolCalls[i]
			check := buildOpenAINonStreamingCheck(s, r, resp, tc)
			decision, err := s.runPolicyCheck(ctx, check)
			if err != nil {
				if strings.EqualFold(s.cfg.FailMode, "allow") {
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
				return refusalDecision, true, check
			}
			if !decision.Allow {
				return decision, true, check
			}
		}
	}
	return Decision{Allow: true}, false, ToolCallCheck{}
}

// buildOpenAINonStreamingCheck builds a ToolCallCheck for one entry in
// the non-streaming response's tool_calls array. Mirrors the streaming
// path's shape (see streaming.go's gateAndFlushOpenAI) so PolicyCheck
// sees identical inputs whether the request was streamed or not.
func buildOpenAINonStreamingCheck(s *Server, r *http.Request, resp *ChatCompletionResponse, tc *ChatCompletionToolCallEcho) ToolCallCheck {
	var args map[string]interface{}
	if len(tc.Function.Arguments) > 0 {
		// Best-effort: invalid JSON arguments leave args nil and the
		// gate sees an empty map. The same forgiving behaviour is in
		// the streaming accumulator.
		_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
	}
	agent := strings.TrimSpace(r.Header.Get("X-Agent-ID"))
	if agent == "" {
		agent = "llm-proxy"
	}
	return ToolCallCheck{
		Provider:     "openai",
		ToolName:     tc.Function.Name,
		ToolCallID:   tc.ID,
		Arguments:    args,
		RawArguments: json.RawMessage(tc.Function.Arguments),
		AgentID:      agent,
		SessionID:    strings.TrimSpace(r.Header.Get("X-Session-ID")),
		TenantID:     s.cfg.TenantID,
		Model:        resp.Model,
		Stream:       false,
	}
}

// gateAnthropicNonStreaming walks the response content[] for tool_use
// blocks. Same first-non-ALLOW-stops semantics as the OpenAI sibling.
func (s *Server) gateAnthropicNonStreaming(
	ctx context.Context,
	r *http.Request,
	resp *AnthropicMessagesResponse,
) (Decision, bool, ToolCallCheck) {
	for i := range resp.Content {
		block := &resp.Content[i]
		if block.Type != "tool_use" {
			continue
		}
		check := buildAnthropicNonStreamingCheck(s, r, resp, block)
		decision, err := s.runPolicyCheck(ctx, check)
		if err != nil {
			if strings.EqualFold(s.cfg.FailMode, "allow") {
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
			return refusalDecision, true, check
		}
		if !decision.Allow {
			return decision, true, check
		}
	}
	return Decision{Allow: true}, false, ToolCallCheck{}
}

// buildAnthropicNonStreamingCheck builds a ToolCallCheck from a
// tool_use content_block in the non-streaming Anthropic response.
// Anthropic's input is already a decoded JSON object on the wire
// (json.RawMessage), so we re-decode into a map for the ToolCallCheck
// arguments field.
func buildAnthropicNonStreamingCheck(s *Server, r *http.Request, resp *AnthropicMessagesResponse, block *AnthropicContentBlock) ToolCallCheck {
	var args map[string]interface{}
	if len(block.Input) > 0 {
		_ = json.Unmarshal(block.Input, &args)
	}
	agent := strings.TrimSpace(r.Header.Get("X-Agent-ID"))
	if agent == "" {
		agent = "llm-proxy"
	}
	return ToolCallCheck{
		Provider:     "anthropic",
		ToolName:     block.Name,
		ToolCallID:   block.ID,
		Arguments:    args,
		RawArguments: block.Input,
		AgentID:      agent,
		SessionID:    strings.TrimSpace(r.Header.Get("X-Session-ID")),
		TenantID:     s.cfg.TenantID,
		Model:        resp.Model,
		Stream:       false,
	}
}

// forwardTo is the shared forwarder. Per docs/LLM_API_PROXY.md § 3.1:
//
//   - Headers (including Authorization, x-api-key, OpenAI-Organization)
//     pass through verbatim except for hop-by-hop and Host.
//   - User-Agent is rewritten to include the proxy's identity so
//     server-side logs at OpenAI/Anthropic can identify proxied
//     traffic. Spec-compliant per RFC 7231.
//   - The request body is re-attached as a fresh io.Reader on each
//     call so retries (currently none in v0.5) would be safe.
//   - The response body is streamed back via io.Copy — the
//     non-streaming JSON shape is small enough that this is fine.
//     Once A22 wires streaming, that path uses a separate routine
//     that pauses/resumes per tool call.
func (s *Server) forwardTo(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, upstream *url.URL, path string) error {
	if upstream == nil {
		return errors.New("upstream URL not configured")
	}

	// Build the upstream URL: <scheme>://<host>[:port]<path><query>
	target := *upstream
	target.Path = joinPath(upstream.Path, path)
	target.RawQuery = r.URL.RawQuery

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("build upstream request: %w", err)
	}

	copyForwardableHeaders(r.Header, req.Header)
	rewriteUserAgent(req.Header, r.Header.Get("User-Agent"))

	// Setting Host on req is the way to override the SNI / Host
	// header for the upstream connection. http.Client honours
	// req.Host when it's non-empty.
	req.Host = upstream.Host

	resp, err := s.httpClient.Do(req)
	if err != nil {
		// Distinguish ctx cancel from network failure so the
		// caller's status mapping can stay correct.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("upstream %s: %w", target.String(), err)
	}
	defer resp.Body.Close()

	// Copy response headers (filtered for hop-by-hop) before
	// writing the status — once WriteHeader is called the header
	// map freezes.
	copyForwardableHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)

	// Stream body back. For non-streaming responses this is one
	// contiguous JSON document; io.Copy is the right primitive.
	//
	// Hook for A22/A24: the non-streaming response may contain
	// tool_calls (OpenAI) or tool_use blocks (Anthropic) that need
	// gating. The proxy currently forwards verbatim; A24 wires the
	// inspect-and-rewrite step here. The contract is documented
	// in docs/LLM_API_PROXY.md § 3.2 ("Non-streaming").
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		// If the client disconnected mid-copy that's not really
		// our error, but io.Copy returns it anyway. The handler
		// converts this to a 502 only for the headers-not-yet-sent
		// case; once we WriteHeader'd, there's nothing useful we
		// can send back, so we just log it via the return value.
		return fmt.Errorf("copy response body: %w", err)
	}
	return nil
}

// copyForwardableHeaders copies src into dst, dropping hop-by-hop
// headers. Header keys are case-insensitive in HTTP; Go's http.Header
// canonicalises on Add, so the lookup table above uses canonical
// names.
//
// The Authorization header is explicitly forwarded — the proxy never
// reads it. The proxy's own auth uses ProxyAuthHeader.
func copyForwardableHeaders(src, dst http.Header) {
	for k, vs := range src {
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		// Explicitly DO NOT propagate the proxy's own auth header
		// to the upstream — it's an inbound-only credential.
		if http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(ProxyAuthHeader) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// rewriteUserAgent sets a User-Agent that identifies the proxy.
// Original UA is preserved as a suffix so upstream logs can still
// see what client kicked off the call (e.g. "openai-python/1.x").
func rewriteUserAgent(h http.Header, original string) {
	original = strings.TrimSpace(original)
	if original == "" {
		h.Set("User-Agent", "agentguard-llm-proxy/"+BuildVersion)
		return
	}
	h.Set("User-Agent", "agentguard-llm-proxy/"+BuildVersion+" "+original)
}

// joinPath concatenates a base URL path with a route path. Avoids
// "//" sequences when base ends with "/" or route starts with "/".
// Returns "/" if both are empty.
func joinPath(base, route string) string {
	switch {
	case base == "" || base == "/":
		if route == "" {
			return "/"
		}
		return route
	case route == "":
		return base
	default:
		bTrim := strings.TrimSuffix(base, "/")
		rTrim := route
		if !strings.HasPrefix(rTrim, "/") {
			rTrim = "/" + rTrim
		}
		return bTrim + rTrim
	}
}
