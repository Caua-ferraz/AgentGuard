package llmproxy

// forward.go is the non-streaming forward path. The proxy is
// intentionally dumb on this path: read the request body into memory
// (capped by --max-buffer-bytes), forward the original bytes to the
// upstream, copy the response status + headers + body back to the
// client.
//
// Tool-call gating on non-streaming responses (inspecting the
// upstream JSON for tool_calls / tool_use blocks and routing them
// through PolicyCheck) is wired by A24 — A21 lays the foundation
// here. See docs/LLM_API_PROXY.md § 3.2 ("Non-streaming") for the
// algorithm A24 will implement.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
func (s *Server) forwardOpenAI(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, path string) error {
	return s.forwardTo(ctx, w, r, body, s.openaiURL, path)
}

// forwardAnthropic mirrors forwardOpenAI for the Anthropic upstream.
func (s *Server) forwardAnthropic(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, path string) error {
	return s.forwardTo(ctx, w, r, body, s.anthropicURL, path)
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
