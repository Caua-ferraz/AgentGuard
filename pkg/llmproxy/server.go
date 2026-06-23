package llmproxy

// server.go is the HTTP server skeleton for agentguard-llm-proxy. It
// wires routes, the non-streaming forward path, the streaming
// pause/resume/rewrite path, scope mapping, and the policy gate +
// refusal construction hooks.
//
// The server is intentionally small: per-request goroutine isolation
// (Go's default), shared http.Client per upstream provider for
// connection pooling, and zero global mutable state. See
// docs/LLM_API_PROXY.md § 6 for the concurrency contract.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/internal/gateclient"
	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// BuildVersion is overridden via -ldflags by the binary entry point.
// Defaults to "dev" for `go test` / `go run`.
var BuildVersion = "dev"

// ProxyAuthHeader is the inbound-auth header the proxy enforces when
// --proxy-api-key is set. Distinct from the Authorization header so
// the upstream's bearer token (which the proxy forwards verbatim) is
// not aliased with the proxy's own credential.
//
// We use a separate header rather than re-keying Authorization to
// avoid sending two `Authorization` values (which is not legal in
// HTTP/1.1 anyway). SDK callers wishing to authenticate with the
// proxy set this header in addition to (not instead of) the
// upstream's Authorization.
const ProxyAuthHeader = "X-AgentGuard-Proxy-Auth"

// ----- Hook input/output types -----

// ToolCallCheck is the bridge-internal shape passed to PolicyCheck.
// The hook reads this, calls /v1/check, returns Decision. The shape
// mirrors mcpgw.ToolsCallRequest deliberately — operators get a
// uniform mental model across the two proxies.
type ToolCallCheck struct {
	// Provider is "openai" or "anthropic". Used to pick upstream-
	// specific synthetic-refusal shapes.
	Provider string

	// ToolName is the function/tool name as the model emitted it
	// (no namespace prefix for the LLM proxy — that's MCP's pattern).
	ToolName string

	// ToolCallID is the upstream-assigned id (OpenAI: call_xxx,
	// Anthropic: toolu_xxx). Surfaced in audit meta so operators can
	// correlate with provider-side logs.
	ToolCallID string

	// Arguments is the parsed tool-call arguments. For OpenAI, this
	// is the result of json.Unmarshal on the
	// tool_calls[*].function.arguments STRING (which holds JSON);
	// for Anthropic, it's the parsed input object. May be nil if the
	// model emitted invalid JSON — the policy hook decides how to
	// handle that.
	Arguments map[string]interface{}

	// RawArguments is the unparsed arguments byte slice, available
	// when callers want to inspect or redact before re-marshalling.
	RawArguments json.RawMessage

	// AgentID, SessionID, TenantID, ApprovalID are the
	// /v1/check-side metadata. AgentID is synthesised from inbound
	// headers (X-Agent-ID) or falls back to "llm-proxy". TenantID
	// comes from cfg.TenantID. ApprovalID is set when the LLM SDK
	// echoed a previously-issued approval id back via a meta channel.
	AgentID    string
	SessionID  string
	TenantID   string
	ApprovalID string

	// Model is the model name from the request body — surfaced in
	// audit meta.
	Model string

	// Stream indicates whether the request was a streaming one.
	// Surfaced in audit meta so operators can distinguish gating
	// patterns.
	Stream bool

	// UpstreamStatus is the HTTP status code the upstream returned.
	// 0 means "no upstream call yet" (shouldn't happen in the
	// gating path; reserved for future failure-mode plumbing).
	UpstreamStatus int
}

// Decision is the verdict returned by PolicyCheck. Alias of the shared
// gateclient.Decision so both proxies speak one verdict shape.
type Decision = gateclient.Decision

// ----- Server -----

// Server is the HTTP server. Constructed via NewServer, run via Run.
// Hooks (PolicyCheck, ScopeMap, BuildRefusal) default to nil-safe
// pass-through; concrete implementations are wired by main.go before
// Run.
//
// Concurrency: Server itself is read-only after construction. Per-
// request goroutines isolate state (no shared mutable map between
// requests). The shared http.Client pools connections per host.
type Server struct {
	cfg *Config

	// httpClient is the shared upstream client. Connection pooling
	// is per-host so OpenAI and Anthropic keepalives don't compete.
	httpClient *http.Client

	// Upstream URLs parsed once at construction time. Stored as
	// *url.URL so handlers don't re-parse on every request.
	openaiURL    *url.URL
	anthropicURL *url.URL

	// PolicyCheck is the policy hook. The default (nil) returns
	// ALLOW (useful for tests). The wired implementation:
	//   1. Builds a policy.ActionRequest from the ToolCallCheck
	//      (scope from ScopeMap, command = tool name + redacted args,
	//      agent_id from auth/header).
	//   2. POSTs to <guard-url>/v1/check with
	//      meta["transport"] = "llm_api_proxy".
	//   3. Returns a Decision struct.
	//
	// Audit + SSE flow: PolicyCheck POSTs to /v1/check, which already
	// writes the audit entry with transport="llm_api_proxy" and
	// broadcasts the SSE event with the llm_api_proxy chip (via the
	// transport-tag plumbing in pkg/proxy + pkg/audit). The proxy
	// itself does NOT emit audit entries directly — single source of
	// truth.
	PolicyCheck func(ctx context.Context, req *ToolCallCheck) (Decision, error)

	// ScopeMap is the scope-resolution hook. The default (nil)
	// returns "unmapped" — which the policy engine fails closed on
	// unless an "unmapped" scope rule is configured. The wired
	// implementation ships a default mapping (bash → shell,
	// read_file → filesystem, etc.) plus optional policy-YAML
	// overrides.
	ScopeMap func(toolName string) string

	// BuildRefusal is the refusal-construction hook. Builds the synthetic-refusal
	// SSE bytes for a denied tool_call. Default (nil) returns a basic
	// generic refusal. The wired implementation constructs the
	// provider-specific refusal shape (OpenAI assistant-text + [DONE];
	// Anthropic text-block at the buffered tool_use's index + stop_reason
	// rewrite).
	//
	// See pkg/llmproxy/streaming.go (defaultRefusalBytes) for the
	// fallback implementation. The OpenAI shape is assistant-text +
	// [DONE]; `role: "tool"` causes SDK hangs and is intentionally
	// not used.
	BuildRefusal func(provider string, decision Decision, ctx *RefusalContext) []byte

	// running guards Run from being called concurrently for the
	// same Server (defensive — one Run per process is the contract).
	running   sync.Mutex
	startTime time.Time

	// streamingActive counts in-flight streaming requests across the
	// whole server process. Enforced against cfg.MaxConcurrentStreams
	// in the streaming dispatch path; exposed via the
	// agentguard_llmproxy_streams_active gauge. Read-only outside the
	// streaming entry/exit fences.
	streamingActive atomic.Int64
}

// NewServer constructs a Server from a parsed Config. URL validation
// already happened in Config.Validate; we only re-parse here to
// stash *url.URL pointers.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	openai, err := url.Parse(cfg.UpstreamOpenAI)
	if err != nil {
		return nil, fmt.Errorf("parse upstream-openai: %w", err)
	}
	anthropic, err := url.Parse(cfg.UpstreamAnthropic)
	if err != nil {
		return nil, fmt.Errorf("parse upstream-anthropic: %w", err)
	}

	// Per-host connection pool defaults from net/http are fine;
	// streaming responses hold one conn per active stream which is
	// expected. We override Timeout=0 (no end-to-end timeout) so
	// streaming responses are not artificially capped — the
	// per-request context (driven by client disconnect) is
	// authoritative.
	client := &http.Client{
		// Timeout intentionally zero: streaming responses must be
		// allowed to last as long as the upstream and client agree.
		// Cancellation rides through context.
		Timeout: 0,
	}

	return &Server{
		cfg:          cfg,
		httpClient:   client,
		openaiURL:    openai,
		anthropicURL: anthropic,
	}, nil
}

// Run starts the HTTP server. Blocks until ctx.Done() (graceful
// shutdown) or ListenAndServe returns an error. http.ErrServerClosed
// is mapped to nil because that's the expected shutdown path.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.TryLock() {
		return errors.New("server already running")
	}
	defer s.running.Unlock()

	mux := s.routes()

	srv := &http.Server{
		Addr:    s.cfg.Listen,
		Handler: mux,
		// ReadHeaderTimeout protects against slowloris on the
		// request-line + headers, but NOT on the body — the proxy
		// must accept large request bodies without artificially
		// timing them out (max-buffer-bytes is the real cap).
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.startTime = time.Now()

	// Graceful shutdown on ctx cancel. Use a separate goroutine so
	// ListenAndServe can return cleanly.
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	err := srv.ListenAndServe()
	<-shutdownDone

	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// routes builds the request multiplexer. Method-prefix patterns
// require Go 1.22+ (project pins go 1.22 in go.mod, see CLAUDE.md
// "Project Conventions").
//
// Every registered handler is wrapped with recoverPanic so a panic in
// a per-request goroutine (parser, accumulator, refusal builder)
// returns 500 to the client instead of crashing the entire process.
// Streaming responses that have already begun writing bytes can't
// emit a clean 500 (headers are gone); recoverPanic logs the stack
// in that case and the client sees a truncated SSE stream — far
// better than a process restart that drops every other in-flight
// request.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// OpenAI-shape routes — non-streaming forwarding plus streaming
	// inspection of tool_calls routed through PolicyCheck.
	mux.HandleFunc("POST /v1/chat/completions", s.recoverPanic(s.authMiddleware(s.handleChatCompletions)))
	mux.HandleFunc("POST /v1/completions", s.recoverPanic(s.authMiddleware(s.handleLegacyCompletions)))

	// Anthropic-shape route.
	mux.HandleFunc("POST /v1/messages", s.recoverPanic(s.authMiddleware(s.handleAnthropicMessages)))

	// Pass-through routes — no tool calls in these responses; the
	// audit entry tag is set by the gate but no policy gating fires.
	mux.HandleFunc("POST /v1/embeddings", s.recoverPanic(s.authMiddleware(s.handlePassThroughOpenAI)))
	mux.HandleFunc("GET /v1/models", s.recoverPanic(s.authMiddleware(s.handlePassThroughOpenAI)))

	// Proxy-level liveness. NOT auth-gated so health checks work
	// even when --proxy-api-key is set.
	mux.HandleFunc("GET /healthz", s.recoverPanic(s.handleHealth))

	return mux
}

// recoverPanic catches any panic raised by a downstream handler, logs
// the stack trace, and (if no bytes have flushed yet) returns a JSON
// 500 to the client. Streaming responses that have already begun
// writing SSE bytes will see only the log line — once headers + bytes
// are on the wire we can't safely inject a JSON error envelope without
// corrupting the stream. The panic is contained either way; the
// process keeps serving other in-flight requests.
//
// Mirrors pkg/proxy/server.go:recoverPanic.
func (s *Server) recoverPanic(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("llmproxy: PANIC %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				// Best-effort 500. If the handler already wrote
				// headers (notably any streaming path that has
				// flushed at least once), http stdlib swallows the
				// WriteHeader and we just log; clients will see the
				// stream end abruptly, which their SDKs already
				// handle as a network-level disconnect.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":{"message":"internal server error","type":"agentguard_error"}}`))
			}
		}()
		next(w, r)
	}
}

// admitStream attempts to acquire a streaming slot. Returns true if
// the request may proceed (caller must release with releaseStream
// when the handler returns); false if the global cap is reached
// (caller has already responded with 503 + Retry-After). When
// MaxConcurrentStreams == 0 the cap is disabled and admitStream is
// always true.
//
// Caller pattern (mirrors authMiddleware pairing):
//
//	if !s.admitStream(w) { return }
//	defer s.releaseStream()
func (s *Server) admitStream(w http.ResponseWriter) bool {
	cap := s.cfg.MaxConcurrentStreams
	if cap <= 0 {
		// Disabled; still bump the gauge so operators can observe
		// in-flight streams even when uncapped.
		n := s.streamingActive.Add(1)
		metrics.SetLLMProxyStreamsActive(n)
		return true
	}
	// Optimistic add-then-check keeps this lock-free; if we overshoot
	// we decrement and refuse, which costs one extra atomic op in the
	// rare overflow case.
	n := s.streamingActive.Add(1)
	if n > int64(cap) {
		s.streamingActive.Add(-1)
		metrics.SetLLMProxyStreamsActive(s.streamingActive.Load())
		metrics.IncLLMProxyStreamsRejected()
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"server overloaded; too many concurrent streams","type":"agentguard_error"}}`))
		return false
	}
	metrics.SetLLMProxyStreamsActive(n)
	return true
}

// releaseStream is the matching counterpart to admitStream. Always
// safe to call once per successful admitStream return; never call it
// when admitStream returned false (the slot was already released).
func (s *Server) releaseStream() {
	n := s.streamingActive.Add(-1)
	metrics.SetLLMProxyStreamsActive(n)
}

// handleHealth is the proxy's own liveness endpoint. Distinct from
// the central server's /v1/health — this reflects the proxy
// process, not the policy engine. See docs/PROXY_ARCHITECTURE.md § 8
// for the planned guard_reachable extension.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]interface{}{
		"status":    "ok",
		"version":   BuildVersion,
		"transport": "llm_api_proxy",
		"uptime_s":  int(time.Since(s.startTime).Seconds()),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// authMiddleware enforces the proxy's own bearer (X-AgentGuard-Proxy-Auth)
// when --proxy-api-key is set. When unset (the default for
// loopback-only deployments) it's a no-op.
//
// Constant-time compare to avoid trivial timing leakage on the key
// (matches central server's auth path).
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	if s.cfg.ProxyAPIKey == "" {
		return next
	}
	expected := []byte(s.cfg.ProxyAPIKey)
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(ProxyAuthHeader)
		// Bearer-prefix tolerated but optional. SDKs that prefer to
		// reuse Authorization-shaped headers can send "Bearer <key>";
		// the simpler "<key>" form also works.
		got = strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			writeJSONError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized: %s missing or invalid", ProxyAuthHeader))
			return
		}
		next(w, r)
	}
}

// ----- OpenAI handlers -----

// handleChatCompletions routes /v1/chat/completions. Streaming
// requests route to handleStreamingChatCompletion (the pause/resume/
// rewrite pipeline in pkg/llmproxy/streaming.go); non-streaming
// requests inspect the upstream response for tool_calls and gate each
// one through forwardChatCompletion, so the wire-level firewall holds
// regardless of stream mode.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	var req ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if isStreamingRequest(r, req.Stream) {
		s.handleStreamingChatCompletion(w, r, body, &req)
		return
	}

	if err := s.forwardChatCompletion(r.Context(), w, r, body, &req); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// handleLegacyCompletions routes /v1/completions (the older
// text-completion endpoint). Same forwarding shape as chat; legacy
// completions don't carry tool calls, but we honour Stream-detection
// for symmetry.
func (s *Server) handleLegacyCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	// Legacy /v1/completions has stream:bool too; reuse the same
	// minimal shape inspection (any unknown fields round-trip via
	// the byte body).
	var probe struct {
		Stream bool `json:"stream,omitempty"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if isStreamingRequest(r, probe.Stream) {
		// Legacy /v1/completions does not emit tool_calls, so the
		// streaming pipeline degenerates to pure passthrough. We
		// reuse the OpenAI streaming runner against the legacy path:
		// the parser observes no tool_call deltas and every event is
		// PassThrough.
		s.handleStreamingLegacyCompletion(w, r, body)
		return
	}

	if err := s.forwardOpenAI(r.Context(), w, r, body, "/v1/completions"); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// handleStreamingLegacyCompletion is the streaming variant of the
// /v1/completions handler. The legacy OpenAI completions endpoint
// does not return tool_calls, so the runner degenerates to pure
// passthrough — but we route through the same SSE machinery so
// byte-identity and flush semantics match the chat-completions path.
func (s *Server) handleStreamingLegacyCompletion(w http.ResponseWriter, r *http.Request, body []byte) {
	if !s.admitStream(w) {
		return
	}
	defer s.releaseStream()

	upstreamResp, err := s.dispatchStreamingUpstream(r.Context(), s.openaiURL, "/v1/completions", r.Header, body)
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
	s.runOpenAIStreamLoop(w, flusher, r, upstreamResp.Body)
}

// handlePassThroughOpenAI forwards /v1/embeddings and /v1/models to
// the OpenAI upstream verbatim. These endpoints don't return tool
// calls so no gating is needed — the proxy is a thin reverse-proxy
// here. Body is bounded for embeddings (the request can be large
// — but max-buffer-bytes is generous at 1 MiB).
func (s *Server) handlePassThroughOpenAI(w http.ResponseWriter, r *http.Request) {
	// /v1/models is GET (no body); /v1/embeddings is POST. We
	// uniformly read+forward the body when present; for GET
	// readRequestBody returns an empty slice cleanly.
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	if err := s.forwardOpenAI(r.Context(), w, r, body, r.URL.Path); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// ----- Anthropic handler -----

// handleAnthropicMessages routes /v1/messages. Streaming and non-
// streaming branches mirror the OpenAI Chat Completions handler.
func (s *Server) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r, s.cfg.MaxBufferBytes)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}

	var req AnthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if isStreamingRequest(r, req.Stream) {
		s.handleStreamingAnthropicMessages(w, r, body, &req)
		return
	}

	// F9 (B2): non-streaming /v1/messages mirrors the streaming gating
	// path. See forwardChatCompletion above for the rationale.
	if err := s.forwardAnthropicMessages(r.Context(), w, r, body, &req); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Errorf("upstream error: %w", err))
	}
}

// ----- Helpers -----

// isStreamingRequest detects whether a request asks for SSE. Two
// independent signals (per docs/LLM_API_PROXY.md § 3.2):
//
//  1. The body sets `stream: true`.
//  2. The Accept header includes "text/event-stream".
//
// Both signals are honoured because some SDKs only set the body flag
// and some only set the header; we err toward streaming if either
// indicates it.
func isStreamingRequest(r *http.Request, bodyStream bool) bool {
	if bodyStream {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(strings.ToLower(accept), "text/event-stream")
}

// writeJSONError writes an error envelope shaped like
// OpenAI/Anthropic's so SDK client error-handling code engages
// normally. status is the HTTP status code; err's text becomes the
// `message`.
func writeJSONError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": err.Error(),
			"type":    "agentguard_error",
		},
	})
}

// writeBodyReadError translates readRequestBody errors into the
// appropriate HTTP status — 413 for over-cap, 400 for malformed.
func writeBodyReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		writeJSONError(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	writeJSONError(w, http.StatusBadRequest, fmt.Errorf("read request body: %w", err))
}

// readRequestBody reads up to maxBytes+1 bytes from r.Body and
// returns errBodyTooLarge when the body exceeds maxBytes. The +1
// is critical: if we read exactly maxBytes we can't distinguish "fit
// exactly" from "truncated"; reading one extra byte makes the
// over-cap case unambiguous.
//
// Returns an empty (nil) slice for requests with no body (GET).
func readRequestBody(r *http.Request, maxBytes int) ([]byte, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, int64(maxBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}

var errBodyTooLarge = errors.New("request body exceeds --max-buffer-bytes")

// Run is the package-level convenience entry point invoked by
// cmd/agentguard-llm-proxy/main.go. Mirrors mcpgw.Run.
func Run(ctx context.Context, cfg *Config) error {
	srv, err := NewServer(cfg)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}
