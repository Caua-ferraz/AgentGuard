package mcpgw

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// MetaApprovalIDKey is the reserved `_meta` key MCP clients use to
// echo an AgentGuard approval id back to the gateway on retry. The
// reverse-DNS prefix `dev.agentguard/` follows the MCP `2025-11-25`
// `_meta` rules and avoids the reserved `io.modelcontextprotocol/`
// and `dev.mcp/` prefixes (per docs/MCP_GATEWAY.md § 6.2).
const MetaApprovalIDKey = "dev.agentguard/approval_id"

// MetaPrefixAgentGuard is the namespace the bridge strips out of
// `_meta` before forwarding tools/call to the upstream. Downstream
// MCP servers should not see the gateway's internal protocol.
const MetaPrefixAgentGuard = "dev.agentguard/"

// GatewayServerName is the ServerInfo.name advertised on `initialize`.
// The gateway never impersonates a downstream — its identity is
// always agentguard-mcp-gateway.
const GatewayServerName = "agentguard-mcp-gateway"

// Bridge is the JSON-RPC orchestrator. It owns the set of upstreams,
// reads frames from the host's stdin, dispatches them per method,
// and writes responses to the host's stdout. Policy and audit are
// implemented as nil-safe hooks so A18 (policy) and A19 (audit/SSE)
// can wire real implementations without re-engineering the bridge.
type Bridge struct {
	cfg       *Config
	upstreams map[string]Upstream // keyed by namespace
	logger    *transportLogger

	// Output mutex: stdin reader is single-threaded, but tools/call
	// dispatch is per-frame goroutine'd, so two responses may want
	// to land on stdout concurrently. Holding outMu around the
	// json-encode + write keeps frames atomic.
	outMu  sync.Mutex
	output io.Writer

	// version is the gateway's own version string, advertised on
	// initialize. Set by the binary entry point via NewBridge.
	version string

	// Captured at initialize time; replayed on tools/list etc. Used
	// when the bridge needs to spawn a synthetic Engine.Check for an
	// upstream that hasn't been initialized yet (cancellation, etc.).
	initOnce        sync.Once
	negotiatedProto string
	clientInfo      ClientInfo

	// Hooks for A18 and A19. All nil-safe — a nil hook means the
	// bridge falls through with conservative defaults (ALLOW for
	// policy, no-op for audit/SSE). Set by the binary entry point
	// (or by tests) before Run().

	// PolicyCheck is the hook A18 wires. The default (nil) ALLOWs
	// every tool call — useful for early bring-up before the policy
	// engine is integrated. A18 sets this to a function that:
	//   1. Builds a policy.ActionRequest from the ToolsCallRequest
	//      (scope: "mcp_tool", command: "<ns>:<tool>", agent_id from
	//      clientInfo, etc.).
	//   2. Optionally also dispatches a second Engine.Check against
	//      the mapped scope per the dual-check pattern (governed by
	//      Config.PolicyMode == "strict").
	//   3. Returns a Decision struct.
	//
	// The bridge calls PolicyCheck with the bridge's context so a
	// cancellation propagates into the hook.
	PolicyCheck func(ctx context.Context, req *ToolsCallRequest) (Decision, error)

	// AuditEmit is the hook A19 wires. The default (nil) is a no-op.
	// A19 sets this to a function that writes one audit.Entry via
	// the shared BufferedAsyncLogger with Transport: "mcp_gateway".
	// The hook MUST NOT block the request hot path — A19 is expected
	// to fan out to its own goroutines internally.
	AuditEmit func(entry AuditEntry)

	// SSEEmit is the hook A19 wires. The default (nil) is a no-op.
	// A19 sets this to a function that pushes one SSE event into
	// the existing pkg/proxy ApprovalQueue's broadcast channel so
	// the dashboard sees MCP traffic with the `mcp_gateway` chip.
	SSEEmit func(event SSEEvent)
}

// ToolsCallRequest is the bridge-internal shape passed to PolicyCheck.
// A18 reads this, calls Engine.Check, returns Decision.
type ToolsCallRequest struct {
	Namespace  string                 // resolved from the prefixed name
	ToolName   string                 // un-prefixed name as the upstream sees it
	FullName   string                 // the prefixed name as the host sent it
	Arguments  map[string]interface{} // tool arguments verbatim
	Meta       map[string]interface{} // _meta with `dev.agentguard/*` keys preserved
	TenantID   string                 // from cfg.TenantID
	AgentID    string                 // synthesised from ClientInfo.Name
	SessionID  string                 // session-scoped key (clientInfo + pid hint)
	ApprovalID string                 // populated from _meta.dev.agentguard/approval_id if present
}

// Decision is the verdict returned by PolicyCheck.
type Decision struct {
	Allow       bool
	Reason      string
	Rule        string
	ApprovalID  string // set when REQUIRE_APPROVAL
	ApprovalURL string
	// RequiresApproval is set when the policy engine returned
	// REQUIRE_APPROVAL. The bridge surfaces it as an isError=true
	// content block (per docs/MCP_GATEWAY.md § 6.1) rather than a
	// JSON-RPC error.
	RequiresApproval bool
}

// AuditEntry is the bridge-internal shape passed to AuditEmit. A19
// translates this into the canonical audit.Entry with
// Transport="mcp_gateway".
type AuditEntry struct {
	Timestamp  time.Time
	AgentID    string
	SessionID  string
	TenantID   string
	Scope      string
	Command    string
	Path       string
	Domain     string
	URL        string
	Decision   string
	Rule       string
	Reason     string
	DurationMs float64
	Meta       map[string]interface{}
}

// SSEEvent is the bridge-internal shape passed to SSEEmit. A19
// translates this into the broadcast channel the dashboard reads.
type SSEEvent struct {
	Type      string                 // "check" | "denied" | "approval_required"
	Timestamp time.Time
	AgentID   string
	Decision  string
	Scope     string
	Command   string
	Meta      map[string]interface{}
}

// NewBridge constructs a Bridge from a parsed Config and a logger
// writer (typically os.Stderr). Upstreams are NOT started until
// Run() is called.
func NewBridge(cfg *Config, logger io.Writer, version string) *Bridge {
	tlog := newTransportLogger(logger, cfg.LogLevel)
	return &Bridge{
		cfg:       cfg,
		upstreams: map[string]Upstream{},
		logger:    tlog,
		version:   version,
	}
}

// SetUpstream wires a custom Upstream into the bridge. Used by tests
// to inject fakes. Must be called before Run.
func (b *Bridge) SetUpstream(up Upstream) {
	b.upstreams[up.Namespace()] = up
}

// Run is the bridge's main loop. Reads JSON-RPC frames from `in`,
// dispatches per method, writes responses to `out`. Returns when:
//   - ctx is cancelled (graceful shutdown);
//   - `in` EOFs (host disconnected);
//   - a fatal error occurs (subprocess startup failure with
//     fail-mode=deny).
//
// Run is goroutine-safe at the entry-point level (one goroutine per
// host) but must not be called concurrently for the same Bridge.
func (b *Bridge) Run(ctx context.Context, in io.Reader, out io.Writer, errLog io.Writer) error {
	b.output = out
	if errLog != nil {
		b.logger = newTransportLogger(errLog, b.cfg.LogLevel)
	}

	// Start every upstream. We do NOT call Initialize here — the
	// host drives Initialize and we forward to upstreams in
	// handleInitialize. Subprocess spawn failures are treated per
	// fail-mode: in `allow` mode we log + continue with a degraded
	// namespace; in `deny` and `fail-closed-with-audit` modes we
	// keep going too — the namespace returns ErrUpstreamUnavail on
	// every call so the host gets clean errors rather than a
	// startup hang.
	for _, spec := range b.cfg.Upstreams {
		if _, exists := b.upstreams[spec.Namespace]; exists {
			// Test injection already wired this namespace.
			continue
		}
		up := NewStdioUpstreamWithOptions(spec, StdioUpstreamOptions{
			Logger: b.logger,
		})
		if err := up.Start(ctx); err != nil {
			b.logger.Infof("startup: upstream %q failed to spawn: %v", spec.Namespace, err)
		}
		b.upstreams[spec.Namespace] = up
	}
	defer b.closeUpstreams()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), MaxStdoutLineBytes)

	// Each tools/call gets its own goroutine so a slow upstream
	// doesn't block the next frame. Other methods are dispatched
	// synchronously to preserve ordering (initialize must complete
	// before any other work).
	var wg sync.WaitGroup

	scanCh := make(chan []byte, 16)
	scanErrCh := make(chan error, 1)
	go func() {
		defer close(scanCh)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			// Copy because Scanner reuses its buffer.
			cp := make([]byte, len(line))
			copy(cp, line)
			scanCh <- cp
		}
		if err := scanner.Err(); err != nil {
			scanErrCh <- err
		}
	}()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case line, ok := <-scanCh:
			if !ok {
				wg.Wait()
				select {
				case err := <-scanErrCh:
					return err
				default:
					return nil
				}
			}
			b.dispatchFrame(ctx, line, &wg)
		}
	}
}

// dispatchFrame parses one frame and routes it. Per Phase 3 A15's
// pattern: malformed frames are logged and dropped without killing
// the bridge.
func (b *Bridge) dispatchFrame(ctx context.Context, line []byte, wg *sync.WaitGroup) {
	// First peek at whether the frame has an id. A frame without an
	// id is a notification; with id it's a request.
	var probe struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		b.logger.Infof("dropping malformed frame: %v", err)
		return
	}
	if probe.Method == "" {
		// No method? Either a stray response from us (which should
		// not happen — host should not send responses) or junk.
		b.logger.Debugf("frame without method dropped: %s", string(line))
		return
	}

	// Notification (no id field present at all).
	if len(probe.ID) == 0 || string(probe.ID) == "null" {
		b.handleNotification(ctx, probe.Method, probe.Params)
		return
	}

	// Request. Decode the id field to its native type so we can echo
	// it on the response.
	var id RequestID
	if err := json.Unmarshal(probe.ID, &id); err != nil {
		b.logger.Infof("invalid id field: %v", err)
		return
	}

	switch probe.Method {
	case MethodInitialize:
		b.writeResponse(b.handleInitialize(ctx, id, probe.Params))
	case MethodToolsList:
		b.writeResponse(b.handleToolsList(ctx, id, probe.Params))
	case MethodToolsCall:
		// Concurrent dispatch so a slow upstream doesn't head-of-line
		// the next frame.
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.writeResponse(b.handleToolsCall(ctx, id, probe.Params))
		}()
	case MethodPing:
		b.writeResponse(NewResponseResult(id, json.RawMessage(`{}`)))
	case MethodLoggingSetLevel:
		// Forward to every upstream best-effort.
		b.writeResponse(b.handleLoggingSetLevel(ctx, id, probe.Params))
	default:
		// resources/* and prompts/* are out of scope for v0.5.
		// TODO(v0.6, #mcp-resources): forward resources/* and
		// prompts/* with namespace-prefixed URIs.
		b.writeResponse(NewResponseError(id, ErrCodeMethodNotFound,
			fmt.Sprintf("method %q not supported by gateway", probe.Method), nil))
	}
}

// handleNotification routes notifications to upstreams. v0.5 broadcasts
// to all upstreams (cancellation, initialized). Per-upstream targeted
// notifications are a future enhancement.
func (b *Bridge) handleNotification(ctx context.Context, method string, params json.RawMessage) {
	n := &Notification{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  params,
	}
	for _, up := range b.upstreams {
		if up.Status() != StatusOK {
			continue
		}
		// Best effort, fire-and-forget. We use a short context
		// derived from the bridge ctx so a sluggish upstream doesn't
		// stall the whole notification fanout.
		nctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		_ = up.Notify(nctx, n)
		cancel()
	}
}

// handleInitialize processes the host's initialize request. Per
// docs/MCP_GATEWAY.md § 3.2:
//   - Negotiate protocol version against SupportedProtocolVersions.
//   - Forward initialize to every upstream with the negotiated version.
//   - Synthesise the gateway's own ServerInfo and merge upstream caps.
func (b *Bridge) handleInitialize(ctx context.Context, id RequestID, raw json.RawMessage) *Response {
	var params InitializeParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return NewResponseError(id, ErrCodeInvalidParams,
			fmt.Sprintf("initialize: invalid params: %v", err), nil)
	}

	negotiated := NegotiateProtocolVersion(params.ProtocolVersion, b.cfg.SupportedProtocolVersions)
	if negotiated == "" {
		data, _ := json.Marshal(map[string]interface{}{
			"requested": params.ProtocolVersion,
			"supported": b.cfg.SupportedProtocolVersions,
		})
		return NewResponseError(id, ErrCodeInvalidParams,
			"Unsupported protocol version", data)
	}

	// Forward initialize to every upstream and collect their caps.
	upstreamCaps := make([]map[string]interface{}, 0, len(b.upstreams))
	lowest := negotiated
	for _, up := range b.upstreams {
		ictx, cancel := context.WithTimeout(ctx, b.cfg.UpstreamTimeout)
		result, err := up.Initialize(ictx, negotiated, params.Capabilities, params.ClientInfo)
		cancel()
		if err != nil {
			b.logger.Infof("initialize: upstream %q init failed: %v", up.Namespace(), err)
			continue
		}
		upstreamCaps = append(upstreamCaps, result.Capabilities)
		// If an upstream pinned an older version, the session
		// degrades to the lowest common denominator (per § 3.2 step 3).
		if result.ProtocolVersion != "" && result.ProtocolVersion < lowest {
			lowest = result.ProtocolVersion
			b.logger.Infof("initialize: upstream %q pinned older version %q, downgrading session", up.Namespace(), result.ProtocolVersion)
		}
	}

	merged := MergeCapabilities(upstreamCaps)

	// Cache for later use (e.g., reconnect) — initOnce keeps the
	// first negotiated state authoritative.
	b.initOnce.Do(func() {
		b.negotiatedProto = lowest
		b.clientInfo = params.ClientInfo
	})

	result := InitializeResult{
		ProtocolVersion: lowest,
		Capabilities:    merged,
		ServerInfo: ServerInfo{
			Name:    GatewayServerName,
			Version: b.version,
		},
	}
	return NewResponseFrom(id, result)
}

// handleToolsList aggregates tools/list across upstreams. Per
// docs/MCP_GATEWAY.md § 4.2: fan out in parallel, concatenate
// results, prefix tool names with the namespace.
//
// Pagination decision (per task spec): v0.5 refuses pagination at
// the gateway and returns all tools in one page. Upstream-side
// pagination is collapsed by walking each upstream's cursor until
// exhausted before returning. Cursor opacity is preserved per spec.
//
// TODO(v0.6, #mcp-pagination): forward host cursor selectively per
// namespace + multiplex nextCursor as base64({"ns":..., "cursor":...}).
func (b *Bridge) handleToolsList(ctx context.Context, id RequestID, _ json.RawMessage) *Response {
	type upResult struct {
		ns    string
		tools []ToolDescriptor
		err   error
	}
	results := make(chan upResult, len(b.upstreams))
	var wg sync.WaitGroup
	for _, up := range b.upstreams {
		if up.Status() != StatusOK {
			continue
		}
		wg.Add(1)
		go func(up Upstream) {
			defer wg.Done()
			tools, err := b.collectAllTools(ctx, up)
			results <- upResult{ns: up.Namespace(), tools: tools, err: err}
		}(up)
	}
	wg.Wait()
	close(results)

	all := make([]ToolDescriptor, 0)
	for r := range results {
		if r.err != nil {
			b.logger.Infof("tools/list: upstream %q error: %v", r.ns, r.err)
			continue
		}
		for _, t := range r.tools {
			// Prefix namespace.
			if strings.ContainsRune(t.Name, ':') {
				// Downstream advertised a tool name with `:` — this
				// breaks our prefix scheme. Skip and warn so the
				// operator notices.
				b.logger.Infof("tools/list: upstream %q tool name %q contains ':'; skipping (would collide with namespace prefix)", r.ns, t.Name)
				continue
			}
			t.Name = r.ns + ":" + t.Name
			all = append(all, t)
		}
	}

	return NewResponseFrom(id, ToolsListResult{Tools: all})
}

// collectAllTools walks an upstream's tools/list pagination until
// exhausted, returning the concatenated descriptors.
func (b *Bridge) collectAllTools(ctx context.Context, up Upstream) ([]ToolDescriptor, error) {
	const maxPages = 64 // belt-and-braces against a misbehaving upstream
	cursor := ""
	out := []ToolDescriptor{}
	for page := 0; page < maxPages; page++ {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}

		ictx, cancel := context.WithTimeout(ctx, b.cfg.UpstreamTimeout)
		resp, err := up.Send(ictx, &Request{
			JSONRPC: JSONRPCVersion,
			Method:  MethodToolsList,
			Params:  raw,
		})
		cancel()
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("upstream error: %s", resp.Error.Message)
		}
		var result ToolsListResult
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			return nil, fmt.Errorf("decode tools/list result: %w", err)
		}
		out = append(out, result.Tools...)
		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}
	return out, nil
}

// handleToolsCall is the policy gate. Per docs/MCP_GATEWAY.md § 4.3:
//  1. Split the prefixed name on the first `:`.
//  2. Validate namespace.
//  3. Run PolicyCheck (A18's hook). On DENY/REQUIRE_APPROVAL surface
//     as an isError=true content block.
//  4. On ALLOW, strip the namespace prefix from the request, strip
//     dev.agentguard/* keys from `_meta`, and forward to upstream.
//  5. Emit audit + SSE.
func (b *Bridge) handleToolsCall(ctx context.Context, id RequestID, raw json.RawMessage) *Response {
	start := time.Now()

	var params ToolsCallParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return NewResponseError(id, ErrCodeInvalidParams,
			fmt.Sprintf("tools/call: invalid params: %v", err), nil)
	}

	ns, toolName, ok := splitNamespacedName(params.Name)
	if !ok {
		return NewResponseError(id, ErrCodeInvalidParams,
			fmt.Sprintf("tools/call: name %q must be \"<namespace>:<tool>\"", params.Name), nil)
	}
	up, exists := b.upstreams[ns]
	if !exists {
		return NewResponseError(id, ErrCodeInvalidParams,
			fmt.Sprintf("tools/call: unknown namespace %q", ns), nil)
	}
	if up.Status() != StatusOK {
		data, _ := json.Marshal(map[string]string{"namespace": ns})
		return NewResponseError(id, ErrCodeUpstreamUnavail,
			fmt.Sprintf("tools/call: upstream %q unavailable", ns), data)
	}

	// Build the policy-hook input.
	approvalID := ""
	if params.Meta != nil {
		if v, ok := params.Meta[MetaApprovalIDKey].(string); ok {
			approvalID = v
		}
	}
	preq := &ToolsCallRequest{
		Namespace:  ns,
		ToolName:   toolName,
		FullName:   params.Name,
		Arguments:  params.Arguments,
		Meta:       params.Meta,
		TenantID:   b.cfg.TenantID,
		AgentID:    b.deriveAgentID(),
		SessionID:  b.deriveSessionID(),
		ApprovalID: approvalID,
	}

	// Run the policy hook.
	dec, err := b.runPolicyCheck(ctx, preq)
	if err != nil {
		// Hook itself failed (e.g., /v1/check unreachable). The hook
		// is responsible for honouring fail-mode; if it bubbles an
		// error here we surface it as a tool error (isError) so the
		// model sees a clean refusal.
		b.logger.Infof("policy hook error: %v", err)
		b.emitAudit(preq, "DENY", "deny:guard_unreachable", err.Error(), start)
		return NewResponseFrom(id, toolErrorResult(fmt.Sprintf("[AgentGuard] policy check failed: %v", err)))
	}

	if !dec.Allow && dec.RequiresApproval {
		// REQUIRE_APPROVAL: surface as isError content block per
		// MCP_GATEWAY.md § 6.1, so the model can either retry with
		// `_meta.dev.agentguard/approval_id` or surface the URL to
		// the user.
		b.emitAudit(preq, "REQUIRE_APPROVAL", dec.Rule, dec.Reason, start)
		b.emitSSE(preq, "approval_required", "REQUIRE_APPROVAL")
		text := fmt.Sprintf(
			"[AgentGuard] Action requires approval.\nReason: %s\nApproval ID: %s\nApprove at: %s",
			dec.Reason, dec.ApprovalID, dec.ApprovalURL)
		// Embed structured info in _meta so MCP-aware clients can
		// pick it up programmatically. The MCP spec says result
		// objects support `_meta`; we use it for round-tripping.
		result := ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: text}},
			IsError: true,
		}
		// We synthesise meta via raw map to preserve existing
		// content-block metadata (none in this synthetic case).
		out, _ := json.Marshal(struct {
			Content []ContentBlock         `json:"content"`
			IsError bool                   `json:"isError"`
			Meta    map[string]interface{} `json:"_meta,omitempty"`
		}{
			Content: result.Content,
			IsError: result.IsError,
			Meta: map[string]interface{}{
				MetaApprovalIDKey:                 dec.ApprovalID,
				"dev.agentguard/approval_url":     dec.ApprovalURL,
			},
		})
		return NewResponseResult(id, out)
	}

	if !dec.Allow {
		// DENY: surface as isError content block. We do NOT use the
		// JSON-RPC error path because the MCP spec reserves
		// JSON-RPC errors for protocol-level failures. (See
		// docs/MCP_GATEWAY.md § 11.)
		b.emitAudit(preq, "DENY", dec.Rule, dec.Reason, start)
		b.emitSSE(preq, "denied", "DENY")
		text := fmt.Sprintf("[AgentGuard] Action denied by policy.\nReason: %s\nRule: %s",
			dec.Reason, dec.Rule)
		result := ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: text}},
			IsError: true,
		}
		return NewResponseFrom(id, result)
	}

	// ALLOW: strip dev.agentguard/* meta keys and the namespace
	// prefix, then forward.
	forwardMeta := stripAgentGuardMeta(params.Meta)
	forwardParams := map[string]interface{}{"name": toolName}
	if params.Arguments != nil {
		forwardParams["arguments"] = params.Arguments
	}
	if forwardMeta != nil {
		forwardParams["_meta"] = forwardMeta
	}
	rawForward, err := json.Marshal(forwardParams)
	if err != nil {
		b.logger.Infof("tools/call: marshal forward params: %v", err)
		b.emitAudit(preq, "DENY", "deny:internal_error", err.Error(), start)
		return NewResponseError(id, ErrCodeInternalError,
			fmt.Sprintf("internal error: %v", err), nil)
	}

	upCtx, cancel := context.WithTimeout(ctx, b.cfg.UpstreamTimeout)
	defer cancel()
	resp, err := up.Send(upCtx, &Request{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Method:  MethodToolsCall,
		Params:  rawForward,
	})
	if err != nil {
		b.emitAudit(preq, "ALLOW", dec.Rule, fmt.Sprintf("upstream send failed: %v", err), start)
		return NewResponseError(id, ErrCodeUpstreamUnavail,
			fmt.Sprintf("upstream %q error: %v", ns, err), nil)
	}

	b.emitAudit(preq, "ALLOW", dec.Rule, dec.Reason, start)
	b.emitSSE(preq, "check", "ALLOW")
	return resp
}

// handleLoggingSetLevel forwards logging/setLevel to every upstream
// best-effort, then returns an empty result.
func (b *Bridge) handleLoggingSetLevel(ctx context.Context, id RequestID, raw json.RawMessage) *Response {
	for _, up := range b.upstreams {
		if up.Status() != StatusOK {
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, b.cfg.UpstreamTimeout)
		_, _ = up.Send(ictx, &Request{
			JSONRPC: JSONRPCVersion,
			Method:  MethodLoggingSetLevel,
			Params:  raw,
		})
		cancel()
	}
	return NewResponseResult(id, json.RawMessage(`{}`))
}

// runPolicyCheck invokes the PolicyCheck hook, falling back to a
// nil-safe ALLOW when no hook is wired (early-bring-up mode).
//
// TODO(v0.6, #mcp-meta-fallback): in-process state for clients that
// strip `_meta` (some MCP host implementations may not preserve
// custom `_meta` keys). The recommended path is the meta round-trip
// per docs/MCP_GATEWAY.md § 6.2; this fallback is the escape hatch.
func (b *Bridge) runPolicyCheck(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
	if b.PolicyCheck == nil {
		return Decision{
			Allow:  true,
			Reason: "policy hook not wired (early bring-up; A18 implements)",
			Rule:   "allow:policy_hook_unwired",
		}, nil
	}
	return b.PolicyCheck(ctx, req)
}

// emitAudit invokes the AuditEmit hook with a populated AuditEntry.
// nil-safe.
func (b *Bridge) emitAudit(req *ToolsCallRequest, decision, rule, reason string, start time.Time) {
	if b.AuditEmit == nil {
		return
	}
	// Best-effort path-extract for the dual-check / dashboard chip.
	// Inferring a path/url from arguments is A18's job; the bridge
	// just forwards whatever raw arguments it has.
	var path, url, domain string
	if req.Arguments != nil {
		if v, ok := req.Arguments["path"].(string); ok {
			path = v
		} else if v, ok := req.Arguments["file_path"].(string); ok {
			path = v
		}
		if v, ok := req.Arguments["url"].(string); ok {
			url = v
		}
	}
	b.AuditEmit(AuditEntry{
		Timestamp:  time.Now().UTC(),
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		TenantID:   req.TenantID,
		Scope:      "mcp_tool",
		Command:    req.FullName,
		Path:       path,
		URL:        url,
		Domain:     domain,
		Decision:   decision,
		Rule:       rule,
		Reason:     reason,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
		Meta: map[string]interface{}{
			"namespace":   req.Namespace,
			"tool_name":   req.ToolName,
			"approval_id": req.ApprovalID,
			"policy_mode": b.cfg.PolicyMode,
		},
	})
}

// emitSSE invokes the SSEEmit hook. nil-safe.
func (b *Bridge) emitSSE(req *ToolsCallRequest, eventType, decision string) {
	if b.SSEEmit == nil {
		return
	}
	b.SSEEmit(SSEEvent{
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		AgentID:   req.AgentID,
		Decision:  decision,
		Scope:     "mcp_tool",
		Command:   req.FullName,
		Meta: map[string]interface{}{
			"namespace": req.Namespace,
			"transport": "mcp_gateway",
		},
	})
}

// writeResponse JSON-encodes resp and writes one frame to b.output
// under the output mutex. Errors are logged but not returned —
// stdout failure is fatal in practice (host pipe broken) and the
// scanner-error path will surface the disconnect.
func (b *Bridge) writeResponse(resp *Response) {
	if resp == nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		b.logger.Infof("write response: marshal failed: %v", err)
		return
	}
	data = append(data, '\n')

	b.outMu.Lock()
	defer b.outMu.Unlock()
	if b.output == nil {
		return
	}
	if _, err := b.output.Write(data); err != nil {
		b.logger.Infof("write response: stdout write failed: %v", err)
	}
}

// closeUpstreams gracefully closes every upstream. Best-effort.
func (b *Bridge) closeUpstreams() {
	for _, up := range b.upstreams {
		if err := up.Close(); err != nil {
			b.logger.Infof("upstream %q close: %v", up.Namespace(), err)
		}
	}
}

// deriveAgentID synthesises an agent-id from the host's clientInfo.
// Format: "mcp-gateway:<clientName>". Falls back to "mcp-gateway"
// when clientInfo isn't populated yet (initialize hasn't happened
// or the host omitted it).
func (b *Bridge) deriveAgentID() string {
	if b.clientInfo.Name == "" {
		return "mcp-gateway"
	}
	return "mcp-gateway:" + b.clientInfo.Name
}

// deriveSessionID returns a stable per-host session id. v0.5 uses
// the client name as the session key; future versions may add a
// per-process pid or a uuid generated at initialize time.
func (b *Bridge) deriveSessionID() string {
	if b.clientInfo.Name == "" {
		return "mcp-gateway-default"
	}
	return "mcp-gateway:" + b.clientInfo.Name
}

// splitNamespacedName splits "<ns>:<tool>" on the first `:`. Returns
// ok=false when the name has no colon or has an empty namespace/tool.
func splitNamespacedName(name string) (ns, tool string, ok bool) {
	idx := strings.IndexByte(name, ':')
	if idx <= 0 || idx == len(name)-1 {
		return "", "", false
	}
	return name[:idx], name[idx+1:], true
}

// stripAgentGuardMeta returns a copy of meta with all
// dev.agentguard/* keys removed. Returns nil if the result would be
// empty (so we don't add an `_meta` field downstream when the host
// only sent gateway-internal keys).
func stripAgentGuardMeta(meta map[string]interface{}) map[string]interface{} {
	if len(meta) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		if strings.HasPrefix(k, MetaPrefixAgentGuard) {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// toolErrorResult returns a ToolsCallResult with a single text
// content block and isError=true.
func toolErrorResult(text string) ToolsCallResult {
	return ToolsCallResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
		IsError: true,
	}
}

// Run is the package-level convenience entry point invoked by
// cmd/agentguard-mcp-gateway/main.go. Wires the bridge against the
// supplied stdio handles and returns when the bridge's main loop
// exits.
func Run(ctx context.Context, cfg *Config, in io.Reader, out io.Writer, errLog io.Writer) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	bridge := NewBridge(cfg, errLog, GatewayBuildVersion)
	return bridge.Run(ctx, in, out, errLog)
}

// GatewayBuildVersion is overridden via -ldflags by the binary entry
// point. Default ("dev") is used when the package is built without
// -ldflags (e.g., go test).
var GatewayBuildVersion = "dev"
