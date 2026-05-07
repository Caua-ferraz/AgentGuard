package mcpgw

// gate.go wires the MCP Gateway's PolicyCheck hook against the central
// AgentGuard server's /v1/check endpoint. The gateway loads the same
// policy YAML the central server loads (via --policy <path>) so it can
// resolve the dual-check tool_scope_map locally without an extra HTTP
// roundtrip; the policy values fed to the hook are kept in lockstep
// with the central server via the policy provider's Watch mechanism.
//
// Dual-check semantics (docs/MCP_GATEWAY.md § 4.4):
//
//   --policy-mode strict (default):
//     1. Engine.Check(scope="mcp_tool", command="<ns>:<tool>") via /v1/check.
//     2. If (1) ALLOWs and the tool name maps to an existing scope per
//        Policy.MapToolScope, Engine.Check against the mapped scope
//        (path/url/domain/command extracted from arguments per scope).
//     3. If either DENYs or REQUIRE_APPROVALs, that wins.
//
//   --policy-mode fast:
//     Only step (1). The mapped scope is informational only; operators
//     who want filesystem semantics in fast mode have to write
//     mcp_tool rules that match on tool-name patterns.
//
// Fail-mode (docs/PROXY_ARCHITECTURE.md § 6.1):
//   --fail-mode deny / fail-closed-with-audit (default): /v1/check
//     unreachable → synthetic DENY with Rule="deny:gateway:fail_closed".
//   --fail-mode allow: /v1/check unreachable → synthetic ALLOW. Used
//     in dev to keep the host responsive when the central server is
//     down; should NOT be the production setting.

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
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// DefaultGuardHTTPTimeout is the per-/v1/check-call timeout the gate
// applies when the operator does not pass a custom http.Client. Five
// seconds matches the SDKs and the value documented in
// docs/PROXY_ARCHITECTURE.md § 6.1.
const DefaultGuardHTTPTimeout = 5 * time.Second

// FailModeRuleClosed is the synthetic Rule string the gate stamps on
// fail-closed denials so operators can alert on it without confusing
// it with a real policy DENY. Stable string contract — referenced from
// dashboard + tests.
const FailModeRuleClosed = "deny:gateway:fail_closed"

// HTTPPolicyClient calls the central AgentGuard server's /v1/check
// endpoint and orchestrates the dual-check pattern. One client per
// gateway process; the underlying http.Client (and its connection
// pool) is reused.
//
// Policy is held atomically — the gateway's main.go subscribes to the
// PolicyProvider's Watch and calls SetPolicy on every reload so the
// tool_scope_map stays in sync with the central server's view. Reads
// are lock-free atomic loads on the hot path.
type HTTPPolicyClient struct {
	GuardURL   string // e.g. "http://127.0.0.1:8080"
	APIKey     string // bearer token; empty if --api-key not set
	TenantID   string // "local" for v0.5
	PolicyMode string // "strict" | "fast"
	FailMode   string // "deny" | "allow" | "fail-closed-with-audit"

	// HTTPClient is reused across calls. Set to a custom client in
	// tests; otherwise the constructor defaults to a 5s-timeout client.
	HTTPClient *http.Client

	// policy holds the active *policy.Policy via atomic load/store so
	// the hot path doesn't take a lock. nil is safe — a nil policy
	// just means "no tool_scope_map known yet, skip dual-check".
	policy atomic.Pointer[policy.Policy]
}

// NewHTTPPolicyClient constructs a gate against cfg + an initial
// policy snapshot. The caller is expected to subscribe to the policy
// provider's Watch and call SetPolicy on every reload.
func NewHTTPPolicyClient(cfg *Config, pol *policy.Policy) *HTTPPolicyClient {
	c := &HTTPPolicyClient{
		GuardURL:   cfg.GuardURL,
		APIKey:     cfg.APIKey,
		TenantID:   cfg.TenantID,
		PolicyMode: cfg.PolicyMode,
		FailMode:   cfg.FailMode,
		HTTPClient: &http.Client{Timeout: DefaultGuardHTTPTimeout},
	}
	c.policy.Store(pol)
	return c
}

// SetPolicy swaps the cached policy snapshot. Called from the policy
// provider's Watch callback in main.go. nil is accepted (resets to
// "no map known"); subsequent dual-check calls fall through to
// mcp_tool-only resolution until SetPolicy is called with a real
// policy again.
func (c *HTTPPolicyClient) SetPolicy(pol *policy.Policy) {
	c.policy.Store(pol)
}

// Check is the function wired into Bridge.PolicyCheck. Runs the
// dual-check pattern when policy mode is strict; falls through to a
// single check otherwise.
func (c *HTTPPolicyClient) Check(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
	if req == nil {
		return Decision{Allow: false, Reason: "nil tools/call request", Rule: "deny:gateway:invalid_request"}, nil
	}

	// 1. mcp_tool scope check. Always runs.
	//
	// ApprovalID propagation: when the host retries a tools/call with
	// `_meta.dev.agentguard/approval_id` set, the bridge stamps it on
	// req.ApprovalID and we forward it as a top-level field on the
	// /v1/check body. The central server's handleCheck consults the
	// approval queue first when this is set; resolved entries short-
	// circuit the policy evaluation entirely so a human's approve/deny
	// is honored across the model's retry. (A19b — closes
	// #mcp-approval-roundtrip.)
	mcpAR := policy.ActionRequest{
		Scope:      "mcp_tool",
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		Command:    req.FullName,
		Meta:       buildMcpMeta(req),
		ApprovalID: req.ApprovalID,
	}
	decMCP, err := c.callV1Check(ctx, mcpAR)
	if err != nil {
		return c.failModeDecision(err), nil
	}
	if !decMCP.Allow {
		return decMCP, nil
	}

	// 2. Mapped-scope check (strict only).
	if strings.EqualFold(c.PolicyMode, "fast") {
		return decMCP, nil
	}

	pol := c.policy.Load()
	if pol == nil {
		// No policy snapshot to read tool_scope_map from. Treat as
		// "no mapping" — same outcome as a tool that no entry covers.
		return decMCP, nil
	}
	mappedScope, ok := pol.MapToolScope(req.FullName)
	if !ok {
		return decMCP, nil
	}

	mappedAR := buildMappedActionRequest(req, mappedScope)
	decMapped, err := c.callV1Check(ctx, mappedAR)
	if err != nil {
		return c.failModeDecision(err), nil
	}
	if !decMapped.Allow {
		// The denying rule wins. Stamp the secondary scope on the
		// reason so operators can see which check produced the verdict.
		if !decMapped.RequiresApproval {
			decMapped.Reason = fmt.Sprintf("%s (mapped scope=%s)", decMapped.Reason, mappedScope)
		}
		return decMapped, nil
	}

	// Both checks ALLOWed. Return the mcp_tool decision (the more
	// specific scope for this request); the secondary outcome is
	// informational and lands in audit metadata via the bridge.
	return decMCP, nil
}

// buildMcpMeta builds the meta map sent on the mcp_tool /v1/check call.
// Argument values are best-effort serialised so policy authors can
// match on them via meta-aware patterns; secrets are redacted by the
// downstream notify Redactor before the value lands in the audit log
// (see docs/MCP_GATEWAY.md § 5).
func buildMcpMeta(req *ToolsCallRequest) map[string]string {
	out := map[string]string{
		"namespace":   req.Namespace,
		"tool_name":   req.ToolName,
		"transport":   "mcp_gateway",
	}
	if req.ApprovalID != "" {
		out["approval_id"] = req.ApprovalID
	}
	if len(req.Arguments) > 0 {
		// Best-effort flatten so simple string args become discoverable
		// rule attributes. Non-stringy values are JSON-encoded.
		for k, v := range req.Arguments {
			switch s := v.(type) {
			case string:
				out["arg_"+k] = s
			default:
				if b, err := json.Marshal(v); err == nil {
					out["arg_"+k] = string(b)
				}
			}
		}
	}
	return out
}

// buildMappedActionRequest projects a ToolsCallRequest into the right
// fields for the mapped scope's Engine.Check call. Best-effort: the
// operator's mcp_tool rules are the primary signal; the mapped scope
// is a secondary safety net that catches dangerous arguments via the
// existing scope rules without requiring duplicate mcp_tool rules.
func buildMappedActionRequest(req *ToolsCallRequest, mappedScope string) policy.ActionRequest {
	ar := policy.ActionRequest{
		Scope:      mappedScope,
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		Meta:       buildMcpMeta(req),
		ApprovalID: req.ApprovalID,
	}

	switch mappedScope {
	case "filesystem":
		// Path is the primary signal. Look at common arg names; first
		// non-empty wins. Action is inferred from the tool-name verb.
		ar.Path = firstStringArg(req.Arguments, "path", "file_path", "filepath", "target_path", "destination", "src", "dst")
		ar.Action = inferFilesystemAction(req.ToolName)
		ar.Command = req.FullName

	case "network":
		ar.URL = firstStringArg(req.Arguments, "url")
		ar.Domain = firstStringArg(req.Arguments, "domain", "host", "hostname")
		if ar.Domain == "" && ar.URL != "" {
			if u, err := url.Parse(ar.URL); err == nil {
				ar.Domain = u.Hostname()
			}
		}
		ar.Command = req.FullName

	case "browser":
		ar.URL = firstStringArg(req.Arguments, "url")
		ar.Domain = firstStringArg(req.Arguments, "domain", "host", "hostname")
		if ar.Domain == "" && ar.URL != "" {
			if u, err := url.Parse(ar.URL); err == nil {
				ar.Domain = u.Hostname()
			}
		}
		ar.Action = req.ToolName
		ar.Command = req.FullName

	case "shell":
		// Shell rules match on Command. Prefer an explicit command/cmd
		// argument, fall back to the namespaced tool name + serialised
		// args so a "shell:run" with command="rm -rf /" matches a
		// shell-scope deny on "rm -rf *".
		cmd := firstStringArg(req.Arguments, "command", "cmd", "script")
		if cmd == "" {
			cmd = req.FullName
			if argStr := firstStringArg(req.Arguments, "args"); argStr != "" {
				cmd = cmd + " " + argStr
			}
		}
		ar.Command = cmd

	case "data":
		// Data scope: value being submitted. Tool-name doubles as the
		// action label so existing data rules can key on it.
		ar.Command = firstStringArg(req.Arguments, "value", "content", "text", "data")
		if ar.Command == "" {
			ar.Command = req.FullName
		}
		ar.Action = "form_input"
		ar.URL = firstStringArg(req.Arguments, "url")
		if ar.URL != "" {
			if u, err := url.Parse(ar.URL); err == nil {
				ar.Domain = u.Hostname()
			}
		}

	default:
		// Generic scope: pass the namespaced tool-name as Command and
		// let the operator's Pattern rules match. This also covers
		// "mcp_tool" if an operator deliberately mapped a tool to it
		// (unusual but harmless — it just runs the same scope twice).
		ar.Command = req.FullName
	}

	return ar
}

// firstStringArg returns the first non-empty string value found in
// args under any of the supplied keys, or "" if none match.
func firstStringArg(args map[string]interface{}, keys ...string) string {
	if len(args) == 0 {
		return ""
	}
	for _, k := range keys {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// inferFilesystemAction maps a tool-name verb to the canonical
// filesystem-scope action ("read"/"write"/"delete"). Best-effort —
// rules that only match by paths are unaffected.
func inferFilesystemAction(toolName string) string {
	tl := strings.ToLower(toolName)
	switch {
	case strings.HasPrefix(tl, "read"), strings.HasPrefix(tl, "list"),
		strings.HasPrefix(tl, "get"), strings.HasPrefix(tl, "stat"):
		return "read"
	case strings.HasPrefix(tl, "write"), strings.HasPrefix(tl, "edit"),
		strings.HasPrefix(tl, "create"), strings.HasPrefix(tl, "append"),
		strings.HasPrefix(tl, "save"), strings.HasPrefix(tl, "copy"),
		strings.HasPrefix(tl, "move"):
		return "write"
	case strings.HasPrefix(tl, "delete"), strings.HasPrefix(tl, "remove"),
		strings.HasPrefix(tl, "unlink"), strings.HasPrefix(tl, "rm"):
		return "delete"
	}
	return ""
}

// callV1Check POSTs an ActionRequest to <GuardURL>/v1/t/<TenantID>/check
// and decodes the CheckResult into a Decision. Errors are returned for
// the caller (Check) to translate into the configured fail-mode.
func (c *HTTPPolicyClient) callV1Check(ctx context.Context, ar policy.ActionRequest) (Decision, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultGuardHTTPTimeout}
	}

	tenant := c.TenantID
	if tenant == "" {
		tenant = "local"
	}
	endpoint := strings.TrimRight(c.GuardURL, "/") + "/v1/t/" + url.PathEscape(tenant) + "/check"

	// Stamp schema_version so the central server's request validator
	// accepts the body.
	ar.SchemaVersion = "v1"
	body, err := json.Marshal(ar)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal /v1/check body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("build /v1/check request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "agentguard-mcp-gateway/1.0")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("/v1/check request: %w", err)
	}
	defer resp.Body.Close()

	// Cap the response body so a misbehaving server doesn't OOM the
	// gateway. /v1/check responses are O(few hundred bytes).
	const maxResp = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	if err != nil {
		return Decision{}, fmt.Errorf("read /v1/check body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Decision{}, fmt.Errorf("/v1/check HTTP %d: %s", resp.StatusCode, truncateForError(string(raw)))
	}

	var cr policy.CheckResult
	if err := json.Unmarshal(raw, &cr); err != nil {
		return Decision{}, fmt.Errorf("decode /v1/check response: %w", err)
	}

	return decisionFromCheckResult(cr), nil
}

// decisionFromCheckResult maps a policy.CheckResult onto the gateway's
// Decision shape.
func decisionFromCheckResult(cr policy.CheckResult) Decision {
	d := Decision{
		Reason: cr.Reason,
		Rule:   cr.Rule,
	}
	switch cr.Decision {
	case policy.Allow:
		d.Allow = true
	case policy.RequireApproval:
		d.Allow = false
		d.RequiresApproval = true
		d.ApprovalID = cr.ApprovalID
		d.ApprovalURL = cr.ApprovalURL
	default: // policy.Deny or any unknown
		d.Allow = false
	}
	return d
}

// failModeDecision returns the synthetic Decision dictated by the
// gate's --fail-mode when /v1/check is unreachable.
func (c *HTTPPolicyClient) failModeDecision(err error) Decision {
	switch strings.ToLower(c.FailMode) {
	case "allow":
		return Decision{
			Allow:  true,
			Reason: "fail-mode allow: " + err.Error(),
			Rule:   "allow:gateway:fail_open",
		}
	default: // "deny", "fail-closed-with-audit", or anything unrecognised
		return Decision{
			Allow:  false,
			Reason: "central server unreachable: " + err.Error(),
			Rule:   FailModeRuleClosed,
		}
	}
}

// truncateForError caps long /v1/check error bodies so a verbose
// upstream response doesn't blow up logs.
func truncateForError(s string) string {
	const maxLen = 256
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ErrPolicyNotLoaded is returned by gateway-side helpers when no policy
// snapshot has been wired into the gate yet. Currently unused inside
// gate.go (the dual-check fall-through handles nil policy gracefully)
// but exposed so downstream callers (cmd/agentguard-mcp-gateway/main.go)
// can sentinel-check.
var ErrPolicyNotLoaded = errors.New("mcpgw: policy snapshot not loaded")
