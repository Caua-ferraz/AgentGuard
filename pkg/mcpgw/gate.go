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
//   --fail-mode deny (default): /v1/check unreachable → synthetic
//     DENY with Rule="deny:gateway:fail_closed".
//   --fail-mode fail-closed-with-audit: same DENY shape but the
//     synthetic Rule is "deny:gateway:fail_closed_audit" so dashboards
//     can break out the two failure modes, and the denial is appended
//     to the local --fail-audit-log JSONL file so the outage window
//     stays reconstructable without the central server.
//   --fail-mode allow: /v1/check unreachable → synthetic ALLOW. Used
//     in dev to keep the host responsive when the central server is
//     down; should NOT be the production setting.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/Caua-ferraz/AgentGuard/pkg/internal/gateclient"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// DefaultGuardHTTPTimeout is the per-/v1/check-call timeout the gate
// applies when the operator does not pass a custom http.Client.
const DefaultGuardHTTPTimeout = gateclient.DefaultGuardHTTPTimeout

// FailModeRuleClosed and FailModeRuleClosedAudit are the synthetic Rule
// strings the gate stamps on fail-closed denials so operators can alert
// on them without confusing them with a real policy DENY. Stable string
// contracts — referenced from dashboard + tests.
//
// FailModeRuleClosedAudit fires on `--fail-mode fail-closed-with-audit`
// so dashboards can break out the two failure modes; the denial is also
// recorded in the local --fail-audit-log file (see failModeDecision).
const (
	FailModeRuleClosed      = "deny:gateway:fail_closed"
	FailModeRuleClosedAudit = "deny:gateway:fail_closed_audit"
	FailModeRuleOpen        = "allow:gateway:fail_open"

	// InvalidResponseRule is stamped when /v1/check returns an
	// unrecognised decision string (treated as a hard DENY).
	InvalidResponseRule = "deny:gateway:invalid_response"
)

// gatewayFailModeRules feeds the gateway's synthetic-rule contract to
// the shared gate client.
var gatewayFailModeRules = gateclient.FailModeRules{
	Open:        FailModeRuleOpen,
	Closed:      FailModeRuleClosed,
	ClosedAudit: FailModeRuleClosedAudit,
	Invalid:     InvalidResponseRule,
}

// HTTPPolicyClient calls the central AgentGuard server's /v1/check
// endpoint and orchestrates the dual-check pattern. One client per
// gateway process; the underlying http.Client (and its connection
// pool) is reused. The /v1/check wire contract and fail-mode
// translation live in pkg/internal/gateclient (shared with the LLM
// API proxy); this client adds the gateway-specific dual-check
// orchestration.
//
// Policy is held atomically — the gateway's main.go subscribes to the
// PolicyProvider's Watch and calls SetPolicy on every reload so the
// tool_scope_map stays in sync with the central server's view. Reads
// are lock-free atomic loads on the hot path.
type HTTPPolicyClient struct {
	GuardURL   string // e.g. "http://127.0.0.1:8080"
	APIKey     string // bearer token; empty if --api-key not set
	TenantID   string // tenant ID; "local" with the bundled FilePolicyProvider
	PolicyMode string // "strict" | "fast"
	FailMode   string // "deny" | "allow" | "fail-closed-with-audit"

	// HTTPClient is reused across calls. Set to a custom client in
	// tests; otherwise the constructor defaults to a 5s-timeout client.
	HTTPClient *http.Client

	// policy holds the active *policy.Policy via atomic load/store so
	// the hot path doesn't take a lock. nil is safe — a nil policy
	// just means "no tool_scope_map known yet, skip dual-check".
	policy atomic.Pointer[policy.Policy]

	// fallback records local audit entries for fail-closed-with-audit
	// denials made while the central server is unreachable. nil (the
	// other fail modes, or --fail-audit-log "") records nothing.
	fallback *gateclient.FallbackAuditWriter
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
	if cfg.FailMode == "fail-closed-with-audit" {
		c.fallback = gateclient.NewFallbackAuditWriter(cfg.FailAuditLog)
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
		return c.failModeDecision(mcpAR, err), nil
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
		return c.failModeDecision(mappedAR, err), nil
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
		"namespace": req.Namespace,
		"tool_name": req.ToolName,
		"transport": "mcp_gateway",
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
		ar.Path = gateclient.FirstStringArg(req.Arguments, "path", "file_path", "filepath", "target_path", "destination", "src", "dst")
		ar.Action = gateclient.InferFilesystemAction(req.ToolName)
		ar.Command = req.FullName

	case "network":
		ar.URL = gateclient.FirstStringArg(req.Arguments, "url")
		ar.Domain = gateclient.FirstStringArg(req.Arguments, "domain", "host", "hostname")
		if ar.Domain == "" && ar.URL != "" {
			if u, err := url.Parse(ar.URL); err == nil {
				ar.Domain = u.Hostname()
			}
		}
		ar.Command = req.FullName

	case "browser":
		ar.URL = gateclient.FirstStringArg(req.Arguments, "url")
		ar.Domain = gateclient.FirstStringArg(req.Arguments, "domain", "host", "hostname")
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
		cmd := gateclient.FirstStringArg(req.Arguments, "command", "cmd", "script")
		if cmd == "" {
			cmd = req.FullName
			if argStr := gateclient.FirstStringArg(req.Arguments, "args"); argStr != "" {
				cmd = cmd + " " + argStr
			}
		}
		ar.Command = cmd

	case "data":
		// Data scope: value being submitted. Tool-name doubles as the
		// action label so existing data rules can key on it.
		ar.Command = gateclient.FirstStringArg(req.Arguments, "value", "content", "text", "data")
		if ar.Command == "" {
			ar.Command = req.FullName
		}
		ar.Action = "form_input"
		ar.URL = gateclient.FirstStringArg(req.Arguments, "url")
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

// callV1Check delegates to the shared gate client with the gateway's
// identity stamped on the User-Agent.
func (c *HTTPPolicyClient) callV1Check(ctx context.Context, ar policy.ActionRequest) (Decision, error) {
	caller := gateclient.Caller{
		GuardURL:   c.GuardURL,
		APIKey:     c.APIKey,
		TenantID:   c.TenantID,
		UserAgent:  "agentguard-mcp-gateway/" + GatewayBuildVersion,
		HTTPClient: c.HTTPClient,
	}
	return caller.CallV1Check(ctx, ar, gatewayFailModeRules)
}

// failModeDecision translates a /v1/check failure into the configured
// fail-mode verdict. In fail-closed-with-audit mode the denial is also
// recorded locally (--fail-audit-log) so operators can reconstruct the
// deny chain for the outage window without the central server.
func (c *HTTPPolicyClient) failModeDecision(ar policy.ActionRequest, err error) Decision {
	d := gateclient.FailModeDecision(c.FailMode, err, gatewayFailModeRules)
	c.fallback.Record(ar, d, "mcp_gateway", c.TenantID)
	return d
}
