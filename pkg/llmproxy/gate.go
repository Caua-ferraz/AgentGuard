package llmproxy

// gate.go wires the LLM API Proxy's PolicyCheck hook against the central
// AgentGuard server's /v1/check endpoint. The proxy loads the same
// policy YAML the central server reads so the bundled
// DefaultLLMToolScopeMap can be overridden by operator entries
// (Policy.ToolScopeMap, see pkg/llmproxy/scope_map.go § "Source-of-truth
// decision"). Hot-reload is wired through the FilePolicyProvider's
// Watch callback in main.go so subsequent gate calls see the operator's
// fresh map without restarting the proxy.
//
// Single-check semantics (docs/PROXY_ARCHITECTURE.md § 4):
//
//   - The LLM API Proxy maps each tool_call directly to ONE existing
//     policy scope (shell|filesystem|network|browser|data|cost) — no
//     dual-check (no synthetic mcp_tool layer like the MCP gateway).
//     Bare LLM tool names live in a disjoint pattern space from
//     namespaced MCP names so the policy author writes one
//     `tool_scope_map:` table and AgentGuard dispatches correctly per
//     transport tag.
//   - Tools not covered by the merged map fall back to the sentinel
//     scope `unmapped`. The policy engine has no built-in handling for
//     `unmapped` so the gate fails closed by default unless the operator
//     opts into an explicit `scope: unmapped` rule.
//
// Fail-mode (docs/PROXY_ARCHITECTURE.md § 6.1):
//
//   - --fail-mode deny (default): /v1/check unreachable → synthetic
//     DENY with Rule="deny:llm_api_proxy:fail_closed".
//   - --fail-mode fail-closed-with-audit: same DENY shape but the
//     synthetic Rule is "deny:llm_api_proxy:fail_closed_audit" so
//     dashboards can break out the two failure modes, and the denial
//     is appended to the local --fail-audit-log JSONL file so the
//     outage window stays reconstructable without the central server.
//   - --fail-mode allow: /v1/check unreachable → synthetic ALLOW.
//     Useful for dev / failover scenarios where availability beats
//     enforcement; NOT a production posture.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/Caua-ferraz/AgentGuard/pkg/internal/gateclient"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// DefaultGuardHTTPTimeout is the per-/v1/check-call timeout the gate
// applies when the operator does not pass a custom http.Client.
const DefaultGuardHTTPTimeout = gateclient.DefaultGuardHTTPTimeout

// FailModeRuleClosed and friends are the synthetic Rule strings the
// gate stamps on fail-mode decisions so operators can alert on them
// without confusing them with real policy verdicts. Stable string
// contracts — referenced from tests + dashboard.
const (
	FailModeRuleClosed      = "deny:llm_api_proxy:fail_closed"
	FailModeRuleClosedAudit = "deny:llm_api_proxy:fail_closed_audit"
	FailModeRuleOpen        = "allow:llm_api_proxy:fail_open"
	InvalidResponseRule     = "deny:llm_api_proxy:invalid_response"
)

// llmFailModeRules feeds the proxy's synthetic-rule contract to the
// shared gate client.
var llmFailModeRules = gateclient.FailModeRules{
	Open:        FailModeRuleOpen,
	Closed:      FailModeRuleClosed,
	ClosedAudit: FailModeRuleClosedAudit,
	Invalid:     InvalidResponseRule,
}

// HTTPPolicyClient is the LLM API Proxy's connection to the central
// AgentGuard server's /v1/check endpoint. One instance per proxy
// process; the underlying http.Client (and its connection pool) is
// reused.
//
// The /v1/check wire contract and fail-mode translation live in
// pkg/internal/gateclient (shared with the MCP gateway). This client
// adds the proxy-specific parts: single-check scope mapping (no
// dual-check — the mapped scope IS the gate scope), per-scope argument
// projection, source-side secret redaction, and
// meta.transport="llm_api_proxy" stamping so the central server's
// audit log attributes entries to this proxy.
type HTTPPolicyClient struct {
	GuardURL string // e.g. "http://127.0.0.1:8080"
	APIKey   string // bearer token; empty if --api-key not set
	TenantID string // tenant ID; "local" with the bundled FilePolicyProvider
	FailMode string // "deny" | "allow" | "fail-closed-with-audit"

	// HTTPClient is reused across calls. Set to a custom client in
	// tests; otherwise the constructor defaults to a 5s-timeout client.
	HTTPClient *http.Client

	// policy holds the active *policy.Policy via atomic load/store so
	// the hot path doesn't take a lock. nil is safe — falls back to the
	// bundled DefaultLLMToolScopeMap.
	policy atomic.Pointer[policy.Policy]

	// mappings caches the merged []policy.ToolScopeMapping derived from
	// the active policy so MapScope doesn't re-merge on every call. The
	// pointer is replaced atomically by SetPolicy.
	mappings atomic.Pointer[[]policy.ToolScopeMapping]

	// redactor is the secret-scrubber applied to argument values before
	// they land in /v1/check meta (and thus the audit log). Built once
	// at construction time from notify.DefaultRedactor() — the central
	// server does its own redaction at notification dispatch but the
	// audit log itself does not, so the proxy redacts at the source.
	redactor *notify.Redactor

	// fallback records local audit entries for fail-closed-with-audit
	// denials made while the central server is unreachable. nil (the
	// other fail modes, or --fail-audit-log "") records nothing.
	fallback *gateclient.FallbackAuditWriter
}

// NewHTTPPolicyClient constructs a gate against cfg + an initial policy
// snapshot. The caller is expected to subscribe to the policy provider's
// Watch and call SetPolicy on every reload.
func NewHTTPPolicyClient(cfg *Config, pol *policy.Policy) *HTTPPolicyClient {
	c := &HTTPPolicyClient{
		GuardURL:   cfg.GuardURL,
		APIKey:     cfg.APIKey,
		TenantID:   cfg.TenantID,
		FailMode:   cfg.FailMode,
		HTTPClient: &http.Client{Timeout: DefaultGuardHTTPTimeout},
		redactor:   notify.DefaultRedactor(),
	}
	if cfg.FailMode == "fail-closed-with-audit" {
		c.fallback = gateclient.NewFallbackAuditWriter(cfg.FailAuditLog)
	}
	c.SetPolicy(pol)
	return c
}

// SetPolicy atomically updates the cached policy snapshot and the
// derived mapping list. Called from main.go's provider.Watch callback
// for hot-reload. nil is accepted (resets to default mappings only).
func (c *HTTPPolicyClient) SetPolicy(pol *policy.Policy) {
	c.policy.Store(pol)
	merged := NewLLMToolScopeMap(pol)
	c.mappings.Store(&merged)
}

// MapScope returns the existing-scope assignment for a tool name.
// Wired into Server.ScopeMap. Tools not covered by the merged map
// return UnmappedScope; the policy engine fails closed on this
// scope unless an explicit `scope: unmapped` rule is configured.
func (c *HTTPPolicyClient) MapScope(toolName string) string {
	mappings := c.mappings.Load()
	if mappings == nil {
		return MapLLMToolScope(toolName, DefaultLLMToolScopeMap)
	}
	return MapLLMToolScope(toolName, *mappings)
}

// Check is the function wired into Server.PolicyCheck. Builds an
// ActionRequest from the ToolCallCheck and POSTs to /v1/check.
//
// Closes the streaming gate: A22 calls this per assembled tool_call
// in either provider's stream; this returns an llmproxy.Decision the
// streaming orchestrator branches on (ALLOW → flush buffered events;
// DENY/REQUIRE_APPROVAL → synthesize refusal).
//
// Errors from /v1/check (network, malformed response, non-2xx status)
// are translated into the configured fail-mode decision; the err is
// returned alongside so callers that need to log/instrument the
// underlying cause can do so. The streaming orchestrator (A22)
// already inspects err for fail-mode-allow short-circuiting.
func (c *HTTPPolicyClient) Check(ctx context.Context, req *ToolCallCheck) (Decision, error) {
	if req == nil {
		return Decision{Allow: false, Reason: "nil tool call request", Rule: "deny:llm_api_proxy:invalid_request"}, nil
	}

	scope := c.MapScope(req.ToolName)

	ar := policy.ActionRequest{
		SchemaVersion: "v1",
		Scope:         scope,
		AgentID:       req.AgentID,
		SessionID:     req.SessionID,
		Command:       formatLLMCommand(req, scope, c.redactor),
		Path:          projectPath(scope, req.Arguments),
		Domain:        projectDomain(scope, req.Arguments),
		URL:           projectURL(scope, req.Arguments),
		ApprovalID:    req.ApprovalID,
		Meta:          buildLLMMeta(req, scope, c.redactor),
	}
	if scope == "filesystem" {
		ar.Action = gateclient.InferFilesystemAction(req.ToolName)
	}
	if scope == "browser" {
		ar.Action = req.ToolName
	}

	dec, err := c.callV1Check(ctx, ar)
	if err != nil {
		return c.failModeDecision(ar, err), err
	}
	return dec, nil
}

// buildLLMMeta builds the meta map sent on the /v1/check call. Argument
// values are redacted via notify.DefaultRedactor before stringifying
// so secrets in tool-call args don't reach the audit log.
func buildLLMMeta(req *ToolCallCheck, scope string, red *notify.Redactor) map[string]string {
	out := map[string]string{
		"transport":    "llm_api_proxy",
		"provider":     req.Provider,
		"tool_name":    req.ToolName,
		"tool_call_id": req.ToolCallID,
		"mapped_scope": scope,
	}
	if req.Model != "" {
		out["model"] = req.Model
	}
	if req.Stream {
		out["stream"] = "true"
	}
	if req.ApprovalID != "" {
		out["approval_id"] = req.ApprovalID
	}
	for k, v := range projectMetaArgs(req.Arguments, red) {
		out["arg_"+k] = v
	}
	return out
}

// projectPath returns the path-like argument value for filesystem-scope
// gating. Common LLM tool conventions: path, file_path, target,
// target_path, filename, file. Returns "" for non-filesystem scopes
// or when no recognised key is present.
func projectPath(scope string, args map[string]interface{}) string {
	if scope != "filesystem" {
		return ""
	}
	for _, k := range []string{"path", "file_path", "filepath", "target", "target_path", "filename", "file", "destination", "src", "dst"} {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// projectURL returns the URL-like arg value for network/browser scope
// gating. The same key set covers both — browser tools commonly emit
// `url`, network tools commonly emit `url`/`uri`/`endpoint`.
func projectURL(scope string, args map[string]interface{}) string {
	if scope != "network" && scope != "browser" {
		return ""
	}
	for _, k := range []string{"url", "uri", "endpoint", "target_url"} {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// projectDomain extracts a domain from a URL-like arg, or returns the
// bare domain/host arg if no URL is present. Mirrors mcpgw's
// buildMappedActionRequest behaviour for network/browser scopes.
func projectDomain(scope string, args map[string]interface{}) string {
	if scope != "network" && scope != "browser" {
		return ""
	}
	rawURL := projectURL(scope, args)
	if rawURL == "" {
		for _, k := range []string{"domain", "host", "hostname"} {
			if v, ok := args[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// formatLLMCommand renders the tool_call as a string the policy engine
// can match against rule patterns. Different scopes use different
// projections so existing rule-author conventions still apply:
//
//   - shell:      `<command_arg>` (or `<tool_name>` if no command)
//   - filesystem: `<tool_name> <path>`
//   - network:    `<tool_name> <url>`
//   - browser:    `<tool_name> <url>`
//   - data:       `<value/content/text/data arg>` (or tool name)
//   - cost:       `<tool_name>` (cost gating uses est_cost separately)
//   - unmapped:   `<tool_name>`
//
// Args are redacted via notify.DefaultRedactor before stringifying.
func formatLLMCommand(req *ToolCallCheck, scope string, red *notify.Redactor) string {
	switch scope {
	case "shell":
		if cmd := gateclient.FirstStringArg(req.Arguments, "command", "cmd", "script", "code"); cmd != "" {
			return redactSingle(red, cmd)
		}
		// Fall back to tool name + serialised args so shell rules that
		// match on a wrapper tool's invocation still fire.
		if argStr := gateclient.FirstStringArg(req.Arguments, "args"); argStr != "" {
			return redactSingle(red, req.ToolName+" "+argStr)
		}
		return req.ToolName

	case "filesystem":
		path := projectPath(scope, req.Arguments)
		if path != "" {
			return redactSingle(red, req.ToolName+" "+path)
		}
		return req.ToolName

	case "network", "browser":
		u := projectURL(scope, req.Arguments)
		if u != "" {
			return redactSingle(red, req.ToolName+" "+u)
		}
		return req.ToolName

	case "data":
		// Data scope: prefer the value being submitted so existing
		// data rules can match on it. Sensitive args go in meta only.
		if v := gateclient.FirstStringArg(req.Arguments, "value", "content", "text", "data"); v != "" {
			return redactSingle(red, v)
		}
		return req.ToolName

	default:
		return req.ToolName
	}
}

// projectMetaArgs returns a redacted, string-valued copy of all args
// for the audit log's meta map. Non-string values are JSON-encoded.
// All values are individually scrubbed via the supplied redactor before
// being written to the map.
func projectMetaArgs(args map[string]interface{}, red *notify.Redactor) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for k, v := range args {
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case nil:
			continue
		default:
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			s = string(b)
		}
		if red != nil {
			s = redactSingle(red, s)
		}
		// Also redact `key=value` shape against the key name itself for
		// args literally called "password"/"token"/"api_key" — the
		// regex in DefaultRedactor only fires when the key+value are
		// stringified together, not when the value is bare. Keep raw
		// value if no redaction occurred.
		if isSecretKeyName(k) {
			s = "[REDACTED]"
		}
		out[k] = s
	}
	return out
}

// isSecretKeyName matches argument names that are known to carry
// secrets (regardless of value shape) so we redact the whole field
// even when the value alone wouldn't trigger DefaultRedactor.
func isSecretKeyName(k string) bool {
	lk := strings.ToLower(k)
	for _, needle := range []string{"password", "token", "secret", "api_key", "apikey", "auth"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

// redactSingle pushes a string through the redactor by wrapping it in a
// synthetic notify.Event (Redactor's public API). Empty strings short-
// circuit to avoid synthesising a useless event.
func redactSingle(red *notify.Redactor, s string) string {
	if s == "" || red == nil {
		return s
	}
	ev := notify.Event{
		Request: policy.ActionRequest{
			Command: s,
		},
	}
	return red.Redact(ev).Request.Command
}

// callV1Check delegates to the shared gate client with the proxy's
// identity stamped on the User-Agent.
func (c *HTTPPolicyClient) callV1Check(ctx context.Context, ar policy.ActionRequest) (Decision, error) {
	caller := gateclient.Caller{
		GuardURL:   c.GuardURL,
		APIKey:     c.APIKey,
		TenantID:   c.TenantID,
		UserAgent:  "agentguard-llm-proxy/" + BuildVersion,
		HTTPClient: c.HTTPClient,
	}
	return caller.CallV1Check(ctx, ar, llmFailModeRules)
}

// failModeDecision translates a /v1/check failure into the configured
// fail-mode verdict. In fail-closed-with-audit mode the denial is also
// recorded locally (--fail-audit-log) so operators can reconstruct the
// deny chain for the outage window without the central server.
func (c *HTTPPolicyClient) failModeDecision(ar policy.ActionRequest, err error) Decision {
	d := gateclient.FailModeDecision(c.FailMode, err, llmFailModeRules)
	c.fallback.Record(ar, d, "llm_api_proxy", c.TenantID)
	return d
}
