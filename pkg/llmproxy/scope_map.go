package llmproxy

// scope_map.go provides the tool-name → existing-policy-scope mapping
// the LLM API Proxy uses to gate tool calls emitted by upstream models.
//
// Phase 4A locked the design: the LLM API Proxy maps to existing
// scopes only — `shell`, `filesystem`, `network`, `browser`, `data`,
// `cost`. No new policy primitives. (See docs/PROXY_ARCHITECTURE.md
// § 4 and docs/LLM_API_PROXY.md § "Tool call → scope mapping".)
//
// Source-of-truth decision (A23, 2026-05-05): this module reuses
// `policy.Policy.ToolScopeMap` rather than introducing a separate
// `LLMToolScopeMap`. Rationale documented in `.audit/v05_decisions.md`
// under "A23: LLM tool scope map source-of-truth": namespaced MCP tool
// names (`<ns>:<tool>`) and bare LLM tool names (`bash`, `read_file`)
// occupy disjoint regions of the pattern space, so collisions are
// impossible without an operator deliberately writing one. A single
// `tool_scope_map:` section in policy YAML therefore safely covers
// both transports — operators write one mapping table, AgentGuard
// dispatches it correctly per request transport.
//
// The map A23 builds layers:
//   1. Operator entries (from Policy.ToolScopeMap) — first-match-wins,
//      so explicit operator overrides beat the bundled defaults.
//   2. Default entries (DefaultLLMToolScopeMap below) — the baked-in
//      mapping for common tool names that ship with most agent
//      frameworks.
//
// A24 wires `MapLLMToolScope` (closing over the merged list) into
// Server.ScopeMap. Tools not in either layer return the sentinel
// scope "unmapped"; the policy engine fails closed on this scope
// unless an operator writes an explicit `scope: unmapped` rule.
// See docs/POLICY_REFERENCE.md § "LLM API Proxy tool scope mapping".

import (
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// UnmappedScope is the sentinel scope returned when a tool name does
// not match any default or operator-supplied entry. The policy engine
// has no built-in handling for this scope — by design — so the gate
// fails closed (default DENY) unless the operator opts into a
// `scope: unmapped` rule. Stable string contract: documented in
// docs/POLICY_REFERENCE.md and referenced from A24's gate code.
const UnmappedScope = "unmapped"

// DefaultLLMToolScopeMap is the baked-in mapping from common tool
// names to existing AgentGuard policy scopes. Per Phase 4A, the LLM
// API Proxy maps to existing scopes only — no new policy primitives.
//
// Patterns are glob-matched (same matcher as policy rule patterns:
// `*` matches any chars including `/`, `?` matches a single char,
// `**` matches zero or more `/`-separated segments). First-match-wins.
//
// Operators override or extend via the `tool_scope_map:` section of
// policy YAML (see docs/POLICY_REFERENCE.md § "LLM API Proxy tool
// scope mapping" for examples).
//
// Categories per docs/LLM_API_PROXY.md § "Tool call → scope mapping":
//   - shell:      bash, run_command, execute_command, sh, cmd, ...
//   - filesystem: read_file, write_file, list_directory, ls, cat, ...
//   - network:    web_search, fetch_url, http_request, ...
//   - browser:    playwright_*, browser_*, chrome_*, firefox_*, ...
//   - data:       (no defaults — operators map fill_form / submit_form
//                  here for PII gating against `data` scope rules)
//   - cost:       (no defaults — model-cost gating is its own scope
//                  with different field semantics; operators wire it
//                  via SDK est_cost rather than via tool-name mapping)
var DefaultLLMToolScopeMap = []policy.ToolScopeMapping{
	// --- Shell / command execution ---
	{Pattern: "bash", Scope: "shell"},
	{Pattern: "sh", Scope: "shell"},
	{Pattern: "shell", Scope: "shell"},
	{Pattern: "run_command", Scope: "shell"},
	{Pattern: "execute_command", Scope: "shell"},
	{Pattern: "cmd", Scope: "shell"},
	{Pattern: "system", Scope: "shell"},
	{Pattern: "exec", Scope: "shell"},

	// --- Filesystem ---
	{Pattern: "read_file", Scope: "filesystem"},
	{Pattern: "write_file", Scope: "filesystem"},
	{Pattern: "list_directory", Scope: "filesystem"},
	{Pattern: "list_files", Scope: "filesystem"},
	{Pattern: "file_read", Scope: "filesystem"},
	{Pattern: "file_write", Scope: "filesystem"},
	{Pattern: "edit_file", Scope: "filesystem"},
	{Pattern: "delete_file", Scope: "filesystem"},
	{Pattern: "create_directory", Scope: "filesystem"},
	{Pattern: "ls", Scope: "filesystem"},
	{Pattern: "cat", Scope: "filesystem"},
	{Pattern: "find", Scope: "filesystem"},
	{Pattern: "glob", Scope: "filesystem"},

	// --- Network (HTTP / web search) ---
	{Pattern: "web_search", Scope: "network"},
	{Pattern: "fetch_url", Scope: "network"},
	{Pattern: "http_request", Scope: "network"},
	{Pattern: "http_get", Scope: "network"},
	{Pattern: "http_post", Scope: "network"},
	{Pattern: "search", Scope: "network"},
	{Pattern: "fetch", Scope: "network"},
	{Pattern: "url_request", Scope: "network"},

	// --- Browser (wildcard for prefix-based families) ---
	{Pattern: "playwright_*", Scope: "browser"},
	{Pattern: "browser_*", Scope: "browser"},
	{Pattern: "chrome_*", Scope: "browser"},
	{Pattern: "firefox_*", Scope: "browser"},
	{Pattern: "selenium_*", Scope: "browser"},
	{Pattern: "navigate", Scope: "browser"},
	{Pattern: "click", Scope: "browser"},
	{Pattern: "screenshot", Scope: "browser"},
}

// NewLLMToolScopeMap merges operator policy entries with the bundled
// defaults. Operator entries appear FIRST in the returned slice so
// first-match-wins iteration honours operator overrides.
//
// pol may be nil (no policy loaded) — returns DefaultLLMToolScopeMap
// directly (without copying — callers must not mutate the slice).
//
// The returned slice is freshly allocated when pol is non-nil, so
// callers may pass it across goroutines or stash it in atomic.Pointer
// without aliasing concerns vs the operator's live policy snapshot.
func NewLLMToolScopeMap(pol *policy.Policy) []policy.ToolScopeMapping {
	if pol == nil || len(pol.ToolScopeMap) == 0 {
		return DefaultLLMToolScopeMap
	}

	merged := make([]policy.ToolScopeMapping, 0, len(pol.ToolScopeMap)+len(DefaultLLMToolScopeMap))
	merged = append(merged, pol.ToolScopeMap...)
	merged = append(merged, DefaultLLMToolScopeMap...)
	return merged
}

// MapLLMToolScope is the function A24 wires into Server.ScopeMap (via
// a closure capturing the merged mapping list). Returns the scope of
// the first matching entry, or UnmappedScope if nothing matches.
//
// "Unmapped" tools are routed to scope "unmapped" at gate time. The
// policy engine has no built-in rules for this scope, so the default
// behaviour is fail-closed (DENY: "No matching allow rule (default
// deny)"). Operators who want unknown LLM tools to pass through must
// write an explicit `scope: unmapped` rule — typically
// `require_approval: [{pattern: "*"}]` so a human sees the tool name
// before it runs.
//
// Implementation note: dispatches through a synthetic *policy.Policy
// so the canonical glob matcher (`pkg/policy/engine.go:globMatch`,
// unexported) is used without re-implementing it. The synthetic
// policy is allocated on every call — cheap (one struct + one slice
// header) and avoids the alternative of exporting globMatch from
// pkg/policy.
func MapLLMToolScope(toolName string, mappings []policy.ToolScopeMapping) string {
	if toolName == "" {
		return UnmappedScope
	}
	if len(mappings) == 0 {
		return UnmappedScope
	}
	// Synthetic policy whose ToolScopeMap is the supplied merged list.
	// MapToolScope is the canonical first-match-wins resolver — see
	// pkg/policy/engine.go.
	synthetic := &policy.Policy{ToolScopeMap: mappings}
	if scope, ok := synthetic.MapToolScope(toolName); ok {
		return scope
	}
	return UnmappedScope
}
