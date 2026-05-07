package llmproxy

// Tests for the LLM API Proxy's tool-name → scope mapping. Pins:
//   1. Default-map coverage for each scope category (shell, fs,
//      network, browser).
//   2. The browser glob pattern (`playwright_*` etc.) actually
//      matches concrete tool names a real model might emit.
//   3. Unmapped tool names return UnmappedScope so the policy
//      engine can fail closed.
//   4. Operator entries beat defaults on collision (the spec calls
//      this out as the central correctness invariant).
//   5. NewLLMToolScopeMap handles nil/empty operator policy without
//      surprising the caller.
//
// These tests are independent of A24's gate wiring — they exercise
// the pure mapping layer A23 owns.

import (
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestMapLLMToolScope_ShellTools(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"bash", "shell"},
		{"sh", "shell"},
		{"shell", "shell"},
		{"run_command", "shell"},
		{"execute_command", "shell"},
		{"cmd", "shell"},
		{"system", "shell"},
		{"exec", "shell"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_FilesystemTools(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"read_file", "filesystem"},
		{"write_file", "filesystem"},
		{"list_directory", "filesystem"},
		{"list_files", "filesystem"},
		{"file_read", "filesystem"},
		{"file_write", "filesystem"},
		{"edit_file", "filesystem"},
		{"delete_file", "filesystem"},
		{"create_directory", "filesystem"},
		{"ls", "filesystem"},
		{"cat", "filesystem"},
		{"find", "filesystem"},
		{"glob", "filesystem"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_NetworkTools(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"web_search", "network"},
		{"fetch_url", "network"},
		{"http_request", "network"},
		{"http_get", "network"},
		{"http_post", "network"},
		{"search", "network"},
		{"fetch", "network"},
		{"url_request", "network"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_BrowserGlob(t *testing.T) {
	// Browser-family tool names tend to be prefix-shaped
	// (`playwright_click`, `browser_navigate`); the default map
	// uses `<family>_*` glob patterns, and we pin that the matcher
	// resolves them correctly through MapLLMToolScope.
	cases := []struct {
		tool string
		want string
	}{
		{"playwright_click", "browser"},
		{"playwright_navigate", "browser"},
		{"playwright_screenshot", "browser"},
		{"browser_navigate", "browser"},
		{"browser_click", "browser"},
		{"chrome_devtools", "browser"},
		{"firefox_open", "browser"},
		{"selenium_find_element", "browser"},
		{"navigate", "browser"},
		{"click", "browser"},
		{"screenshot", "browser"},
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, c := range cases {
		got := MapLLMToolScope(c.tool, mappings)
		if got != c.want {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

func TestMapLLMToolScope_Unmapped(t *testing.T) {
	cases := []string{
		"unknown_tool",
		"my_company_internal_thing",
		"random_function",
		// MCP-shaped names should NOT match the bare LLM defaults
		// (the namespace prefix prevents accidental matching).
		"fs:read_file",
		"github:create_issue",
	}
	mappings := NewLLMToolScopeMap(nil)
	for _, tool := range cases {
		got := MapLLMToolScope(tool, mappings)
		if got != UnmappedScope {
			t.Errorf("MapLLMToolScope(%q) = %q, want %q", tool, got, UnmappedScope)
		}
	}
}

func TestMapLLMToolScope_EmptyToolName(t *testing.T) {
	mappings := NewLLMToolScopeMap(nil)
	got := MapLLMToolScope("", mappings)
	if got != UnmappedScope {
		t.Errorf("MapLLMToolScope(\"\") = %q, want %q", got, UnmappedScope)
	}
}

func TestMapLLMToolScope_EmptyMappings(t *testing.T) {
	got := MapLLMToolScope("bash", nil)
	if got != UnmappedScope {
		t.Errorf("MapLLMToolScope(_, nil) = %q, want %q", got, UnmappedScope)
	}
	got = MapLLMToolScope("bash", []policy.ToolScopeMapping{})
	if got != UnmappedScope {
		t.Errorf("MapLLMToolScope(_, []) = %q, want %q", got, UnmappedScope)
	}
}

func TestMapLLMToolScope_OperatorOverride(t *testing.T) {
	// Operator policy maps `read_file` → `data` (e.g. an LLM that
	// embeds PII into "read_file" requests because it's actually a
	// document fetcher). The default map says `read_file` →
	// `filesystem`. The merged-list semantics mandate that the
	// operator wins.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "read_file", Scope: "data"},
		},
	}
	mappings := NewLLMToolScopeMap(pol)

	if got := MapLLMToolScope("read_file", mappings); got != "data" {
		t.Errorf("operator override: MapLLMToolScope(read_file) = %q, want data", got)
	}

	// Default `bash` mapping still resolves to shell — operator
	// override doesn't blank out the rest of the map.
	if got := MapLLMToolScope("bash", mappings); got != "shell" {
		t.Errorf("default fallthrough after override: MapLLMToolScope(bash) = %q, want shell", got)
	}
}

func TestMapLLMToolScope_OperatorAddsNewTool(t *testing.T) {
	// Operator adds a tool name that's not in the default map.
	// Verify it resolves and that defaults still work.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "deploy_to_prod", Scope: "shell"},
			{Pattern: "send_email", Scope: "network"},
		},
	}
	mappings := NewLLMToolScopeMap(pol)

	if got := MapLLMToolScope("deploy_to_prod", mappings); got != "shell" {
		t.Errorf("operator-added tool: deploy_to_prod = %q, want shell", got)
	}
	if got := MapLLMToolScope("send_email", mappings); got != "network" {
		t.Errorf("operator-added tool: send_email = %q, want network", got)
	}
	// Defaults are still active.
	if got := MapLLMToolScope("read_file", mappings); got != "filesystem" {
		t.Errorf("default after operator-add: read_file = %q, want filesystem", got)
	}
}

func TestNewLLMToolScopeMap_NilPolicy(t *testing.T) {
	got := NewLLMToolScopeMap(nil)
	// nil policy returns the default map directly (no allocation).
	if len(got) != len(DefaultLLMToolScopeMap) {
		t.Fatalf("nil policy: got %d entries, want %d", len(got), len(DefaultLLMToolScopeMap))
	}
	// Sanity-check: same first entry as the default.
	if got[0].Pattern != DefaultLLMToolScopeMap[0].Pattern {
		t.Errorf("nil policy: first entry pattern = %q, want %q",
			got[0].Pattern, DefaultLLMToolScopeMap[0].Pattern)
	}
}

func TestNewLLMToolScopeMap_EmptyPolicyMap(t *testing.T) {
	// An operator policy with no tool_scope_map: section is identical
	// to nil for our purposes — we want the bare defaults.
	pol := &policy.Policy{Version: "1", Name: "x"}
	got := NewLLMToolScopeMap(pol)
	if len(got) != len(DefaultLLMToolScopeMap) {
		t.Fatalf("empty policy map: got %d entries, want %d",
			len(got), len(DefaultLLMToolScopeMap))
	}
}

func TestNewLLMToolScopeMap_MergeOrder(t *testing.T) {
	// Operator entries MUST appear before defaults in the merged
	// list — that's how first-match-wins gives the operator the
	// override. This is the central invariant of the merge.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "read_file", Scope: "data"},
			{Pattern: "custom_tool", Scope: "shell"},
		},
	}
	got := NewLLMToolScopeMap(pol)

	// Length: operator (2) + defaults (everything in
	// DefaultLLMToolScopeMap).
	wantLen := 2 + len(DefaultLLMToolScopeMap)
	if len(got) != wantLen {
		t.Fatalf("merged length = %d, want %d", len(got), wantLen)
	}

	// First two entries are the operator's, in order.
	if got[0].Pattern != "read_file" || got[0].Scope != "data" {
		t.Errorf("got[0] = %+v, want {read_file data}", got[0])
	}
	if got[1].Pattern != "custom_tool" || got[1].Scope != "shell" {
		t.Errorf("got[1] = %+v, want {custom_tool shell}", got[1])
	}
	// Third entry is the first default ("bash"/shell).
	if got[2].Pattern != DefaultLLMToolScopeMap[0].Pattern {
		t.Errorf("got[2].Pattern = %q, want %q (first default)",
			got[2].Pattern, DefaultLLMToolScopeMap[0].Pattern)
	}
}

func TestNewLLMToolScopeMap_DoesNotMutateInput(t *testing.T) {
	// The merge must NOT mutate the operator's policy slice — it's
	// a live snapshot from policy.Provider, and a callee scribbling
	// on it would race with the watcher.
	pol := &policy.Policy{
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "deploy", Scope: "shell"},
		},
	}
	original := pol.ToolScopeMap
	originalLen := len(original)
	originalCap := cap(original)

	_ = NewLLMToolScopeMap(pol)

	if len(pol.ToolScopeMap) != originalLen {
		t.Errorf("operator slice len mutated: was %d, now %d",
			originalLen, len(pol.ToolScopeMap))
	}
	if cap(pol.ToolScopeMap) != originalCap {
		// cap change implies a hidden append-extend.
		t.Errorf("operator slice cap mutated: was %d, now %d",
			originalCap, cap(pol.ToolScopeMap))
	}
	// And the slice header itself wasn't reseated.
	if &pol.ToolScopeMap[0] != &original[0] {
		t.Errorf("operator backing array reseated")
	}
}

func TestDefaultLLMToolScopeMap_NoEmptyEntries(t *testing.T) {
	// Defensive: an empty pattern or scope in the default map would
	// fail policy.validateToolScopeMap if an operator pasted it
	// into their YAML. Pin that the bundled defaults are clean.
	for i, m := range DefaultLLMToolScopeMap {
		if m.Pattern == "" {
			t.Errorf("DefaultLLMToolScopeMap[%d]: empty pattern (scope=%q)", i, m.Scope)
		}
		if m.Scope == "" {
			t.Errorf("DefaultLLMToolScopeMap[%d]: empty scope (pattern=%q)", i, m.Pattern)
		}
	}
}

func TestDefaultLLMToolScopeMap_OnlyKnownScopes(t *testing.T) {
	// The default map must only point at scopes the engine
	// recognises; an operator's `agentguard validate` will reject
	// anything else, but our bundled defaults have to be clean from
	// day one.
	known := map[string]bool{
		"shell":      true,
		"filesystem": true,
		"network":    true,
		"browser":    true,
		"data":       true,
		"cost":       true,
		"mcp_tool":   true,
	}
	for i, m := range DefaultLLMToolScopeMap {
		if !known[m.Scope] {
			t.Errorf("DefaultLLMToolScopeMap[%d]: scope %q is not a known engine scope (pattern=%q)",
				i, m.Scope, m.Pattern)
		}
	}
}
