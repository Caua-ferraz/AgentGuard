package policy

import (
	"strings"
	"testing"
)

// Tests for the `mcp_tool` scope and `tool_scope_map` accessor, added
// in v0.5 to back the MCP Gateway's dual-check pattern. The engine
// treats `mcp_tool` as a generic scope (same dispatch path as `data`):
// standard Pattern, Action, and Domain matching apply with no
// scope-specific custom logic. The tool_scope_map is consulted by the
// gateway (in pkg/mcpgw) to fire a second Engine.Check against the
// mapped existing scope.
//
// These tests pin:
//   1. The accessor (Policy.MapToolScope) resolves first-match-wins.
//   2. The engine's generic dispatch handles `mcp_tool` correctly.
//   3. LoadFromFile / Validate accept tool_scope_map and reject bad
//      scopes / empty entries.

func TestMapToolScope(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "mcp-map",
		ToolScopeMap: []ToolScopeMapping{
			// First match wins. Specific patterns must come first.
			{Pattern: "fs:read_file", Scope: "filesystem"},
			{Pattern: "fs:write_file", Scope: "filesystem"},
			{Pattern: "fs:*", Scope: "filesystem"},
			{Pattern: "github:*", Scope: "network"},
			{Pattern: "*:execute_*", Scope: "shell"},
			{Pattern: "*:run_command", Scope: "shell"},
		},
	}

	cases := []struct {
		tool      string
		wantScope string
		wantOK    bool
	}{
		{"fs:read_file", "filesystem", true},
		{"fs:write_file", "filesystem", true},
		{"fs:list_directory", "filesystem", true}, // matched by fs:*
		{"github:create_issue", "network", true},
		{"github:execute_workflow", "network", true}, // github:* wins (declared first)
		{"shell:execute_command", "shell", true},     // *:execute_* matches
		{"runner:run_command", "shell", true},
		{"unknown:tool", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := pol.MapToolScope(c.tool)
		if ok != c.wantOK || got != c.wantScope {
			t.Errorf("MapToolScope(%q) = (%q, %v), want (%q, %v)",
				c.tool, got, ok, c.wantScope, c.wantOK)
		}
	}
}

func TestMapToolScope_NilPolicy(t *testing.T) {
	var p *Policy
	if scope, ok := p.MapToolScope("fs:read_file"); ok || scope != "" {
		t.Fatalf("nil policy: want ('', false), got (%q, %v)", scope, ok)
	}
}

func TestMapToolScope_EmptyMap(t *testing.T) {
	pol := &Policy{Version: "1", Name: "x"}
	if scope, ok := pol.MapToolScope("fs:read_file"); ok || scope != "" {
		t.Fatalf("empty map: want ('', false), got (%q, %v)", scope, ok)
	}
}

func TestMCPToolScope_DispatchesGenerically_Allow(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "mcp-allow",
		Rules: []RuleSet{
			{
				Scope: "mcp_tool",
				Allow: []Rule{
					{Pattern: "fs:read_*"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)
	res := engine.Check(ActionRequest{
		Scope:   "mcp_tool",
		Command: "fs:read_file",
	}, "local")
	if res.Decision != Allow {
		t.Fatalf("expected ALLOW for fs:read_file under mcp_tool allow, got %s (reason=%s, rule=%s)",
			res.Decision, res.Reason, res.Rule)
	}
}

func TestMCPToolScope_DispatchesGenerically_Deny(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "mcp-deny",
		Rules: []RuleSet{
			{
				Scope: "mcp_tool",
				Deny: []Rule{
					{Pattern: "fs:write_file", Message: "writes blocked"},
				},
				Allow: []Rule{
					{Pattern: "*"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)
	res := engine.Check(ActionRequest{
		Scope:   "mcp_tool",
		Command: "fs:write_file",
	}, "local")
	if res.Decision != Deny {
		t.Fatalf("expected DENY for fs:write_file, got %s", res.Decision)
	}
	if !strings.Contains(res.Rule, "deny:mcp_tool") {
		t.Fatalf("rule should be deny:mcp_tool:..., got %q", res.Rule)
	}
}

func TestMCPToolScope_DispatchesGenerically_Approval(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "mcp-approval",
		Rules: []RuleSet{
			{
				Scope: "mcp_tool",
				RequireApproval: []Rule{
					{Pattern: "*:execute_*"},
				},
				Allow: []Rule{
					{Pattern: "*"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)
	res := engine.Check(ActionRequest{
		Scope:   "mcp_tool",
		Command: "shell:execute_command",
	}, "local")
	if res.Decision != RequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL, got %s", res.Decision)
	}
}

func TestMCPToolScope_DefaultDeny(t *testing.T) {
	// No mcp_tool rules and no allow → default DENY (matches every
	// other scope in the engine).
	pol := &Policy{
		Version: "1",
		Name:    "empty",
		Rules: []RuleSet{
			{Scope: "mcp_tool"},
		},
	}
	engine := NewEngineFromPolicy(pol)
	res := engine.Check(ActionRequest{
		Scope:   "mcp_tool",
		Command: "fs:read_file",
	}, "local")
	if res.Decision != Deny {
		t.Fatalf("expected default DENY, got %s", res.Decision)
	}
}

func TestPolicyLoad_AcceptsToolScopeMap(t *testing.T) {
	yaml := `
version: "1"
name: "with-tool-scope-map"
rules:
  - scope: mcp_tool
    allow:
      - pattern: "fs:*"
tool_scope_map:
  - pattern: "fs:read_file"
    scope: filesystem
  - pattern: "fs:*"
    scope: filesystem
  - pattern: "github:*"
    scope: network
`
	prov := NewStaticPolicyProvider(nil)
	if err := prov.Validate([]byte(yaml)); err != nil {
		t.Fatalf("validate failed unexpectedly: %v", err)
	}
}

func TestPolicyLoad_RejectsUnknownScope(t *testing.T) {
	yaml := `
version: "1"
name: "bad-scope"
tool_scope_map:
  - pattern: "x:y"
    scope: made_up
`
	prov := NewStaticPolicyProvider(nil)
	err := prov.Validate([]byte(yaml))
	if err == nil {
		t.Fatal("expected validation to reject unknown scope, got nil")
	}
	if !strings.Contains(err.Error(), "made_up") {
		t.Fatalf("error should mention the bad scope, got %v", err)
	}
}

func TestPolicyLoad_RejectsEmptyPattern(t *testing.T) {
	yaml := `
version: "1"
name: "empty-pattern"
tool_scope_map:
  - pattern: ""
    scope: filesystem
`
	prov := NewStaticPolicyProvider(nil)
	if err := prov.Validate([]byte(yaml)); err == nil {
		t.Fatal("expected validation to reject empty pattern")
	}
}

func TestPolicyLoad_RejectsEmptyScope(t *testing.T) {
	yaml := `
version: "1"
name: "empty-scope"
tool_scope_map:
  - pattern: "fs:*"
    scope: ""
`
	prov := NewStaticPolicyProvider(nil)
	if err := prov.Validate([]byte(yaml)); err == nil {
		t.Fatal("expected validation to reject empty scope")
	}
}
