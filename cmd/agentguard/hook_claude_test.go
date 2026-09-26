package main

// Tests for the Claude Code integration: the hook's mapping and answers
// (against a fake server), the settings.json edit, and the policy block.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/configs"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// hookInput is a PreToolUse input as Claude Code sends it.
func hookInput(tool string, input map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "sess-1", "cwd": "/home/u/proj", "hook_event_name": "PreToolUse",
		"permission_mode": "default", "tool_name": tool, "tool_input": input,
	})
	return string(b)
}

func TestClaudeRequest(t *testing.T) {
	cases := []struct {
		tool  string
		input map[string]any
		want  policy.ActionRequest
		ok    bool
	}{
		{"Bash", map[string]any{"command": "npm test", "description": "run tests"}, policy.ActionRequest{Scope: "shell", Command: "npm test"}, true},
		{"PowerShell", map[string]any{"command": "Get-ChildItem"}, policy.ActionRequest{Scope: "shell", Command: "Get-ChildItem"}, true},
		{"Edit", map[string]any{"file_path": "/home/u/proj/a.go", "old_string": "x", "new_string": "y"}, policy.ActionRequest{Scope: "filesystem", Action: "write", Path: "/home/u/proj/a.go"}, true},
		{"Write", map[string]any{"file_path": "b.go", "content": "x"}, policy.ActionRequest{Scope: "filesystem", Action: "write", Path: filepath.Join("/home/u/proj", "b.go")}, true},
		{"NotebookEdit", map[string]any{"notebook_path": "/n.ipynb"}, policy.ActionRequest{Scope: "filesystem", Action: "write", Path: "/n.ipynb"}, true},
		{"Read", map[string]any{"file_path": "/home/u/.ssh/id_rsa"}, policy.ActionRequest{Scope: "filesystem", Action: "read", Path: "/home/u/.ssh/id_rsa"}, true},
		{"WebFetch", map[string]any{"url": "https://docs.python.org/3/x", "prompt": "p"}, policy.ActionRequest{Scope: "network", URL: "https://docs.python.org/3/x", Domain: "docs.python.org"}, true},
		{"mcp__github__create_issue", map[string]any{"title": "x"}, policy.ActionRequest{Scope: "mcp_tool", Command: "github:create_issue"}, true},
		{"mcp__plugin_tools_db__query", nil, policy.ActionRequest{Scope: "mcp_tool", Command: "plugin_tools_db:query"}, true},
		{"TodoWrite", map[string]any{"todos": []any{}}, policy.ActionRequest{}, false},
		{"mcp__broken", nil, policy.ActionRequest{}, false},
	}
	for _, c := range cases {
		var in claudeHookInput
		_ = json.Unmarshal([]byte(hookInput(c.tool, c.input)), &in)
		got, ok := claudeRequest(in)
		if ok != c.ok {
			t.Errorf("%s: checked = %v, want %v", c.tool, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Scope != c.want.Scope || got.Command != c.want.Command || got.Action != c.want.Action ||
			got.Path != c.want.Path || got.Domain != c.want.Domain || got.URL != c.want.URL {
			t.Errorf("%s: request = %+v, want %+v", c.tool, got, c.want)
		}
		if got.AgentID != claudeAgentID || got.SessionID != "sess-1" || got.Meta["transport"] != claudeTransport || got.Meta["tool"] != c.tool {
			t.Errorf("%s: agent/session/meta = %q %q %v", c.tool, got.AgentID, got.SessionID, got.Meta)
		}
	}
}

// fakeGuard is an AgentGuard server for the hook: "ls" is allowed, "evil"
// denied, "rm -rf x" needs approval (resolved as approval says).
type fakeGuard struct {
	*httptest.Server
	mu       sync.Mutex
	approval string // "" pending, "ALLOW", "DENY", "gone"
	requests []policy.ActionRequest
	auth     []string
	status   int // non-zero: every /v1/check answers this code
}

func newFakeGuard(t *testing.T) *fakeGuard {
	g := &fakeGuard{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.auth = append(g.auth, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/v1/check":
			if g.status != 0 {
				w.WriteHeader(g.status)
				return
			}
			var req policy.ActionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			g.requests = append(g.requests, req)
			res := policy.CheckResult{Decision: policy.Allow, Reason: "ok", Rule: "allow:shell:*"}
			switch {
			case req.Command == "evil":
				res = policy.CheckResult{Decision: policy.Deny, Reason: "evil is blocked", Rule: "deny:shell:evil"}
			case req.Command == "rm -rf x" && req.ApprovalID == "":
				res = policy.CheckResult{Decision: policy.RequireApproval, Reason: "rm needs approval", ApprovalID: "ap_1"}
			}
			_ = json.NewEncoder(w).Encode(res)
		case "/v1/status/ap_1":
			switch g.approval {
			case "gone":
				http.NotFound(w, r)
			case "":
				_ = json.NewEncoder(w).Encode(map[string]string{"id": "ap_1", "status": "pending"})
			default:
				_ = json.NewEncoder(w).Encode(map[string]string{"id": "ap_1", "status": "resolved", "decision": g.approval})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func runHook(t *testing.T, cfg hookConfig, input string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := claudeHook(strings.NewReader(input), &out, &errOut, cfg)
	return code, out.String(), errOut.String()
}

func TestClaudeHookAnswers(t *testing.T) {
	g := newFakeGuard(t)
	cfg := hookConfig{serverURL: g.URL, apiKey: "k", wait: 400 * time.Millisecond, poll: 20 * time.Millisecond}
	bash := func(cmd string) string { return hookInput("Bash", map[string]any{"command": cmd}) }

	// Allowed: no output at all, so Claude Code's own permissions decide.
	if code, out, _ := runHook(t, cfg, bash("ls")); code != 0 || out != "" {
		t.Errorf("allow: code %d, output %q; want 0 and nothing", code, out)
	}
	// Denied: a deny decision Claude sees, and exit 2.
	code, out, errOut := runHook(t, cfg, bash("evil"))
	var ans map[string]map[string]string
	_ = json.Unmarshal([]byte(out), &ans)
	h := ans["hookSpecificOutput"]
	if code != 2 || h["hookEventName"] != "PreToolUse" || h["permissionDecision"] != "deny" ||
		!strings.Contains(h["permissionDecisionReason"], "evil is blocked") || !strings.Contains(errOut, "evil is blocked") {
		t.Errorf("deny: code %d, answer %v, stderr %q", code, h, errOut)
	}
	if g.auth[0] != "Bearer k" {
		t.Errorf("the API key wasn't sent: %q", g.auth[0])
	}

	// Needs approval, then approved: the call goes ahead, and the re-check
	// carries the approval id (so the server consumes and audits it).
	g.approval = "ALLOW"
	if code, out, _ := runHook(t, cfg, bash("rm -rf x")); code != 0 || out != "" {
		t.Errorf("approved: code %d, output %q", code, out)
	}
	if last := g.requests[len(g.requests)-1]; last.ApprovalID != "ap_1" || last.Command != "rm -rf x" {
		t.Errorf("the approved call wasn't re-checked with its approval: %+v", last)
	}
	for _, c := range []struct{ approval, want string }{
		{"DENY", "a person denied"},
		{"", "no one approved it within"},
		{"gone", "is gone"},
	} {
		g.approval = c.approval
		if code, out, _ := runHook(t, cfg, bash("rm -rf x")); code != 2 || !strings.Contains(out, c.want) {
			t.Errorf("approval %q: code %d, output %q; want 2 and %q", c.approval, code, out, c.want)
		}
	}
}

// No verdict — the server is down, rejects the key, or the input is
// garbage — lets the call through with a warning the user sees.
func TestClaudeHookWarnsWithoutAVerdict(t *testing.T) {
	g := newFakeGuard(t)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()
	bash := hookInput("Bash", map[string]any{"command": "ls"})

	for _, c := range []struct {
		name  string
		cfg   hookConfig
		input string
		setup func()
		want  string
	}{
		{"server down", hookConfig{serverURL: downURL}, bash, nil, "Start the server"},
		{"key rejected", hookConfig{serverURL: g.URL}, bash, func() { g.status = http.StatusUnauthorized }, "rejected the API key"},
		{"garbage input", hookConfig{serverURL: g.URL}, "not json", nil, "couldn't read"},
	} {
		if c.setup != nil {
			c.setup()
		}
		code, out, _ := runHook(t, c.cfg, c.input)
		var msg map[string]string
		_ = json.Unmarshal([]byte(out), &msg)
		if code != 0 || !strings.Contains(msg["systemMessage"], c.want) {
			t.Errorf("%s: code %d, output %q; want 0 and a systemMessage with %q", c.name, code, out, c.want)
		}
	}
}

func TestClaudeHookIgnoresWhatItDoesntCheck(t *testing.T) {
	g := newFakeGuard(t)
	cfg := hookConfig{serverURL: g.URL}
	for _, input := range []string{
		hookInput("TodoWrite", map[string]any{"todos": []any{}}),
		strings.Replace(hookInput("Bash", map[string]any{"command": "ls"}), "PreToolUse", "PostToolUse", 1),
	} {
		if code, out, _ := runHook(t, cfg, input); code != 0 || out != "" {
			t.Errorf("code %d, output %q for %s", code, out, input)
		}
	}
	if len(g.requests) != 0 {
		t.Errorf("the server was asked about %d calls it shouldn't see", len(g.requests))
	}
}

// ── settings.json ───────────────────────────────────────────────────────

func TestConnectClaudeCodeKeepsTheRestOfTheSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	original := `{
  "model": "opus",
  "permissions": {"allow": ["Bash(npm test)"], "deny": []},
  "hooks": {
    "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "prettier --write"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./my-check.sh"}]}]
  },
  "theme": "dark"
}
`
	_ = os.WriteFile(path, []byte(original), 0o600)
	exe := filepath.Join(dir, "bin", "agentguard")

	for range 2 { // connecting twice leaves one entry
		if err := connectClaudeCode(path, exe); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(path)
	text := string(got)
	if strings.Count(text, "hook claude-code") != 1 {
		t.Errorf("want exactly one AgentGuard hook:\n%s", text)
	}
	for _, want := range []string{`"model": "opus"`, `"Bash(npm test)"`, "prettier --write", "./my-check.sh", `"theme": "dark"`, `"timeout": 330`, `"matcher": "` + claudeHookMatcher + `"`} {
		if !strings.Contains(text, want) {
			t.Errorf("settings lost or lack %q:\n%s", want, text)
		}
	}
	if i, j, k := strings.Index(text, `"model"`), strings.Index(text, `"permissions"`), strings.Index(text, `"theme"`); i >= j || j >= k {
		t.Errorf("key order changed:\n%s", text)
	}
	if b, err := os.ReadFile(path + ".agentguard-backup"); err != nil || len(b) == 0 {
		t.Errorf("no backup: %v", err)
	}
	if !claudeConnected(path) {
		t.Error("claudeConnected = false after connecting")
	}

	removed, err := disconnectClaudeCode(path)
	if err != nil || !removed {
		t.Fatalf("disconnect = %v, %v", removed, err)
	}
	after, _ := os.ReadFile(path)
	if strings.Contains(string(after), "hook claude-code") || !strings.Contains(string(after), "./my-check.sh") || !strings.Contains(string(after), "prettier") {
		t.Errorf("disconnect must remove only AgentGuard's hook:\n%s", after)
	}
}

func TestConnectClaudeCodeFreshAndBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "new", "settings.json")
	if err := connectClaudeCode(fresh, "/bin/agentguard"); err != nil {
		t.Fatal(err)
	}
	if !claudeConnected(fresh) {
		t.Fatal("not connected after writing a new settings file")
	}
	if _, err := disconnectClaudeCode(fresh); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(fresh); strings.TrimSpace(string(b)) != "{}" {
		t.Errorf("an emptied hooks section should go away, got %s", b)
	}

	broken := filepath.Join(dir, "broken.json")
	_ = os.WriteFile(broken, []byte("{ not json"), 0o600)
	if err := connectClaudeCode(broken, "/bin/agentguard"); err == nil {
		t.Error("a settings file that isn't JSON must not be overwritten")
	}
	if b, _ := os.ReadFile(broken); string(b) != "{ not json" {
		t.Errorf("the broken file was changed: %q", b)
	}
}

// ── The policy block ────────────────────────────────────────────────────

func TestStarterPolicyHasTheClaudeCodeBlock(t *testing.T) {
	lf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	if !bytes.Contains(lf(configs.Default), lf(configs.ClaudeCode)) {
		t.Error("configs/default.yaml must end with configs/claude-code.yaml verbatim")
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	_ = os.WriteFile(path, configs.Default, 0o644)
	if has, err := policyHasClaudeRules(path); err != nil || !has {
		t.Errorf("starter policy: has Claude Code rules = %v, %v", has, err)
	}
}

func TestAddClaudeRules(t *testing.T) {
	base := "version: \"1\"\nname: t\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n"
	for _, c := range []struct {
		name, policy string
		wantErr      bool
	}{
		{"no agents section", base + "# the end\n", false},
		{"an agents section", base + "agents:\n  research-bot:\n    override:\n      - scope: network\n        allow:\n          - domain: \"arxiv.org\"\n", false},
		{"windows line endings", strings.ReplaceAll(base, "\n", "\r\n"), false},
		// The block would swallow research-bot as a field of its own; the
		// file still loads, so only comparing before and after catches it.
		{"agents indented by 4, which can't take the block", base + "agents:\n    research-bot:\n        override:\n            - scope: network\n              allow:\n                  - domain: \"arxiv.org\"\n", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "p.yaml")
			_ = os.WriteFile(path, []byte(c.policy), 0o644)
			err := addClaudeRules(path)
			if (err != nil) != c.wantErr {
				t.Fatalf("addClaudeRules err = %v, want error %v", err, c.wantErr)
			}
			got, _ := os.ReadFile(path)
			if c.wantErr {
				if string(got) != c.policy {
					t.Error("a failed add must leave the policy as it was")
				}
				return
			}
			pol, lerr := policy.LoadFromFile(path)
			if lerr != nil {
				t.Fatalf("policy doesn't load after the add: %v", lerr)
			}
			if _, ok := pol.Agents[claudeAgentID]; !ok {
				t.Error("no claude-code agent after the add")
			}
			if c.name == "an agents section" {
				if _, ok := pol.Agents["research-bot"]; !ok {
					t.Error("the existing agent was lost")
				}
			}
			if !strings.Contains(string(got), `pattern: "ls *"`) {
				t.Error("the operator's rules were rewritten")
			}
		})
	}
}

// Connect Claude Code from the menu: add the rules, write the hook; then
// uninstall removes the hook.
func TestSetupConnectsAndUninstallDisconnects(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	ui := &scriptedUI{t: t, choices: []int{0, 0, 1}}
	svc := &fakeService{}
	s := &setup{m: m, ui: ui, svc: svc}
	s.doSetup()
	// A policy from before this release: no Claude Code block.
	_ = os.WriteFile(m.policyPath(), []byte("version: \"1\"\nname: old\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n"), 0o644)

	ui.choices = []int{0} // "Add AgentGuard's Claude Code rules"
	s.connectClaude()
	if has, _ := policyHasClaudeRules(m.policyPath()); !has {
		t.Error("the Claude Code rules weren't added")
	}
	if !claudeConnected(claudeSettingsPath()) {
		t.Fatal("Claude Code isn't connected")
	}
	if !strings.Contains(ui.out.String(), "dashboard") {
		t.Error("connecting should say where approvals happen")
	}

	ui.choices = []int{1} // uninstall, keep my policy and data
	s.doUninstall()
	if claudeConnected(claudeSettingsPath()) {
		t.Error("uninstall left Claude Code's hook pointing at a deleted program")
	}
}
