package main

// Tests for the Cursor, Gemini CLI and Codex hooks, and for what every
// agent's hook shares: the answers against a fake server, failing open
// and failing closed, and calls that are several checks.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func jsonInput(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Shapes from https://cursor.com/docs/hooks.
func cursorInput(event string, fields map[string]any) string {
	in := map[string]any{
		"conversation_id": "conv-1", "generation_id": "gen-1", "hook_event_name": event,
		"workspace_roots": []string{"/home/u/proj"}, "cursor_version": "1.7.2",
	}
	for k, v := range fields {
		in[k] = v
	}
	return jsonInput(in)
}

// Shapes from https://geminicli.com/docs/hooks/reference/.
func geminiInput(tool string, input map[string]any) string {
	return jsonInput(map[string]any{
		"session_id": "sess-1", "cwd": "/home/u/proj", "hook_event_name": "BeforeTool",
		"timestamp": "2026-10-13T12:00:00Z", "tool_name": tool, "tool_input": input,
	})
}

// Shapes from https://learn.chatgpt.com/docs/hooks.
func codexInput(tool string, input any) string {
	return jsonInput(map[string]any{
		"session_id": "sess-1", "turn_id": "turn-1", "cwd": "/home/u/proj", "hook_event_name": "PreToolUse",
		"model": "gpt-5", "permission_mode": "default", "tool_name": tool, "tool_input": input,
	})
}

// wantReq is the part of a request the mapping tables compare.
type wantReq struct{ Scope, Action, Path, Command, URL, Domain string }

func toWant(reqs []policy.ActionRequest) []wantReq {
	var out []wantReq
	for _, r := range reqs {
		out = append(out, wantReq{r.Scope, r.Action, r.Path, r.Command, r.URL, r.Domain})
	}
	return out
}

// checkMapping parses each input with a and compares the requests, the
// agent, the session and the transport.
func checkMapping(t *testing.T, a hookAgent, cases []mappingCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			call, checked, err := a.parse([]byte(c.input))
			if (err != nil) != c.wantErr {
				t.Fatalf("parse error = %v, want error %v", err, c.wantErr)
			}
			if checked != (c.want != nil) {
				t.Fatalf("checked = %v, want %v", checked, c.want != nil)
			}
			if got := toWant(call.reqs); !reflect.DeepEqual(got, c.want) {
				t.Errorf("requests = %+v\nwant       %+v", got, c.want)
			}
			for _, r := range call.reqs {
				if r.AgentID != a.agentID || r.Meta["transport"] != a.transport || r.SessionID == "" {
					t.Errorf("agent/session/transport = %q %q %q", r.AgentID, r.SessionID, r.Meta["transport"])
				}
			}
		})
	}
}

type mappingCase struct {
	name    string
	input   string
	want    []wantReq // nil: not checked
	wantErr bool
}

func TestCursorRequest(t *testing.T) {
	proj := func(p string) string { return filepath.Join("/home/u/proj", p) }
	checkMapping(t, cursorHookAgent, []mappingCase{
		{"a shell command", cursorInput("beforeShellExecution", map[string]any{"command": "npm test", "cwd": "/home/u/proj", "sandbox": false}),
			[]wantReq{{Scope: "shell", Command: "npm test"}}, false},
		{"an MCP tool, named by its mcp.json server", cursorInput("beforeMCPExecution", map[string]any{"tool_name": "create_issue", "tool_input": `{"title":"x"}`, "mcp_server_name": "linear", "command": "npx linear-mcp"}),
			[]wantReq{{Scope: "mcp_tool", Command: "linear:create_issue"}}, false},
		{"an MCP tool without a server name", cursorInput("beforeMCPExecution", map[string]any{"tool_name": "query", "tool_input": "{}"}),
			[]wantReq{{Scope: "mcp_tool", Command: "query"}}, false},
		{"a file read", cursorInput("beforeReadFile", map[string]any{"file_path": "/home/u/.ssh/id_rsa", "content": "..."}),
			[]wantReq{{Scope: "filesystem", Action: "read", Path: "/home/u/.ssh/id_rsa"}}, false},
		{"a Write, relative to the workspace", cursorInput("preToolUse", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "src/a.ts", "content": "x"}, "tool_use_id": "t1"}),
			[]wantReq{{Scope: "filesystem", Action: "write", Path: proj("src/a.ts")}}, false},
		{"a Write without a path can't be read", cursorInput("preToolUse", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"content": "x"}}), nil, true},
		{"another tool in preToolUse", cursorInput("preToolUse", map[string]any{"tool_name": "Grep", "tool_input": map[string]any{"pattern": "x"}}), nil, false},
		{"another event", cursorInput("afterFileEdit", map[string]any{"file_path": "/x"}), nil, false},
	})
}

func TestGeminiRequests(t *testing.T) {
	proj := func(p string) string { return filepath.Join("/home/u/proj", p) }
	checkMapping(t, geminiHookAgent, []mappingCase{
		{"a shell command", geminiInput("run_shell_command", map[string]any{"command": "npm test", "dir_path": "."}),
			[]wantReq{{Scope: "shell", Command: "npm test"}}, false},
		{"write_file", geminiInput("write_file", map[string]any{"file_path": "/home/u/proj/a.go", "content": "x"}),
			[]wantReq{{Scope: "filesystem", Action: "write", Path: "/home/u/proj/a.go"}}, false},
		{"replace, relative to cwd", geminiInput("replace", map[string]any{"file_path": "b.go", "old_string": "x", "new_string": "y"}),
			[]wantReq{{Scope: "filesystem", Action: "write", Path: proj("b.go")}}, false},
		{"read_file", geminiInput("read_file", map[string]any{"file_path": "/home/u/.aws/credentials"}),
			[]wantReq{{Scope: "filesystem", Action: "read", Path: "/home/u/.aws/credentials"}}, false},
		{"read_many_files: one read per include", geminiInput("read_many_files", map[string]any{"include": []string{"src/**/*.ts", "/etc/passwd"}}),
			[]wantReq{{Scope: "filesystem", Action: "read", Path: proj("src/**/*.ts")}, {Scope: "filesystem", Action: "read", Path: "/etc/passwd"}}, false},
		{"read_many_files without includes can't be read", geminiInput("read_many_files", map[string]any{"recursive": true}), nil, true},
		{"web_fetch: one check per URL in the prompt", geminiInput("web_fetch", map[string]any{"prompt": "Summarize https://docs.python.org/3/x and https://example.com/a."}),
			[]wantReq{{Scope: "network", URL: "https://docs.python.org/3/x", Domain: "docs.python.org"}, {Scope: "network", URL: "https://example.com/a", Domain: "example.com"}}, false},
		{"web_fetch without a URL", geminiInput("web_fetch", map[string]any{"prompt": "what's new?"}), nil, false},
		{"an MCP tool, server from mcp_context", jsonInput(map[string]any{
			"session_id": "sess-1", "hook_event_name": "BeforeTool", "tool_name": "mcp_my_db_run_query", "tool_input": map[string]any{},
			"mcp_context": map[string]any{"server_name": "my_db", "tool_name": "run_query", "command": "db-mcp"},
		}), []wantReq{{Scope: "mcp_tool", Command: "my_db:run_query"}}, false},
		{"an MCP tool without mcp_context", geminiInput("mcp_github_create_issue", map[string]any{}),
			[]wantReq{{Scope: "mcp_tool", Command: "github:create_issue"}}, false},
		{"a tool AgentGuard doesn't check", geminiInput("write_todos", map[string]any{"todos": []any{}}), nil, false},
		{"another event", strings.Replace(geminiInput("run_shell_command", map[string]any{"command": "ls"}), "BeforeTool", "AfterTool", 1), nil, false},
	})
}

func TestCodexRequests(t *testing.T) {
	proj := func(p string) string { return filepath.Join("/home/u/proj", p) }
	patch := "*** Begin Patch\n*** Add File: docs/new.md\n+hello\n*** Update File: src/main.rs\n*** Move to: src/lib.rs\n@@\n-a\n+b\n*** Delete File: /tmp/old.txt\n*** Update File: src/main.rs\n*** End Patch\n"
	checkMapping(t, codexHookAgent, []mappingCase{
		{"a shell command", codexInput("Bash", map[string]any{"command": "cargo test"}),
			[]wantReq{{Scope: "shell", Command: "cargo test"}}, false},
		{"a shell command as an argument list", codexInput("Bash", map[string]any{"command": []string{"bash", "-lc", "ls -la"}}),
			[]wantReq{{Scope: "shell", Command: "bash -lc ls -la"}}, false},
		{"apply_patch: one write per file, moves included", codexInput("apply_patch", map[string]any{"command": patch}),
			[]wantReq{
				{Scope: "filesystem", Action: "write", Path: proj("docs/new.md")},
				{Scope: "filesystem", Action: "write", Path: proj("src/main.rs")},
				{Scope: "filesystem", Action: "write", Path: proj("src/lib.rs")},
				{Scope: "filesystem", Action: "write", Path: "/tmp/old.txt"},
			}, false},
		{"apply_patch naming no file can't be read", codexInput("apply_patch", map[string]any{"command": "*** Begin Patch\n*** End Patch\n"}), nil, true},
		{"an MCP tool", codexInput("mcp__fs__read", map[string]any{"path": "/x"}),
			[]wantReq{{Scope: "mcp_tool", Command: "fs:read"}}, false},
		{"another local tool", codexInput("update_plan", map[string]any{"plan": []any{}}), nil, false},
		{"another event", strings.Replace(codexInput("Bash", map[string]any{"command": "ls"}), "PreToolUse", "PostToolUse", 1), nil, false},
	})
}

// ── Answers, for every agent ────────────────────────────────────────────

// agentCase is one agent's side of the shared answer tests: a shell call
// in its input format, and how to read its answer back.
type agentCase struct {
	agent hookAgent
	shell func(cmd string) string
	// read returns "allow", "deny" or "warn" and the message, from the
	// exit code and output.
	read func(t *testing.T, code int, stdout, stderr string) (verdict, msg string)
}

func agentCases() []agentCase {
	claudeStyle := func(t *testing.T, code int, stdout, stderr string) (string, string) {
		var out struct {
			SystemMessage string `json:"systemMessage"`
			Hook          struct {
				Event    string `json:"hookEventName"`
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		_ = json.Unmarshal([]byte(stdout), &out)
		switch {
		case code == 0 && stdout == "":
			return "allow", ""
		case code == 0 && out.SystemMessage != "":
			return "warn", out.SystemMessage
		case code == 2 && out.Hook.Decision == "deny" && out.Hook.Event == "PreToolUse" && strings.TrimSpace(stderr) == out.Hook.Reason:
			return "deny", out.Hook.Reason
		}
		t.Errorf("unexpected answer: code %d, stdout %q, stderr %q", code, stdout, stderr)
		return "", ""
	}
	return []agentCase{
		{claudeHookAgent, func(cmd string) string { return hookInput("Bash", map[string]any{"command": cmd}) }, claudeStyle},
		{codexHookAgent, func(cmd string) string { return codexInput("Bash", map[string]any{"command": cmd}) }, claudeStyle},
		{cursorHookAgent, func(cmd string) string {
			return cursorInput("beforeShellExecution", map[string]any{"command": cmd, "cwd": "/home/u/proj"})
		}, func(t *testing.T, code int, stdout, _ string) (string, string) {
			// Every Cursor answer is JSON with a permission, exit 0.
			var out map[string]string
			if err := json.Unmarshal([]byte(stdout), &out); err != nil || code != 0 {
				t.Errorf("Cursor needs JSON and exit 0: code %d, stdout %q", code, stdout)
				return "", ""
			}
			switch {
			case out["permission"] == "allow" && out["user_message"] == "":
				return "allow", ""
			case out["permission"] == "allow":
				return "warn", out["user_message"]
			case out["permission"] == "deny" && out["user_message"] != "":
				return "deny", out["user_message"]
			}
			t.Errorf("unexpected answer: %q", stdout)
			return "", ""
		}},
		{geminiHookAgent, func(cmd string) string { return geminiInput("run_shell_command", map[string]any{"command": cmd}) },
			func(t *testing.T, code int, stdout, _ string) (string, string) {
				var out map[string]string
				_ = json.Unmarshal([]byte(stdout), &out)
				switch {
				case code != 0:
				case stdout == "":
					return "allow", ""
				case out["decision"] == "deny":
					return "deny", out["reason"]
				case out["systemMessage"] != "":
					return "warn", out["systemMessage"]
				}
				t.Errorf("unexpected answer: code %d, stdout %q", code, stdout)
				return "", ""
			}},
	}
}

func runAgent(a hookAgent, cfg hookConfig, input string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := runAgentHook(a, strings.NewReader(input), &out, &errOut, cfg)
	return code, out.String(), errOut.String()
}

func TestAgentHookAnswers(t *testing.T) {
	for _, ac := range agentCases() {
		t.Run(ac.agent.name, func(t *testing.T) {
			g := newFakeGuard(t)
			cfg := hookConfig{serverURL: g.URL, apiKey: "k", wait: 400 * time.Millisecond, poll: 20 * time.Millisecond}
			for _, c := range []struct {
				name, command, approval string
				verdict, msg            string
			}{
				{"allowed", "ls", "", "allow", ""},
				{"denied", "evil", "", "deny", "evil is blocked (rule deny:shell:evil)"},
				{"approval granted", "rm -rf x", "ALLOW", "allow", ""},
				{"approval denied", "rm -rf x", "DENY", "deny", "a person denied"},
				{"approval timed out", "rm -rf x", "", "deny", "no one approved it within"},
				{"approval gone", "rm -rf x", "gone", "deny", "is gone"},
			} {
				g.mu.Lock()
				g.approval = c.approval
				g.mu.Unlock()
				code, out, errOut := runAgent(ac.agent, cfg, ac.shell(c.command))
				verdict, msg := ac.read(t, code, out, errOut)
				if verdict != c.verdict || !strings.Contains(msg, c.msg) {
					t.Errorf("%s: %s %q, want %s with %q", c.name, verdict, msg, c.verdict, c.msg)
				}
			}
			g.mu.Lock()
			defer g.mu.Unlock()
			rechecked := false
			for _, r := range g.requests {
				if r.ApprovalID == "ap_1" && r.Command == "rm -rf x" && r.AgentID == ac.agent.agentID && r.Meta["transport"] == ac.agent.transport {
					rechecked = true
				}
			}
			if !rechecked {
				t.Errorf("the approved call wasn't re-checked with its approval, as this agent: %+v", g.requests)
			}
			if g.auth[0] != "Bearer k" {
				t.Errorf("the API key wasn't sent: %q", g.auth[0])
			}
		})
	}
}

// Without a verdict, every agent's call goes ahead with a warning by
// default, and is blocked with deny:hook:fail_closed under --fail-closed.
func TestAgentHookFailOpenAndFailClosed(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()
	for _, ac := range agentCases() {
		for _, failClosed := range []bool{false, true} {
			name := ac.agent.name + "/fail-open"
			if failClosed {
				name = ac.agent.name + "/fail-closed"
			}
			t.Run(name, func(t *testing.T) {
				rejecting := newFakeGuard(t)
				rejecting.status = http.StatusUnauthorized
				for _, c := range []struct {
					name, url, input, want string
				}{
					{"server down", downURL, ac.shell("ls"), "Start the server"},
					{"key rejected", rejecting.URL, ac.shell("ls"), "rejected the API key"},
					{"garbage input", rejecting.URL, "not json", "couldn't read"},
					{"empty input", rejecting.URL, "", "couldn't read"},
				} {
					cfg := hookConfig{serverURL: c.url, failClosed: failClosed}
					code, out, errOut := runAgent(ac.agent, cfg, c.input)
					verdict, msg := ac.read(t, code, out, errOut)
					want := "warn"
					if failClosed {
						want = "deny"
					}
					if verdict != want || !strings.Contains(msg, c.want) {
						t.Errorf("%s: %s %q, want %s with %q", c.name, verdict, msg, want, c.want)
					}
					if failClosed != strings.Contains(msg, failClosedRule) {
						t.Errorf("%s: the message names %s = %v, want %v: %q", c.name, failClosedRule, !failClosed, failClosed, msg)
					}
				}
			})
		}
	}
}

// A patch touching several files is one check per file: one denied file
// blocks the whole patch, and files that need approval wait for it.
func TestCodexPatchMostSevereVerdictWins(t *testing.T) {
	g := newFakeGuard(t)
	cfg := hookConfig{serverURL: g.URL, wait: 400 * time.Millisecond, poll: 20 * time.Millisecond}
	patch := func(files ...string) string {
		var b strings.Builder
		b.WriteString("*** Begin Patch\n")
		for _, f := range files {
			b.WriteString("*** Update File: " + f + "\n@@\n-a\n+b\n")
		}
		b.WriteString("*** End Patch\n")
		return codexInput("apply_patch", map[string]any{"command": b.String()})
	}
	for _, c := range []struct {
		name     string
		files    []string
		approval string
		wantCode int
		want     string
	}{
		{"all allowed", []string{"a.go", "b.go"}, "", 0, ""},
		{"one denied blocks the patch", []string{"a.go", "secret", "approve-me"}, "ALLOW", 2, "secrets are blocked"},
		{"approval granted", []string{"a.go", "approve-me"}, "ALLOW", 0, ""},
		{"approval not given", []string{"a.go", "approve-me"}, "", 2, "no one approved it within"},
	} {
		g.mu.Lock()
		g.approval = c.approval
		before := len(g.requests)
		g.mu.Unlock()
		code, out, _ := runAgent(codexHookAgent, cfg, patch(c.files...))
		if code != c.wantCode || !strings.Contains(out, c.want) {
			t.Errorf("%s: code %d, output %q; want %d with %q", c.name, code, out, c.wantCode, c.want)
		}
		g.mu.Lock()
		if checked := len(g.requests) - before; checked < len(c.files) {
			t.Errorf("%s: %d checks for %d files", c.name, checked, len(c.files))
		}
		g.mu.Unlock()
	}
}

func TestHookCommandLine(t *testing.T) {
	dir := t.TempDir()
	env := []string{"AGENTGUARD_URL=http://127.0.0.1:1"}
	// The flag goes before or after the agent; without it the call goes
	// ahead with a warning.
	for _, args := range [][]string{{"hook", "--fail-closed", "codex"}, {"hook", "codex", "--fail-closed"}} {
		r := agentguardStdin(t, dir, env, codexInput("Bash", map[string]any{"command": "ls"}), args...)
		r.expect(t, 2, failClosedRule, failClosedRule)
	}
	agentguardStdin(t, dir, env, codexInput("Bash", map[string]any{"command": "ls"}), "hook", "codex").expect(t, 0, "systemMessage", "")
	agentguard(t, dir, nil, "hook", "codex", "extra").expect(t, 2, "", `unexpected argument "extra"`)
	agentguard(t, dir, nil, "hook", "--fail-close", "codex").expect(t, 2, "", "did you mean --fail-closed?")
}
