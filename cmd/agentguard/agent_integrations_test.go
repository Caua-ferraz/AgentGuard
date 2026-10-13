package main

// Tests for connecting Cursor, Gemini CLI and Codex CLI: each agent's
// settings edit, the policy blocks, and the setup menu's connect,
// fail-closed and uninstall flows.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/configs"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func integration(t *testing.T, agentID string) agentIntegration {
	t.Helper()
	for _, a := range agentIntegrations {
		if a.agentID == agentID {
			return a
		}
	}
	t.Fatalf("no integration for %s", agentID)
	return agentIntegration{}
}

// settingsCase is one agent's settings file: one with the user's own
// settings and hooks in it, and strings that must survive a connect.
type settingsCase struct {
	agentID  string
	original string
	keep     []string
	want     []string // in the file after connecting
}

func settingsCases() []settingsCase {
	return []settingsCase{
		{
			agentID: cursorAgentID,
			original: `{
  "version": 1,
  "hooks": {
    "afterFileEdit": [{"command": "./format.sh"}],
    "beforeShellExecution": [{"command": "./approve-network.sh", "timeout": 30, "matcher": "curl|wget"}]
  }
}
`,
			keep: []string{"./format.sh", "./approve-network.sh", `"matcher": "curl|wget"`},
			want: []string{`"beforeMCPExecution"`, `"beforeReadFile"`, `"preToolUse"`, `"matcher": "Write"`, `"timeout": 330`},
		},
		{
			agentID: geminiAgentID,
			original: `{
  "model": {"name": "gemini-2.5-pro"},
  "hooks": {
    "BeforeTool": [{"matcher": "write_file", "hooks": [{"type": "command", "command": "./security.sh", "timeout": 5000}]}],
    "AfterTool": [{"matcher": "*", "hooks": [{"type": "command", "command": "./audit.sh"}]}]
  },
  "ui": {"theme": "dark"}
}
`,
			keep: []string{`"gemini-2.5-pro"`, "./security.sh", "./audit.sh", `"theme": "dark"`},
			want: []string{`"timeout": 330000`, `"name": "agentguard"`, `"matcher": "` + geminiHookMatcher + `"`},
		},
		{
			agentID: codexAgentID,
			original: `{
  "description": "my hooks",
  "hooks": {
    "SessionStart": [{"matcher": "startup", "hooks": [{"type": "command", "command": "python3 notes.py"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 policy.py", "timeout": 30}]}]
  }
}
`,
			keep: []string{`"my hooks"`, "notes.py", "policy.py"},
			want: []string{`"timeout": 330`, `"matcher": "Bash|apply_patch|mcp__.*"`, `"statusMessage"`},
		},
	}
}

func TestConnectAgentsKeepTheRestOfTheSettings(t *testing.T) {
	for _, c := range settingsCases() {
		t.Run(c.agentID, func(t *testing.T) {
			a := integration(t, c.agentID)
			path := filepath.Join(t.TempDir(), "settings.json")
			_ = os.WriteFile(path, []byte(c.original), 0o600)
			exe := filepath.Join(t.TempDir(), "bin", "agentguard")
			for range 2 { // connecting twice leaves one entry per list
				if err := a.connect(path, exe, false); err != nil {
					t.Fatal(err)
				}
			}
			got, _ := os.ReadFile(path)
			text := string(got)
			if n := strings.Count(text, "hook "+c.agentID); n != len(a.lists) {
				t.Errorf("want %d AgentGuard hooks, got %d:\n%s", len(a.lists), n, text)
			}
			for _, want := range append(c.keep, c.want...) {
				if !strings.Contains(text, want) {
					t.Errorf("settings lost or lack %s:\n%s", want, text)
				}
			}
			// Keys stay in their order: compare the order of the kept
			// strings before and after.
			last := -1
			for _, k := range c.keep {
				i := strings.Index(text, k)
				if i < last {
					t.Errorf("order changed around %s:\n%s", k, text)
				}
				last = i
			}
			if b, err := os.ReadFile(path + ".agentguard-backup"); err != nil || len(b) == 0 {
				t.Errorf("no backup: %v", err)
			}
			if connected, failClosed := hooksConnected(path, a.agentID, a.lists); !connected || failClosed {
				t.Errorf("connected = %v, failClosed = %v; want true, false", connected, failClosed)
			}

			removed, err := disconnectHooks(path, a.agentID, a.lists)
			if err != nil || !removed {
				t.Fatalf("disconnect = %v, %v", removed, err)
			}
			after, _ := os.ReadFile(path)
			if strings.Contains(string(after), "hook "+c.agentID) {
				t.Errorf("AgentGuard's hook is still there:\n%s", after)
			}
			for _, k := range c.keep {
				if !strings.Contains(string(after), k) {
					t.Errorf("disconnect removed %s, which isn't AgentGuard's:\n%s", k, after)
				}
			}
			if again, err := disconnectHooks(path, a.agentID, a.lists); err != nil || again {
				t.Errorf("a second disconnect = %v, %v; want nothing to do", again, err)
			}
		})
	}
}

func TestConnectAgentsFreshAndBrokenFiles(t *testing.T) {
	for _, c := range []struct {
		agentID, emptied string
	}{
		{cursorAgentID, `{"version":1}`},
		{geminiAgentID, `{}`},
		{codexAgentID, `{}`},
	} {
		t.Run(c.agentID, func(t *testing.T) {
			a := integration(t, c.agentID)
			dir := t.TempDir()
			fresh := filepath.Join(dir, "new", "settings.json")
			if err := a.connect(fresh, "/bin/agentguard", false); err != nil {
				t.Fatal(err)
			}
			if connected, _ := hooksConnected(fresh, a.agentID, a.lists); !connected {
				t.Fatal("not connected after writing a new settings file")
			}
			if _, err := disconnectHooks(fresh, a.agentID, a.lists); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(fresh)
			var compact bytes.Buffer
			_ = json.Compact(&compact, b)
			if compact.String() != c.emptied {
				t.Errorf("an emptied hooks section should go away: got %s, want %s", compact.String(), c.emptied)
			}

			// A settings file setup can't read as JSON is never
			// overwritten, comments included (Gemini CLI allows them).
			for _, broken := range []string{"{ not json", "{\n  // my settings\n  \"theme\": \"dark\"\n}\n"} {
				path := filepath.Join(dir, "broken.json")
				_ = os.WriteFile(path, []byte(broken), 0o600)
				if err := a.connect(path, "/bin/agentguard", false); err == nil {
					t.Error("a settings file that isn't JSON must not be overwritten")
				}
				if b, _ := os.ReadFile(path); string(b) != broken {
					t.Errorf("the broken file was changed: %q", b)
				}
			}
		})
	}
}

// Connecting fail-closed puts --fail-closed on every hook command (and
// Cursor's own failClosed on its entries); connecting again fail-open
// takes both off.
func TestConnectAgentsFailClosed(t *testing.T) {
	for _, a := range agentIntegrations {
		t.Run(a.agentID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := a.connect(path, "/bin/agentguard", true); err != nil {
				t.Fatal(err)
			}
			text, _ := os.ReadFile(path)
			if n := strings.Count(string(text), "hook "+a.agentID+" --fail-closed"); n != len(a.lists) {
				t.Errorf("want %d fail-closed hooks, got %d:\n%s", len(a.lists), n, text)
			}
			if a.agentID == cursorAgentID && strings.Count(string(text), `"failClosed": true`) != len(a.lists) {
				t.Errorf("Cursor's entries should fail closed too:\n%s", text)
			}
			if connected, failClosed := hooksConnected(path, a.agentID, a.lists); !connected || !failClosed {
				t.Errorf("connected = %v, failClosed = %v; want both", connected, failClosed)
			}
			if err := a.connect(path, "/bin/agentguard", false); err != nil {
				t.Fatal(err)
			}
			text, _ = os.ReadFile(path)
			if strings.Contains(string(text), "--fail-closed") || strings.Contains(string(text), "failClosed") {
				t.Errorf("connecting fail-open left fail-closed behind:\n%s", text)
			}
		})
	}
}

// ── The policy blocks ───────────────────────────────────────────────────

// Each agent's block is the Claude Code block for its own agent id.
func TestPolicyBlocksMirrorTheClaudeCodeBlock(t *testing.T) {
	lf := func(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
	for _, c := range []struct {
		block      []byte
		name, id   string
		configFile string
	}{
		{configs.Cursor, "Cursor", cursorAgentID, "cursor.yaml"},
		{configs.GeminiCLI, "Gemini CLI", geminiAgentID, "gemini-cli.yaml"},
		{configs.Codex, "Codex CLI", codexAgentID, "codex.yaml"},
	} {
		want := strings.NewReplacer("Claude Code", c.name, "claude-code", c.id).Replace(lf(configs.ClaudeCode))
		if lf(c.block) != want {
			t.Errorf("configs/%s isn't configs/claude-code.yaml for agent %q", c.configFile, c.id)
		}
		path := filepath.Join(t.TempDir(), "p.yaml")
		_ = os.WriteFile(path, configs.Default, 0o644)
		// The starter policy has only the Claude Code block.
		if has, err := policyHasAgentRules(path, c.id); err != nil || has {
			t.Errorf("starter policy: has %s rules = %v, %v; want false", c.id, has, err)
		}
		// Added to the starter policy, next to the Claude Code block.
		if err := addAgentRules(path, c.id, c.name, c.block); err != nil {
			t.Fatalf("adding the %s rules to the starter policy: %v", c.name, err)
		}
		pol, err := policy.LoadFromFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := pol.Agents[c.id]; !ok {
			t.Errorf("no %s agent after the add", c.id)
		}
		if _, ok := pol.Agents[claudeAgentID]; !ok {
			t.Error("the Claude Code block was lost")
		}
	}
}

func TestAddAgentRulesToOlderPolicies(t *testing.T) {
	base := "version: \"1\"\nname: t\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n"
	for _, a := range agentIntegrations[1:] {
		for _, c := range []struct {
			name, policy string
			wantErr      bool
		}{
			{"no agents section", base, false},
			{"an agents section", base + "agents:\n  research-bot:\n    override:\n      - scope: network\n        allow:\n          - domain: \"arxiv.org\"\n", false},
			{"agents indented by 4", base + "agents:\n    research-bot:\n        override:\n            - scope: network\n              allow:\n                  - domain: \"arxiv.org\"\n", true},
		} {
			t.Run(a.agentID+"/"+c.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "p.yaml")
				_ = os.WriteFile(path, []byte(c.policy), 0o644)
				err := addAgentRules(path, a.agentID, a.name, a.block)
				if (err != nil) != c.wantErr {
					t.Fatalf("err = %v, want error %v", err, c.wantErr)
				}
				got, _ := os.ReadFile(path)
				if c.wantErr {
					if string(got) != c.policy || !strings.Contains(err.Error(), a.name) {
						t.Errorf("a failed add must leave the policy as it was and name the agent: %v", err)
					}
					return
				}
				if has, err := policyHasAgentRules(path, a.agentID); err != nil || !has {
					t.Errorf("has rules = %v, %v after the add", has, err)
				}
			})
		}
	}
}

// ── Setup ───────────────────────────────────────────────────────────────

// Connect each agent from the menu, failing closed: add its rules, write
// its hook; then uninstall removes every hook.
func TestSetupConnectsEveryAgentFailClosedAndUninstallDisconnects(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	ui := &scriptedUI{t: t, choices: []int{0, 0, 1}}
	svc := &fakeService{}
	s := &setup{m: m, ui: ui, svc: svc}
	s.doSetup()

	for _, a := range agentIntegrations[1:] {
		ui.out.Reset()
		ui.choices = []int{0, 1} // add the rules; server down: block the calls
		s.connectAgent(a)
		if has, _ := policyHasAgentRules(m.policyPath(), a.agentID); !has {
			t.Errorf("%s: the rules weren't added", a.name)
		}
		if connected, failClosed := a.connected(); !connected || !failClosed {
			t.Errorf("%s: connected = %v, failClosed = %v", a.name, connected, failClosed)
		}
		out := ui.out.String()
		if !strings.Contains(out, "dashboard") || !strings.Contains(out, "calls are blocked until it's back") {
			t.Errorf("%s: the notes should say where approvals happen and that calls are blocked:\n%s", a.name, out)
		}
		if a.agentID == codexAgentID && !strings.Contains(out, "/hooks") {
			t.Errorf("Codex: connecting should say to trust the hook under /hooks:\n%s", out)
		}
		var labels []string
		for _, it := range s.menu() {
			labels = append(labels, it.Label)
		}
		if !strings.Contains(strings.Join(labels, "|"), "Disconnect "+a.name) {
			t.Errorf("%s: the menu doesn't offer to disconnect it: %v", a.name, labels)
		}
	}
	ui.out.Reset()
	s.printStatus()
	if !strings.Contains(ui.out.String(), "Codex CLI is connected: its tool calls are checked (blocked while the server is down)") {
		t.Errorf("status doesn't show the fail-closed connection:\n%s", ui.out.String())
	}

	ui.choices = []int{1} // uninstall, keep my policy and data
	s.doUninstall()
	for _, a := range agentIntegrations {
		if connected, _ := a.connected(); connected {
			t.Errorf("uninstall left %s's hook pointing at a deleted program", a.name)
		}
	}
}

// With the server down, the note after connecting follows the chosen mode.
func TestSetupConnectNotesFollowTheFailMode(t *testing.T) {
	m := testMachine(t)
	serverUp(t)
	s := &setup{m: m, ui: &scriptedUI{t: t, choices: []int{0, 0, 1}}, svc: &fakeService{}}
	s.doSetup()
	serverHealth = func(int) string { return "" } // serverUp restores it
	for _, c := range []struct {
		choice int
		want   string
	}{
		{0, "Gemini CLI's calls go ahead with a warning"},
		{1, "Gemini CLI's calls are blocked"},
	} {
		ui := &scriptedUI{t: t, choices: []int{1, c.choice}} // connect without the rules
		s.ui = ui
		s.connectAgent(integration(t, geminiAgentID))
		if !strings.Contains(ui.out.String(), c.want) {
			t.Errorf("choice %d: want %q in:\n%s", c.choice, c.want, ui.out.String())
		}
	}
}

// Gemini CLI runs hooks with PowerShell on Windows, which needs & to run a
// quoted path.
func TestGeminiHookCommandOnWindows(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for _, c := range []struct{ goos, prefix string }{{"windows", `& "`}, {"linux", `"`}} {
		goos = c.goos
		path := filepath.Join(t.TempDir(), "settings.json")
		if err := connectGemini(path, `C:\Users\Jo Doe\agentguard.exe`, false); err != nil {
			t.Fatal(err)
		}
		root, _ := readJSONObject(path)
		entries, _ := listAt(root, geminiHookList)
		var e struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		}
		_ = json.Unmarshal(entries[0], &e)
		if got := e.Hooks[0].Command; !strings.HasPrefix(got, c.prefix) || !strings.HasSuffix(got, " hook gemini-cli") {
			t.Errorf("%s: command = %q, want it to start with %q", c.goos, got, c.prefix)
		}
		if connected, _ := hooksConnected(path, geminiAgentID, [][]string{geminiHookList}); !connected {
			t.Errorf("%s: not recognised as AgentGuard's hook", c.goos)
		}
	}
}
