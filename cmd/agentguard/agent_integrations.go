package main

// agent_integrations.go: the coding agents `agentguard setup` can connect,
// as one table the menu, the status lines and uninstall loop over. Each
// entry knows where the agent keeps its hooks, the entry AgentGuard adds
// there, and the agent's block of policy rules.

import (
	"os"
	"path/filepath"

	"github.com/Caua-ferraz/AgentGuard/configs"
)

type agentIntegration struct {
	name    string // "Claude Code", in menu items and messages
	short   string // the status row's label: "Claude"
	agentID string // the agent the checks are made as, and the hook's argument
	block   []byte // the agent's policy block, from configs/
	// checks says what the hook checks, after "New <name> sessions check".
	checks       string
	detected     func() bool
	settingsPath func() string
	// lists is where in the settings file AgentGuard's entries live.
	lists   [][]string
	connect func(path, exe string, failClosed bool) error
	// note, when set, is shown after connecting: a step the user still has
	// to take in the agent.
	note string
}

// agentIntegrations is every agent setup connects, in menu order.
var agentIntegrations = []agentIntegration{
	{
		name: "Claude Code", short: "Claude", agentID: claudeAgentID, block: configs.ClaudeCode,
		checks:       "Bash, file reads and edits, web fetches and MCP tools",
		detected:     claudeCodeDetected,
		settingsPath: claudeSettingsPath,
		lists:        [][]string{claudeHookList},
		connect:      connectClaudeCodeMode,
	},
	{
		name: "Cursor", short: "Cursor", agentID: cursorAgentID, block: configs.Cursor,
		checks:       "shell commands, file reads, file writes and MCP tools",
		detected:     func() bool { return dirOrCommand(cursorConfigDir(), "cursor", "cursor-agent") },
		settingsPath: cursorHooksPath,
		lists:        cursorHookLists(),
		connect:      connectCursor,
	},
	{
		name: "Gemini CLI", short: "Gemini", agentID: geminiAgentID, block: configs.GeminiCLI,
		checks:       "shell commands, file reads and writes, web fetches and MCP tools",
		detected:     func() bool { return dirOrCommand(geminiConfigDir(), "gemini") },
		settingsPath: geminiSettingsPath,
		lists:        [][]string{geminiHookList},
		connect:      connectGemini,
	},
	{
		name: "Codex CLI", short: "Codex", agentID: codexAgentID, block: configs.Codex,
		checks:       "shell commands, patches (each file they touch) and MCP tools",
		detected:     func() bool { return dirOrCommand(codexHome(), "codex") },
		settingsPath: codexHooksPath,
		lists:        [][]string{codexHookList},
		connect:      connectCodex,
		// https://learn.chatgpt.com/docs/hooks: "Codex requires you to review
		// and trust the exact hook definition", and skips it until then.
		note: "Codex runs a new or changed hook only after you trust it: type /hooks in Codex and trust AgentGuard's.",
	},
}

// connected reports whether the agent's settings have AgentGuard's hook,
// and whether it fails closed.
func (a agentIntegration) connected() (connected, failClosed bool) {
	return hooksConnected(a.settingsPath(), a.agentID, a.lists)
}

// disconnect removes AgentGuard's hook; it reports whether there was one.
func (a agentIntegration) disconnect() (bool, error) {
	return disconnectHooks(a.settingsPath(), a.agentID, a.lists)
}

// homeDir is the user's home folder joined with elem, or "" when it isn't
// known.
func homeDir(elem ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home}, elem...)...)
}

// inDir joins dir and name, or is "" when dir is unknown.
func inDir(dir, name string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, name)
}

// ── Cursor ──────────────────────────────────────────────────────────────

// cursorConfigDir is Cursor's user folder: $CURSOR_CONFIG_DIR (the Cursor
// CLI's override), else ~/.cursor, where Cursor reads the user hooks.json.
func cursorConfigDir() string {
	if d := os.Getenv("CURSOR_CONFIG_DIR"); d != "" {
		return d
	}
	return homeDir(".cursor")
}

func cursorHooksPath() string { return inDir(cursorConfigDir(), "hooks.json") }

func cursorHookLists() [][]string {
	var lists [][]string
	for _, e := range cursorHookEvents {
		lists = append(lists, []string{"hooks", e.event})
	}
	return lists
}

// connectCursor adds AgentGuard's entry to each event's list in
// hooks.json. Fail-closed also sets Cursor's own failClosed, so a crash or
// timeout of the hook blocks the call too.
func connectCursor(path, exe string, failClosed bool) error {
	type entry struct {
		Command    string `json:"command"`
		Timeout    int    `json:"timeout"`
		Matcher    string `json:"matcher,omitempty"`
		FailClosed bool   `json:"failClosed,omitempty"`
	}
	var lists []hookList
	for _, e := range cursorHookEvents {
		lists = append(lists, hookList{[]string{"hooks", e.event}, entry{hookCommand(exe, cursorAgentID, failClosed), hookTimeoutSeconds, e.matcher, failClosed}})
	}
	// hooks.json needs "version": 1.
	return connectHooks(path, cursorAgentID, lists, func(root *orderedObject) {
		if _, ok := root.vals["version"]; !ok {
			root.set("version", []byte("1"))
		}
	})
}

// ── Gemini CLI ──────────────────────────────────────────────────────────

var geminiHookList = []string{"hooks", "BeforeTool"}

// geminiConfigDir is Gemini CLI's user folder: $GEMINI_CLI_HOME/.gemini,
// else ~/.gemini.
func geminiConfigDir() string {
	if d := os.Getenv("GEMINI_CLI_HOME"); d != "" {
		return filepath.Join(d, ".gemini")
	}
	return homeDir(".gemini")
}

func geminiSettingsPath() string { return inDir(geminiConfigDir(), "settings.json") }

// connectGemini adds AgentGuard's BeforeTool entry to settings.json. A
// settings file with comments isn't JSON to setup, so it is left alone.
func connectGemini(path, exe string, failClosed bool) error {
	entry := struct {
		Matcher string `json:"matcher"`
		Hooks   []any  `json:"hooks"`
	}{
		Matcher: geminiHookMatcher,
		Hooks: []any{struct {
			Type        string `json:"type"`
			Command     string `json:"command"`
			Name        string `json:"name"`
			Timeout     int    `json:"timeout"`
			Description string `json:"description"`
		}{"command", hookCommand(exe, geminiAgentID, failClosed), "agentguard", geminiHookTimeoutMs, "Checks tool calls against your AgentGuard policy"}},
	}
	return connectHooks(path, geminiAgentID, []hookList{{geminiHookList, entry}}, nil)
}

// ── Codex CLI ───────────────────────────────────────────────────────────

var codexHookList = []string{"hooks", "PreToolUse"}

// codexHome is Codex's folder: $CODEX_HOME, else ~/.codex.
func codexHome() string {
	if d := os.Getenv("CODEX_HOME"); d != "" {
		return d
	}
	return homeDir(".codex")
}

// codexHooksPath is hooks.json, not config.toml: Codex reads both, and JSON
// can be edited without touching the rest of the user's configuration.
func codexHooksPath() string { return inDir(codexHome(), "hooks.json") }

func connectCodex(path, exe string, failClosed bool) error {
	entry := struct {
		Matcher string `json:"matcher"`
		Hooks   []any  `json:"hooks"`
	}{
		Matcher: codexHookMatcher,
		Hooks: []any{struct {
			Type          string `json:"type"`
			Command       string `json:"command"`
			Timeout       int    `json:"timeout"`
			StatusMessage string `json:"statusMessage"`
		}{"command", hookCommand(exe, codexAgentID, failClosed), hookTimeoutSeconds, "Checking with AgentGuard"}},
	}
	return connectHooks(path, codexAgentID, []hookList{{codexHookList, entry}}, nil)
}
