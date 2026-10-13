package main

// claude_settings.go: connecting Claude Code — AgentGuard's PreToolUse
// entry in Claude Code's user settings (~/.claude/settings.json), and the
// Claude Code rules in the policy. agent_settings.go does the editing.

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Caua-ferraz/AgentGuard/configs"
)

// claudeHookList is where Claude Code keeps PreToolUse hooks.
var claudeHookList = []string{"hooks", "PreToolUse"}

// claudeConfigDir is Claude Code's user folder: $CLAUDE_CONFIG_DIR, else
// ~/.claude (on Windows too).
func claudeConfigDir() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude")
}

func claudeSettingsPath() string {
	if d := claudeConfigDir(); d != "" {
		return filepath.Join(d, "settings.json")
	}
	return ""
}

// claudeCodeDetected reports whether Claude Code looks installed: its user
// folder exists or `claude` is on PATH.
func claudeCodeDetected() bool {
	return dirOrCommand(claudeConfigDir(), "claude")
}

// dirOrCommand reports whether dir exists or one of commands is on PATH:
// how setup tells an agent is installed.
func dirOrCommand(dir string, commands ...string) bool {
	if dir != "" {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return true
		}
	}
	for _, c := range commands {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

// claudeConnected reports whether the settings file has AgentGuard's entry.
func claudeConnected(path string) bool {
	connected, _ := hooksConnected(path, claudeAgentID, [][]string{claudeHookList})
	return connected
}

// connectClaudeCode adds (or refreshes) AgentGuard's PreToolUse entry,
// failing open.
func connectClaudeCode(path, exe string) error {
	return connectClaudeCodeMode(path, exe, false)
}

// connectClaudeCodeMode adds (or refreshes) AgentGuard's PreToolUse entry;
// failClosed adds --fail-closed to the hook's command.
func connectClaudeCodeMode(path, exe string, failClosed bool) error {
	entry := struct {
		Matcher string `json:"matcher"`
		Hooks   []any  `json:"hooks"`
	}{
		Matcher: claudeHookMatcher,
		Hooks: []any{struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
		}{"command", hookCommand(exe, claudeAgentID, failClosed), claudeHookTimeout}},
	}
	return connectHooks(path, claudeAgentID, []hookList{{claudeHookList, entry}}, nil)
}

// disconnectClaudeCode removes AgentGuard's entry; it reports whether there
// was one.
func disconnectClaudeCode(path string) (bool, error) {
	return disconnectHooks(path, claudeAgentID, [][]string{claudeHookList})
}

// policyHasClaudeRules reports whether the policy has rules for agent
// "claude-code".
func policyHasClaudeRules(path string) (bool, error) {
	return policyHasAgentRules(path, claudeAgentID)
}

// addClaudeRules adds the Claude Code block (configs/claude-code.yaml) to
// the policy; see addAgentRules.
func addClaudeRules(path string) error {
	return addAgentRules(path, claudeAgentID, "Claude Code", configs.ClaudeCode)
}
