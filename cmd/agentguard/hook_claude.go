package main

// hook_claude.go: `agentguard hook claude-code`, the command Claude Code
// runs before each tool call (a PreToolUse hook; see
// https://code.claude.com/docs/en/hooks). It turns the call into an
// AgentGuard check on the running server, as agent "claude-code", and
// answers Claude Code (hook.go has the steps every agent shares):
//
//   - ALLOW: nothing. Claude Code's own permission rules and prompts still
//     apply — AgentGuard only ever takes permissions away. (A hook "allow"
//     would skip Claude Code's prompt.)
//   - DENY: a "deny" decision with the reason, which Claude sees, and exit
//     code 2, which blocks whatever else happens.
//   - No verdict: a warning the user sees (systemMessage), and the call goes
//     ahead; with --fail-closed, a deny.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const (
	claudeAgentID   = "claude-code"
	claudeTransport = audit.TransportClaudeCode
	// claudeHookMatcher is the tools the settings entry sends to the hook:
	// the ones that touch the machine. Anything else (subagents, to-do
	// lists, searches of the conversation) never reaches AgentGuard.
	claudeHookMatcher = "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*"
	// claudeHookTimeout (seconds) must stay above approvalWait: a hook that
	// times out lets the call through.
	claudeHookTimeout = hookTimeoutSeconds
)

var claudeHookAgent = hookAgent{
	name:      "claude-code",
	agentID:   claudeAgentID,
	transport: claudeTransport,
	who:       "Claude",
	parse:     parseClaudeHook,
	allow:     func(io.Writer, hookCall) int { return 0 },
	deny: func(stdout, stderr io.Writer, _ hookCall, reason string) int {
		return hookDeny(stdout, stderr, reason)
	},
	warn: func(stdout, _ io.Writer, _ hookCall, msg string) int { return hookWarn(stdout, msg) },
}

// claudeHookInput is the part of Claude Code's PreToolUse input the hook
// uses.
type claudeHookInput struct {
	SessionID     string         `json:"session_id"`
	Cwd           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	AgentType     string         `json:"agent_type"` // set inside a subagent
}

// claudeHook reads one PreToolUse input and writes Claude Code's answer,
// returning the exit code.
func claudeHook(stdin io.Reader, stdout, stderr io.Writer, cfg hookConfig) int {
	return runAgentHook(claudeHookAgent, stdin, stdout, stderr, cfg)
}

func parseClaudeHook(raw []byte) (hookCall, bool, error) {
	var in claudeHookInput
	if err := decodeHookInput(raw, &in); err != nil {
		return hookCall{}, false, err
	}
	call := hookCall{event: in.HookEventName, tool: in.ToolName}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return call, false, nil
	}
	req, ok := claudeRequest(in)
	if !ok {
		return call, false, nil // not a tool AgentGuard checks
	}
	call.reqs = []policy.ActionRequest{req}
	return call, true, nil
}

// claudeRequest maps a Claude Code tool call to an AgentGuard request; ok
// is false for tools AgentGuard doesn't check.
func claudeRequest(in claudeHookInput) (policy.ActionRequest, bool) {
	str := func(key string) string {
		s, _ := in.ToolInput[key].(string)
		return s
	}
	// A relative path is relative to Claude Code's folder.
	abs := func(p string) string { return hookAbs(in.Cwd, p) }
	req := policy.ActionRequest{
		AgentID:   claudeAgentID,
		SessionID: in.SessionID,
		Meta:      hookMeta(claudeTransport, in.ToolName, in.Cwd),
	}
	if in.AgentType != "" {
		req.Meta["subagent"] = in.AgentType
	}
	switch in.ToolName {
	case "Bash", "PowerShell":
		req.Scope, req.Command = "shell", str("command")
	case "Write", "Edit", "MultiEdit":
		req.Scope, req.Action, req.Path = "filesystem", "write", abs(str("file_path"))
	case "NotebookEdit":
		req.Scope, req.Action, req.Path = "filesystem", "write", abs(str("notebook_path"))
	case "Read":
		req.Scope, req.Action, req.Path = "filesystem", "read", abs(str("file_path"))
	case "WebFetch":
		req = networkRequest(req, str("url"))
	default:
		// mcp__<server>__<tool>, the MCP gateway's "<server>:<tool>" form,
		// so the same mcp_tool rules apply.
		rest, found := strings.CutPrefix(in.ToolName, "mcp__")
		server, tool, split := strings.Cut(rest, "__")
		if !found || !split || server == "" || tool == "" {
			return req, false
		}
		req = mcpToolRequest(req, server, tool)
	}
	return req, true
}

// hookDeny blocks the call with a PreToolUse "deny" (Claude Code and Codex
// read the same shape): the agent sees the reason. Exit code 2 blocks it
// even if the JSON were misread.
func hookDeny(stdout, stderr io.Writer, reason string) int {
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": reason,
	}}
	_ = json.NewEncoder(stdout).Encode(out)
	fmt.Fprintln(stderr, reason)
	return 2
}

// hookWarn lets the call through and shows the user why it wasn't checked.
func hookWarn(stdout io.Writer, msg string) int {
	_ = json.NewEncoder(stdout).Encode(map[string]any{"systemMessage": msg})
	return 0
}
