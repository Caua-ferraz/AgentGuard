package main

// hook_cursor.go: `agentguard hook cursor`, the command Cursor runs before
// the agent's tool calls (Cursor hooks, https://cursor.com/docs/hooks).
// Checks are made as agent "cursor". Setup registers it for four events:
//
//   - beforeShellExecution {command, cwd}: shell.
//   - beforeMCPExecution {tool_name, tool_input, mcp_server_name}: mcp_tool
//     "<server>:<tool>", the MCP gateway's form.
//   - beforeReadFile {file_path}: filesystem read.
//   - preToolUse with matcher "Write" {tool_name, tool_input}: filesystem
//     write. The docs only show preToolUse's tool_input for Shell, which is
//     why the documented per-kind events above carry everything else; for
//     Write the hook reads tool_input.file_path (falling back to "path"),
//     and a Write without one counts as input it couldn't read.
//
// Cursor's answers differ from Claude Code's: every permission event wants
// JSON on stdout, and "invalid JSON or a response that doesn't match the
// hook's schema blocks the action" — so ALLOW is an explicit
// {"permission":"allow"}, not silence (no output is a hook failure, which
// failClosed turns into a block). Cursor's docs don't say whether a hook's
// allow skips Cursor's own approval prompts. DENY is {"permission":"deny"}
// with the reason as user_message and agent_message (beforeReadFile's
// schema has no agent_message), exit 0 so Cursor reads the messages.

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const (
	cursorAgentID   = "cursor"
	cursorTransport = audit.TransportCursor
)

// cursorHookEvents are the hooks.json entries setup writes, with their
// matchers ("" for none).
var cursorHookEvents = []struct{ event, matcher string }{
	{"beforeShellExecution", ""},
	{"beforeMCPExecution", ""},
	{"beforeReadFile", ""},
	{"preToolUse", "Write"},
}

var cursorHookAgent = hookAgent{
	name:      "cursor",
	agentID:   cursorAgentID,
	transport: cursorTransport,
	who:       "Cursor",
	parse:     parseCursorHook,
	allow: func(stdout io.Writer, _ hookCall) int {
		return cursorAnswer(stdout, map[string]any{"permission": "allow"})
	},
	deny: func(stdout, _ io.Writer, call hookCall, reason string) int {
		out := map[string]any{"permission": "deny", "user_message": reason}
		if call.event != "beforeReadFile" && call.event != "" {
			out["agent_message"] = reason
		}
		return cursorAnswer(stdout, out)
	},
	// Cursor has no warning field for a call that goes ahead; user_message
	// is in every permission event's schema, so it is the best place.
	warn: func(stdout, _ io.Writer, _ hookCall, msg string) int {
		return cursorAnswer(stdout, map[string]any{"permission": "allow", "user_message": msg})
	},
}

func cursorAnswer(stdout io.Writer, out map[string]any) int {
	_ = json.NewEncoder(stdout).Encode(out)
	return 0
}

// cursorHookInput is the part of Cursor's hook input the hook uses, for
// all four events.
type cursorHookInput struct {
	HookEventName  string   `json:"hook_event_name"`
	ConversationID string   `json:"conversation_id"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Cwd            string   `json:"cwd"`
	// Command is the shell command of beforeShellExecution (and, for a
	// stdio MCP server, its launch command in beforeMCPExecution).
	Command  string `json:"command"`
	ToolName string `json:"tool_name"`
	// ToolInput is an object in preToolUse and a JSON string in
	// beforeMCPExecution.
	ToolInput     json.RawMessage `json:"tool_input"`
	MCPServerName string          `json:"mcp_server_name"`
	FilePath      string          `json:"file_path"`
}

func parseCursorHook(raw []byte) (hookCall, bool, error) {
	var in cursorHookInput
	if err := decodeHookInput(raw, &in); err != nil {
		return hookCall{}, false, err
	}
	call := hookCall{event: in.HookEventName}
	req, tool, ok, err := cursorRequest(in)
	call.tool = tool
	if err != nil || !ok {
		return call, false, err
	}
	call.reqs = []policy.ActionRequest{req}
	return call, true, nil
}

// cursorRequest maps one Cursor hook event to an AgentGuard request; ok is
// false for an event or tool AgentGuard doesn't check. tool names the call
// in messages.
func cursorRequest(in cursorHookInput) (req policy.ActionRequest, tool string, ok bool, err error) {
	// Relative paths are relative to the agent's folder: cwd when Cursor
	// sends one, else the first workspace root.
	cwd := in.Cwd
	if cwd == "" && len(in.WorkspaceRoots) > 0 {
		cwd = in.WorkspaceRoots[0]
	}
	switch in.HookEventName {
	case "beforeShellExecution":
		tool = "Shell"
	case "beforeMCPExecution":
		tool = "MCP:" + in.ToolName
	case "beforeReadFile":
		tool = "Read"
	case "preToolUse":
		tool = in.ToolName
	default:
		return req, in.HookEventName, false, nil
	}
	req = policy.ActionRequest{
		AgentID:   cursorAgentID,
		SessionID: in.ConversationID,
		Meta:      hookMeta(cursorTransport, tool, cwd),
	}
	switch in.HookEventName {
	case "beforeShellExecution":
		req.Scope, req.Command = "shell", in.Command
	case "beforeMCPExecution":
		if in.ToolName == "" {
			return req, tool, false, errors.New("the MCP call has no tool name")
		}
		if in.MCPServerName == "" {
			// No server to name: the policy sees the bare tool name, which
			// only a rule for any server matches.
			req.Scope, req.Command = "mcp_tool", in.ToolName
		} else {
			req = mcpToolRequest(req, in.MCPServerName, in.ToolName)
		}
	case "beforeReadFile":
		if in.FilePath == "" {
			return req, tool, false, errors.New("the read has no file_path")
		}
		req.Scope, req.Action, req.Path = "filesystem", "read", hookAbs(cwd, in.FilePath)
	case "preToolUse":
		if in.ToolName != "Write" {
			return req, tool, false, nil
		}
		var input struct {
			FilePath string `json:"file_path"`
			Path     string `json:"path"`
		}
		_ = json.Unmarshal(in.ToolInput, &input)
		p := input.FilePath
		if p == "" {
			p = input.Path
		}
		if p == "" {
			return req, tool, false, errors.New("the Write call has no file_path")
		}
		req.Scope, req.Action, req.Path = "filesystem", "write", hookAbs(cwd, p)
	}
	return req, tool, true, nil
}
