package main

// hook_gemini.go: `agentguard hook gemini-cli`, the command Gemini CLI runs
// before each tool call (a BeforeTool hook,
// https://geminicli.com/docs/hooks/reference/; tool names and argument keys
// from https://geminicli.com/docs/reference/tools). Checks are made as agent
// "gemini-cli":
//
//   - run_shell_command {command}: shell.
//   - write_file, replace {file_path}: filesystem write.
//   - read_file {file_path}: filesystem read; read_many_files {include}: a
//     read for each entry (paths or globs).
//   - web_fetch {prompt}: network, once for each http(s) URL in the prompt
//     (the tool has no URL argument of its own).
//   - mcp_<server>_<tool>: mcp_tool "<server>:<tool>". A server name can
//     hold underscores, so the hook takes the server and tool from
//     mcp_context (server_name, tool_name) when Gemini CLI sends it.
//
// Answers: ALLOW is no output (exit 0 with nothing to parse lets the tool
// run, and Gemini CLI's own confirmations still apply); DENY is
// {"decision":"deny","reason":...}, which the agent sees as the tool's
// error; no verdict is {"systemMessage":...}, shown in the terminal.

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const (
	geminiAgentID   = "gemini-cli"
	geminiTransport = audit.TransportGeminiCLI
	// geminiHookMatcher is the tools the settings entry sends to the hook.
	// Gemini CLI matches it as a regular expression, so it is anchored.
	geminiHookMatcher = "^(run_shell_command|write_file|replace|read_file|read_many_files|web_fetch|mcp_.*)$"
	// geminiHookTimeoutMs: Gemini CLI counts hook timeouts in milliseconds.
	geminiHookTimeoutMs = hookTimeoutSeconds * 1000
)

var geminiHookAgent = hookAgent{
	name:      "gemini-cli",
	agentID:   geminiAgentID,
	transport: geminiTransport,
	who:       "Gemini",
	parse:     parseGeminiHook,
	allow:     func(io.Writer, hookCall) int { return 0 },
	deny: func(stdout, _ io.Writer, _ hookCall, reason string) int {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"decision": "deny", "reason": reason})
		return 0
	},
	warn: func(stdout, _ io.Writer, _ hookCall, msg string) int { return hookWarn(stdout, msg) },
}

// geminiHookInput is the part of Gemini CLI's BeforeTool input the hook
// uses.
type geminiHookInput struct {
	SessionID     string         `json:"session_id"`
	Cwd           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	MCPContext    *struct {
		ServerName string `json:"server_name"`
		ToolName   string `json:"tool_name"`
	} `json:"mcp_context"`
}

func parseGeminiHook(raw []byte) (hookCall, bool, error) {
	var in geminiHookInput
	if err := decodeHookInput(raw, &in); err != nil {
		return hookCall{}, false, err
	}
	call := hookCall{event: in.HookEventName, tool: in.ToolName}
	if in.HookEventName != "" && in.HookEventName != "BeforeTool" {
		return call, false, nil
	}
	reqs, ok, err := geminiRequests(in)
	if err != nil || !ok {
		return call, false, err
	}
	call.reqs = reqs
	return call, true, nil
}

// urlInText finds the http(s) URLs in web_fetch's prompt.
var urlInText = regexp.MustCompile(`https?://[^\s"'<>()\[\]{}]+`)

// geminiRequests maps a Gemini CLI tool call to AgentGuard requests; ok is
// false for tools AgentGuard doesn't check.
func geminiRequests(in geminiHookInput) ([]policy.ActionRequest, bool, error) {
	str := func(key string) string {
		s, _ := in.ToolInput[key].(string)
		return s
	}
	base := policy.ActionRequest{
		AgentID:   geminiAgentID,
		SessionID: in.SessionID,
		Meta:      hookMeta(geminiTransport, in.ToolName, in.Cwd),
	}
	file := func(action, p string) policy.ActionRequest {
		req := base
		req.Scope, req.Action, req.Path = "filesystem", action, hookAbs(in.Cwd, p)
		return req
	}
	switch in.ToolName {
	case "run_shell_command":
		req := base
		req.Scope, req.Command = "shell", str("command")
		return []policy.ActionRequest{req}, true, nil
	case "write_file", "replace":
		return []policy.ActionRequest{file("write", str("file_path"))}, true, nil
	case "read_file":
		return []policy.ActionRequest{file("read", str("file_path"))}, true, nil
	case "read_many_files":
		var reqs []policy.ActionRequest
		switch inc := in.ToolInput["include"].(type) {
		case string:
			reqs = append(reqs, file("read", inc))
		case []any:
			for _, p := range inc {
				if s, ok := p.(string); ok && s != "" {
					reqs = append(reqs, file("read", s))
				}
			}
		}
		if len(reqs) == 0 {
			return nil, false, errors.New("read_many_files has no include paths")
		}
		return reqs, true, nil
	case "web_fetch":
		var reqs []policy.ActionRequest
		seen := map[string]bool{}
		for _, u := range urlInText.FindAllString(str("prompt"), -1) {
			u = strings.TrimRight(u, ".,;:!?")
			if !seen[u] {
				seen[u] = true
				reqs = append(reqs, networkRequest(base, u))
			}
		}
		// No URL in the prompt: nothing for a network rule to judge.
		return reqs, len(reqs) > 0, nil
	}
	rest, found := strings.CutPrefix(in.ToolName, "mcp_")
	if !found {
		return nil, false, nil
	}
	server, tool, _ := strings.Cut(rest, "_")
	if c := in.MCPContext; c != nil && c.ServerName != "" && c.ToolName != "" {
		server, tool = c.ServerName, c.ToolName
	}
	if server == "" || tool == "" {
		return nil, false, nil
	}
	return []policy.ActionRequest{mcpToolRequest(base, server, tool)}, true, nil
}
