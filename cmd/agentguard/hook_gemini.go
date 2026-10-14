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
	"fmt"
	"io"
	"net/url"
	"strconv"
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
		targets, err := webFetchTargets(str("url"), str("prompt"))
		if err != nil {
			return nil, false, err
		}
		reqs := make([]policy.ActionRequest, len(targets))
		for i, t := range targets {
			reqs[i] = base
			reqs[i].Scope, reqs[i].URL, reqs[i].Domain = "network", t.url, t.host
		}
		return reqs, true, nil
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

// fetchTarget is one URL web_fetch would fetch and the host it would reach.
type fetchTarget struct{ url, host string }

// webFetchTargets lists what Gemini CLI's web_fetch would fetch: its url
// argument (the direct-fetch form of the tool), and every whitespace-
// separated word of its prompt that contains "://", which Gemini parses as a
// URL. The host is read the way Gemini's parser (WHATWG, in Node) reads it,
// not with a pattern of our own: a scheme in capitals or a userinfo such as
// "x(@" must not hide the host it really connects to. A web_fetch with no
// URL to check, or a URL whose host can't be read, is an error, so the call
// gets the hook's no-verdict answer instead of passing unchecked.
func webFetchTargets(urlArg, prompt string) ([]fetchTarget, error) {
	words := strings.Fields(prompt)
	if urlArg != "" {
		words = append([]string{urlArg}, words...)
	}
	var out []fetchTarget
	seen := map[string]bool{}
	for _, w := range words {
		i := strings.Index(w, "://")
		if i < 0 {
			continue
		}
		scheme := strings.ToLower(w[:i])
		if scheme != "http" && scheme != "https" {
			continue // Gemini fetches http(s) only
		}
		host := whatwgHost(w[i+3:])
		if host == "" {
			return nil, fmt.Errorf("web_fetch URL %q has no host the hook can read", w)
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, fetchTarget{url: w, host: host})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("web_fetch has no http(s) URL the hook can read")
	}
	return out, nil
}

// whatwgHost returns the host a WHATWG URL parser finds in what follows
// "http(s)://": leading slashes and backslashes are skipped, the authority
// ends at / \ ? or #, the host follows the last @, the port is dropped, and
// the host is percent-decoded, lowercased and, when it is an IPv4 address
// in any of the forms the parser accepts (0xa9fea9fe, 2852039166, 0251.0376.
// 0251.0376), written as a dotted quad.
func whatwgHost(rest string) string {
	rest = strings.TrimLeft(rest, `/\`)
	if i := strings.IndexAny(rest, `/\?#`); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	host := rest
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i >= 0 {
			return strings.ToLower(host[1:i])
		}
		return ""
	}
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	if dec, err := url.PathUnescape(host); err == nil {
		host = dec
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, ok := whatwgIPv4(host); ok {
		return ip
	}
	return host
}

// whatwgIPv4 parses host the way the WHATWG URL parser's IPv4 parser does:
// up to four dot-separated numbers, each decimal, 0x hex or 0-led octal, the
// last one filling the remaining bytes.
func whatwgIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 || host == "" {
		return "", false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		base := 10
		switch {
		case strings.HasPrefix(p, "0x"):
			p, base = p[2:], 16
		case len(p) > 1 && p[0] == '0':
			p, base = p[1:], 8
		}
		if p == "" {
			if base != 16 {
				return "", false
			}
			p = "0"
		}
		n, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return "", false
		}
		nums[i] = n
	}
	var v uint64
	for i, n := range nums[:len(nums)-1] {
		if n > 255 {
			return "", false
		}
		v |= n << (8 * (3 - i))
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return "", false
	}
	v |= last
	return fmt.Sprintf("%d.%d.%d.%d", v>>24&255, v>>16&255, v>>8&255, v&255), true
}
