package main

// hook_codex.go: `agentguard hook codex`, the command Codex CLI runs before
// each tool call (a PreToolUse hook, https://learn.chatgpt.com/docs/hooks,
// which https://developers.openai.com/codex/hooks redirects to). Checks are
// made as agent "codex":
//
//   - Bash {command}: shell. Codex reports its unified exec tool as Bash too.
//   - apply_patch {command}: the patch text. Every file it adds, updates,
//     deletes or moves to ("*** Add File: <path>" and the like) is a
//     filesystem write; one patch can touch several files, and the most
//     severe verdict among them wins.
//   - mcp__<server>__<tool>: mcp_tool "<server>:<tool>".
//
// Codex reads the same answers as Claude Code: nothing to allow (Codex's own
// approvals still apply), a PreToolUse "deny" plus exit code 2 to block, and
// a systemMessage for a call that goes ahead unchecked.

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const (
	codexAgentID   = "codex"
	codexTransport = audit.TransportCodexCLI
	// codexHookMatcher is the tools the hooks.json entry sends to the hook.
	codexHookMatcher = "Bash|apply_patch|mcp__.*"
)

var codexHookAgent = hookAgent{
	name:      "codex",
	agentID:   codexAgentID,
	transport: codexTransport,
	who:       "Codex",
	parse:     parseCodexHook,
	allow:     func(io.Writer, hookCall) int { return 0 },
	deny: func(stdout, stderr io.Writer, _ hookCall, reason string) int {
		return hookDeny(stdout, stderr, reason)
	},
	warn: func(stdout, _ io.Writer, _ hookCall, msg string) int { return hookWarn(stdout, msg) },
}

// codexHookInput is the part of Codex's PreToolUse input the hook uses.
type codexHookInput struct {
	SessionID     string          `json:"session_id"`
	TurnID        string          `json:"turn_id"`
	Cwd           string          `json:"cwd"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

func parseCodexHook(raw []byte) (hookCall, bool, error) {
	var in codexHookInput
	if err := decodeHookInput(raw, &in); err != nil {
		return hookCall{}, false, err
	}
	call := hookCall{event: in.HookEventName, tool: in.ToolName}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return call, false, nil
	}
	reqs, ok, err := codexRequests(in)
	if err != nil || !ok {
		return call, false, err
	}
	call.reqs = reqs
	return call, true, nil
}

// codexRequests maps a Codex tool call to AgentGuard requests; ok is false
// for tools AgentGuard doesn't check.
func codexRequests(in codexHookInput) ([]policy.ActionRequest, bool, error) {
	base := policy.ActionRequest{
		AgentID:   codexAgentID,
		SessionID: in.SessionID,
		Meta:      hookMeta(codexTransport, in.ToolName, in.Cwd),
	}
	if in.TurnID != "" {
		base.Meta["turn_id"] = in.TurnID
	}
	switch in.ToolName {
	case "Bash":
		cmd, argv := codexCommand(in.ToolInput)
		// ["apply_patch", "<patch>"] is Codex's own patch call made through
		// the shell tool (Codex also accepts "applypatch"): its files get
		// the apply_patch checks, not a shell rule matched against the
		// patch text. Only the bare names count. Codex handles those
		// itself; a path such as ./apply_patch runs whatever program is
		// there, so it gets the shell check like any other command.
		if len(argv) == 2 && (argv[0] == "apply_patch" || argv[0] == "applypatch") {
			paths := patchPaths(argv[1])
			if len(paths) == 0 {
				return nil, false, errors.New("the patch names no files")
			}
			reqs := make([]policy.ActionRequest, len(paths))
			for i, p := range paths {
				reqs[i] = base
				reqs[i].Scope, reqs[i].Action, reqs[i].Path = "filesystem", "write", hookAbs(in.Cwd, p)
			}
			return reqs, true, nil
		}
		req := base
		req.Scope, req.Command = "shell", cmd
		reqs := []policy.ActionRequest{req}
		// A patch can also arrive through the shell ("apply_patch <<'EOF'
		// *** Begin Patch ..."): the files it writes get the same filesystem
		// checks as the apply_patch tool, not only the shell rule.
		if strings.Contains(cmd, "*** Begin Patch") {
			for _, p := range patchPaths(cmd) {
				w := base
				w.Scope, w.Action, w.Path = "filesystem", "write", hookAbs(in.Cwd, p)
				reqs = append(reqs, w)
			}
		}
		return reqs, true, nil
	case "apply_patch":
		patch, _ := codexCommand(in.ToolInput)
		paths := patchPaths(patch)
		if len(paths) == 0 {
			return nil, false, errors.New("the patch names no files")
		}
		reqs := make([]policy.ActionRequest, len(paths))
		for i, p := range paths {
			reqs[i] = base
			reqs[i].Scope, reqs[i].Action, reqs[i].Path = "filesystem", "write", hookAbs(in.Cwd, p)
		}
		return reqs, true, nil
	}
	rest, found := strings.CutPrefix(in.ToolName, "mcp__")
	server, tool, split := strings.Cut(rest, "__")
	if !found || !split || server == "" || tool == "" {
		return nil, false, nil
	}
	return []policy.ActionRequest{mcpToolRequest(base, server, tool)}, true, nil
}

// codexCommand is tool_input.command: a string, or an argument list. An
// argument list is also returned as the command line a shell would read back
// as those same arguments, each one quoted where needed, so the policy sees
// ["bash", "-lc", "rm -rf /"] as bash running "rm -rf /" and
// ["git", "commit", "-m", "a; b"] as one git command. Joined with plain
// spaces, the first read as a harmless bash call and the second as two
// commands.
func codexCommand(input json.RawMessage) (string, []string) {
	var in struct {
		Command any `json:"command"`
	}
	_ = json.Unmarshal(input, &in)
	switch c := in.Command.(type) {
	case string:
		return c, nil
	case []any:
		argv := make([]string, 0, len(c))
		quoted := make([]string, 0, len(c))
		for _, p := range c {
			if s, ok := p.(string); ok {
				argv = append(argv, s)
				quoted = append(quoted, shellQuote(s))
			}
		}
		return strings.Join(quoted, " "), argv
	}
	return "", nil
}

// shellQuote quotes one argument for a POSIX shell. Arguments made only of
// characters that are never special stay as they are, so ordinary commands
// still read naturally in the audit log and match plain rules.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for i := 0; i < len(s); i++ {
		if !shellSafeByte(s[i]) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// shellSafeByte reports whether c never needs quoting in a POSIX shell word.
func shellSafeByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("@%+=:,./_-", c) >= 0
}

// patchPaths lists the files an apply_patch patch writes, in order and
// without repeats: the targets of its Add, Update and Delete headers and
// the new name of a moved file.
func patchPaths(patch string) []string {
	var paths []string
	seen := map[string]bool{}
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if p, ok := strings.CutPrefix(line, prefix); ok {
				if p = strings.TrimSpace(p); p != "" && !seen[p] {
					seen[p] = true
					paths = append(paths, p)
				}
			}
		}
	}
	return paths
}
