package main

// hook_claude.go: `agentguard hook claude-code`, the command Claude Code
// runs before each tool call (a PreToolUse hook; see
// https://code.claude.com/docs/en/hooks). It turns the call into an
// AgentGuard check on the running server, as agent "claude-code", and
// answers Claude Code:
//
//   - ALLOW: nothing. Claude Code's own permission rules and prompts still
//     apply — AgentGuard only ever takes permissions away. (A hook "allow"
//     would skip Claude Code's prompt.)
//   - DENY: a "deny" decision with the reason, which Claude sees, and exit
//     code 2, which blocks whatever else happens.
//   - REQUIRE_APPROVAL: wait for an AgentGuard approval (dashboard,
//     `agentguard approve`, a notifier) for up to approvalWait, like the
//     SDKs' wait_for_approval, then deny. The settings entry setup writes
//     gives the hook a longer timeout, because Claude Code lets a call
//     through when a hook times out.
//   - No verdict (server not running, bad key): let the call through with a
//     warning the user sees (systemMessage). Claude Code keeps working.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/internal/localconfig"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const (
	claudeAgentID   = "claude-code"
	claudeTransport = "claude_code"
	// claudeHookMatcher is the tools the settings entry sends to the hook:
	// the ones that touch the machine. Anything else (subagents, to-do
	// lists, searches of the conversation) never reaches AgentGuard.
	claudeHookMatcher = "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*"
	// approvalWait is how long a call that needs approval waits for one.
	approvalWait = 5 * time.Minute
	// claudeHookTimeout (seconds) must stay above approvalWait: a hook that
	// times out lets the call through.
	claudeHookTimeout = 330
)

// hookConfig is where the hook finds the server and how it waits; tests
// shrink the waits.
type hookConfig struct {
	serverURL string
	apiKey    string
	wait      time.Duration
	poll      time.Duration
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

func hookUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: agentguard hook claude-code

The command Claude Code runs before each tool call, once 'agentguard setup'
has connected it (Connect Claude Code). It reads the call from stdin, checks
it on the running AgentGuard server as agent "claude-code", and answers:
nothing when the policy allows it (Claude Code's own permissions still
apply), a block with the reason when it denies it, and for calls that need
approval it waits up to 5 minutes for one (dashboard or 'agentguard
approve'). When the server can't be reached, the call goes ahead with a
warning.

You don't run it yourself. Claude Code passes the tool call as JSON:
https://code.claude.com/docs/en/hooks

Environment:
  AGENTGUARD_URL       The server; default: the one agentguard setup runs.
  AGENTGUARD_API_KEY   Its API key; default: the key agentguard setup saved.

Example (what Claude Code does):
  echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' |
    agentguard hook claude-code
`)
}

func runHookCmd(args []string) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	positional, code, ok := parseCommand(fs, hookUsage, args)
	if !ok {
		return code
	}
	switch {
	case len(positional) == 0:
		return usageError("hook", "missing the agent: agentguard hook claude-code")
	case positional[0] != "claude-code":
		return usageError("hook", "unknown agent %q (supported: claude-code)", positional[0])
	case len(positional) > 1:
		return usageError("hook", "unexpected argument %q", positional[1])
	}
	cfg := hookConfig{serverURL: hookServerURL(), apiKey: resolveClientAPIKey(""), wait: approvalWait, poll: 2 * time.Second}
	return claudeHook(os.Stdin, os.Stdout, os.Stderr, cfg)
}

// hookServerURL is AGENTGUARD_URL, else the server `agentguard setup`
// runs (its port is in setup.json), else the default.
func hookServerURL() string {
	if u := strings.TrimRight(os.Getenv("AGENTGUARD_URL"), "/"); u != "" {
		return u
	}
	if dir := localconfig.ConfigDir(goos); dir != "" {
		if st, err := loadState(machine{configDir: dir}); err == nil && st != nil {
			return baseURL(st.Port)
		}
	}
	return defaultServerURL
}

// claudeHook is the testable core: it reads one PreToolUse input and
// writes Claude Code's answer, returning the exit code.
func claudeHook(stdin io.Reader, stdout, stderr io.Writer, cfg hookConfig) int {
	var in claudeHookInput
	if err := json.NewDecoder(io.LimitReader(stdin, 16<<20)).Decode(&in); err != nil {
		return hookWarn(stdout, fmt.Sprintf("AgentGuard couldn't read this tool call (%v), so it wasn't checked.", err))
	}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return 0
	}
	req, ok := claudeRequest(in)
	if !ok {
		return 0 // not a tool AgentGuard checks
	}
	res, err := hookCheck(cfg, req)
	if err != nil {
		return hookWarn(stdout, fmt.Sprintf("AgentGuard didn't check this %s call: %v. Start the server with 'agentguard setup'.", in.ToolName, err))
	}
	switch res.Decision {
	case policy.Allow:
		return 0
	case policy.RequireApproval:
		final, err := hookWaitForApproval(cfg, req, res)
		if err != nil {
			return hookWarn(stdout, fmt.Sprintf("AgentGuard couldn't finish the approval for this %s call: %v. It wasn't checked.", in.ToolName, err))
		}
		if final.Decision == policy.Allow {
			return 0
		}
		return hookDeny(stdout, stderr, final.Reason)
	default: // DENY, or a decision this version doesn't know: block
		return hookDeny(stdout, stderr, denyText(res))
	}
}

// claudeRequest maps a Claude Code tool call to an AgentGuard request; ok
// is false for tools AgentGuard doesn't check.
func claudeRequest(in claudeHookInput) (policy.ActionRequest, bool) {
	str := func(key string) string {
		s, _ := in.ToolInput[key].(string)
		return s
	}
	// A relative path is relative to Claude Code's folder. "/x" and "\x"
	// are absolute everywhere here: Windows' own rule wants a drive letter.
	abs := func(p string) string {
		if p == "" || in.Cwd == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
			return p
		}
		return filepath.Join(in.Cwd, p)
	}
	req := policy.ActionRequest{
		AgentID:   claudeAgentID,
		SessionID: in.SessionID,
		Meta:      map[string]string{"transport": claudeTransport, "tool": in.ToolName},
	}
	if in.Cwd != "" {
		req.Meta["cwd"] = in.Cwd
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
		req.Scope, req.URL = "network", str("url")
		if u, err := url.Parse(req.URL); err == nil {
			req.Domain = u.Hostname()
		}
	default:
		// mcp__<server>__<tool>, the MCP gateway's "<server>:<tool>" form,
		// so the same mcp_tool rules apply.
		rest, found := strings.CutPrefix(in.ToolName, "mcp__")
		server, tool, split := strings.Cut(rest, "__")
		if !found || !split || server == "" || tool == "" {
			return req, false
		}
		req.Scope, req.Command = "mcp_tool", server+":"+tool
	}
	return req, true
}

// hookCheck POSTs req to /v1/check. An error means there's no verdict:
// the server can't be reached, refused the key, or answered garbage.
func hookCheck(cfg hookConfig, req policy.ActionRequest) (policy.CheckResult, error) {
	var res policy.CheckResult
	body, err := json.Marshal(req)
	if err != nil {
		return res, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, cfg.serverURL+"/v1/check", bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	attachAuth(httpReq, cfg.apiKey)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(httpReq)
	if err != nil {
		return res, fmt.Errorf("can't reach it at %s (%s)", cfg.serverURL, connectFailure(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return res, errors.New("the server rejected the API key")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil || res.Decision == "" {
		return res, fmt.Errorf("unreadable answer from %s (HTTP %d)", cfg.serverURL, resp.StatusCode)
	}
	return res, nil
}

// hookWaitForApproval polls /v1/status/<id> like the SDKs do until the
// approval is resolved or cfg.wait passes. An approved call is checked
// again with its approval_id, which consumes the one-shot approval and
// audits the run as allow:approved.
func hookWaitForApproval(cfg hookConfig, req policy.ActionRequest, first policy.CheckResult) (policy.CheckResult, error) {
	where := cfg.serverURL + "/dashboard"
	timedOut := policy.CheckResult{
		Decision: policy.Deny,
		Reason: fmt.Sprintf("AgentGuard: this needs approval (%s) and no one approved it within %s, so it was blocked. Approve it at %s or with 'agentguard approve %s', then ask Claude to try again.",
			first.Reason, cfg.wait, where, first.ApprovalID),
	}
	if first.ApprovalID == "" {
		return timedOut, nil
	}
	deadline := time.Now().Add(cfg.wait)
	client := &http.Client{Timeout: 10 * time.Second}
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(float64(cfg.poll) * (0.8 + 0.4*rand.Float64()))) // jittered, like the SDKs
		httpReq, err := http.NewRequest(http.MethodGet, cfg.serverURL+"/v1/status/"+url.PathEscape(first.ApprovalID), nil)
		if err != nil {
			return timedOut, err
		}
		attachAuth(httpReq, cfg.apiKey)
		resp, err := client.Do(httpReq)
		if err != nil {
			continue // a blip; keep waiting
		}
		var status struct {
			Status   string `json:"status"`
			Decision string `json:"decision"`
		}
		code := resp.StatusCode
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&status)
		resp.Body.Close()
		switch {
		case code == http.StatusUnauthorized || code == http.StatusForbidden:
			return timedOut, errors.New("the server rejected the API key")
		case code == http.StatusNotFound:
			return policy.CheckResult{Decision: policy.Deny, Reason: "AgentGuard: the approval request for this call is gone (was the server restarted?), so it was blocked. Ask Claude to try again."}, nil
		case status.Status != "resolved":
			continue
		case policy.Decision(status.Decision) == policy.Allow:
			req.ApprovalID = first.ApprovalID
			res, err := hookCheck(cfg, req)
			if err != nil {
				return timedOut, err
			}
			if res.Decision != policy.Allow {
				res.Reason = "AgentGuard: the approval was already used or has expired (" + res.Reason + "); ask Claude to try again."
				res.Decision = policy.Deny
			}
			return res, nil
		default:
			return policy.CheckResult{Decision: policy.Deny, Reason: "AgentGuard: a person denied this call in AgentGuard (" + first.Reason + ")."}, nil
		}
	}
	return timedOut, nil
}

func denyText(res policy.CheckResult) string {
	text := "AgentGuard blocked this: " + res.Reason
	if res.Rule != "" {
		text += " (rule " + res.Rule + ")"
	}
	return text
}

// hookDeny blocks the call: Claude sees the reason. Exit code 2 blocks it
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
