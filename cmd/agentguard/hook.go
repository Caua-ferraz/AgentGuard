package main

// hook.go: `agentguard hook <agent>`, the command a coding agent runs before
// each tool call. Each agent sends the call in its own JSON and wants its
// answer in its own JSON; a hookAgent adapter (hook_claude.go,
// hook_cursor.go, hook_gemini.go, hook_codex.go) translates both ways. What
// happens in between is the same for every agent:
//
//   - ALLOW: the agent's "go ahead", which for most agents is no answer at
//     all, so the agent's own permission rules and prompts still apply.
//   - DENY: the agent's "block", with the reason.
//   - REQUIRE_APPROVAL: wait for an AgentGuard approval (dashboard,
//     `agentguard approve`, a notifier) for up to approvalWait, like the
//     SDKs' wait_for_approval, then block. The settings entry setup writes
//     gives the hook a longer timeout than that, because the agents let a
//     call through when a hook times out.
//   - No verdict (server not running, bad key, input the hook can't read):
//     let the call through with a warning, or with --fail-closed, block it.
//
// One call can stand for several checks (a Codex patch that touches several
// files): each is checked, and the most severe verdict wins.

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

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
	"github.com/Caua-ferraz/AgentGuard/internal/localconfig"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const (
	// approvalWait is how long a call that needs approval waits for one.
	approvalWait = 5 * time.Minute
	// hookTimeoutSeconds is the timeout the settings entries give the hook,
	// in seconds (Gemini CLI counts milliseconds: see geminiHookTimeoutMs).
	// It must stay above approvalWait: a hook that times out lets the call
	// through.
	hookTimeoutSeconds = 330
	// failClosedRule is the rule a --fail-closed hook names when it blocks
	// a call it couldn't check.
	failClosedRule = "deny:hook:fail_closed"
)

// hookConfig is where the hook finds the server, how it waits, and what it
// does without a verdict; tests shrink the waits.
type hookConfig struct {
	serverURL  string
	apiKey     string
	wait       time.Duration
	poll       time.Duration
	failClosed bool
}

// hookAgent is one coding agent's side of the hook: how to read its input
// and how to write each answer. The answers return the exit code.
type hookAgent struct {
	name      string // the hook's argument: `agentguard hook <name>`
	agentID   string // the agent the checks are made as
	transport string // meta["transport"], the audit log's transport tag
	// who is how messages to the agent's user name it: "ask Claude to try
	// again".
	who string
	// parse reads the agent's input. checked is false for a call AgentGuard
	// doesn't look at (another tool or event), which is answered with allow.
	// An error means the input couldn't be read: no verdict.
	parse func(raw []byte) (call hookCall, checked bool, err error)
	allow func(stdout io.Writer, call hookCall) int
	deny  func(stdout, stderr io.Writer, call hookCall, reason string) int
	warn  func(stdout, stderr io.Writer, call hookCall, msg string) int
}

// hookCall is one tool call as the adapter read it.
type hookCall struct {
	event string // the agent's hook event, for agents whose answer differs by event
	tool  string // the tool's name, for messages
	reqs  []policy.ActionRequest
}

// hookAgents is every agent `agentguard hook` knows, in the order the help
// lists them.
var hookAgents = []hookAgent{claudeHookAgent, cursorHookAgent, geminiHookAgent, codexHookAgent}

func hookAgentNames() []string {
	names := make([]string, len(hookAgents))
	for i, a := range hookAgents {
		names[i] = a.name
	}
	return names
}

func hookUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: agentguard hook <agent> [flags]

The command a coding agent runs before each tool call, once 'agentguard
setup' has connected it. It reads the call from stdin, checks it on the
running AgentGuard server as that agent, and answers in the agent's own
format: go ahead when the policy allows it (the agent's own permissions
still apply), a block with the reason when it denies it, and for calls that
need approval it waits up to 5 minutes for one (dashboard or 'agentguard
approve'). When the server can't be reached, the call goes ahead with a
warning, unless --fail-closed is given.

Agents (each is also the agent the checks are made as):
  claude-code   Claude Code, a PreToolUse hook in ~/.claude/settings.json
  cursor        Cursor, hooks in ~/.cursor/hooks.json
  gemini-cli    Gemini CLI, a BeforeTool hook in ~/.gemini/settings.json
  codex         Codex CLI, a PreToolUse hook in ~/.codex/hooks.json

`)
	clihelp.WriteGroups(w, fs, []clihelp.Group{{Title: "When the server can't answer", Names: []string{"fail-closed"}}}, clihelp.Options{})
	fmt.Fprint(w, `
You don't run it yourself. The agent passes the tool call as JSON; the
formats are in docs/CODING_AGENTS.md.

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
	failClosed := fs.Bool("fail-closed", false, "Block calls AgentGuard can't check (server down, API key refused, unreadable input) instead of letting them through with a warning")
	positional, code, ok := parseCommand(fs, func(w io.Writer) { hookUsage(w, fs) }, args)
	if !ok {
		return code
	}
	supported := strings.Join(hookAgentNames(), ", ")
	if len(positional) == 0 {
		return usageError("hook", "missing the agent: agentguard hook <agent>, one of %s", supported)
	}
	var agent *hookAgent
	for i := range hookAgents {
		if hookAgents[i].name == positional[0] {
			agent = &hookAgents[i]
		}
	}
	switch {
	case agent == nil:
		return usageError("hook", "unknown agent %q (supported: %s)", positional[0], supported)
	case len(positional) > 1:
		return usageError("hook", "unexpected argument %q", positional[1])
	}
	cfg := hookConfig{serverURL: hookServerURL(), apiKey: resolveClientAPIKey(""), wait: approvalWait, poll: 2 * time.Second, failClosed: *failClosed}
	return runAgentHook(*agent, os.Stdin, os.Stdout, os.Stderr, cfg)
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

// runAgentHook is the testable core: it reads one tool call from stdin,
// checks it, and writes the agent's answer, returning the exit code.
func runAgentHook(a hookAgent, stdin io.Reader, stdout, stderr io.Writer, cfg hookConfig) int {
	// noVerdict answers a call that couldn't be checked: open is the
	// warning when it goes ahead, closed the reason when --fail-closed
	// blocks it.
	var call hookCall
	noVerdict := func(open, closed string) int {
		if cfg.failClosed {
			return a.deny(stdout, stderr, call, closed+" (rule "+failClosedRule+")")
		}
		return a.warn(stdout, stderr, call, open)
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, 16<<20))
	checked := false
	if err == nil {
		call, checked, err = a.parse(raw)
	}
	if err != nil {
		return noVerdict(
			fmt.Sprintf("AgentGuard couldn't read this tool call (%v), so it wasn't checked.", err),
			fmt.Sprintf("AgentGuard couldn't read this tool call (%v), so it was blocked.", err))
	}
	if !checked || len(call.reqs) == 0 {
		return a.allow(stdout, call)
	}

	results := make([]policy.CheckResult, len(call.reqs))
	for i, req := range call.reqs {
		res, err := hookCheck(cfg, req)
		if err != nil {
			return noVerdict(
				fmt.Sprintf("AgentGuard didn't check this %s call: %v. Start the server with 'agentguard setup'.", call.tool, err),
				fmt.Sprintf("AgentGuard blocked this %s call because it couldn't check it: %v. Start the server with 'agentguard setup', then ask %s to try again.", call.tool, err, a.who))
		}
		results[i] = res
	}
	// The most severe verdict wins: a deny (or a decision this version
	// doesn't know) blocks before anyone is asked to approve the rest.
	for _, res := range results {
		if res.Decision != policy.Allow && res.Decision != policy.RequireApproval {
			return a.deny(stdout, stderr, call, denyText(res))
		}
	}
	// Approvals share one wait, so several of them still answer within
	// the hook's timeout.
	deadline := time.Now().Add(cfg.wait)
	for i, res := range results {
		if res.Decision != policy.RequireApproval {
			continue
		}
		final, err := hookWaitForApproval(cfg, a.who, call.reqs[i], res, deadline)
		if err != nil {
			return noVerdict(
				fmt.Sprintf("AgentGuard couldn't finish the approval for this %s call: %v. It wasn't checked.", call.tool, err),
				fmt.Sprintf("AgentGuard blocked this %s call because it couldn't finish the approval: %v.", call.tool, err))
		}
		if final.Decision != policy.Allow {
			return a.deny(stdout, stderr, call, final.Reason)
		}
	}
	return a.allow(stdout, call)
}

// decodeHookInput reads the first JSON value of raw into v, as a decoder
// on stdin would: what follows it is ignored.
func decodeHookInput(raw []byte, v any) error {
	return json.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

// hookAbs makes a tool's path absolute against the agent's folder. "/x" and
// "\x" are absolute everywhere here: Windows' own rule wants a drive letter.
func hookAbs(cwd, p string) string {
	if p == "" || cwd == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return p
	}
	return filepath.Join(cwd, p)
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
// approval is resolved or the deadline passes. An approved call is checked
// again with its approval_id, which consumes the one-shot approval and
// audits the run as allow:approved. who names the agent in the messages
// ("ask Claude to try again").
func hookWaitForApproval(cfg hookConfig, who string, req policy.ActionRequest, first policy.CheckResult, deadline time.Time) (policy.CheckResult, error) {
	where := cfg.serverURL + "/dashboard"
	timedOut := policy.CheckResult{
		Decision: policy.Deny,
		Reason: fmt.Sprintf("AgentGuard: this needs approval (%s) and no one approved it within %s, so it was blocked. Approve it at %s or with 'agentguard approve %s', then ask %s to try again.",
			first.Reason, cfg.wait, where, first.ApprovalID, who),
	}
	if first.ApprovalID == "" {
		return timedOut, nil
	}
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
			return policy.CheckResult{Decision: policy.Deny, Reason: "AgentGuard: the approval request for this call is gone (was the server restarted?), so it was blocked. Ask " + who + " to try again."}, nil
		case status.Status != "resolved":
			continue
		case policy.Decision(status.Decision) == policy.Allow:
			req.ApprovalID = first.ApprovalID
			res, err := hookCheck(cfg, req)
			if err != nil {
				return timedOut, err
			}
			if res.Decision != policy.Allow {
				res.Reason = "AgentGuard: the approval was already used or has expired (" + res.Reason + "); ask " + who + " to try again."
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

// mcpToolRequest fills req for an MCP tool call in the MCP gateway's
// "<server>:<tool>" form, so the same mcp_tool rules apply to every agent.
func mcpToolRequest(req policy.ActionRequest, server, tool string) policy.ActionRequest {
	req.Scope, req.Command = "mcp_tool", server+":"+tool
	return req
}

// networkRequest fills req for a fetch of rawURL.
func networkRequest(req policy.ActionRequest, rawURL string) policy.ActionRequest {
	req.Scope, req.URL = "network", rawURL
	if u, err := url.Parse(rawURL); err == nil {
		req.Domain = u.Hostname()
	}
	return req
}

// hookMeta is the meta every agent's requests carry.
func hookMeta(transport, tool, cwd string) map[string]string {
	meta := map[string]string{"transport": transport, "tool": tool}
	if cwd != "" {
		meta["cwd"] = cwd
	}
	return meta
}
