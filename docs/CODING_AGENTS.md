# Coding agents

AgentGuard checks the tool calls of four coding agents — shell commands, file reads and edits, web fetches, MCP tools — against your policy before they run: **Claude Code**, **Cursor**, **Gemini CLI** and **Codex CLI**. It does it with each agent's own hooks: the agent runs `agentguard hook <agent>` before each of those calls, and the hook asks your running AgentGuard server.

| Agent | Hook | Settings file setup edits | Checked as agent | Audit transport |
|---|---|---|---|---|
| Claude Code | `agentguard hook claude-code` ([PreToolUse](https://code.claude.com/docs/en/hooks)) | `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`) | `claude-code` | `claude_code` |
| Cursor | `agentguard hook cursor` ([hooks](https://cursor.com/docs/hooks)) | `~/.cursor/hooks.json` (or `$CURSOR_CONFIG_DIR/hooks.json`) | `cursor` | `cursor` |
| Gemini CLI | `agentguard hook gemini-cli` ([BeforeTool](https://geminicli.com/docs/hooks/reference/)) | `~/.gemini/settings.json` (or `$GEMINI_CLI_HOME/.gemini/settings.json`) | `gemini-cli` | `gemini_cli` |
| Codex CLI | `agentguard hook codex` ([PreToolUse](https://learn.chatgpt.com/docs/hooks)) | `~/.codex/hooks.json` (or `$CODEX_HOME/hooks.json`) | `codex` | `codex_cli` |

Every check lands in the audit log and the dashboard with the agent's id, its session id and its transport.

## Connect an agent

```bash
agentguard setup
```

Choose **Connect Claude Code** (or Cursor, Gemini CLI, Codex CLI). The item shows when the agent looks installed: its settings folder exists or its command is on your `PATH`. Setup asks two things:

1. **If your policy has no rules for the agent**, whether to add them (see [The policy](#the-policy)).
2. **If AgentGuard isn't running**: let calls through with a warning (the default), or block them. See [Failing open or closed](#failing-open-or-closed).

It then adds AgentGuard's entry to the agent's user settings, so every project is covered, and keeps the old file as `<file>.agentguard-backup`. Everything else in the file stays as it was. New sessions of the agent pick it up. **Disconnect** in the same menu removes the entry, and uninstalling AgentGuard removes every agent's entry.

**Codex CLI** runs a new or changed hook only after you trust it: after connecting (or changing the failure mode), type `/hooks` in Codex and trust AgentGuard's hook. Until then Codex skips it and warns at startup.

## What happens

| AgentGuard says | The agent |
|---|---|
| **ALLOW** | Carries on. Claude Code, Gemini CLI and Codex get no answer at all, so their own permission rules and prompts still apply: AgentGuard only takes permissions away. Cursor needs an answer from every permission hook, so it gets `{"permission":"allow"}`; Cursor's docs don't say whether that skips Cursor's own approval prompts. |
| **DENY** | Blocks the call. The agent sees the reason, e.g. *AgentGuard blocked this: Keys and cloud credentials are off-limits to Claude Code (rule deny:filesystem:read)*. |
| **REQUIRE_APPROVAL** | Waits up to 5 minutes for someone to approve it — in the dashboard (`http://127.0.0.1:8080/dashboard`), with `agentguard approve <id>`, or through a notifier your policy sets up. Approved, the call runs and is audited as approved; denied or unanswered, it's blocked and the agent is told why. |
| *No answer* (server not running, wrong API key, input the hook can't read) | Fail-open (the default): the call goes ahead with a warning that it wasn't checked. Fail-closed: the call is blocked. |

While a call waits for approval, the agent shows the hook running; keep the dashboard open or set up a notifier. Setup gives the hook 330 seconds (330000 ms for Gemini CLI, which counts milliseconds), longer than the 5-minute wait: the agents let a call through when a hook runs out of time, so the hook always answers first.

When one call stands for several checks — a Codex patch that touches three files, a Gemini `read_many_files` — each is checked, and the most severe verdict wins: one denied file blocks the whole patch.

## Failing open or closed

By default a hook that can't get a verdict lets the call through with a warning, so the agent keeps working when the server is stopped. With `--fail-closed` on the hook's command — what setup writes when you choose **Block them** — such a call is blocked instead, with the reason and rule `deny:hook:fail_closed`:

```
AgentGuard blocked this Bash call because it couldn't check it: can't reach it at http://localhost:8080 (connection refused). Start the server with 'agentguard setup', then ask Claude to try again. (rule deny:hook:fail_closed)
```

That covers the server being down or slow to answer, a rejected API key, an approval that can't be finished, and input the hook can't read. For Cursor, setup also sets Cursor's own `failClosed: true`, so a hook that crashes or times out blocks the call too. The other agents let a call through when the hook itself crashes or times out, whatever the flag says.

Choose fail-closed when an unchecked call is worse than a stalled agent. To switch modes, connect the agent again and choose the other answer (and, for Codex, trust the changed hook under `/hooks`).

## What gets checked

### Claude Code

| Claude Code tool | Checked as |
|---|---|
| `Bash`, `PowerShell` | `shell`: the command |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `filesystem`, action `write`: the file |
| `Read` | `filesystem`, action `read`: the file |
| `WebFetch` | `network`: the URL's host |
| `mcp__<server>__<tool>` | `mcp_tool`: `<server>:<tool>`, the form the [MCP gateway](MCP_GATEWAY.md) uses, so the same rules apply |

Other tools (subagents, to-do lists, searching) aren't sent to AgentGuard.

### Cursor

Setup registers the hook for four Cursor events, because Cursor documents the input of each per-kind event but not `preToolUse`'s input for file tools:

| Cursor event | Checked as |
|---|---|
| `beforeShellExecution` | `shell`: the command |
| `beforeMCPExecution` | `mcp_tool`: `<server>:<tool>`, with the server's name from `mcp.json` |
| `beforeReadFile` | `filesystem`, action `read`: the file |
| `preToolUse`, matcher `Write` | `filesystem`, action `write`: `tool_input.file_path` |

Cursor's deletes through its `Delete` tool aren't checked (its input isn't documented); deletes through the shell are. Cursor has no hook before a web fetch.

### Gemini CLI

| Gemini CLI tool | Checked as |
|---|---|
| `run_shell_command` | `shell`: the command |
| `write_file`, `replace` | `filesystem`, action `write`: the file |
| `read_file` | `filesystem`, action `read`: the file |
| `read_many_files` | `filesystem`, action `read`: each `include` entry (a path or a glob) |
| `web_fetch` | `network`: each `http(s)` URL in the prompt (the tool has no URL argument) |
| `mcp_<server>_<tool>` | `mcp_tool`: `<server>:<tool>`, with the names from `mcp_context` when Gemini CLI sends it |

`google_web_search` and the other tools aren't sent to AgentGuard.

### Codex CLI

| Codex tool | Checked as |
|---|---|
| `Bash` (shell commands and unified exec) | `shell`: the command |
| `apply_patch` | `filesystem`, action `write`: every file the patch adds, updates, deletes or moves to |
| `mcp__<server>__<tool>` | `mcp_tool`: `<server>:<tool>` |

Hosted tools such as web search don't go through Codex's hooks.

## The policy

A coding agent works on your real projects, so the starter policy's sandbox rules (files only under `./workspace`, a short list of commands) would block most of its work. The starter policy therefore ends with rules for agent `claude-code` that replace them for Claude Code only, and setup offers the same rules for the other agents when you connect them:

- **Files:** read and write anywhere, except keys and cloud credentials (`.ssh`, `.aws`, `.gnupg`: denied) and system folders (`/etc`, `/usr`, `C:/Windows`: no writes). `.env` files need approval.
- **Shell:** any command, except fork bombs and raw disk writes (denied); `sudo`, `rm -rf`, `git push --force`, `git reset --hard`, `git clean`, `curl … | sh` and `Remove-Item -Recurse` need approval. A chained command is checked piece by piece, so `git status && rm -rf /` needs approval too.
- **Web:** any site except cloud metadata endpoints.
- **MCP tools and the browser:** the policy's normal rules.

Each block uses `override_mode: replace`, so the base deny and approval lists don't apply on top (they would put everyday commands like `python -m pytest` behind approval). It is plain policy YAML — edit it like any other rule; the server reloads the file when you save. The blocks are [`configs/claude-code.yaml`](../configs/claude-code.yaml), [`configs/cursor.yaml`](../configs/cursor.yaml), [`configs/gemini-cli.yaml`](../configs/gemini-cli.yaml) and [`configs/codex.yaml`](../configs/codex.yaml); per-agent rules are explained in [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#per-agent-overrides).

When a policy has no block for the agent you connect, setup offers to add it, as text under your policy's `agents:` section (or a new one at the end), and keeps the old file as `.agentguard-backup`. If the result wouldn't load, or would change anything else in your policy — for example because your `agents:` entries are indented differently — the file is left alone: copy the block from `configs/` under `agents:` yourself.

## Without setup

The entries setup writes, if you'd rather add them by hand. Use the full path to `agentguard`, and add ` --fail-closed` after the agent's name to fail closed.

Claude Code, in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*",
        "hooks": [
          { "type": "command", "command": "\"/home/you/.local/bin/agentguard\" hook claude-code", "timeout": 330 }
        ]
      }
    ]
  }
}
```

Cursor, in `~/.cursor/hooks.json` (with `"failClosed": true` on each entry to fail closed):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "\"/home/you/.local/bin/agentguard\" hook cursor", "timeout": 330 }],
    "beforeMCPExecution": [{ "command": "\"/home/you/.local/bin/agentguard\" hook cursor", "timeout": 330 }],
    "beforeReadFile": [{ "command": "\"/home/you/.local/bin/agentguard\" hook cursor", "timeout": 330 }],
    "preToolUse": [{ "command": "\"/home/you/.local/bin/agentguard\" hook cursor", "timeout": 330, "matcher": "Write" }]
  }
}
```

Gemini CLI, in `~/.gemini/settings.json` (the timeout is in milliseconds; on Windows, where Gemini CLI runs hooks with PowerShell, start the command with `& `):

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "^(run_shell_command|write_file|replace|read_file|read_many_files|web_fetch|mcp_.*)$",
        "hooks": [
          { "type": "command", "command": "\"/home/you/.local/bin/agentguard\" hook gemini-cli", "name": "agentguard", "timeout": 330000, "description": "Checks tool calls against your AgentGuard policy" }
        ]
      }
    ]
  }
}
```

Codex CLI, in `~/.codex/hooks.json` (then trust it under `/hooks`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          { "type": "command", "command": "\"/home/you/.local/bin/agentguard\" hook codex", "timeout": 330, "statusMessage": "Checking with AgentGuard" }
        ]
      }
    ]
  }
}
```

The hook finds the server through `AGENTGUARD_URL`, else the one `agentguard setup` runs, else `http://localhost:8080`; and the API key through `AGENTGUARD_API_KEY`, else the key setup saved.

## Good to know

- **MCP tools are checked by name only**, like the gateway's `fast` mode: the policy sees `github:create_issue`, not its arguments.
- **Web searches aren't checked**: they have a query, not a site.
- **Gemini CLI's settings may have comments**; setup only edits plain JSON. With comments in the file, setup leaves it alone and says so: add the entry by hand.
- **Hooks are a guardrail, not a sandbox.** Each agent decides which calls go through its hooks; Codex's docs say as much. A command the agent runs some other way isn't seen.
- **The LLM API proxy** also knows Claude Code's tool names, if you route Claude Code through it with `ANTHROPIC_BASE_URL` instead: see [`LLM_API_PROXY.md`](LLM_API_PROXY.md). The hooks are the simpler route: nothing sits between the agent and its model.
