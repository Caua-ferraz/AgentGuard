# Claude Code

AgentGuard checks Claude Code's tool calls — shell commands, file reads and edits, web fetches, MCP tools — against your policy before they run. It does it with a Claude Code [hook](https://code.claude.com/docs/en/hooks): Claude Code runs `agentguard hook claude-code` before each of those calls, and the hook asks your running AgentGuard server.

## Connect it

```bash
agentguard setup
```

Choose **Connect Claude Code**. It adds one entry to Claude Code's user settings (`~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`), so every project is covered, and keeps the old file as `settings.json.agentguard-backup`. Everything else in the file stays as it was. New Claude Code sessions pick it up. **Disconnect Claude Code** in the same menu removes the entry, and uninstalling AgentGuard removes it too.

If your policy has no rules for Claude Code yet, setup offers to add them (see [The policy](#the-policy)).

## What gets checked

| Claude Code tool | Checked as |
|---|---|
| `Bash`, `PowerShell` | `shell`: the command |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `filesystem`, action `write`: the file |
| `Read` | `filesystem`, action `read`: the file |
| `WebFetch` | `network`: the URL's host |
| `mcp__<server>__<tool>` | `mcp_tool`: `<server>:<tool>`, the form the [MCP gateway](MCP_GATEWAY.md) uses, so the same rules apply |

Other tools (subagents, to-do lists, searching) aren't sent to AgentGuard. Every check is made as agent `claude-code`, with Claude Code's session id, and lands in the audit log and the dashboard with transport `claude_code`.

## What happens

| AgentGuard says | Claude Code |
|---|---|
| **ALLOW** | Carries on as if there were no hook. Claude Code's own permission rules and prompts still apply: AgentGuard only takes permissions away. |
| **DENY** | Blocks the call. Claude sees the reason, e.g. *AgentGuard blocked this: Keys and cloud credentials are off-limits to Claude Code (rule deny:filesystem:read)*. |
| **REQUIRE_APPROVAL** | Waits up to 5 minutes for someone to approve it — in the dashboard (`http://127.0.0.1:8080/dashboard`), with `agentguard approve <id>`, or through a notifier your policy sets up. Approved, the call runs and is audited as approved; denied or unanswered, it's blocked and Claude is told why. |
| *No answer* (server not running, wrong API key) | The call goes ahead, and a warning that it wasn't checked is added to the conversation. Start the server with `agentguard setup`. |

While a call waits for approval, Claude Code shows the hook running; nothing appears in its terminal, so keep the dashboard open or set up a notifier. The settings entry gives the hook 330 seconds, longer than the 5-minute wait: Claude Code lets a call through when a hook runs out of time, so the hook always answers first.

## The policy

Claude Code works on your real projects, so the starter policy's sandbox rules (files only under `./workspace`, a short list of commands) would block most of its work. The starter policy therefore ends with rules for agent `claude-code` that replace them for Claude Code only:

- **Files:** read and write anywhere, except keys and cloud credentials (`.ssh`, `.aws`, `.gnupg`: denied) and system folders (`/etc`, `/usr`, `C:/Windows`: no writes). `.env` files need approval.
- **Shell:** any command, except fork bombs and raw disk writes (denied); `sudo`, `rm -rf`, `git push --force`, `git reset --hard`, `git clean`, `curl … | sh` and `Remove-Item -Recurse` need approval. A chained command is checked piece by piece, so `git status && rm -rf /` needs approval too.
- **Web:** any site except cloud metadata endpoints.
- **MCP tools and the browser:** the policy's normal rules.

The block uses `override_mode: replace`, so the base deny and approval lists don't apply on top (they would put everyday commands like `python -m pytest` behind approval). It is plain policy YAML — edit it like any other rule; the server reloads the file when you save. The block is in [`configs/claude-code.yaml`](../configs/claude-code.yaml); per-agent rules are explained in [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#per-agent-overrides).

A policy written before this release has no such block. **Connect Claude Code** offers to add it, as text under your policy's `agents:` section (or a new one at the end), and keeps the old file as `.agentguard-backup`. If the result wouldn't load, or would change anything else in your policy — for example because your `agents:` entries are indented differently — the file is left alone and setup points here: copy the block from `configs/claude-code.yaml` under `agents:` yourself.

## Without setup

The entry setup writes, if you'd rather add it by hand (use the full path to `agentguard`):

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

The hook finds the server through `AGENTGUARD_URL`, else the one `agentguard setup` runs, else `http://localhost:8080`; and the API key through `AGENTGUARD_API_KEY`, else the key setup saved.

## Good to know

- **MCP tools are checked by name only**, like the gateway's `fast` mode: the policy sees `github:create_issue`, not its arguments.
- **`WebSearch` isn't checked**: it has a query, not a site.
- **The LLM API proxy** also knows Claude Code's tool names, if you route Claude Code through it with `ANTHROPIC_BASE_URL` instead: see [`LLM_API_PROXY.md`](LLM_API_PROXY.md). The hook is the simpler route: nothing sits between Claude Code and Anthropic.
