# Cline — AgentGuard MCP Gateway

Drop-in `cline_mcp_settings.json` that routes Cline's MCP tool calls
through the AgentGuard gateway. Cline (formerly Claude Dev) is a VS Code
extension that exposes an autonomous agent in the editor; this config
gates every tool call against your policy.

> Source: <https://docs.cline.bot/mcp/configuring-mcp-servers> (verified
> 2026-05-05). Cline's schema mirrors Claude Desktop's `mcpServers` shape
> and adds `disabled` and `alwaysAllow` keys per entry.

## Config file path

Cline stores its MCP config inside VS Code's extension `globalStorage`
directory. The fastest way to open the file is from inside VS Code:

1. Open the Cline panel.
2. Click the **MCP Servers** tab.
3. Click **Configure MCP Servers** — VS Code opens
   `cline_mcp_settings.json` in an editor tab.

Concrete paths (subject to change between Cline releases — verify with the
Configure-MCP-Servers button):

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Windows | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |
| Linux | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |

The extension publisher slug (`saoudrizwan.claude-dev`) may have changed if
you installed Cline under a different publisher; in that case use the
**Configure MCP Servers** button to find the actual path. Cursor / Codium
forks of VS Code use a different parent directory (e.g.
`~/.config/Cursor/User/...`).

## What this config does

```
VS Code (Cline panel) ──stdio──► agentguard-mcp-gateway ──► fs / fetch / github upstreams
                                          │
                                          └─HTTP──► http://127.0.0.1:8080/v1/check
                                                    (policy / audit / dashboard)
```

The Cline-specific keys:

- `disabled: false` — leave the server enabled. Set `true` to skip without
  removing the entry.
- `alwaysAllow: []` — names of tools Cline will auto-approve in its own UI.
  Leave empty so Cline's per-action prompts still fire **and** AgentGuard's
  policy is the authoritative gate. Adding tool names here only suppresses
  Cline's prompt; it does **not** bypass the AgentGuard policy.

## Setup

1. **Install binaries** (Go 1.22+):

   ```bash
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest
   ```

2. **Pick a policy file** and update `--policy` in the JSON. `configs/default.yaml`
   from this repo is a sensible starting point.

3. **Export the API key** in the shell that launches VS Code:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

   On macOS, VS Code launched from Finder/Spotlight does not see your
   `~/.zshrc` exports. Either launch VS Code from a terminal (`code .`) or
   put `AGENTGUARD_API_KEY` in your VS Code `terminal.integrated.env.*`
   settings, then mirror it into the `env` block of the config above.

4. **Start the central AgentGuard server:**

   ```bash
   agentguard serve \
     --policy /etc/agentguard/policy.yaml \
     --dashboard \
     --watch \
     --api-key "$AGENTGUARD_API_KEY"
   ```

5. **Save the JSON.** Cline picks up MCP-config changes immediately — the
   server panel shows `agentguard` once the file parses cleanly.

## Verification

Open the Cline chat in VS Code and ask:

- "Read `/tmp/test.txt`" — Cline calls `fs:read_text_file` through the
  gateway, AgentGuard's default policy ALLOWs it, dashboard shows the
  event.
- "List recent issues from `<your repo>`" — gateway routes via `github:`,
  AgentGuard either ALLOWs or surfaces an approval depending on policy.
- "Read `/etc/passwd`" — DENY, dashboard shows the deny event.

## Notes

- If your VS Code window doesn't have the AgentGuard API key in its
  environment, the gateway still works (it falls back to whatever is in
  the JSON's `env` block). Don't paste raw keys — pull from a secret
  manager instead.
- Cline auto-approves tools in `alwaysAllow` at its own layer, but
  AgentGuard's policy still gates them. The two layers compose: Cline
  trusts the tool, AgentGuard verifies the call against the policy.
