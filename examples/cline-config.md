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

The example config starts three downstream MCP servers, each with its own
launcher:

| Upstream | Launcher | Install |
|---|---|---|
| `fs` — filesystem server | `npx` | [Node.js](https://nodejs.org/) 20+ |
| `fetch` — fetch server | `uvx` | [uv](https://docs.astral.sh/uv/getting-started/installation/) |
| `github` — [GitHub's MCP server](https://github.com/github/github-mcp-server) | `docker` | [Docker](https://docs.docker.com/get-started/get-docker/) |

Install the launchers for the upstreams you keep and delete the
`--upstream` entries you don't need. A missing launcher disables only
that namespace: the gateway logs
`info mcpgw: startup: upstream "fetch" failed to spawn: …` and serves the
others. The GitHub server reads `GITHUB_PERSONAL_ACCESS_TOKEN` from the
config's `env` block; the gateway passes its environment to every
upstream, and `docker run -e GITHUB_PERSONAL_ACCESS_TOKEN` forwards it
into the container.

1. **Install binaries** (Go 1.25+):

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
- "List recent issues from `<your repo>`" — gateway routes via `github:`;
  the default policy requires approval for every `github:*` call, so the
  tool returns an approval request and the dashboard lists it (see the
  [approval flow](../docs/MCP_GATEWAY.md#6-approval-flow)).
- "Read `/etc/passwd`" — DENY, dashboard shows the deny event.

## API key handling

Do **not** pass `--api-key "$AGENTGUARD_API_KEY"` as an `args` entry.
Cline (like Claude Desktop) does **not** shell-expand `$VAR`
references inside JSON `args` — the gateway would receive the literal
string `$AGENTGUARD_API_KEY` and authentication would fail. Instead,
use the `env` block above to inject the key as an environment
variable; the gateway picks up `AGENTGUARD_API_KEY` automatically
when the `--api-key` flag is absent.

## Tenant ID

`--tenant-id` picks the tenant whose policy evaluates the gateway's
calls (they go to `/v1/t/<tenant>/check`). Keep `local` — the policy
the server loads with `--policy` — unless you've registered another
tenant on the central server with
`agentguard tenant put <id> --policy <file.yaml>`. A tenant the server
doesn't know answers `404`, which the gateway
treats like an unreachable server: `--fail-mode` decides, so with `deny`
every call is refused.

## Notes

- If your VS Code window doesn't have the AgentGuard API key in its
  environment, the gateway still works (it falls back to whatever is in
  the JSON's `env` block). Don't paste raw keys — pull from a secret
  manager instead.
- Cline auto-approves tools in `alwaysAllow` at its own layer, but
  AgentGuard's policy still gates them. The two layers compose: Cline
  trusts the tool, AgentGuard verifies the call against the policy.
