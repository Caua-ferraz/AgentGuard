# Continue.dev — AgentGuard MCP Gateway

Drop-in MCP config that routes Continue's agent-mode tool calls through
the AgentGuard gateway.

> Source: <https://docs.continue.dev/customize/deep-dives/mcp> (verified
> 2026-05-05). Continue accepts either a YAML block file under
> `.continue/mcpServers/` (preferred) **or** an `mcpServers` block in the
> legacy `~/.continue/config.json`. Both shapes are documented below.
>
> The docs note: "MCP can only be used in **agent** mode" — slash-command
> and chat modes do not invoke tools.

## Option A — YAML block file (preferred, current docs)

Save the following to `<workspace>/.continue/mcpServers/agentguard.yaml`:

```yaml
name: AgentGuard MCP Gateway
version: 0.0.1
schema: v1
mcpServers:
  - name: agentguard
    type: stdio
    command: agentguard-mcp-gateway
    args:
      - "--upstream"
      - "fs:npx -y @modelcontextprotocol/server-filesystem /tmp"
      - "--upstream"
      - "fetch:uvx mcp-server-fetch"
      - "--upstream"
      - "github:docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server"
      - "--guard-url"
      - "http://127.0.0.1:8080"
      - "--policy"
      - "/etc/agentguard/policy.yaml"
      - "--tenant-id"
      - "local"
      - "--policy-mode"
      - "strict"
      - "--fail-mode"
      - "deny"
      - "--log-level"
      - "info"
    env:
      AGENTGUARD_API_KEY: set-from-shell-or-secret-store
      GITHUB_PERSONAL_ACCESS_TOKEN: set-from-shell-or-secret-store
```

> Don't add `--api-key "$AGENTGUARD_API_KEY"` to the `args` list —
> Continue does **not** shell-expand `$VAR` references in args. The
> gateway reads `AGENTGUARD_API_KEY` from its environment when the
> `--api-key` flag is absent, so the `env:` block above is sufficient.
> See "API key handling" below.

The file is auto-detected — no Continue restart needed for the YAML path
(restart the chat panel to be safe).

## Option B — JSON in `~/.continue/config.json`

If you're on a Continue release that still uses `config.json`, paste the
contents of `continue-config.json` into the top-level object (merge with
your existing `mcpServers` block if you have one).

| OS | Path |
|----|------|
| macOS / Linux | `~/.continue/config.json` |
| Windows | `%USERPROFILE%\.continue\config.json` |

## What this config does

```
Continue (agent mode) ──stdio──► agentguard-mcp-gateway ──► fs / fetch / github
                                       │
                                       └─HTTP──► http://127.0.0.1:8080/v1/check
                                                 (policy + audit + dashboard)
```

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

2. **Pick a policy** and update `--policy` (`configs/default.yaml` ships
   with this repo).

3. **Export the API key** in the shell that launches your editor:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

4. **Start the central AgentGuard server:**

   ```bash
   agentguard serve --policy /etc/agentguard/policy.yaml --dashboard --watch --api-key "$AGENTGUARD_API_KEY"
   ```

5. **Save the YAML / JSON.** Switch Continue into agent mode and try a
   tool-using prompt.

## Verification

In Continue's agent-mode chat:

- "Read `/tmp/notes.txt`" → ALLOW (default policy), dashboard shows event.
- "Fetch `https://example.com`" → REQUIRE_APPROVAL under the default
  policy (`fetch:*`). Even after approval it is denied, because
  `example.com` isn't on the default `network` allow-list — add it under
  `scope: network` to let it through (see the [approval flow](../docs/MCP_GATEWAY.md#6-approval-flow)).
- "Read `/etc/passwd`" → DENY, dashboard shows event.

## API key handling

Do **not** pass `--api-key "$AGENTGUARD_API_KEY"` as an `args` entry.
Continue does **not** shell-expand `$VAR` references inside JSON or
YAML `args` — the gateway would receive the literal string
`$AGENTGUARD_API_KEY` and authentication would fail. Instead, use the
`env` block above to inject the key as an environment variable; the
gateway picks up `AGENTGUARD_API_KEY` automatically when the
`--api-key` flag is absent.

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

- Continue's docs explicitly say JSON configs from Claude Desktop and
  Cursor can be dropped under `.continue/mcpServers/` — so
  `claude-desktop-config.json` from this directory works too.
- Agent mode is the only mode that invokes MCP tools. If you don't see
  tools in chat, switch the dropdown to **Agent**.
