# Zed — AgentGuard MCP Gateway

Drop-in config that routes Zed's Assistant tool calls through the
AgentGuard gateway. Zed names its MCP integration *context servers*; the
top-level config key is `context_servers`, not `mcpServers`.

> Source: <https://zed.dev/docs/ai/mcp.html> (verified 2026-05-05). Zed's
> MCP support is stable but the docs note ongoing schema iteration —
> verify the key name and the per-server fields against current docs at
> deploy time.

## Config file path

Zed stores MCP config in its main `settings.json`. Paths:

| OS | Path |
|----|------|
| macOS | `~/.config/zed/settings.json` |
| Linux | `~/.config/zed/settings.json` |
| Windows | `%APPDATA%\Zed\settings.json` |

Open it from inside Zed via the command palette: `zed: open settings`.

## Merging into your settings

`zed-config.json` in this directory is a complete file you can use
verbatim only if `settings.json` is empty. Otherwise, merge the
`context_servers` block into your existing settings:

```jsonc
{
  // ... your existing Zed settings ...

  "context_servers": {
    "agentguard": {
      "command": "agentguard-mcp-gateway",
      "args": [
        "--upstream", "fs:npx -y @modelcontextprotocol/server-filesystem /tmp",
        "--guard-url", "http://127.0.0.1:8080",
        "--policy", "/etc/agentguard/policy.yaml",
        "--tenant-id", "local",
        "--policy-mode", "strict"
      ],
      "env": {
        "AGENTGUARD_API_KEY": "set-from-shell-or-secret-store"
      }
    }
  }
}
```

## What this config does

```
Zed (Assistant) ──stdio──► agentguard-mcp-gateway ──► fs / fetch / github upstreams
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

2. **Pick a policy** and update `--policy`. `configs/default.yaml` ships
   with this repo.

3. **Export the API key** before launching Zed:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

   On macOS, Zed launched from Finder/Spotlight does not inherit your
   shell rc files. Either launch from a terminal (`zed .`) or set the
   variable as a launchd / GUI environment variable, then mirror it into
   the `env` block above.

4. **Start the central AgentGuard server:**

   ```bash
   agentguard server --policy /etc/agentguard/policy.yaml --dashboard --watch --api-key "$AGENTGUARD_API_KEY"
   ```

5. **Save settings.json.** Zed reloads it live; the Assistant should
   surface the merged tool list under the AgentGuard context server.

## Verification

In Zed's Assistant panel:

- Ask the model to read a file from `/tmp` → ALLOW (default policy).
- Ask it to read `/etc/passwd` → DENY, visible on the dashboard.
- Open <http://127.0.0.1:8080/dashboard> to see the live event feed.

## API key handling

Do **not** pass `--api-key "$AGENTGUARD_API_KEY"` as an `args` entry.
Zed does **not** shell-expand `$VAR` references inside JSON `args` —
the gateway would receive the literal string `$AGENTGUARD_API_KEY`
and authentication would fail. Instead, use the `env` block above to
inject the key as an environment variable; the gateway picks up
`AGENTGUARD_API_KEY` automatically when the `--api-key` flag is
absent.

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

- Zed also supports remote / HTTP context servers via a `url`+`headers`
  shape. The AgentGuard gateway is stdio-only; Streamable HTTP isn't
  implemented (see [`MCP_GATEWAY.md` § 10](../docs/MCP_GATEWAY.md#10-currently-out-of-scope)).
- Zed does not support an `${env:VAR}` interpolation syntax (unlike
  Cursor); the `env` block on a context-server entry is the only way to
  feed secrets to the subprocess. Don't paste raw keys — wire them in
  from your shell's environment via a small launcher script.
