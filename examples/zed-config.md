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

1. **Install binaries** (Go 1.22+):

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
   agentguard serve --policy /etc/agentguard/policy.yaml --dashboard --watch --api-key "$AGENTGUARD_API_KEY"
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

v0.5 is single-tenant. Use `--tenant-id local` (the only value the
central server recognizes). Multi-tenant routing lands in v0.6 — until
then, `--tenant-id <anything-other-than-local>` returns 404 from
`/v1/check`, the gateway hits its `--fail-mode` path, and every action
denies (or is blanket-allowed, depending on your `--fail-mode`).

## Notes

- Zed also supports remote / HTTP context servers via a `url`+`headers`
  shape. The AgentGuard gateway is stdio-only in v0.5; remote transport
  is `TODO(v0.6, #mcp-streamable-http)`.
- Zed does not support an `${env:VAR}` interpolation syntax (unlike
  Cursor); the `env` block on a context-server entry is the only way to
  feed secrets to the subprocess. Don't paste raw keys — wire them in
  from your shell's environment via a small launcher script.
