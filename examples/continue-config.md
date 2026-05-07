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
      - "fetch:npx -y @modelcontextprotocol/server-fetch"
      - "--upstream"
      - "github:npx -y @modelcontextprotocol/server-github"
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

1. **Install binaries** (Go 1.22+):

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
- "Fetch `https://example.com`" → ALLOW or REQUIRE_APPROVAL depending on
  the `network` rules in your policy.
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

v0.5 is single-tenant. Use `--tenant-id local` (the only value the
central server recognizes). Multi-tenant routing lands in v0.6 — until
then, `--tenant-id <anything-other-than-local>` returns 404 from
`/v1/check`, the gateway hits its `--fail-mode` path, and every action
denies (or is blanket-allowed, depending on your `--fail-mode`).

## Notes

- Continue's docs explicitly say JSON configs from Claude Desktop and
  Cursor can be dropped under `.continue/mcpServers/` — so
  `claude-desktop-config.json` from this directory works too.
- Agent mode is the only mode that invokes MCP tools. If you don't see
  tools in chat, switch the dropdown to **Agent**.
