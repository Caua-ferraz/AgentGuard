# Cursor — AgentGuard MCP Gateway

Drop-in `mcp.json` that routes Cursor's MCP tool calls through the
AgentGuard gateway, gating every call against your policy before forwarding
to the real downstream MCP server.

> Source: <https://cursor.com/docs/context/mcp> (verified 2026-05-05).
> Cursor's MCP support evolves quickly — verify the schema against current
> docs at deploy time. The `type: "stdio"` field is documented as required
> for stdio servers in current revisions.

## Config file path

Cursor supports two scopes:

| Scope | Path |
|----|------|
| Global (all projects) | `~/.cursor/mcp.json` |
| Project-specific | `<workspace>/.cursor/mcp.json` |

A project-level file overrides the global file for that workspace, so a
single `agentguard` server entry in `~/.cursor/mcp.json` is enough to gate
every Cursor session.

## What this config does

```
Cursor (Composer / agent mode)
    │ stdio (MCP)
    ▼
agentguard-mcp-gateway
    │
    ├─stdio──► server-filesystem (scoped to ${workspaceFolder})
    ├─stdio──► server-fetch
    ├─stdio──► server-github
    │
    └─HTTP──► http://127.0.0.1:8080/v1/check
              (central AgentGuard: policy + audit + dashboard)
```

`${workspaceFolder}` is a Cursor variable that expands to the open
project's root, so the filesystem upstream is automatically scoped to the
current workspace. `${env:VAR}` reads the variable from Cursor's launching
environment.

## Setup

1. **Install binaries** (Go 1.22+):

   ```bash
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest
   ```

2. **Drop a policy file in the project root:**

   ```bash
   mkdir -p .agentguard
   cp /path/to/AgentGuard/configs/default.yaml .agentguard/policy.yaml
   ```

   Adjust `--policy` in the JSON if you put the file elsewhere.

3. **Export the API key** in the shell that starts Cursor:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

   On macOS, set this in `~/.zshrc` so Cursor (launched from Spotlight or
   Finder) inherits it. On Windows, set it as a User Environment Variable.

4. **Run the central server** in a terminal:

   ```bash
   agentguard serve \
     --policy .agentguard/policy.yaml \
     --dashboard \
     --watch \
     --api-key "$AGENTGUARD_API_KEY"
   ```

5. **Save the config**, then **reload Cursor** (Cmd/Ctrl-Shift-P → "Reload
   Window"). The MCP server panel should show `agentguard` and its merged
   tools list.

## Verification

In Cursor's chat (Composer):

- "Read `package.json` from this workspace" → ALLOW (in default policy).
- "Read `/etc/passwd`" (or `C:\Windows\System32\drivers\etc\hosts` on
  Windows) → DENY, surfaced on the dashboard at
  <http://127.0.0.1:8080/dashboard>.

## API key handling

Do **not** pass `--api-key "$AGENTGUARD_API_KEY"` as an `args` entry.
Cursor's `${env:VAR}` interpolation has been unreliable across
versions, and JSON-level `$VAR` shell-expansion never happens. The
safe path is to set `AGENTGUARD_API_KEY` in the `env` block (or
inherited from Cursor's parent shell) and **omit** the `--api-key`
flag entirely — the gateway picks up the env var automatically when
the flag is absent.

## Tenant ID

v0.5 is single-tenant. Use `--tenant-id local` (the only value the
central server recognizes). Multi-tenant routing lands in v0.6 — until
then, `--tenant-id <anything-other-than-local>` (including templated
values like `cursor-${env:USER}`) returns 404 from `/v1/check`, the
gateway hits its `--fail-mode` path, and every action denies (or is
blanket-allowed, depending on your `--fail-mode`).

## Notes

- Cursor passes namespace-prefixed tool names through verbatim, so policies
  written against `fs:read_text_file` (or any other namespace) work without
  changes.
- If you have an existing top-level `mcpServers` block, add the
  `agentguard` entry inside it; Cursor merges entries by name.
- The `env` field on a server entry is forwarded to the gateway's parent
  process, which then forwards it to each spawned upstream — but
  `${env:VAR}` interpolation happens at Cursor's level, before the gateway
  sees the args.
