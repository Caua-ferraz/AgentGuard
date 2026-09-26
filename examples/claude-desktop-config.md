# Claude Desktop — AgentGuard MCP Gateway

Drop-in `claude_desktop_config.json` that routes Claude Desktop's MCP tool
calls through `agentguard-mcp-gateway`, which gates every tool call against
your AgentGuard policy before forwarding to the real downstream MCP server.

> Source: <https://modelcontextprotocol.io/quickstart/user> (verified
> 2026-05-05). The Claude Desktop config format is stable; verify against
> the current docs at deploy time.

## Config file path

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | not officially supported by Claude Desktop today |

The fastest way to open the file is the in-app **Settings → Developer → Edit
Config** button — Claude Desktop creates the file if it doesn't exist and
opens it in your default editor.

## What this config does

```
Claude Desktop ──stdio──► agentguard-mcp-gateway ──stdio──► server-filesystem (npx)
                                  │                       ──stdio──► mcp-server-fetch (uvx)
                                  │                       ──stdio──► github-mcp-server (docker)
                                  │
                                  └─HTTP──► http://127.0.0.1:8080/v1/check
                                            (the central AgentGuard server,
                                             which evaluates policy + writes
                                             the audit log + surfaces approvals
                                             on the dashboard)
```

The gateway namespaces tools per upstream — Claude sees `fs:read_text_file`,
`fetch:fetch`, `github:list_issues`, etc. The same names appear in the
audit log so every decision is unambiguous.

## Setup (5 steps)

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

1. **Install the binaries** (Go 1.25+):

   ```bash
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest
   ```

   Confirm both end up on `PATH`:

   ```bash
   which agentguard agentguard-mcp-gateway
   ```

   Claude Desktop spawns the gateway as a subprocess and inherits its `PATH`
   from the parent shell that launched the app — if `which` fails, replace
   `"command": "agentguard-mcp-gateway"` in the JSON with the absolute path
   to the binary.

2. **Pick a policy.** A starter is `configs/default.yaml` in this repo.
   Copy it somewhere stable:

   ```bash
   sudo mkdir -p /etc/agentguard
   sudo cp configs/default.yaml /etc/agentguard/policy.yaml
   ```

   Then update `--policy /etc/agentguard/policy.yaml` in the JSON to match.

3. **Generate an API key** and put it in the `env` block of the JSON
   (the gateway reads `AGENTGUARD_API_KEY` from the subprocess
   environment when the `--api-key` flag is absent — see "API key
   handling" below):

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

4. **Start the central AgentGuard server:**

   ```bash
   agentguard server \
     --policy /etc/agentguard/policy.yaml \
     --dashboard \
     --watch \
     --api-key "$AGENTGUARD_API_KEY"
   ```

   Open the dashboard at <http://127.0.0.1:8080/dashboard>.

5. **Save the JSON, then fully quit + restart Claude Desktop** (Cmd-Q, not
   just close the window). On restart you should see the MCP-server
   indicator in the chat input area.

## Verification

In a Claude Desktop chat:

- "Read `/tmp/hello.txt`" → AgentGuard's default policy allows reads under
  `/tmp`, the call succeeds, and the dashboard shows an `ALLOW` event.
- "Read `/etc/passwd`" → policy denies, Claude reports the tool returned an
  error, the dashboard shows a `DENY` event.
- "Fetch `https://api.github.com/zen`" → the default policy requires
  approval for `fetch:*`: the tool returns an approval request (ID + URL)
  and the dashboard lists it as pending. The call runs only when the
  client retries with that approval ID (see the [approval flow](../docs/MCP_GATEWAY.md#6-approval-flow)),
  and only for hosts on the policy's `network` allow-list —
  `api.github.com` is; most others are denied even after approval.

If actions appear in Claude but never show on the dashboard, see the
**Common gotchas** section in [`docs/MCP_GATEWAY.md`](../docs/MCP_GATEWAY.md#11-client-integration).

## API key handling

Do **not** pass `--api-key "$AGENTGUARD_API_KEY"` as an `args` entry.
Claude Desktop does **not** shell-expand `$VAR` references inside the
JSON `args` array — the gateway would receive the literal string
`$AGENTGUARD_API_KEY` and authentication would fail. Instead, use the
`env` block above to inject the key as an environment variable; the
gateway picks up `AGENTGUARD_API_KEY` automatically when the
`--api-key` flag is absent.

If you really must pass the key on the command line, write the literal
key into the `args` entry — but that bakes a secret into your config
file, so prefer the `env` block.

## Tenant ID

`--tenant-id` picks the tenant whose policy evaluates the gateway's
calls (they go to `/v1/t/<tenant>/check`). Keep `local` — the policy
the server loads with `--policy` — unless you've registered another
tenant on the central server with
`agentguard tenant put <id> --policy <file.yaml>`. A tenant the server
doesn't know answers `404`, which the gateway
treats like an unreachable server: `--fail-mode` decides, so with `deny`
every call is refused.

## Trimming the example

The bundled config wires `fs`, `fetch`, and `github` upstreams. Remove any
you don't need (each one is a subprocess the gateway starts with it) and
add others from <https://github.com/modelcontextprotocol/servers>.
