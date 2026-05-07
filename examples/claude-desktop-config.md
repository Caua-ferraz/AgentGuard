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
Claude Desktop ──stdio──► agentguard-mcp-gateway ──stdio──► server-filesystem
                                  │                       ──stdio──► server-fetch
                                  │                       ──stdio──► server-github
                                  │
                                  └─HTTP──► http://127.0.0.1:8080/v1/check
                                            (the central AgentGuard server,
                                             which evaluates policy + writes
                                             the audit log + surfaces approvals
                                             on the dashboard)
```

The gateway namespaces tools per upstream — Claude sees `fs:read_text_file`,
`fetch:fetch`, `github:create_issue`, etc. The same names appear in the
audit log so every decision is unambiguous.

## Setup (5 steps)

1. **Install the binaries** (Go 1.22+):

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

3. **Generate an API key** and export it in the shell that launches Claude
   Desktop:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

   Put the same value in the `env` block of the JSON. The flag value
   `"$AGENTGUARD_API_KEY"` resolves from this `env` block — Claude Desktop
   does **not** expand shell variables in flag strings.

4. **Start the central AgentGuard server:**

   ```bash
   agentguard serve \
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
- "Fetch `https://api.openai.com/v1/models`" → if you've enabled the
  `fetch` upstream and a `network` rule, the gateway gates it.

If actions appear in Claude but never show on the dashboard, see the
**Common gotchas** section in [`docs/MCP_GATEWAY.md`](../docs/MCP_GATEWAY.md#client-integration).

## Trimming the example

The bundled config wires `fs`, `fetch`, and `github` upstreams. Remove any
you don't need (each upstream costs an `npx` subprocess on startup) and
add others from <https://github.com/modelcontextprotocol/servers>.
