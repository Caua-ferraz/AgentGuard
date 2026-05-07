# MCP Gateway Quickstart (90 seconds)

You'll go from "Claude Desktop talks to MCP servers" to "Claude Desktop
talks to MCP servers, gated by a policy file" in under 90 seconds.

By the end, every tool call Claude wants to make passes through
AgentGuard, is evaluated against a YAML policy, and shows up live on a
dashboard you can approve / deny from.

## Prerequisites

- **Claude Desktop** installed: <https://claude.ai/download>
- **Go 1.22+** (for `go install`): <https://go.dev/dl/>
- **`npx`** (Node.js 18+): <https://nodejs.org/> — used to launch the
  upstream MCP servers

This walkthrough uses Claude Desktop. The same pattern works for Cursor,
Cline, Continue.dev, and Zed — see [`examples/`](../examples/) for ready
configs.

## 30 seconds — install AgentGuard

```bash
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest
```

Confirm both binaries are on `PATH`:

```bash
which agentguard agentguard-mcp-gateway
# /Users/you/go/bin/agentguard
# /Users/you/go/bin/agentguard-mcp-gateway
```

If `which` finds nothing, add `$(go env GOPATH)/bin` to your shell's
`PATH` and re-source the rc file.

## 30 seconds — run the policy server

Generate an API key and start the central AgentGuard server with a
default policy:

```bash
export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"

git clone https://github.com/Caua-ferraz/AgentGuard.git
agentguard serve \
  --policy AgentGuard/configs/default.yaml \
  --dashboard \
  --watch \
  --api-key "$AGENTGUARD_API_KEY"
```

Open the dashboard: <http://127.0.0.1:8080/dashboard> — log in with the
API key you just exported. Leave this terminal running.

## 30 seconds — wire Claude Desktop

In Claude Desktop, click **menu → Settings → Developer → Edit Config** to
open `claude_desktop_config.json`. Replace its contents with:

```jsonc
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard-mcp-gateway",
      "args": [
        "--upstream", "fs:npx -y @modelcontextprotocol/server-filesystem /tmp",
        "--guard-url", "http://127.0.0.1:8080",
        "--api-key", "$AGENTGUARD_API_KEY",
        "--policy", "/absolute/path/to/AgentGuard/configs/default.yaml",
        "--policy-mode", "strict",
        "--fail-mode", "deny"
      ],
      "env": {
        "AGENTGUARD_API_KEY": "<paste the key from step 2 here>"
      }
    }
  }
}
```

Replace `/absolute/path/to/AgentGuard/configs/default.yaml` with your
actual clone path. Claude Desktop does not expand shell variables in flag
strings — the `env` block is the only place the API key is looked up.

The exact file path of `claude_desktop_config.json`:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

Save, then **fully quit and restart Claude Desktop** (Cmd-Q on macOS, not
just close the window).

## Verify (the satisfying part)

Open a new chat and ask:

> "Read the file `/tmp/hello.txt` and tell me what's in it."

(If the file doesn't exist, ask Claude to *create* it first — the default
policy ALLOWs filesystem writes under `/tmp`.) Watch the dashboard — an
`ALLOW` event appears in the live feed within a second.

Now try:

> "Read `/etc/passwd`."

The dashboard logs a `DENY`. Claude reports the tool returned an error
with the policy reason embedded.

That's the loop. Every tool call → policy check → audit log → live
dashboard. No agent code change required.

## Next steps

- **Customize the policy:** [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md)
  for the full schema, including `require_approval` rules that pause the
  call until you click the dashboard's approve button.
- **Add more upstreams** (github, fetch, slack, postgres):
  [`docs/MCP_GATEWAY.md § Multi-upstream`](MCP_GATEWAY.md#3-multi-upstream-management)
  and the official server catalog at
  <https://github.com/modelcontextprotocol/servers>.
- **Approval flow walkthrough:** [`docs/APPROVAL_WORKFLOW.md`](APPROVAL_WORKFLOW.md)
  shows how `REQUIRE_APPROVAL` decisions flow through Slack / webhooks /
  the dashboard.
- **Other MCP clients:**
  - Cursor: [`examples/cursor-config.json`](../examples/cursor-config.json)
  - Cline (VS Code): [`examples/cline-config.json`](../examples/cline-config.json)
  - Continue.dev: [`examples/continue-config.json`](../examples/continue-config.json)
  - Zed: [`examples/zed-config.json`](../examples/zed-config.json)
- **Threat model.** The gateway is wire-level for the configured upstreams
  — but an agent that controls its own runtime can still bypass it by
  pointing at a different MCP server. Read
  [README § Limitations & Threat Model](../README.md#limitations--threat-model)
  before you trust this as a last line of defense.
