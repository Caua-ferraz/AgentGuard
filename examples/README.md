# Integration Examples

Copy-paste working configs for AgentGuard's integration paths. Every
example was last verified against the upstream client docs on **2026-05-05**;
each `<client>-config.md` file cites the source URL and the verification
date.

## MCP Gateway

The gateway binary is `agentguard-mcp-gateway` (Go 1.22+,
`go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest`).
It sits between an MCP client and one or more downstream MCP servers,
gating every `tools/call` against the central AgentGuard server's
`/v1/check`. See [`docs/MCP_GATEWAY.md`](../docs/MCP_GATEWAY.md) for the
wire-format design and [`docs/QUICKSTART_MCP.md`](../docs/QUICKSTART_MCP.md)
for the 90-second walkthrough.

| Client | Config file | Where it lives |
|---|---|---|
| Claude Desktop | [`claude-desktop-config.json`](claude-desktop-config.json) | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | [`cursor-config.json`](cursor-config.json) | global `~/.cursor/mcp.json` or per-project `<workspace>/.cursor/mcp.json` |
| Cline (VS Code) | [`cline-config.json`](cline-config.json) | inside VS Code's `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` (use the in-app "Configure MCP Servers" button) |
| Continue.dev | [`continue-config.json`](continue-config.json) (legacy) or YAML in [`continue-config.md`](continue-config.md) | `~/.continue/config.json` or `<workspace>/.continue/mcpServers/*.yaml` |
| Zed | [`zed-config.json`](zed-config.json) | `~/.config/zed/settings.json` (key: `context_servers`, not `mcpServers`) |

Each `<client>-config.json` has a sibling `<client>-config.md` with the
authoritative file path, OS-specific gotchas, the source-doc URL +
verification date, and concrete verification steps.

## Other integration paths

- **SDK (compatibility tier).** [`quickstart.py`](quickstart.py) — the
  Python SDK example: explicit `Guard.check(...)` calls in agent code.
  The SDK is documented in [`docs/SDK_PYTHON.md`](../docs/SDK_PYTHON.md).
- **LLM API Proxy.** Coming in v0.5 (Phase 4C). The proxy binary will
  ship alongside `agentguard-mcp-gateway` and add an OpenAI- /
  Anthropic-compatible base URL that intercepts tool calls in completion
  streams. Track progress in [`docs/LLM_API_PROXY.md`](../docs/LLM_API_PROXY.md).
