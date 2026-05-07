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

## LLM API Proxy

The proxy binary is `agentguard-llm-proxy` (Go 1.22+,
`go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest`).
It speaks the OpenAI Chat Completions and Anthropic Messages wire
formats, forwards traffic to the real upstream, and gates tool calls
inside the response stream against the central AgentGuard server's
`/v1/check`. Existing code that already uses the OpenAI / Anthropic
SDKs works unchanged after setting one environment variable. See
[`docs/LLM_API_PROXY.md`](../docs/LLM_API_PROXY.md) for the wire-format
design and [`docs/QUICKSTART_LLM_PROXY.md`](../docs/QUICKSTART_LLM_PROXY.md)
for the 90-second walkthrough.

| SDK | Example | Path convention |
|---|---|---|
| OpenAI Python | [`openai-sdk-config.py`](openai-sdk-config.py) + [`openai-sdk-config.md`](openai-sdk-config.md) | `OPENAI_BASE_URL=http://127.0.0.1:8081/v1` (with `/v1`) |
| Anthropic Python | [`anthropic-sdk-config.py`](anthropic-sdk-config.py) + [`anthropic-sdk-config.md`](anthropic-sdk-config.md) | `ANTHROPIC_BASE_URL=http://127.0.0.1:8081` (no `/v1`) |
| LangChain | [`langchain-agent-config.py`](langchain-agent-config.py) + [`langchain-agent-config.md`](langchain-agent-config.md) | `ChatOpenAI(base_url="http://127.0.0.1:8081/v1")` |
| CrewAI | [`crewai-agent-config.py`](crewai-agent-config.py) + [`crewai-agent-config.md`](crewai-agent-config.md) | `LLM(base_url="http://127.0.0.1:8081/v1", ...)` |

Each example is runnable end-to-end (`python <file>.py` after `pip
install`). The paired `.md` walks through the two-binary setup,
expected ALLOW / DENY / REQUIRE_APPROVAL behaviour with the bundled
default policy, and SDK-specific gotchas. Quickstart:
[`docs/QUICKSTART_LLM_PROXY.md`](../docs/QUICKSTART_LLM_PROXY.md).

## Other integration paths

- **SDK (compatibility tier).** [`quickstart.py`](quickstart.py) — the
  Python SDK example: explicit `Guard.check(...)` calls in agent code.
  The SDK is documented in [`docs/SDK_PYTHON.md`](../docs/SDK_PYTHON.md).
  Use it when the proxy isn't practical (offline scripts, custom
  transports), and pair it with the proxy whenever both are available.
