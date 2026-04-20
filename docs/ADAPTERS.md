# Framework Adapters

AgentGuard ships Python adapters that wrap popular agent frameworks so every tool call, navigation, or MCP request passes through `/v1/check` before executing. All adapters live under `plugins/python/agentguard/adapters/` and are gated behind pip extras (`pip install agentguardproxy[langchain]` etc.).

| Framework | Module | Extra |
|---|---|---|
| LangChain | `agentguard.adapters.langchain` | `[langchain]` |
| CrewAI | `agentguard.adapters.crewai` | `[crewai]` |
| browser-use | `agentguard.adapters.browseruse` | `[browser-use]` |
| MCP (Claude Desktop / Cursor / etc.) | `agentguard.adapters.mcp` | core — no extra |

All adapters share the same philosophy: **decide via policy first, call the wrapped callable only if `ALLOW`**. On `DENY` or `REQUIRE_APPROVAL` the adapter either returns a marker string (for LangChain/CrewAI, whose tools must return text to the LLM) or raises `PermissionError` (for browser-use, whose async page methods have no other return channel). The MCP adapter returns a JSON-RPC result with `isError: true`.

---

## LangChain — `GuardedToolkit`

Source: `plugins/python/agentguard/adapters/langchain.py`.

### Usage

```python
from agentguard.adapters.langchain import GuardedToolkit
from langchain.tools import Tool

tools = [
    Tool(name="http_get", description="Fetch a URL", func=requests.get),
    Tool(name="file_read", description="Read a file from disk", func=open),
    Tool(name="shell", description="Run a shell command", func=os.system),
]

toolkit = GuardedToolkit(
    tools=tools,
    guard_url="http://localhost:8080",
    agent_id="my-langchain-agent",
    default_scope="shell",  # fallback when nothing else matches
)

agent = create_react_agent(llm, toolkit.tools, prompt)
```

`toolkit.tools` is a drop-in replacement for the original list — each tool is wrapped in a `GuardedTool` that preserves `.name`, `.description`, and `.args_schema`, and proxies every other attribute back to the original via `__getattr__`.

### Scope inference

LangChain tools have a free-form `name + description`. The toolkit runs two passes to decide the scope.

**Static inference (at construction)** scans `name + description` for keywords:

| Keyword group | Scope |
|---|---|
| `http`, `api`, `fetch`, `request`, `url`, `web` | `network` |
| `file`, `read`, `write`, `directory`, `path` | `filesystem` |
| `browser`, `navigate`, `click`, `page` | `browser` |
| `shell`, `command`, `exec`, `terminal`, `bash` | `shell` |
| none of the above | `default_scope` (default `shell`) |

**Runtime upgrade (at call)** looks at the tool input dict and promotes the scope if a more specific key appears:

- Any `url` or `domain` in the input → `network`.
- Any `path` or `file_path` in the input → `filesystem`.

The runtime upgrade always wins over the static guess. A tool statically classified as `shell` but called with `{"path": "/etc/passwd"}` will be checked against the `filesystem` rule set.

### Parameter extraction

`_infer_check_params` forwards to `/v1/check`:

- `command` ← `tool_input` (if string) or `tool_input["command"] / ["cmd"]`
- `url`, `domain` (derived via `urlparse`)
- `path` ← `tool_input["path"] / ["file_path"]`
- `action` inferred from the tool's own name: `read`/`get` → `read`; `write`/`save`/`create` → `write`; `delete`/`remove` → `delete`
- `session_id`, `est_cost` if present in the input (lets cost-scope policies work)

### Approval / deny behavior

LangChain tools must return a string to the LLM. The wrapper returns human-readable markers:

- `DENY`: `"[AgentGuard] Action denied.\nReason: <policy reason>"`
- `REQUIRE_APPROVAL`: `"[AgentGuard] Action requires approval. Approve at: <url>\nReason: <reason>"`

The LLM sees these strings and can reason about retry. The wrapper does **not** raise on deny — raising would surface as an agent error rather than a structured observation.

If you prefer to block until a human approves, call `guard.wait_for_approval(...)` in your own tool wrapper; the adapter does not do this automatically because it would turn every tool call into a potentially 5-minute blocking operation.

### Async tools

`arun` mirrors `run`. The policy check itself is synchronous (urllib), but the wrapped tool's `arun` is awaited. If your LangChain tool only has `run`, the wrapper still works — it only calls whichever method you invoke.

---

## CrewAI — `guard_crew_tools`

Source: `plugins/python/agentguard/adapters/crewai.py`.

### Usage

```python
from agentguard.adapters.crewai import guard_crew_tools
from crewai import Agent, Task

guarded = guard_crew_tools(
    tools=[my_search_tool, my_filesystem_tool],
    guard_url="http://localhost:8080",
    agent_id="crew-researcher",
    default_scope="shell",
)

agent = Agent(role="Researcher", tools=guarded, ...)
```

### Why `run` *and* `_run` are both hooked

CrewAI's `BaseTool` exposes a public `run(tool_input)` method for direct invocation and a protected `_run(...)` that its executor calls internally during agent orchestration. The wrapper overrides **both**:

```python
def run(self, tool_input="", **kwargs):
    # policy check, then self._tool._run(...)

def _run(self, *args, **kwargs):
    return self.run(*args, **kwargs)
```

If we hooked only `run`, a CrewAI agent orchestrating tools would bypass the policy by calling `_run` directly. The redirect ensures there is no back door.

### Scope inference differences from LangChain

CrewAI scope inference is the same two-pass approach (input keys → keyword inference → configured default) but with one behavioral difference: **the `shell` keyword group does not include CrewAI's default `"shell"` term**, because CrewAI tools' names rarely contain that literal token. Explicitly construct `GuardedCrewTool(tool, scope="shell")` if you want to pin a scope.

### Return values on deny / approval

Same as LangChain — strings, not exceptions. CrewAI agents read the returned text and re-plan.

---

## browser-use — `GuardedBrowser` + `GuardedPage`

Source: `plugins/python/agentguard/adapters/browseruse.py`.

### Two integration styles

**1. Check-then-act.** Call a `check_*` method, inspect the result, then drive the browser yourself:

```python
from agentguard.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080", agent_id="browse-bot")

nav = browser.check_navigation("https://example.com")
if nav.allowed:
    await page.goto("https://example.com")
elif nav.needs_approval:
    print(f"Awaiting approval: {nav.approval_url}")
else:
    print(f"Blocked: {nav.reason}")
```

**2. Wrap the page.** `wrap_page(page)` returns a `GuardedPage` whose async `goto()` raises `PermissionError` on deny/approval and otherwise forwards to the real page:

```python
guarded_page = browser.wrap_page(page)
await guarded_page.goto("https://example.com")  # may raise PermissionError
```

All other `page` attributes pass through `__getattr__`, so `guarded_page.click(...)`, `guarded_page.title()`, etc., work unchanged. Only `goto` is intercepted today — extend the class if you want to guard clicks/types programmatically.

### Methods

| Method | Scope sent | What it checks |
|---|---|---|
| `check_navigation(url)` | `browser` | Navigation target + extracted `domain`. |
| `check_action(action, target, meta=...)` | `browser` | Clicks, screenshots, etc. Sends `command: "<action> <target>"`. |
| `check_form_input(url, field_name, value)` | **`data`** | Typing into a form field. Uses the `data` scope so policy can distinguish content-egress from navigation. |

`check_form_input` is the only method that uses the `data` scope — it is designed for preventing PII/credential leakage into web forms. A `data`-scope rule can match on `command: "input:<field_name>"` or on `domain`. The value itself is **not** sent to the policy engine (it would end up in the audit log); only the field name and destination domain are evaluated.

### Why `goto` raises instead of returning a string

Browser navigation is side-effectful with no natural "return text to the LLM" slot — if `goto` silently no-op'd on deny, the downstream `page.content()` would run against a stale page. Raising `PermissionError` forces the agent framework's retry/fail path.

---

## MCP — `GuardedMCPServer`

Source: `plugins/python/agentguard/adapters/mcp.py`.

### What MCP is

The [Model Context Protocol](https://modelcontextprotocol.io) is a JSON-RPC over stdio protocol that Claude Desktop, Cursor, and similar clients use to talk to tool servers. `GuardedMCPServer` implements the server side: it reads JSON-RPC requests on stdin, routes them, and writes responses on stdout. Every `tools/call` request is routed through AgentGuard before the real handler runs.

### Supported methods

| Method | Behavior |
|---|---|
| `initialize` | Returns pinned `protocolVersion: "2024-11-05"` + `serverInfo` + `capabilities.tools`. |
| `notifications/initialized` | Acknowledged (no response body; JSON-RPC notification). |
| `tools/list` | Returns every registered tool's `name`, `description`, `inputSchema`. |
| `tools/call` | Policy check → handler → content block. |
| any other | `{ "error": { "code": -32601, "message": "Unknown method: ..." } }` |

### Protocol version pinning

`MCP_PROTOCOL_VERSION = "2024-11-05"`. If a client requests a different version in `initialize.params.protocolVersion`, the server **logs a WARN to stderr** and still responds with the pinned version. stdout is reserved for JSON-RPC on the stdio transport, so the warning must not go to stdout.

This is intentional: v0.4.1 does not negotiate; v0.5.0 will. If you see the warn repeatedly, either update AgentGuard or downgrade the client.

### Registering tools

```python
from agentguard.adapters.mcp import GuardedMCPServer

server = GuardedMCPServer(
    guard_url="http://localhost:8080",
    agent_id="mcp-claude-desktop",
)

server.add_tool(
    name="read_file",
    description="Read a file from disk",
    input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    scope="filesystem",
    handler=lambda path: open(path).read(),
)

server.run()  # blocks, reads stdin forever
```

### Scope inference on `tools/call`

The per-tool `scope` set at `add_tool` time is the default. The adapter upgrades to a more specific scope based on the arguments:

- `arguments["url"]` or `arguments["domain"]` → `network` (extracts `domain` via `urlparse`).
- `arguments["path"]` or `arguments["file_path"]` → `filesystem`.

Parameter mapping is the same as the other adapters: `command`/`cmd`, `url`, `path`/`file_path`, plus `session_id` / `est_cost` for cost scope. If the tool's scope is `shell` and no `command`/`cmd` is present, the adapter synthesizes one: `f"{tool.name} {json.dumps(arguments)}"` — so a policy can still match on the tool-name pattern even when the tool is argument-driven.

### Error redaction

If the wrapped handler raises, the adapter returns:

```
Error (<ExceptionType>): <redacted message>
```

The redaction regex list mirrors `pkg/notify/notify.go`'s `DefaultRedactor` — Bearer tokens, AWS `AKIA...`, GitHub `ghp_...`, Slack tokens (`xox[baprs]-...`), and `key=value` for `secret/token/password/api_key`. The raw, unredacted exception is written to stderr for operator visibility; only the redacted form crosses the JSON-RPC boundary back to the MCP client.

This matters because the MCP client is arbitrary (Claude Desktop, Cursor, a script). A naive `str(e)` leak of a bearer token would cross a trust boundary.

### Running as a standalone MCP server

```bash
python -m agentguard.adapters.mcp --guard-url http://localhost:8080 --agent-id mcp-agent
```

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python",
      "args": ["-m", "agentguard.adapters.mcp", "--guard-url", "http://localhost:8080"]
    }
  }
}
```

The standalone form starts with **no tools registered**. It is meant for downstream composition — you either subclass `GuardedMCPServer` and call `add_tool` in `__init__`, or use it as a pass-through front-end for another MCP server (future work).

---

## Common patterns across adapters

### Configuring the underlying `Guard`

All adapters accept either `guard=<Guard instance>` (re-use) or `guard_url=... + agent_id=...` (construct). Share one `Guard` across adapters in the same process so env-fallback behavior is consistent:

```python
from agentguard import Guard
from agentguard.adapters.langchain import GuardedToolkit
from agentguard.adapters.crewai import guard_crew_tools

shared = Guard("http://localhost:8080", agent_id="multi-framework-agent", api_key="…")
langchain_tools = GuardedToolkit(my_lc_tools, ...).tools  # or inject shared via custom construction
crew_tools = guard_crew_tools(my_crew_tools, ...)
```

### Fail-closed by default

Each adapter delegates to `Guard.check(...)`. The underlying `Guard` is fail-closed unless constructed with `fail_mode="allow"`. If your proxy is down in development, tools will return deny markers — set `fail_mode="allow"` or run the proxy locally.

### Cost scope hints

Every adapter forwards `session_id` and `est_cost` from the tool input to the policy check. If your tools carry those keys (even nominally), cost-scope rules work across frameworks without extra wiring.

### What the adapters do NOT do

- They do **not** rate-limit locally. Rate limiting lives in the proxy.
- They do **not** block on `REQUIRE_APPROVAL`. Call `guard.wait_for_approval(...)` yourself if you want blocking.
- They do **not** modify tool input or output. Only the decision gates execution.
- They do **not** attempt schema validation of `arguments` against `inputSchema` (MCP) — that is the upstream protocol's job.

---

## Related docs

- [`docs/SDK_PYTHON.md`](SDK_PYTHON.md) — underlying `Guard` client reference.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — scopes each adapter emits to (`shell`, `filesystem`, `network`, `browser`, `data`, `cost`).
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — adapter-specific failure symptoms.
- `plugins/python/agentguard/adapters/*.py` — source of truth; all behavior documented above is code-backed.
