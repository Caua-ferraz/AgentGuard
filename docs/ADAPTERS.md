# Framework Adapters

AgentGuard ships Python adapters that wrap popular agent frameworks so every tool call, navigation, or MCP request passes through `/v1/check` before executing. All adapters live under `plugins/python/agentguard/adapters/` and are gated behind pip extras (`pip install agentguardproxy[langchain]` etc.).

| Integration | Tier | Module / Binary | Extra | Doc |
|---|---|---|---|---|
| **MCP Gateway** | Hero (wire-level) | `agentguard-mcp-gateway` binary | n/a (Go binary) | [`MCP_GATEWAY.md`](MCP_GATEWAY.md), [`QUICKSTART_MCP.md`](QUICKSTART_MCP.md) |
| **LLM API Proxy** | Hero (wire-level) | `agentguard-llm-proxy` binary | n/a (Go binary) | [`LLM_API_PROXY.md`](LLM_API_PROXY.md), [`QUICKSTART_LLM_PROXY.md`](QUICKSTART_LLM_PROXY.md) |
| LangChain | Compatibility (SDK) | `agentguard.adapters.langchain` | `[langchain]` | this doc |
| CrewAI | Compatibility (SDK) | `agentguard.adapters.crewai` | `[crewai]` | this doc |
| browser-use | Compatibility (SDK) | `agentguard.adapters.browseruse` | `[browser-use]` | this doc |
| MCP (Python adapter) | Compatibility (SDK) | `agentguard.adapters.mcp` | `[mcp]` (or core for legacy installs) | this doc |

The MCP Gateway and the LLM API Proxy are the **hero** integration paths — they enforce at the wire by sitting between the agent and its tools / model API, with no opt-in required by the agent code. The Python adapters in this doc form the **compatibility tier** for direct callers (offline scripts, custom transports, advisory enforcement) — each one gates the modern API of its target framework, and the agent must call the wrapped object for the gate to fire.

## Compatibility Matrix

The version pins live in [`plugins/python/pyproject.toml`](../plugins/python/pyproject.toml) under `[project.optional-dependencies]`. The CI `integration-tests` job runs each adapter against the real upstream package (the newest release inside each pin) on every push and PR, and on a weekly cron (Monday 06:00 UTC), so a breaking upstream release surfaces before a customer hits it. Each leg runs the framework's `test_real_*` suite and its `test_at_*` suite (a real agent loop end to end); the langchain leg also drives the real `agentguard-llm-proxy` binary (`test_at_llm_proxy_e2e.py`), and the `mcp` leg drives the Python MCP gateway adapter against a real stdio MCP server. The advisory `python-extras-all` job installs `.[all,dev]` into a fresh environment, runs `pip check`, and runs the whole Python suite, so an extras set that stops resolving — or resolves to an unsupported framework version — shows up.

| AgentGuard | LangChain | CrewAI | browser-use | MCP |
|---|---|---|---|---|
| 1.2.x | `langchain >=0.3,<2.0`, `langchain-core >=0.3,<2.0` | `crewai >=1.0,<2.0` | `browser-use >=0.4,<1.0`, `playwright >=1.40` | `mcp >=0.9,<3.0` |
| 0.5.x – 1.1.x | `langchain >=0.3,<2.0`, `langchain-core >=0.3,<2.0` | `crewai >=0.80,<2.0` | `browser-use >=0.4,<1.0`, `playwright >=1.40` | `mcp >=0.9,<2.0` |
| 0.4.x | `>=0.1` (no upper bound — silent rot) | `>=0.1` | `>=0.1` (`goto` only) | wire protocol `2024-11-05` |

The floors cover the API surface AgentGuard's adapters were built and hardened against (LangChain 0.3+'s split `langchain-core` package, CrewAI 1.0+ — see below — and browser-use 0.4+'s stable Page surface). Each ceiling sits at the next upstream major, so a new major can't install until it has been verified. As of 2026-09-24, the newest LangChain (1.x), CrewAI (1.x), browser-use (0.x) and MCP (2.x) releases are inside their pins.

**`pip install agentguardproxy[all]`** resolves, as of 2026-09-24, to crewai 1.15, browser-use 0.11, langchain 1.4, mcp 1.28 and pydantic 2.12, and `pip check` is clean. The newest browser-use (0.13) pins `mcp==2.1.1` and `pydantic>=2.13`, which conflict with crewai 1.x, so pip picks an older browser-use; every adapter suite passes on that set.

### Pinning rationale

The 0.5 line introduces upper bounds because the prior `>=0.1` floor allowed silent rot when frameworks renamed methods or added new bypass paths. Specifically:

- **LangChain** moved from a single `langchain` package on 0.1 to a split `langchain-core` (Runnable protocol) + `langchain` (agents / chains) on 0.3. LangChain has since reached 1.x, which the `<2.0` ceiling already admits and CI installs today; 2.0 gets re-verified before the ceiling moves.
- **CrewAI** moved its `BaseTool` to inherit from `langchain_core.runnables.Runnable` around 0.80, exposing the modern `invoke` / `ainvoke` / `stream` / `batch` surface. The floor is **1.0** since v1.2.0: on 0.19x a crew kickoff dispatched agent tool calls through a path the adapter does not wrap (the tool ran with no `/v1/check` call), so the adapter now refuses CrewAI below 1.0 with an `ImportError` instead of returning tools that look gated but aren't. (Before 1.2.0 the floor was 0.80, and `[all]` could resolve to crewai 0.193, where wrapping a tool failed with a `cache_function` TypeError.)
- **browser-use** 0.4 is the first release where the `Browser` / `Page` API stabilised enough that we could write a strict allowlist against it. Earlier versions reshape the page proxy across minor releases.
- **MCP** Python SDK (`mcp` on PyPI): the ceiling is `<3.0` since v1.2.0, after the adapter's suite and the gateway end-to-end suite passed on mcp 2.2.0 (and 2.1.1). 1.x stays supported.

### Bumping the upper bound

1. Locally: `pip install -e ".[<framework>,dev]"` against the new major.
2. Run `pytest -m integration tests/integration/test_real_<framework>.py -v`. All tests must pass.
3. Update the upper bound in `plugins/python/pyproject.toml`.
4. Update this table.
5. Check the framework's changelog for new method names — if the framework added a method that side-steps our gate (`Runnable.with_listeners` did this in `langchain-core` 0.3.x), extend the adapter's gated set BEFORE bumping the pin.

### Which integration-tests legs block CI

Since v1.0.0, the LangChain and CrewAI legs are required: a red leg fails CI (and, since v1.2.0, the MCP leg). The browser-use leg is advisory (`continue-on-error`) for two reasons. Its `playwright install` step downloads about 200 MB of Chromium from a CDN and is the known flake. And like every leg, it tests against live upstream releases, so a red browser-use leg usually means upstream drift, not an AgentGuard regression. A red advisory leg still shows in the run, and the weekly cron run surfaces upstream breakage even when no PR is open. (Before v1.0.0 the whole job was non-blocking.)

Authors of adapter changes are still expected to drive the integration job to green locally before merging: from `plugins/python`, run `pytest -v -m integration tests/integration/test_real_<framework>.py` (the same invocation CI uses).

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

The Python adapter does not negotiate protocol versions — for full version negotiation, use the `agentguard-mcp-gateway` Go binary instead (see [`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md)). If you see the warn repeatedly with the Python adapter, downgrade the client to `2024-11-05`.

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

The redaction regex list is `pkg/notify/notify.go`'s `DefaultRedactor`, pattern for pattern (a test checks they're identical) — Bearer tokens, AWS `AKIA...`, Slack tokens (`xox[baprs]-...`), `key=value` for `secret/token/password/api_key`, and from 1.2.0 `sk-...` LLM keys, Google `AIza...` keys, GitHub `gh[pousr]_...` and `github_pat_...` tokens, JWTs, PEM private keys and `Authorization` / `x-api-key` header values. The raw, unredacted exception is written to stderr for operator visibility; only the redacted form crosses the JSON-RPC boundary back to the MCP client.

This matters because the MCP client is arbitrary (Claude Desktop, Cursor, a script). A naive `str(e)` leak of a bearer token would cross a trust boundary.

### Running as a standalone MCP server

The module entry point has two modes — gateway and empty-server.

#### Gateway mode (preferred, v0.5+)

`--upstream "<command>"` spawns the given downstream MCP server, brokers JSON-RPC frames between the client (Claude Desktop, Cursor, …) and the upstream, and gates every `tools/call` through AgentGuard:

```bash
python -m agentguard.adapters.mcp \
  --guard-url http://localhost:8080 \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentguard-fs": {
      "command": "python",
      "args": [
        "-m", "agentguard.adapters.mcp",
        "--guard-url", "http://localhost:8080",
        "--upstream", "npx -y @modelcontextprotocol/server-filesystem /tmp"
      ]
    }
  }
}
```

The Python gateway is a compatibility-tier alternative to the
production `agentguard-mcp-gateway` Go binary (see
[`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md)). Limitations vs the Go
binary:

- Single upstream only — no capability merging.
- No tool-name namespacing / prefixing.
- Server-initiated notifications (`notifications/tools/list_changed`) are not relayed.
- Only `tools/*` is gated; `prompts/*` and `resources/*` are not.

#### Empty-server mode (back-compat)

Running the entry point without `--upstream` keeps the v0.4.x behaviour: a server that registers no tools. Useful for programmatic embedding via `GuardedMCPServer.add_tool(...)` in custom code; useless when wired to Claude Desktop verbatim. The adapter logs a stderr WARN at startup so an operator following the docs literally sees the misconfiguration immediately:

```bash
python -m agentguard.adapters.mcp --guard-url http://localhost:8080
# WARN agentguard.mcp: starting with NO tools registered. Pass --upstream …
```

For programmatic use you typically don't invoke `python -m`; you import the class directly (see "Registering tools" above).

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
