# AgentGuard Python SDK

Lightweight Python client for [AgentGuard](https://github.com/Caua-ferraz/AgentGuard) — the firewall for AI agents.

- **Zero runtime dependencies** for the core SDK (stdlib `urllib`).
- **Fail-closed by default** — if the proxy is unreachable, `check()` returns `DENY`.
- **Framework adapters** for LangChain, CrewAI, browser-use, and MCP, gated behind optional extras.

> **Deep reference:** [`docs/SDK_PYTHON.md`](../../docs/SDK_PYTHON.md) — full API, exception hierarchy, fail-mode details, adapter internals.

## Install

```bash
pip install agentguardproxy

# With framework adapters
pip install agentguardproxy[langchain]
pip install agentguardproxy[crewai]
pip install agentguardproxy[browser-use]
pip install agentguardproxy[all]
```

## Quick start

```python
from agentguard import Guard

guard = Guard(
    base_url="http://localhost:8080",   # or set AGENTGUARD_URL
    agent_id="my-agent",
    api_key="…",                        # or set AGENTGUARD_API_KEY (needed for approve/deny/status)
)

result = guard.check("shell", command="rm -rf ./old_data")

if result.allowed:
    execute(command)
elif result.needs_approval:
    print(f"Approve at: {result.approval_url}")
    # Block until a human resolves it, or 5 min deadline, whichever first
    final = guard.wait_for_approval(result.approval_id, timeout=300)
    if final.allowed:
        execute(command)
else:
    print(f"Blocked: {result.reason}")
```

### Environment variables

| Var | Default | Used by |
|---|---|---|
| `AGENTGUARD_URL` | `http://localhost:8080` | `Guard(base_url="")` fallback |
| `AGENTGUARD_API_KEY` | *(empty)* | `Guard(api_key="")` fallback; sent as `Authorization: Bearer <key>` on `/v1/approve`, `/v1/deny`, `/v1/status` |

### Fail mode

```python
# Default: fail closed. Proxy unreachable → CheckResult(decision="DENY", reason="AgentGuard unreachable (deny): …")
guard = Guard("http://localhost:8080")

# Opt in to fail open. Proxy unreachable → CheckResult(decision="ALLOW", reason="AgentGuard unreachable (allow): …")
# Use only when your threat model treats AgentGuard as advisory.
guard = Guard("http://localhost:8080", fail_mode="allow")
```

Three classes of transport failure are caught: `urllib.error.URLError` (connection refused / DNS / SSL), `OSError` (post-connect timeouts and resets), and `json.JSONDecodeError` (garbage response body).

## The `@guarded` decorator

```python
from agentguard import Guard, guarded, AgentGuardDenied, AgentGuardApprovalRequired

guard = Guard("http://localhost:8080", agent_id="my-agent")

@guarded("shell", guard=guard)
def run_command(cmd: str):
    os.system(cmd)

try:
    run_command("ls")
    run_command("rm -rf /")        # raises AgentGuardDenied
except AgentGuardDenied as e:
    log(f"blocked: {e.result.reason}")
```

On `REQUIRE_APPROVAL` the decorator raises `AgentGuardApprovalRequired` immediately. To block until a human resolves it, opt in:

```python
@guarded("cost", guard=guard, wait_for_approval=True, approval_timeout=300)
def expensive_call(prompt: str): ...
```

All three exceptions (`AgentGuardDenied`, `AgentGuardApprovalRequired`, `AgentGuardApprovalTimeout`) extend `PermissionError`, so existing `except PermissionError:` handlers keep working unchanged.

## Framework adapters

### LangChain

```python
from agentguard.adapters.langchain import GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="langchain-agent",
)
agent = create_react_agent(llm, toolkit.tools, prompt)
```

Scope is inferred from each tool's name/description (`http/api`→network, `file/path`→filesystem, `browser`→browser, `shell`→shell) and upgraded at call time if the input dict contains `url`, `domain`, or `path` keys.

### CrewAI

```python
from agentguard.adapters.crewai import guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_crew_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)
```

Hooks both `run` and `_run` (CrewAI calls `_run` internally).

### browser-use

```python
from agentguard.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080")

if browser.check_navigation("https://example.com").allowed:
    await page.goto("https://example.com")

# Or wrap the page directly so goto() enforces policy for you:
guarded_page = browser.wrap_page(page)
await guarded_page.goto("https://example.com")   # raises PermissionError on deny/approval
```

### MCP

```python
from agentguard.adapters.mcp import GuardedMCPServer

server = GuardedMCPServer(guard_url="http://localhost:8080")
server.add_tool("my_tool", "Description", handler=my_handler)
server.run()   # stdio JSON-RPC MCP server; pins MCP_PROTOCOL_VERSION
```

Or as a drop-in stdio server:

```bash
python -m agentguard.adapters.mcp --guard-url http://localhost:8080
```

## API reference (summary)

### `Guard(base_url="", agent_id="", timeout=5, api_key="", fail_mode="deny")`

| Method | Behavior |
|---|---|
| `check(scope, *, action, command, path, domain, url, session_id, est_cost, meta)` | POST `/v1/check`. Returns `CheckResult`. Transport failure → fail-closed `DENY` (or `ALLOW` if `fail_mode="allow"`). |
| `approve(id)` / `deny(id)` | POST `/v1/approve/{id}` / `/v1/deny/{id}`. Returns `bool` success. Sends Bearer if `api_key` set. |
| `wait_for_approval(id, timeout=300, poll_interval=2)` | Polls `GET /v1/status/{id}` until `resolved` or deadline. Timeout → `CheckResult(DENY, "Approval timed out")`. |

### `CheckResult`

Fields: `decision`, `reason`, `matched_rule`, `approval_id`, `approval_url`. Properties: `.allowed`, `.denied`, `.needs_approval`.

### Exception hierarchy (all extend `PermissionError`)

- `AgentGuardError` — base; carries `.result: CheckResult`.
- `AgentGuardDenied` — policy said DENY.
- `AgentGuardApprovalRequired` — policy said REQUIRE_APPROVAL and the decorator was not configured to wait. Carries `.approval_id`, `.approval_url`.
- `AgentGuardApprovalTimeout` — `wait_for_approval` deadline elapsed. Carries `.approval_id`.

## License

Apache 2.0
