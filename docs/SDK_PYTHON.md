# Python SDK — Deep Reference

Companion to the short [`plugins/python/README.md`](../plugins/python/README.md). This page covers the details you need when things go sideways: fail modes, timeouts, exception semantics, adapter internals, and testing patterns.

Package on PyPI: `agentguardproxy`. Import name: `agentguard`.

Source: `plugins/python/agentguard/__init__.py` (core) and `plugins/python/agentguard/adapters/*.py` (framework integrations).

---

## Table of contents

- [Install and import](#install-and-import)
- [Environment variables](#environment-variables)
- [`Guard` constructor in detail](#guard-constructor-in-detail)
- [`check()` — argument guide](#check--argument-guide)
- [Fail-mode semantics](#fail-mode-semantics)
- [Timeouts](#timeouts)
- [`approve`, `deny`, `wait_for_approval`](#approve-deny-wait_for_approval)
- [Exception hierarchy](#exception-hierarchy)
- [`@guarded` decorator](#guarded-decorator)
- [Adapters](#adapters)
  - [LangChain](#langchain)
  - [CrewAI](#crewai)
  - [browser-use](#browser-use)
  - [MCP](#mcp)
- [Testing against a fake proxy](#testing-against-a-fake-proxy)

---

## Install and import

```bash
pip install agentguardproxy            # core only
pip install agentguardproxy[langchain]
pip install agentguardproxy[crewai]
pip install agentguardproxy[browser-use]
pip install agentguardproxy[mcp]
pip install agentguardproxy[all]       # everything
pip install agentguardproxy[dev]       # pytest, coverage, etc.
```

```python
from agentguard import (
    Guard, CheckResult, guarded,
    AgentGuardError, AgentGuardDenied,
    AgentGuardApprovalRequired, AgentGuardApprovalTimeout,
)
```

The core SDK has **no runtime dependencies** — it uses only the standard library (`urllib`, `json`, `dataclasses`, `functools`, `time`). Adapters pull in their respective frameworks through PyPI extras.

---

## Environment variables

| Variable | Default | Consumed by |
|---|---|---|
| `AGENTGUARD_URL` | `http://localhost:8080` | `Guard(base_url="")` fallback. |
| `AGENTGUARD_API_KEY` | *(empty)* | `Guard(api_key="")` fallback. Sent as `Authorization: Bearer <key>` on `/v1/approve/{id}`, `/v1/deny/{id}`, and every poll of `/v1/status/{id}` inside `wait_for_approval`. |

Explicit arguments always win over env vars; env vars always win over package defaults.

---

## `Guard` constructor in detail

```python
Guard(
    base_url: str = "",
    agent_id: str = "",
    timeout: int = 5,
    api_key: str = "",
    fail_mode: str = "deny",   # or "allow"
)
```

- `base_url` — trailing `/` is stripped. Empty string falls back to `AGENTGUARD_URL`, then to `"http://localhost:8080"`.
- `agent_id` — sent with every `check()` as the `agent_id` JSON field. Policy `agents.<id>.override` blocks key off this value.
- `timeout` — per-HTTP-call timeout in seconds. Applies to `/v1/check`, `/v1/approve`, `/v1/deny`, and each poll inside `wait_for_approval`.
- `api_key` — empty string falls back to `AGENTGUARD_API_KEY`. Required whenever the server is started with `--api-key`.
- `fail_mode` — see [Fail-mode semantics](#fail-mode-semantics). Invalid values raise `ValueError` at construction so misconfiguration fails at startup rather than mid-request.

`Guard` instances are thread-safe for concurrent `check()` calls (all state read-only after init). They are cheap; creating one per request is fine, and reusing one is slightly cheaper.

---

## `check()` — argument guide

```python
guard.check(
    scope: str,
    *,
    action: str = "",
    command: str = "",
    path: str = "",
    domain: str = "",
    url: str = "",
    session_id: str = "",
    est_cost: float = 0.0,
    meta: Optional[dict] = None,
) -> CheckResult
```

All fields past `scope` are keyword-only. Fill the ones your scope cares about:

| Scope | Fields to set |
|---|---|
| `shell` | `command` (optional `action`) |
| `filesystem` | `action` + `path` |
| `network` | `domain` or `url` |
| `browser` | `domain` or `url` |
| `cost` | `est_cost` and `session_id` |
| `data` (or any generic scope) | whichever string(s) your rules match on |

Unset fields are dropped from the request body to keep audit entries clean. `est_cost=0.0` is also dropped (use a non-zero value when you want the cost engine to consider the call).

The request body is always JSON with `Content-Type: application/json` and capped at 1 MiB by the server (configurable via the policy `proxy.request.max_body_bytes` key).

### The returned `CheckResult`

```python
@dataclass
class CheckResult:
    decision: str           # "ALLOW", "DENY", "REQUIRE_APPROVAL"
    reason: str
    matched_rule: str = ""
    approval_id: str = ""
    approval_url: str = ""
```

Convenience booleans: `.allowed`, `.denied`, `.needs_approval`.

---

## Fail-mode semantics

Exactly three transport errors collapse into a synthetic `CheckResult` controlled by `fail_mode`:

- `urllib.error.URLError` — connection-phase failure (connect refused, DNS, SSL handshake).
- `OSError` — post-connect failure (`ConnectionResetError`, `BrokenPipeError`, `socket.timeout` surfaced from `resp.read()`).
- `json.JSONDecodeError` — the body parsed as non-JSON; from the caller's perspective this is indistinguishable from an unreachable proxy.

```python
# fail_mode="deny" (default)
CheckResult(decision="DENY",  reason="AgentGuard unreachable (deny): <original error>")

# fail_mode="allow"
CheckResult(decision="ALLOW", reason="AgentGuard unreachable (allow): <original error>")
```

**When to use `"allow"`:** rarely. Acceptable only if (a) your agent is already in a trusted environment, (b) AgentGuard is advisory rather than authoritative, and (c) you log and alert on the `"AgentGuard unreachable"` reason so the outage is visible.

**When to stick with `"deny"`:** any production path where an unsupervised agent must not act. That is the safe default and the v0.4.0 behavior.

---

## Timeouts

| Knob | Default | Effect |
|---|---|---|
| `Guard(timeout=5)` | 5s | Per-HTTP-call timeout. |
| `wait_for_approval(timeout=300)` | 300s | Wall-clock deadline for the whole poll loop. |
| `wait_for_approval(poll_interval=2)` | 2s | Sleep between polls. |

`wait_for_approval` quietly swallows individual poll failures (`URLError`) and keeps retrying until the deadline — the assumption is that the server is momentarily unreachable but will come back within the approval window. A final deadline miss returns `CheckResult(decision="DENY", reason="Approval timed out")`, which the `@guarded(wait_for_approval=True)` wrapper surfaces as `AgentGuardApprovalTimeout`.

**Pick `timeout` higher than your human-SLA.** If approvers need 15 minutes on average, `timeout=300` will fire false negatives.

**Restart kills in-flight approvals.** The approval queue is in-memory; a proxy restart loses every pending ID. Your poll loop will keep retrying against a queue that no longer has the entry. Resolve this either by catching the timeout and re-issuing the `check` call (which will create a new approval ID) or by not restarting the proxy while approvals are outstanding.

---

## `approve`, `deny`, `wait_for_approval`

```python
guard.approve("ap_1a2b3c…")               # True / False
guard.deny("ap_1a2b3c…")                  # True / False
guard.wait_for_approval("ap_1a2b3c…",
                        timeout=300,
                        poll_interval=2)  # CheckResult
```

All three send `Authorization: Bearer <api_key>` when `api_key` is set. If the server was started without `--api-key`, the key is ignored. If the server **was** started with `--api-key` and you do not set one on the SDK side, you will get `401` on approve/deny and `wait_for_approval` will loop until the deadline.

`approve`/`deny` treat any `URLError` as failure and return `False`. They do **not** distinguish network error from 4xx. If you need that distinction, call the HTTP API directly.

---

## Exception hierarchy

All raised by the `@guarded` decorator. All extend `PermissionError` so legacy `except PermissionError:` keeps working.

```
PermissionError
└── AgentGuardError         .result: Optional[CheckResult]
    ├── AgentGuardDenied
    ├── AgentGuardApprovalRequired   .approval_id, .approval_url
    └── AgentGuardApprovalTimeout    .approval_id
```

The `.result` attribute lets you skip re-parsing the reason string:

```python
try:
    do_thing()
except AgentGuardDenied as e:
    log.warning("blocked by rule %s: %s",
                e.result.matched_rule, e.result.reason)
except AgentGuardApprovalRequired as e:
    notify_slack(f"Action {e.approval_id} waiting at {e.approval_url}")
```

---

## `@guarded` decorator

```python
@guarded(
    scope: str,
    guard: Optional[Guard] = None,
    *,
    wait_for_approval: bool = False,
    approval_timeout: int = 300,
    approval_poll_interval: int = 2,
    **check_kwargs,
)
```

Behavior:

1. Creates a default `Guard()` if `guard=None` (picks up env vars).
2. Extracts a `command` string: the first positional arg, else the `command=` or `cmd=` kwarg, else `""`.
3. Calls `guard.check(scope, command=..., **check_kwargs)`.
4. Branches on the decision:
   - `ALLOW` → runs the wrapped function.
   - `REQUIRE_APPROVAL` + `wait_for_approval=False` → raises `AgentGuardApprovalRequired` immediately.
   - `REQUIRE_APPROVAL` + `wait_for_approval=True` → blocks on `wait_for_approval`. Resolved ALLOW runs the function; resolved DENY raises `AgentGuardDenied`; timeout raises `AgentGuardApprovalTimeout`.
   - `DENY` → raises `AgentGuardDenied`.

Any `**check_kwargs` you pass are forwarded verbatim to `Guard.check()`. Useful for pinning `session_id=`, `meta=`, etc.

---

## Adapters

All adapters import lazily — the extras you do not install are never imported and never crash the core SDK.

### LangChain

```python
from agentguard.adapters.langchain import GuardedTool, GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="research-agent",
)

agent = create_react_agent(llm, toolkit.tools, prompt)
```

- Wraps each tool's `run` (sync) and `arun` (async).
- Default scope per tool is inferred from `tool.name + tool.description` keywords:
  - `http`, `api`, `fetch`, `request` → `network`
  - `file`, `path`, `read`, `write` → `filesystem`
  - `browser`, `navigate`, `click` → `browser`
  - `shell`, `exec`, `command` → `shell`
  - fallback → `data`
- At call time, if the tool input is a dict containing `url` or `domain` → scope upgraded to `network`; `path` or `file_path` → `filesystem`.

Pass `scope=` to `GuardedTool` to override inference manually.

### CrewAI

```python
from agentguard.adapters.crewai import GuardedCrewTool, guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_crew_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)
```

Hooks **both** `run` and `_run` because CrewAI sometimes invokes tools through the private `_run` path. Scope inference mirrors the LangChain adapter.

### browser-use

```python
from agentguard.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080",
                         agent_id="scraper")

result = browser.check_navigation("https://news.ycombinator.com")
if result.allowed:
    await page.goto(result.url)

# Action-level check
browser.check_action("click", "#login-btn")

# Form input uses the `data` scope (useful if policy distinguishes PII entry)
browser.check_form_input("https://example.com/signup",
                         field="email", value="user@corp.com")

# Or wrap the page so goto() is enforced transparently
guarded_page = browser.wrap_page(page)
await guarded_page.goto("https://news.ycombinator.com")   # PermissionError on deny
```

`GuardedPage.goto` raises `PermissionError` (specifically `AgentGuardDenied` or `AgentGuardApprovalRequired`) if the check fails.

### MCP

```python
from agentguard.adapters.mcp import GuardedMCPServer

server = GuardedMCPServer(guard_url="http://localhost:8080",
                         agent_id="mcp-server")
server.add_tool("search_web", "Search the web", handler=search_handler)
server.add_tool("read_file",  "Read a local file", handler=read_handler)
server.run()   # blocks; stdio JSON-RPC
```

Or drop-in:

```bash
python -m agentguard.adapters.mcp --guard-url http://localhost:8080
```

Implements `initialize`, `tools/list`, `tools/call`, and the `notifications/initialized` notification. The adapter pins `MCP_PROTOCOL_VERSION = "2024-11-05"`. v0.4.1 warns (does not error) on protocol-version mismatches from the client.

Tool-call scope inference (from the tool's argument names):

- `command` or `cmd` → `shell`
- `url` → `network`
- `path` or `file_path` → `filesystem`
- fallback → `data`

Tool-call failures are returned as MCP content blocks with `isError: true`.

---

## Testing against a fake proxy

### Option A — run the real binary

The repo's `tests/test_end_to_end_real_server.py` does exactly this: spawn `./agentguard serve --policy <test-policy.yaml>` on a random port, talk to it with `Guard`, and assert decisions. This is the most realistic path and what CI uses.

### Option B — `responses` / `httpretty`

For unit tests, stub the HTTP layer:

```python
import responses
from agentguard import Guard

@responses.activate
def test_denies_rm_rf():
    responses.add(
        responses.POST,
        "http://localhost:8080/v1/check",
        json={"decision": "DENY", "reason": "destructive command", "matched_rule": "deny:shell:rm-rf"},
    )
    guard = Guard("http://localhost:8080")
    r = guard.check("shell", command="rm -rf /")
    assert r.denied
    assert "destructive" in r.reason
```

### Option C — `fail_mode="allow"` for disconnected tests

If you intentionally do not run a proxy in your unit tests and you want `check()` to succeed, construct `Guard(..., fail_mode="allow")`. Only do this in tests; it is the wrong default anywhere else.

---

## Related docs

- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — getting the server set up so the SDK can reach it.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — what you pass to `check()`.
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — "Python SDK always returns DENY", "approvals disappeared after restart", etc.
- [`docs/ADAPTERS.md`](ADAPTERS.md) — per-framework deep dive (written separately so this file does not balloon).
