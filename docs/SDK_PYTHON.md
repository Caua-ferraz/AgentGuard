# Python SDK — Deep Reference

Companion to the short [`plugins/python/README.md`](../plugins/python/README.md). This page covers the details you need when things go sideways: fail modes, timeouts, exception semantics, adapter internals, and testing patterns.

Package on PyPI: `agentguardproxy`. Import name: `agentguard`.

Source: `plugins/python/agentguard/core.py` (Guard client, exceptions, constants), `plugins/python/agentguard/decorators.py` (`@guarded`), and `plugins/python/agentguard/adapters/*.py` (framework integrations). The package `__init__.py` re-exports the public surface — always import from the package root.

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

**Restarts pause approvals; they no longer kill them.** Since v0.6 the server persists the approval queue by default (`--persist`), so pending IDs survive a restart and your poll loop picks up where it left off. The exceptions: a server running `--persist=false` loses every pending ID on restart, and an entry created in the final ≥1 s store-sync window before a hard crash may be gone. In either case the poll loop retries against a queue that no longer has the entry — catch the timeout and re-issue the `check` call (which creates a new approval ID).

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

| Framework | Entry point | One-liner |
|---|---|---|
| LangChain | `agentguard.adapters.langchain` — `GuardedTool`, `GuardedToolkit` | Wrap a tool list; every `run`/`arun` is policy-checked. |
| CrewAI | `agentguard.adapters.crewai` — `GuardedCrewTool`, `guard_crew_tools` | Same, hooking both `run` and `_run`. |
| browser-use | `agentguard.adapters.browseruse` — `GuardedBrowser` | Gate navigation, actions, and form input; `wrap_page` enforces `goto` transparently. |
| MCP | `agentguard.adapters.mcp` — `GuardedMCPServer` (or `python -m agentguard.adapters.mcp`) | A guarded stdio MCP server; every `tools/call` is checked first. |

Per-framework usage, scope-inference rules (keyword tables, runtime
upgrades, `default_scope` fallback), version pins, and deny/approval
return semantics are documented once in [`ADAPTERS.md`](ADAPTERS.md).

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
