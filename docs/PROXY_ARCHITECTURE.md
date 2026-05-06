# Proxy Architecture (v0.5)

> **Phase 4A design doc — locks the architecture for Phase 4B (MCP Gateway)
> and Phase 4C (LLM API Proxy) implementation.**

This doc covers the cross-cutting decisions that apply to **both** Phase 4
proxies. The two follow-up docs cover the proxy-specific wire format and
data plane:

- [`docs/MCP_GATEWAY.md`](./MCP_GATEWAY.md) — `agentguard-mcp-gateway`
- [`docs/LLM_API_PROXY.md`](./LLM_API_PROXY.md) — `agentguard-llm-proxy`

Read this one first.

---

## 1. The hero claim, restated honestly

v0.5 ships the AgentGuard firewall as a **wire-level enforcement boundary**
via two integration paths:

1. **MCP Gateway** — a JSON-RPC bridge that sits between an MCP client
   (Claude Desktop, Cursor, IDE plugins) and one or more downstream MCP
   servers. Every `tools/call` is gated by the policy engine before
   reaching the upstream.
2. **LLM API Proxy** — an HTTP server that speaks
   `/v1/chat/completions` (OpenAI) and `/v1/messages` (Anthropic) wire
   formats and forwards to the real upstream after gating any tool calls
   the model emits — including tool calls that arrive inside an SSE
   stream.

The Python and TypeScript SDKs become the **compatibility tier** for
direct callers: code paths that talk to AgentGuard via `Guard.check`
remain a first-class integration, but they're no longer the only way to
get coverage.

This positioning — and the wire-level honesty caveat below — ties back to
the README's threat-model section.

### 1.1 What "wire-level" does and does not mean

The two proxies are wire-level **for the configured base URL or the
gateway subprocess**. An agent can still bypass either path by:

- ignoring `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` and dialing the real
  upstream directly,
- launching an MCP server with no AgentGuard gateway in front of it,
- using a tool the SDK doesn't know about.

The README's "Limitations & Threat Model" section already documents the
fundamental opt-in property; this doc inherits that caveat. AgentGuard
is a **defensive guardrail for cooperating agents**, not a mandatory
syscall interceptor.

---

## 2. Shared substrate

The two proxies do **not** duplicate the policy engine, audit logger,
approval queue, or SSE bus. They both consume primitives that already
landed in Phases 1–3.

### 2.1 Policy via `pkg/policy.PolicyProvider`

Both proxies hold a `*policy.Engine` constructed from a
`policy.PolicyProvider`. v0.5 wires `FilePolicyProvider`; v0.6 multi-tenant
drops in via the same interface (`Get` / `Watch` / `Validate` / `Close`,
see `pkg/policy/provider.go`).

Each tool/API call resolves to **one** `Engine.Check(req, tenantID)` call.
The `tenantID` is `"local"` in v0.5; the proxies plumb it via the
existing `pkg/proxy/tenant.go` `WithTenantID` / `TenantIDFromContext`
contract.

### 2.2 Audit via `pkg/audit.BufferedAsyncLogger`

Both proxies write through `BufferedAsyncLogger` (Phase 2 A8) so audit
I/O does not block the data path. The wrapper handles disk-overflow and
worker-pool draining; the proxies just call `Logger.Log(entry)`.

The `audit.Entry` already includes `Scope`, `Decision`, `Rule`,
`Reason`, and `Meta`. Phase 4 adds a `Transport` field — see § 3.

### 2.3 Approval queue and SSE bus via `pkg/proxy.ApprovalQueue`

The existing AgentGuard HTTP server (`agentguard serve`) owns the
approval queue and the SSE bus. The two proxies do **not** maintain
their own approval state. When a check returns `REQUIRE_APPROVAL` the
proxy:

- receives `ApprovalID` and `ApprovalURL` in the `CheckResult`,
- surfaces them to the agent (synthetic refusal for the LLM proxy;
  `isError: true` content block for the MCP gateway),
- the operator approves on the dashboard (or via `agentguard approve`
  CLI) — the resolution lands on the **central guard server's**
  `ApprovalQueue` and is broadcast on its SSE bus.

The dashboard's mixed feed therefore shows MCP-gateway approvals,
LLM-proxy approvals, and direct-SDK approvals on the same wire — chipped
by the new `transport` field so operators can filter at a glance.

### 2.4 Notifier via `pkg/notify.Dispatcher`

Webhook / Slack / console notifications are the central guard server's
job. The proxies do not run their own dispatcher — they receive
`REQUIRE_APPROVAL` / `DENY` `CheckResult`s back from `/v1/check` and the
central server has already fanned out the event by the time the proxy
sees the response.

### 2.5 Diagram — single host

```
                        ┌─────────────────────────────────┐
                        │      agentguard serve           │
                        │  (central host: 127.0.0.1:8080) │
   /v1/check ─────►     │  • Engine.Check                 │
   /v1/approve ─────►   │  • ApprovalQueue + SSE bus      │
   /v1/audit ─────►     │  • BufferedAsyncLogger          │
                        │  • Notifier (webhook/Slack)     │
                        │  • Dashboard (/dashboard, /api) │
                        └─────────────────▲───────────────┘
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              │                           │                           │
        /v1/check                   /v1/check                   /v1/check
              │                           │                           │
   ┌──────────┴──────────┐    ┌───────────┴────────────┐    ┌─────────┴─────────┐
   │ agentguard-         │    │ agentguard-llm-proxy   │    │ Python/TS SDKs    │
   │ mcp-gateway         │    │ (127.0.0.1:8081)       │    │ (Guard.check)     │
   │ (stdio child of     │    │ • /v1/chat/completions │    │                   │
   │  Claude Desktop)    │    │ • /v1/messages         │    │                   │
   │ • bridges JSON-RPC  │    │ • streaming pause/     │    │                   │
   │ • spawns N upstream │    │   resume/rewrite       │    │                   │
   │   MCP servers       │    │                        │    │                   │
   └─────────────────────┘    └────────────────────────┘    └───────────────────┘
       ▲       │                       ▲      │                     ▲
       │       ▼                       │      ▼                     │
   stdio in   stdio out             OpenAI/Anthropic         direct agent code
   (client)   (downstream            (real upstream)           (LangChain, etc.)
              MCP servers)
```

---

## 3. Audit transport tag

Phase 4 needs to chip every audit entry by **how the agent talked to the
firewall**. Three values:

| transport         | source                                         |
|-------------------|------------------------------------------------|
| `mcp_gateway`     | `agentguard-mcp-gateway` (Phase 4B)            |
| `llm_api_proxy`   | `agentguard-llm-proxy` (Phase 4C)              |
| `sdk`             | direct `/v1/check` callers (Python/TS SDKs, hand-rolled HTTP clients, framework adapters) |

### 3.1 Where the field lives

**Decision:** top-level `Entry.Transport string` field.

**Alternatives considered:**

- `Meta["transport"] string` — nests under existing free-form bag.
  Rejected because the dashboard chip and the `Logger.Query` filter want
  a stable indexed field, not a string lookup inside a map. The
  performance gap on a JSON-Lines log is small but the API gap on
  `Query(filter QueryFilter{Transport: "mcp_gateway"})` is glaring.

- Bump audit `schema_version` from `2` to `3`. Rejected because the
  field is **purely additive**: existing readers ignore unknown
  top-level keys; existing writers continue to emit v2 entries with no
  `transport` field, which the v0.5 reader treats as `"sdk"` by default.

### 3.2 Reader rules

- New entries (v0.5+ writers) **MUST** include `"transport"`.
- Pre-v0.5 entries (no `"transport"` key) **default to `"sdk"`** at read
  time — this matches the only writer path that existed before Phase 4.
- `Logger.Query` accepts `Transport string` in the filter; matches by
  exact equality. Empty filter value matches all.

### 3.3 Wire schema impact

`pkg/proxy/schema/v1/schema.json` — the cross-language contract that
governs `/v1/check` request and response — is **not** affected. The
`transport` tag is an audit-side concern. The proxy that calls
`/v1/check` knows its own transport and stamps the audit entry locally;
it does not negotiate this with the central server.

The `CheckResult` schema stays at `schema_version: "v1"`. No bump.

---

## 4. Binary structure

### 4.1 Decision: two binaries

Phase 4B and Phase 4C ship two new binaries on top of the existing
`agentguard` binary:

| binary                       | role                                                  |
|------------------------------|-------------------------------------------------------|
| `agentguard`                 | central server (`serve`, `validate`, `audit`, etc.)   |
| `agentguard-mcp-gateway`     | stdio bridge, child of an MCP host (Claude Desktop)   |
| `agentguard-llm-proxy`       | HTTP server, sidecar for OpenAI/Anthropic-compatible callers |

All three live under `cmd/`:

```
cmd/agentguard/main.go               (existing)
cmd/agentguard-mcp-gateway/main.go   (Phase 4B — new)
cmd/agentguard-llm-proxy/main.go     (Phase 4C — new)
```

Each `cmd/agentguard-*/main.go` is a **thin entry point**. Real logic
lives in:

```
pkg/mcpgateway/      (Phase 4B)
pkg/llmproxy/        (Phase 4C)
```

…and consumes existing `pkg/policy`, `pkg/audit`, `pkg/proxy`,
`pkg/notify`, `pkg/metrics`.

### 4.2 Why not subcommands of `agentguard`?

| factor                | subcommands     | two binaries (chosen)        |
|-----------------------|-----------------|------------------------------|
| Lifecycle             | one process     | three independent processes  |
| Deployment            | one container   | three containers / sidecars  |
| Failure isolation     | crash blast = all 3 | crash blast = 1          |
| Binary size           | one fat binary  | three slim binaries          |
| Versioning            | trivially synced| `bump-version.sh` updates all|
| MCP gateway lifecycle | conflict — Claude Desktop spawns it as `command:` and keeps stdin open; `agentguard serve` is a long-running HTTP daemon. Same process can't be both. | clean separation |

The MCP gateway in particular **must** be a separate binary because MCP
clients spawn it via `claude_desktop_config.json`'s `command` field with
stdin/stdout reserved for JSON-RPC. Mixing that with an HTTP server in
the same process is a recipe for stdout corruption.

The LLM API proxy *could* live as `agentguard llm-proxy`, but: (a) it
does not need the policy/audit/notify/dashboard code in its memory image
when it runs as a sidecar, and (b) deployments that scale the proxy
horizontally don't want to redeploy the central server every time they
ship a proxy fix.

### 4.3 Versioning

All three binaries share the v0.5 release. `bump-version.sh` already
sed-replaces six files; Phase 4B/4C add the new `cmd/agentguard-*/main.go`
files to that list.

`agentguard-mcp-gateway version` and `agentguard-llm-proxy version`
emit the same `version` / `commit` triplet as `agentguard version`.

### 4.4 Same `pkg/` codebase

Critical: there is **one** policy engine, **one** audit format, **one**
approval queue type. The two new binaries import the same packages and
configure them differently. Implementation drift between the proxies
fails CI because the `pkg/` tests run for all callers.

---

## 5. Deployment topologies

### 5.1 Local-only (developer machine)

All three binaries on `127.0.0.1`. Everything chats over loopback.

```
agentguard serve --port 8080 --dashboard --policy configs/default.yaml
agentguard-mcp-gateway --guard-url http://127.0.0.1:8080 --upstream "fs:npx -y @modelcontextprotocol/server-filesystem /tmp"
agentguard-llm-proxy --listen 127.0.0.1:8081 --guard-url http://127.0.0.1:8080
```

The agent's environment:

```
OPENAI_BASE_URL=http://127.0.0.1:8081
```

…and Claude Desktop's `claude_desktop_config.json` points at the gateway
binary.

### 5.2 Single-host server

One host runs `agentguard serve`. Gateways and proxies run as sidecars
on the same host or on agent-facing hosts pointing at the central
server's `/v1/check` over the network. Set `--api-key` on the central
server and pass it to every gateway/proxy via `--api-key`.

### 5.3 Distributed (v0.6 multi-tenant)

Out of scope for v0.5 but the architecture does not preclude it:

- multi-tenant `PolicyProvider` plugs into `Engine.Check` unchanged,
- tenant URL routing already exists in `pkg/proxy/tenant.go`,
- the proxies plumb tenant ID via the same context-key.

`TODO(v0.6, #N): shard ApprovalQueue / SSE bus / audit query / rate
limiter by tenantID` — already tracked in `pkg/proxy/tenant.go` and the
v0.5 decision log.

---

## 6. Failure modes

### 6.1 Central guard server (`agentguard serve`) is unreachable

This is the case the SDK already handles (`fail-mode: deny|allow`).
Both proxies adopt the **same** flag for parity:

```
--fail-mode deny|allow|fail-closed-with-audit   (default: deny)
```

| value                       | behavior on `/v1/check` failure                           |
|-----------------------------|-----------------------------------------------------------|
| `deny`                      | synthesise `DENY` with `Rule="deny:guard_unreachable"`. The agent sees a deny. **Default.** |
| `allow`                     | synthesise `ALLOW` with `Rule="allow:guard_unreachable"`. **Use only in trusted dev environments.** Logged as WARN at startup. |
| `fail-closed-with-audit`    | synthesise `DENY` AND attempt to write a local audit entry to a fallback file (`<flag>.fallback.jsonl`). Useful when the central server is down but you still want a record of attempts. |

The Python SDK (always fail-closed) and TypeScript SDK (configurable
`failMode`) keep their existing behaviour — the new flag just brings the
proxies into line.

### 6.2 MCP gateway: downstream subprocess crashes

Reconnect with capped backoff (1s → 2s → 5s → 30s → 60s, cap 60s). The
namespace is marked degraded; `tools/list` excludes its tools while the
flag is set; `tools/call` returns JSON-RPC `-32603 Internal error`.
Detail in `MCP_GATEWAY.md` § 7.

### 6.3 LLM API proxy: upstream OpenAI/Anthropic returns 5xx or times out

Pass-through: forward the upstream's status code and body verbatim.
Write one audit entry tagged `transport: "llm_api_proxy"` with the
upstream status in `Meta["upstream_status"]`. Do not transform errors
into AgentGuard-shaped JSON — the agent's own retry/error-handling path
gets to see the real upstream response.

### 6.4 Proxy itself crashes

Both proxies are stateless w.r.t. policy decisions. Restart loses
in-flight gating context only. The MCP gateway's degraded-namespace
flags are reset; the LLM proxy's per-stream buffers are dropped (the
client's stream errors out and the agent retries).

In-flight `REQUIRE_APPROVAL` records live on the **central server's**
ApprovalQueue, not in the proxy. Restarting a proxy does not lose
approvals.

---

## 7. Configuration parity

Both binaries share these flags:

| flag                  | meaning                                            | default                |
|-----------------------|----------------------------------------------------|------------------------|
| `--guard-url`         | central server `/v1/check` base URL                | `http://127.0.0.1:8080`|
| `--api-key`           | bearer token for `/v1/check` (from `AGENTGUARD_API_KEY` env if unset) | unset (warn) |
| `--tenant-id`         | tenant header value                                | `local`                |
| `--fail-mode`         | `deny` / `allow` / `fail-closed-with-audit`        | `deny`                 |
| `--log-level`         | `info` / `debug`                                   | `info`                 |
| `--version`           | print `version commit date` and exit               | —                      |

Proxy-specific flags (upstreams, listen address, etc.) live in the
respective doc.

---

## 8. Health & observability

Both proxies expose a `/health` endpoint (or, for the MCP gateway, a
JSON-RPC `agentguard/health` extension) returning:

```json
{
  "status": "ok",
  "version": "0.5.0",
  "guard_reachable": true,
  "warnings": []
}
```

`warnings` carries human-readable degradation info (e.g., MCP gateway:
`["upstream namespace 'github' degraded since 2026-05-06T12:34:56Z"]`).

Both proxies emit Prometheus metrics on `/metrics`:

| metric                                                | scope              |
|------------------------------------------------------|--------------------|
| `agentguard_proxy_requests_total{transport,decision}` | both               |
| `agentguard_proxy_check_duration_seconds{transport}`  | both (histogram)   |
| `agentguard_mcp_upstream_state{namespace,state}`      | mcp_gateway only   |
| `agentguard_llm_buffered_bytes{stream_id}`            | llm_api_proxy only |
| `agentguard_llm_stream_overflow_total`                | llm_api_proxy only |

Metric names are reserved here; the implementing workers (A18/A22) add
the registrations.

---

## 9. Open questions for Phase 4A review

1. **MCP scope dual-check** (`mcp_tool` + mapped scope) vs single-check
   with `meta["mapped_scope"]` — see `MCP_GATEWAY.md` § 4.4. Default
   recommendation: dual-check, behind a `--policy-mode strict|fast`
   flag. This is the most expensive open call.

2. **LLM proxy buffer bound on tool-call accumulation.** Recommendation:
   1 MiB per content block (`--max-buffer-bytes 1048576`). Anything
   larger triggers a synthetic refusal. See `LLM_API_PROXY.md` § 6.

3. **Approval re-submission semantics for the MCP gateway.** When a
   tool call returns `REQUIRE_APPROVAL` and the operator approves, how
   does the agent retry? Recommendation: client retries with
   `_meta.agentguard.approval_id` echoed in the call params; the
   gateway looks up the resolution and either forwards (ALLOW) or
   refuses (DENY). The `_meta` namespace prefix `dev.agentguard/` is
   reserved per the MCP spec's `_meta` rules. Detail in
   `MCP_GATEWAY.md` § 6.

These are the three points the Phase 4A review should sign off before
4B/4C start coding.

---

## 10. References (external)

- **MCP spec, v2025-11-25** — current revision as of 2026-05-06.
  - Specification overview: <https://modelcontextprotocol.io/specification/>
  - Base protocol: <https://modelcontextprotocol.io/specification/2025-11-25/basic>
  - Lifecycle: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
  - Transports: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
  - Tools: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
  - Older revision still in the field: `2024-11-05` (the original v1, what the Python SDK adapter pins to). Streamable HTTP (`2025-03-26`+) supersedes the deprecated HTTP+SSE transport.

- **Anthropic Messages API** — verified 2026-05-06.
  - Reference: <https://platform.claude.com/docs/en/api/messages>

- **OpenAI Chat Completions API** — verified 2026-05-06.
  - Reference: <https://platform.openai.com/docs/api-reference/chat/create>
  - **Unknown — verify against <https://platform.openai.com/docs/api-reference/chat/streaming> at implementation time.** The OpenAI docs returned 403 to the design-time WebFetch attempts. The `LLM_API_PROXY.md` doc cites the canonical streaming shape from prior knowledge; Phase 4C must cross-check the JSON before locking the parser.

- **Prior art (architectural reference, not feature copying)**:
  - `mcp-proxy` (sparfenyuk): <https://github.com/sparfenyuk/mcp-proxy> — stdio↔HTTP bridge.
  - MCP Inspector: <https://github.com/modelcontextprotocol/inspector> — debugging tool.
  - LiteLLM: <https://github.com/BerriAI/litellm> — LLM-proxy structural reference. No router, fallback, or cost-analytics features are imported into AgentGuard v0.5.
  - mitmproxy: <https://github.com/mitmproxy/mitmproxy> — Python interception proxy.
  - go-mitmproxy: <https://github.com/lqqyt2423/go-mitmproxy> — Go equivalent. Confirms streaming-response interception is a tractable Go problem (verified 2026-05-06).
