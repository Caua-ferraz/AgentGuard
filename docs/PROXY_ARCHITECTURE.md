# Proxy Architecture

This doc covers the cross-cutting decisions that apply to **both**
AgentGuard proxies. The two follow-up docs cover the proxy-specific wire
format and data plane:

- [`docs/MCP_GATEWAY.md`](./MCP_GATEWAY.md) — `agentguard-mcp-gateway`
- [`docs/LLM_API_PROXY.md`](./LLM_API_PROXY.md) — `agentguard-llm-proxy`

Read this one first.

---

## 1. The hero claim, restated honestly

AgentGuard exposes its firewall as a **wire-level enforcement boundary**
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

The Python and TypeScript SDKs are the **compatibility tier** for
direct callers: code paths that talk to AgentGuard via `Guard.check`
remain a first-class integration, but they are not the only way to
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
approval queue, or SSE bus. They both consume primitives provided by
the central server packages.

### 2.1 Policy via `pkg/policy.PolicyProvider`

Both proxies hold a `*policy.Engine` constructed from a
`policy.PolicyProvider`. AgentGuard wires `FilePolicyProvider`; since
v0.6 the store-backed multi-tenant provider drops in via the same
interface (`Get` / `Watch` / `Validate` / `Close`, see
`pkg/policy/provider.go`).

Each tool/API call resolves to **one** `Engine.Check(req, tenantID)` call.
The `tenantID` defaults to `"local"` (the proxies' `--tenant-id` flag);
the proxies plumb it via the existing `pkg/proxy/tenant.go`
`WithTenantID` / `TenantIDFromContext` contract.

### 2.2 Audit via `pkg/audit.BufferedAsyncLogger`

Both proxies write through `BufferedAsyncLogger` so audit I/O does not
block the data path. The wrapper handles disk-overflow and worker-pool
draining; the proxies just call `Logger.Log(entry)`.

The `audit.Entry` includes `Scope`, `Decision`, `Rule`, `Reason`,
`Meta`, and `Transport` — see § 3.

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

### 2.5 Gate client via `pkg/internal/gateclient`

The wire-level `/v1/check` contract is implemented **once** in
`pkg/internal/gateclient` and consumed by both proxies: the HTTP call
shape (tenant-scoped URL, schema_version stamping, bearer auth, 64 KiB
response cap), the fail-mode translation, the shared `Decision` type
(re-exported by each proxy via type alias), and the shared CLI flag
set + validation (`--guard-url`, `--api-key`, `--tenant-id`,
`--fail-mode`, `--log-level`, `--policy`, with the AGENTGUARD_API_KEY
env fallback). Each proxy keeps only its own scope-mapping and
argument-projection logic. The package is internal — it is substrate,
not public API; the per-binary synthetic Rule strings remain each
proxy's stable contract.

## 3. Audit transport tag

Every audit entry is chipped by **how the agent talked to the
firewall**. Three values:

| transport         | source                                         |
|-------------------|------------------------------------------------|
| `mcp_gateway`     | `agentguard-mcp-gateway`                       |
| `llm_api_proxy`   | `agentguard-llm-proxy`                         |
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
  time — this matches the only writer path that existed before the
  proxies shipped.
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

The proxies ship as two binaries alongside the central `agentguard`
binary:

| binary                       | role                                                  |
|------------------------------|-------------------------------------------------------|
| `agentguard`                 | central server (`serve`, `validate`, `audit`, etc.)   |
| `agentguard-mcp-gateway`     | stdio bridge, child of an MCP host (Claude Desktop)   |
| `agentguard-llm-proxy`       | HTTP server, sidecar for OpenAI/Anthropic-compatible callers |

All three live under `cmd/`:

```
cmd/agentguard/main.go
cmd/agentguard-mcp-gateway/main.go
cmd/agentguard-llm-proxy/main.go
```

Each `cmd/agentguard-*/main.go` is a **thin entry point**. Real logic
lives in `pkg/mcpgw/` and `pkg/llmproxy/`, consuming the existing
`pkg/policy`, `pkg/audit`, `pkg/proxy`, `pkg/notify`, and `pkg/metrics`
packages.

### 4.2 Why not subcommands of `agentguard`?

Settled decision: three separate binaries. The MCP gateway **must** be
one — MCP clients spawn it via `claude_desktop_config.json`'s `command`
field with stdin/stdout reserved for JSON-RPC, which cannot coexist with
a long-running HTTP daemon in the same process. The LLM proxy is
separate for failure isolation and so sidecar deployments can ship proxy
fixes without redeploying the central server. Versions stay synced via
`bump-version.sh` (§ 4.3).

### 4.3 Versioning

All three binaries share a single release version. `bump-version.sh`
sed-replaces the version string across `cmd/agentguard/main.go`,
`cmd/agentguard-mcp-gateway/main.go`, `cmd/agentguard-llm-proxy/main.go`,
and the SDK manifests.

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
OPENAI_BASE_URL=http://127.0.0.1:8081/v1
ANTHROPIC_BASE_URL=http://127.0.0.1:8081
```

Note the asymmetry: the OpenAI SDK appends paths under `OPENAI_BASE_URL`
including the `/v1` segment that the proxy registers (`POST /v1/chat/completions`),
so the env var must include `/v1`. The Anthropic SDK convention is the opposite —
`ANTHROPIC_BASE_URL` is the *origin* and the SDK appends `/v1/messages` itself,
so the env var must NOT include a `/v1` suffix.

…and Claude Desktop's `claude_desktop_config.json` points at the gateway
binary.

### 5.2 Single-host server

One host runs `agentguard serve`. Gateways and proxies run as sidecars
on the same host or on agent-facing hosts pointing at the central
server's `/v1/check` over the network. Set `--api-key` on the central
server and pass it to every gateway/proxy via `--api-key`.

### 5.3 Multi-tenant (shipped in v0.6)

Multi-tenancy is supported on a single central server since v0.6:

- per-tenant policies live in the durable store, managed via
  `agentguard tenant put/list/rm` (see [`CLI.md`](CLI.md#agentguard-tenant-v06)),
- tenant URL routing (`/v1/t/{tenant}/…`) is live in `pkg/proxy/tenant.go`,
- the approval queue, rate limiter, cost accounting, and audit query are
  all sharded by tenant ID,
- the proxies stamp their tenant via `--tenant-id` (default `local`).

### 5.4 Multi-node (shipped in v1.0, PostgreSQL)

Multiple central-server replicas can share state — tenant policies,
approvals, rate-limit and cost consumption — by pointing `--store-dsn` at
one PostgreSQL and giving each replica a `--node-id`. Each node's memory
stays authoritative for its own `/v1/check` decisions (the hot path never
performs a synchronous database call); a background reconciler merges the
other nodes' state in every `--reconcile-interval` (default 2s). The
consequences of that design are documented, not hidden: distributed
rate/cost limiting is bounded-overshoot rather than globally strict, and
cross-node approval visibility lags by at most one interval. See
[`OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments) and
[`COMPATIBILITY.md`](COMPATIBILITY.md#topology).

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
| `deny`                      | synthesise `DENY` with `Rule="deny:<gateway>:fail_closed"` (LLM proxy emits `deny:llm_api_proxy:fail_closed`; MCP gateway emits `deny:gateway:fail_closed`). The agent sees a deny. **Default.** |
| `allow`                     | synthesise `ALLOW` with `Rule="allow:<gateway>:fail_open"`. **Use only in trusted dev environments.** Logged as WARN at startup. |
| `fail-closed-with-audit`    | synthesise `DENY` with a **distinct** `Rule="deny:<gateway>:fail_closed_audit"` so dashboards can break out central-server-outage events from plain fail-closed denials, **and append the denial to a local fallback audit file** (`--fail-audit-log`, default `agentguard-fail-audit.jsonl`, canonical `audit.Entry` JSONL) so the outage window stays reconstructable without the central server. |

Independent of `--fail-mode`: when `/v1/check` answers 2xx but with an
**unrecognised decision string**, both proxies deny with the stable
`Rule="deny:<gateway>:invalid_response"` (`deny:llm_api_proxy:
invalid_response` / `deny:gateway:invalid_response`) so a misbehaving
or version-skewed central server is visible on dashboards instead of
silently passing through.

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

The two proxies have very different surfaces here:

- **LLM API Proxy** registers **`/healthz`** (note: not `/health`) returning
  a flat status object:

  ```json
  {
    "status": "ok",
    "version": "0.9.0",
    "transport": "llm_api_proxy",
    "uptime_s": 412
  }
  ```

  No `guard_reachable` field, no `warnings` array. The proxy does **not**
  expose its own `/metrics` endpoint; per-request metrics flow through
  the central server's `/v1/check` instrumentation (see § 8.1 below).
- **MCP Gateway** is a stdio JSON-RPC binary with **no HTTP surface at
  all** — no `/health`, no `/metrics`. Operators inspect it via the
  process's stderr log lines. Health is implicit in whether the host
  client (Claude Desktop, Cursor, etc.) reports the gateway as alive.

### 8.1 Where the metrics actually live

Per-request gating metrics are emitted on the **central server's**
`/metrics` endpoint, distinguished by the `Entry.Transport` audit field:

| metric                                                       | source                            |
|--------------------------------------------------------------|-----------------------------------|
| `agentguard_checks_total`                                    | central server                    |
| `agentguard_request_duration_ms`                             | central server                    |
| `agentguard_llmproxy_buffer_overflow_total`                  | LLM API Proxy (process-local)     |
| `agentguard_llmproxy_streams_active`                         | LLM API Proxy (process-local)     |

Process-local LLM-proxy series (`agentguard_llmproxy_*`) are recorded in
the proxy's in-process registry but are **not exported anywhere yet** —
no `/metrics` endpoint, no periodic log dump. Until an export path
ships, treat them as internal counters; observable proxy behaviour
(denials, overflows surfacing as denials) lands in the central server's
audit stream and metrics.

The MCP gateway has no scrape surface; its decisions surface in the
central server's audit stream via `Entry.Transport == "mcp_gateway"`.

---

## 9. Notable cross-cutting decisions

A few cross-cutting design decisions are worth surfacing in one place;
the proxy-specific docs cover the full detail.

1. **MCP scope dual-check** (`mcp_tool` + mapped scope) is enabled by
   default behind a `--policy-mode strict|fast` flag. Dual-check honours
   existing scope rules without operators having to duplicate them as
   `mcp_tool` rules. See `MCP_GATEWAY.md` § 4.4.

2. **LLM proxy buffer bound on tool-call accumulation** is 1 MiB per
   content block (`--max-buffer-bytes 1048576`). Anything larger
   triggers a synthetic refusal. See `LLM_API_PROXY.md` § 6.

3. **Approval re-submission for the MCP gateway.** When a tool call
   returns `REQUIRE_APPROVAL` and the operator approves, the client
   retries with `_meta.dev.agentguard/approval_id` echoed in the call
   params; the gateway looks up the resolution and either forwards
   (ALLOW) or refuses (DENY). The `_meta` namespace prefix
   `dev.agentguard/` is reserved per the MCP spec's `_meta` rules.
   Detail in `MCP_GATEWAY.md` § 6.

---

## 10. References (external)

- **MCP spec** — <https://modelcontextprotocol.io/specification/> (gateway targets `2025-11-25`; the Python SDK adapter pins the older `2024-11-05`).
- **Anthropic Messages API** — <https://platform.claude.com/docs/en/api/messages>.
- **OpenAI Chat Completions API** — <https://platform.openai.com/docs/api-reference/chat/create> (streaming wire shape cross-checked in `LLM_API_PROXY.md` § 5.1).
- **Prior art consulted** (architectural reference only): sparfenyuk/mcp-proxy, MCP Inspector, LiteLLM, mitmproxy, go-mitmproxy.
