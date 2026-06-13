# HTTP API Reference

Every endpoint AgentGuard exposes, with auth requirements, request/response shapes, and status codes. Source: `pkg/proxy/server.go`, `pkg/proxy/auth.go`, `pkg/proxy/tenant.go`.

```
Base URL: http(s)://<host>:<port>
Default:  http://localhost:8080
```

---

## URL families: legacy vs tenant-aware (v0.5+)

Every operational endpoint is exposed at **both** of these paths:

| Family | Pattern | Tenant resolution |
|---|---|---|
| Legacy | `/v1/<suffix>` | Always evaluates against tenant `local`. Wire-compatible with v0.4.x clients. |
| Tenant-aware | `/v1/t/{tenant}/<suffix>` | `{tenant}` is extracted from the URL and validated by the engine's `PolicyProvider`. |

Since v0.6, `{tenant}` is validated against the policy registry: `local` is always recognised (the bundled file policy), and additional tenants are registered with `agentguard tenant put <id> --policy <yaml>` (requires `--persist`). An unregistered tenant returns `404` with body `{"error":"tenant not found"}`; a store infrastructure failure during tenant resolution returns `500 {"error":"policy provider error"}`. `/v1/check` and `/v1/t/local/check` remain identical in responses, audit entries, and headers.

**Tenant ID format constraints:**
- Non-empty after URL-decoding.
- URL-safe characters only — SDKs `URL-encode` the value before building the path, so reserved characters (`/`, spaces, etc.) are escaped to `%XX`.
- Must be registered (or `local`) — unknown tenants 404.

**Runtime state is partitioned by tenant (v0.6+).** Each tenant gets isolated approvals (no cross-tenant existence oracle), rate-limit buckets (`scope:tenant:agent` keys), session-cost accumulators, SSE feeds, and tenant-scoped audit reads — `/v1/t/<tenant>/audit` only returns that tenant's entries.

The wire format ([`docs/WIRE_PROTOCOL.md`](WIRE_PROTOCOL.md)) does **not** change between families: the same request body and response shape (`schema_version: "v1"`) flow through both.

The legacy paths are not deprecated. v0.5 documents both as supported.

---

## Auth model

AgentGuard uses two orthogonal auth schemes:

1. **Bearer token** (`Authorization: Bearer <key>`) — for machine-to-machine access. Comes from the `--api-key` flag on the server.
2. **Session cookie + CSRF** — for browser (`/dashboard`) access. `POST /auth/login` with the same API key sets an HttpOnly `ag_session` cookie and a JS-readable `ag_csrf` cookie (double-submit). State-changing endpoints additionally require `X-CSRF-Token: <ag_csrf value>`.

**When the server is started without `--api-key`**, auth middleware is a pass-through and the server binds to `127.0.0.1` only.

Auth posture is **identical** across both URL families — the middleware is URL-agnostic, so a token / session that works against `/v1/audit` works against `/v1/t/local/audit` and vice versa.

| Endpoint (legacy) | Endpoint (tenant-aware) | Auth | State-changing (CSRF)? |
|---|---|---|---|
| `POST /v1/check` | `POST /v1/t/{tenant}/check` | **open by design** | n/a |
| `POST /v1/approve/{id}` | `POST /v1/t/{tenant}/approve/{id}` | Bearer or session | yes |
| `POST /v1/deny/{id}` | `POST /v1/t/{tenant}/deny/{id}` | Bearer or session | yes |
| `GET  /v1/status/{id}` | `GET  /v1/t/{tenant}/status/{id}` | Bearer or session | no |
| `GET  /v1/audit` | `GET  /v1/t/{tenant}/audit` | Bearer or session | no |
| `GET  /api/pending` | `GET  /v1/t/{tenant}/api/pending` | Bearer or session | no |
| `GET  /api/stream` | `GET  /v1/t/{tenant}/api/stream` | Bearer or session | no |
| `GET  /api/stats` | `GET  /v1/t/{tenant}/api/stats` | Bearer or session | no |
| `GET  /v1/health` | `GET  /v1/t/{tenant}/health` | open | no |
| `POST /auth/login` | — | open (validates key) | no |
| `POST /auth/logout` | — | open | no |
| `GET  /health` | — | open | no |
| `GET  /metrics` | — | open | no |
| `GET  /dashboard` | — | open (HTML based on session) | no |

`/v1/check` is intentionally unauthenticated so local agents can call it with zero setup. Gate it at the network layer (reverse proxy allowlist, firewall, service mesh) if your threat model requires.

---

## `POST /v1/check` · `POST /v1/t/{tenant}/check`

The core policy query. The SDKs wrap this. Both URL families produce identical responses; pick whichever matches your deployment topology.

### Request

```http
POST /v1/check HTTP/1.1
Content-Type: application/json

{
  "schema_version": "v1",
  "agent_id": "my-agent",
  "scope": "shell",
  "command": "rm -rf ./old_data",
  "session_id": "sess-abc",
  "est_cost": 0.12,
  "meta": {"run_id": "123"}
}
```

The tenant-aware variant is exactly the same body sent to a different path:

```http
POST /v1/t/local/check HTTP/1.1
Content-Type: application/json

{ "schema_version": "v1", "scope": "shell", "command": "ls -la" }
```

`schema_version` may be omitted (the server defaults to `"v1"`); any other value is rejected with `400` and an error body `{"error":"unsupported schema_version; expected v1","received":"..."}`. See [`docs/WIRE_PROTOCOL.md`](WIRE_PROTOCOL.md) for the full versioning contract.

| Field | Type | Required | Notes |
|---|---|---|---|
| `agent_id` | string | yes | Used for per-agent overrides, rate-limit keying, audit filtering. |
| `scope` | string | yes | `shell`, `filesystem`, `network`, `browser`, `cost`, `data`, or any custom string. |
| `command` | string | — | For `shell` scope (required to match `pattern`). |
| `action` | string | — | For `filesystem` scope (required alongside `path`). |
| `path` | string | — | For `filesystem`. Normalized with `filepath.Clean + ToSlash`. |
| `domain` | string | — | For `network` / `browser`. |
| `url` | string | — | For `network` / `browser`. |
| `session_id` | string | — | For `cost` scope accumulator. |
| `est_cost` | float | — | For `cost` scope. Negative values denied. |
| `meta` | object | — | Free-form string→string map; logged as-is. |

Body is limited to `MaxRequestBodyBytes` (default 1 MB; configurable via `proxy.request.max_body_bytes`). Exceeded → `413`.

### Response

```json
{
  "decision": "ALLOW",
  "reason": "Allowed by shell rule",
  "matched_rule": "allow:shell:<pattern>",
  "approval_id": "",
  "approval_url": ""
}
```

| Field | Present when |
|---|---|
| `decision` | always — `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. |
| `reason` | always. |
| `matched_rule` | always except default-deny fall-through. |
| `approval_id` / `approval_url` | only when `decision == REQUIRE_APPROVAL`. |

### Response headers

| Header | Unit | What it measures |
|---|---|---|
| `X-AgentGuard-Policy-Ms` | ms (3-decimal) | Time in `Engine.Check`. |
| `X-AgentGuard-Audit-Ms` | ms (3-decimal) | Time in `Logger.Log`. |
| `X-AgentGuard-Total-Ms` | ms (3-decimal) | End-to-end server processing. |

### Status codes

| Code | Meaning |
|---|---|
| `200` | Policy evaluated (ALLOW / DENY / REQUIRE_APPROVAL — inspect body). |
| `400` | Malformed JSON or missing `scope`/`agent_id`. |
| `413` | Body exceeds `MaxRequestBodyBytes`. |
| `500` | `crypto/rand` failure while generating an approval ID. Never silently returns a deterministic ID. |

Rate-limit denials return `200` with `decision: "DENY"` and `matched_rule: "deny:ratelimit:<scope>"` — clients should treat that as a logical deny, not a transport error.

---

## `POST /v1/approve/{id}` · `POST /v1/deny/{id}` · tenant-aware mirrors

Tenant-aware mirrors live at `POST /v1/t/{tenant}/approve/{id}` and `POST /v1/t/{tenant}/deny/{id}`. Auth posture and request body are identical.

Resolve a pending approval. Idempotent: resolving an already-resolved ID returns the existing state.

### Request (Bearer)

```http
POST /v1/approve/ap_1a2b…890 HTTP/1.1
Authorization: Bearer $KEY
```

### Request (session + CSRF)

```http
POST /v1/approve/ap_1a2b…890 HTTP/1.1
Cookie: ag_session=…; ag_csrf=xyz…
X-CSRF-Token: xyz…
```

### Response

```json
{ "status": "approved" }    // or "denied"
```

### Status codes

| Code | Meaning |
|---|---|
| `200` | Resolved. |
| `401` | Missing Bearer or invalid session. |
| `403` | Session valid but CSRF token missing/mismatched. |
| `404` | No such approval ID. |
| `409` | Already resolved with a different decision (some builds return `200` with original decision — inspect `status`). |

---

## `GET /v1/status/{id}` · tenant-aware mirror

Tenant-aware mirror: `GET /v1/t/{tenant}/status/{id}`. Auth posture and response body are identical.

Poll for approval resolution. This is what `guard.wait_for_approval` / `guard.waitForApproval` hits.

### Response

```json
{
  "id": "ap_1a2b…",
  "resolved": true,
  "decision": "ALLOW",
  "request": { /* original ActionRequest */ },
  "created_at": "2026-04-19T12:00:00Z"
}
```

`resolved: false` → still pending. Poll every 2 s (SDK default).

### Status codes

| Code | Meaning |
|---|---|
| `200` | Found. |
| `401` | Unauthenticated. |
| `404` | No such approval ID (possibly evicted or lost to restart). |

---

## `GET /v1/audit` · tenant-aware mirror

Tenant-aware mirror: `GET /v1/t/{tenant}/audit`. Auth posture and query parameters are identical. Since v0.6 the tenant-aware URL is scoped to its tenant's entries; the legacy `/v1/audit` serves the `local` tenant.

Query the audit log.

### Query parameters

| Param | Type | Default | Notes |
|---|---|---|---|
| `agent_id` | string | — | Exact match. |
| `session_id` | string | — | Exact match. |
| `decision` | string | — | `ALLOW`, `DENY`, `REQUIRE_APPROVAL`. |
| `scope` | string | — | Exact match on `request.scope`. |
| `limit` | int | `auditDefaultLimit` (default 100) | Silently clamped at `auditMaxLimit` (default 1000). `<1` or non-integer → `400`. |
| `offset` | int | `0` | Skip N matching entries. Must be ≥ 0. |
| `transport` | string | — | Filter on the `Entry.Transport` audit field. Recognised values: `sdk`, `mcp_gateway`, `llm_api_proxy`. Pre-v0.5 entries have no transport tag and are excluded when this filter is set. |

### Response

Array of entries (JSON Lines rows as JSON objects):

```json
[
  {
    "timestamp": "2026-04-19T12:03:44Z",
    "agent_id": "researcher-01",
    "request": {"scope":"shell","command":"rm -rf /","agent_id":"researcher-01"},
    "result":  {"decision":"DENY","reason":"…","matched_rule":"deny:shell:…"}
  }
]
```

### Pagination

Use `limit` + `offset` for stable pagination:

```bash
curl -s -H "Authorization: Bearer $K" \
  "http://localhost:8080/v1/audit?limit=100&offset=200"
```

For large exports, prefer `curl` over the CLI subcommand — the CLI doesn't expose `offset`.

---

## `POST /auth/login`

Exchange an API key for a browser session.

### Request

```json
{ "api_key": "<key>" }
```

### Response

```json
{
  "csrf_token": "xyz…",
  "expires_at": "2026-04-19T13:00:00Z"
}
```

Sets cookies:

| Cookie | Flags | Purpose |
|---|---|---|
| `ag_session` | `HttpOnly`, `Secure` (if TLS or `--tls-terminated-upstream`), `SameSite=Strict`, `Path=/` | Opaque session ID. |
| `ag_csrf` | `Secure` (same rules), `SameSite=Strict`, `Path=/` — **not** HttpOnly so JS can read it | Double-submit CSRF token. |

### Status codes

| Code | Meaning |
|---|---|
| `200` | Session created. |
| `401` | Invalid API key. |
| `503` | `MaxSessions=1024` reached; `Retry-After: 5`. |

Constant-time compare is used on the submitted key (`subtle.ConstantTimeCompare`).

---

## `POST /auth/logout`

Destroys the current session and expires both cookies.

```http
POST /auth/logout HTTP/1.1
Cookie: ag_session=…
```

Returns `200` with no body. Safe to call with no session (no-op).

---

## `GET /health`

```json
{ "status": "ok", "version": "0.5.1" }
```

Always `200` once the HTTP server is accepting connections. Use for liveness probes (see [`DEPLOYMENT.md`](DEPLOYMENT.md)). The legacy `/health` body shape is unchanged in v0.5 — for the richer operator probe see `/v1/health` below.

---

## `GET /v1/health` · `GET /v1/t/{tenant}/health`

Operator-grade health endpoint introduced in v0.5. Richer than `/health`: includes the resolved tenant, uptime, last-request and last-policy-load timestamps, and a warnings array.

### Response

```json
{
  "status": "ok",
  "version": "0.5.1",
  "tenant": "local",
  "last_request_at": "2026-05-05T19:04:54.646Z",
  "last_policy_load_at": "2026-05-05T19:04:53.549Z",
  "uptime_seconds": 1,
  "warnings": []
}
```

| Field | Notes |
|---|---|
| `status` | `"ok"` or `"degraded"` *(v0.7)*. Degraded means the process serves but a durability signal is unhealthy — currently an audit buffered-overflow backlog (entries durable on disk but not yet queryable). The HTTP code stays `200` either way so liveness probes don't flap; act on the field, not the code. |
| `tenant` | Echoes the resolved tenant — `"local"` on `/v1/health`, `{tenant}` from the path on the tenant-aware variant. |
| `last_request_at` | RFC 3339 with millisecond precision; omitted (`undefined`) when no traffic since boot. |
| `last_policy_load_at` | RFC 3339 with millisecond precision; stamped by the engine on every successful provider load. |
| `warnings` | `"no traffic in 5m+"`, `"policy not reloaded in 24h+"`, plus metrics-derived signals *(v0.7)*: `"audit: N corrupt line(s) skipped during queries"`, `"audit: N entry(ies) in buffered overflow backlog"`, `"notify: N notification(s) dropped (queue_full)"`. The metrics-derived signals are process-wide, not per-tenant. |

### Status codes

| Code | Meaning |
|---|---|
| `200` | Tenant resolved; body returned. |
| `404` | Tenant unknown (only on the `/v1/t/{tenant}/health` variant; the tenant must be `local` or registered via `agentguard tenant put`). Body: `{"error":"tenant not found"}`. |

---

## `GET /metrics`

Prometheus text exposition format. Unauthenticated. Full metric catalog in [`OBSERVABILITY.md`](OBSERVABILITY.md).

```bash
curl -s http://localhost:8080/metrics | head
# HELP agentguard_checks_total Total number of policy check requests
# TYPE agentguard_checks_total counter
# agentguard_checks_total 12034
# ...
```

---

## `GET /api/pending`

JSON array of unresolved approvals. Same auth as other dashboard endpoints.

```json
[
  {
    "id": "ap_1a2b…",
    "request": {"scope":"shell","command":"rm -rf /","agent_id":"researcher-01"},
    "created_at": "2026-04-19T12:03:44Z",
    "resolved": false
  }
]
```

---

## `GET /api/stats`

O(1) atomic counter snapshot. Cheap; safe for per-page-load polling.

```json
{
  "total_checks": 12034,
  "total_allowed": 10998,
  "total_denied":  842,
  "total_approvals": 194,
  "pending_count": 3
}
```

Prefer `/api/stream` (SSE) for real-time deltas — only call `/api/stats` on page load and on SSE reconnect.

---

## `GET /api/stream`

Server-Sent Events. Used by the dashboard for live updates.

```http
GET /api/stream HTTP/1.1
Authorization: Bearer $KEY
Accept: text/event-stream
```

Response headers set:

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

Events:

```
data: {"type":"check","timestamp":"2026-04-19T12:03:44Z","request":{…},"result":{…}}\n\n
```

| `type` | Fires on |
|---|---|
| `check` | Every `/v1/check` response (any decision). |
| `approval_required` | REQUIRE_APPROVAL decision stored in queue. |
| `denied` | DENY decision (also emits `check`). |
| `resolved` | `/v1/approve/{id}` or `/v1/deny/{id}` resolved an entry. |

Subscriber channel buffer is `64` (`SSEChannelBufferSize`). Slow consumers drop events — counted in `agentguard_sse_events_dropped_total{reason="slow_consumer"}`.

**The client must handle disconnects.** There is no server-side auto-reconnect; use `EventSource` in the browser (which auto-reconnects) or handle `io.EOF` in a custom consumer and refetch `/api/stats` on reconnect.

---

## `GET /dashboard`

Renders `loginHTML` if no valid session, else `dashboardHTML`. Sets security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store
```

The dashboard JS loads `/api/stats`, `/api/pending`, `/v1/audit?limit=200`, and subscribes to `/api/stream`. CSRF token is read from `document.cookie['ag_csrf']` and echoed as `X-CSRF-Token` on approve/deny.

---

## CORS

`withCORS` middleware reflects `Origin`:

- **Strict mode** (`--allowed-origin https://app.example`): only the exact origin is reflected.
- **Permissive-localhost mode** (default, `--allowed-origin` unset): reflects any `http://localhost:*` / `http://127.0.0.1:*` origin. The trailing `:` is mandatory — `localhost.evil.com` does not match.

`Vary: Origin` is always set. OPTIONS preflight short-circuits `204`.

Safe because session cookies are `SameSite=Strict` and state-changing endpoints require `X-CSRF-Token`.

---

## Error envelope

Most error responses are `text/plain` from `http.Error` (e.g. `"Method not allowed\n"`). The structured JSON envelope is used by:

- Tenant-routing 404 (`/v1/t/<unknown>/<any>`): `{"error":"tenant not found"}`
- Tenant-routing 500 (provider infrastructure failure): `{"error":"policy provider error"}`
- Health 404 (`/v1/t/<unknown>/health`): `{"error":"tenant not found"}`
- Recovered panic 500: `{"error":"internal server error"}`
- `/v1/check` schema mismatch 400: `{"error":"unsupported schema_version; expected v1","received":"v2"}`

Other error responses (auth 401/403, `/v1/check` 400 for bad JSON, audit 400 for bad `?limit`) are plain-text and may differ between releases — programmatic clients should rely on the HTTP status code rather than message-text matching.

---

## Common error patterns

| Symptom | Cause | Fix |
|---|---|---|
| `401` on every gated endpoint | Server has `--api-key`; client sending none. | Set `Authorization: Bearer …` or log in. |
| `403` on POST approve/deny from dashboard | Session valid, CSRF missing. | Echo `document.cookie['ag_csrf']` as `X-CSRF-Token`. |
| `404` on every `/v1/t/<x>/...` | Tenant `<x>` not registered. | Register it (`agentguard tenant put <x> --policy <yaml>`, requires `--persist`) or use `/v1/...` / `/v1/t/local/...`. |
| `413` on `/v1/check` | Body > 1 MB. | Trim `meta` payloads or raise `proxy.request.max_body_bytes`. |
| `503` on `/auth/login` | 1024 concurrent sessions. | Probing bot; firewall it. |
| SSE connection drops every minute | Idle proxy timeout upstream. | Set `proxy_read_timeout 3600s` on reverse proxy. |

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for the full symptom-keyed catalog.

---

## SDK tenant_id (v0.5+)

Both SDKs accept an optional tenant identifier that switches every HTTP call to the tenant-aware URL family.

**Python:**

```python
from agentguard import Guard

# Default — legacy /v1/... URLs.
g = Guard("http://localhost:8080", agent_id="my-agent")

# Tenant-aware — /v1/t/acme/... URLs.
g = Guard("http://localhost:8080", agent_id="my-agent", tenant_id="acme")

# Env var fallback. Empty string explicitly suppresses the env var.
# Env: AGENTGUARD_TENANT_ID=acme
g = Guard("http://localhost:8080", agent_id="my-agent")  # → /v1/t/acme/...
g = Guard("http://localhost:8080", agent_id="my-agent", tenant_id="")  # → /v1/...
```

`tenant_id="local"` is treated as an alias for the legacy URL family.

**TypeScript:**

```typescript
import { AgentGuard } from "@agentguard/sdk";

// Default — legacy /v1/... URLs.
const g = new AgentGuard({ baseUrl: "http://localhost:8080", agentId: "my-agent" });

// Tenant-aware — /v1/t/acme/... URLs.
const g = new AgentGuard({
  baseUrl: "http://localhost:8080",
  agentId: "my-agent",
  tenantId: "acme",
});
```

Same env-var fallback (`AGENTGUARD_TENANT_ID`) and same `"local"` alias semantics as Python.

---

## Related docs

- [`docs/CLI.md`](CLI.md) — the CLI subcommands that wrap these endpoints.
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — reverse proxy / TLS / CORS.
- [`docs/OBSERVABILITY.md`](OBSERVABILITY.md) — full `/metrics` reference.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — schema for policy evaluation behind `/v1/check`.
- [`docs/WIRE_PROTOCOL.md`](WIRE_PROTOCOL.md) — `schema_version` contract and JSON-Schema source of truth.
