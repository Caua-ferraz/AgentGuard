# HTTP API Reference

Every endpoint AgentGuard exposes, with auth requirements, request/response shapes, and status codes. Source: `pkg/proxy/server.go`, `pkg/proxy/auth.go`.

```
Base URL: http(s)://<host>:<port>
Default:  http://localhost:8080
```

---

## Auth model

AgentGuard uses two orthogonal auth schemes:

1. **Bearer token** (`Authorization: Bearer <key>`) — for machine-to-machine access. Comes from the `--api-key` flag on the server.
2. **Session cookie + CSRF** — for browser (`/dashboard`) access. `POST /auth/login` with the same API key sets an HttpOnly `ag_session` cookie and a JS-readable `ag_csrf` cookie (double-submit). State-changing endpoints additionally require `X-CSRF-Token: <ag_csrf value>`.

**When the server is started without `--api-key`**, auth middleware is a pass-through and the server binds to `127.0.0.1` only.

| Endpoint | Auth | State-changing (CSRF)? |
|---|---|---|
| `POST /v1/check` | **open by design** | n/a |
| `POST /v1/approve/{id}` | Bearer or session | yes |
| `POST /v1/deny/{id}` | Bearer or session | yes |
| `GET  /v1/status/{id}` | Bearer or session | no |
| `GET  /v1/audit` | Bearer or session | no |
| `POST /auth/login` | open (validates key) | no |
| `POST /auth/logout` | open | no |
| `GET  /health` | open | no |
| `GET  /metrics` | open | no |
| `GET  /dashboard` | open (HTML based on session) | no |
| `GET  /api/pending` | Bearer or session | no |
| `GET  /api/stream` | Bearer or session | no |
| `GET  /api/stats` | Bearer or session | no |

`/v1/check` is intentionally unauthenticated so local agents can call it with zero setup. Gate it at the network layer (reverse proxy allowlist, firewall, service mesh) if your threat model requires.

---

## `POST /v1/check`

The core policy query. The SDKs wrap this.

### Request

```http
POST /v1/check HTTP/1.1
Content-Type: application/json

{
  "agent_id": "my-agent",
  "scope": "shell",
  "command": "rm -rf ./old_data",
  "session_id": "sess-abc",
  "est_cost": 0.12,
  "meta": {"run_id": "123"}
}
```

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

## `POST /v1/approve/{id}` · `POST /v1/deny/{id}`

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

## `GET /v1/status/{id}`

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

## `GET /v1/audit`

Query the audit log.

### Query parameters

| Param | Type | Default | Notes |
|---|---|---|---|
| `agent_id` | string | — | Exact match. |
| `session_id` | string | — | Exact match. |
| `decision` | string | — | `ALLOW`, `DENY`, `REQUIRE_APPROVAL`. |
| `scope` | string | — | Exact match on `request.scope`. |
| `limit` | int | `auditDefaultLimit` (default 50) | Silently clamped at `auditMaxLimit` (default 200). `<1` or non-integer → `400`. |
| `offset` | int | `0` | Skip N matching entries. Must be ≥ 0. |

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
{ "status": "ok", "version": "0.4.1" }
```

Always `200` once the HTTP server is accepting connections. Use for liveness probes (see [`DEPLOYMENT.md`](DEPLOYMENT.md)).

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

## Common error patterns

| Symptom | Cause | Fix |
|---|---|---|
| `401` on every gated endpoint | Server has `--api-key`; client sending none. | Set `Authorization: Bearer …` or log in. |
| `403` on POST approve/deny from dashboard | Session valid, CSRF missing. | Echo `document.cookie['ag_csrf']` as `X-CSRF-Token`. |
| `413` on `/v1/check` | Body > 1 MB. | Trim `meta` payloads or raise `proxy.request.max_body_bytes`. |
| `503` on `/auth/login` | 1024 concurrent sessions. | Probing bot; firewall it. |
| SSE connection drops every minute | Idle proxy timeout upstream. | Set `proxy_read_timeout 3600s` on reverse proxy. |

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for the full symptom-keyed catalog.

---

## Related docs

- [`docs/CLI.md`](CLI.md) — the CLI subcommands that wrap these endpoints.
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — reverse proxy / TLS / CORS.
- [`docs/OBSERVABILITY.md`](OBSERVABILITY.md) — full `/metrics` reference.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — schema for policy evaluation behind `/v1/check`.
