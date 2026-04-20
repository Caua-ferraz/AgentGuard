# Dashboard Guide

The embedded web UI at `/dashboard`. Zero-dep HTML/JS bundled in the binary — no separate frontend to deploy.

![AgentGuard dashboard layout](assets/dashboard.svg)

---

## When to use it

- **Triaging approvals** in real time as agents request them.
- **Spot-checking audit decisions** without grepping `audit.jsonl`.
- **Confirming the proxy is alive** when you can't reach `/health` directly.

For structured dashboards (Grafana, Datadog, etc.), use `/metrics` — see [`OBSERVABILITY.md`](OBSERVABILITY.md). The built-in dashboard is for humans, not SLOs.

---

## Enabling it

```bash
agentguard serve --dashboard --api-key $KEY
```

Without `--api-key`, the dashboard is effectively unauthenticated — everyone on `127.0.0.1` (the only bind surface in that mode) sees everything. In production you always want `--api-key`.

---

## Login flow

1. Browse to `http(s)://<host>:<port>/dashboard`.
2. Server renders `loginHTML` with a single `<input>` for the API key.
3. Submit → `POST /auth/login` with `{api_key: "..."}`.
4. On success, the server sets two cookies:
   - `ag_session` — HttpOnly, `SameSite=Strict`, opaque ID. Browser JS cannot read this.
   - `ag_csrf` — NOT HttpOnly, `SameSite=Strict`, matches the server's stored CSRF token. JS reads it and echoes it on mutating requests.
5. Both cookies get `Secure` when `r.TLS != nil` **or** `--tls-terminated-upstream` is set. Otherwise `Secure` is omitted (still safe because HTTPS is enforced upstream).
6. Redirect to `/dashboard` — now renders `dashboardHTML`.

### "Login loops me back to login"

Means cookies aren't sticking. Three usual culprits:

- `Secure` cookie flag emitted but browser sees plain HTTP (a reverse proxy is terminating TLS but you didn't set `--tls-terminated-upstream`). Fix: start server with that flag.
- Cookies dropped by browser because of a `SameSite=Strict` + cross-site iframe context. Don't embed the dashboard in a cross-site iframe.
- `MaxSessions=1024` hit — `/auth/login` returns `503`. Unlikely outside of a probing bot.

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for deeper diagnosis.

---

## Layout

The dashboard is a single HTML page (`dashboardHTML` in `pkg/proxy/server.go`) that:

1. Fetches `/api/stats` once on page load.
2. Fetches `/api/pending` once on page load.
3. Fetches `/v1/audit?limit=200` once on page load (server clamps to `auditMaxLimit`, typically 200).
4. Subscribes to `/api/stream` for live deltas.

Sections you'll see:

| Section | Source | Purpose |
|---|---|---|
| **Stats bar** | `/api/stats` + SSE | `checks / allowed / denied / approvals / pending`. Updates live on each `check` event. |
| **Pending Approvals** | `/api/pending` + SSE | Each entry shows scope, command/path/domain, agent, timestamp. Approve / Deny buttons. |
| **Audit** | `/v1/audit?limit=200` | Most recent decisions. No auto-refresh — reload the page for a newer slice. |
| **LIVE badge** | EventSource state | Green when `EventSource.readyState === OPEN`. |

---

## Approving / denying from the UI

Each pending item has two buttons. Clicking either:

1. Reads `document.cookie['ag_csrf']` for the CSRF token.
2. `fetch('/v1/approve/{id}' or '/v1/deny/{id}', { method: 'POST', headers: { 'X-CSRF-Token': csrf } })`.
3. On success the server broadcasts a `resolved` SSE event; the item fades from the pending list.

If the fetch returns `401`/`403`, `agFetch` (the dashboard's helper) redirects to `/dashboard` — forcing re-login. This is the symptom of an expired session (see below).

---

## Audit tab

Shows timestamp, decision, scope, agent, and the action's key identifier (command / path / domain). Click an entry to expand JSON details (if built into your dashboard build) or `curl` the audit API for the full record.

Dashboard always requests `limit=200`; the server clamps at `auditMaxLimit` (default 200, configurable via `proxy.audit.max_limit`). The dashboard does not paginate — for deep historical queries use the CLI or `curl /v1/audit?offset=...`.

---

## SSE (`/api/stream`) behavior

- The dashboard opens an `EventSource` on page load and listens for four event types: `check`, `approval_required`, `denied`, `resolved`.
- On a slow consumer, the server drops events silently and increments `agentguard_sse_events_dropped_total{reason="slow_consumer"}`. The UI will appear to miss events.
- **There is no client-side auto-reconnect beyond what `EventSource` does natively.** If the server restarts, the browser reconnects on its own within a few seconds. If the reverse proxy closes the stream (idle timeout), `EventSource` also reconnects.

### LIVE badge semantics

Green when the EventSource is open. On disconnect, it turns amber/red. The indicator is **not** a liveness check on the server — it only reflects local stream state. Use `/health` for real liveness.

---

## Session expiry

Sessions live for `SessionTTL=1h` by default (configurable via `proxy.session.ttl`). After that:

- The next request hits `requireAuthOrSession`, sees no valid session, returns `401`.
- `agFetch` intercepts `401`/`403` and redirects to `/dashboard` → login page.
- You re-enter your API key; a new session is issued.

To stay logged in across an operator shift, raise the TTL:

```yaml
proxy:
  session:
    ttl: "8h"
```

Reload the policy (send SIGHUP or touch the file with `--watch`) and new logins honor the new TTL. Existing sessions keep their original expiry.

---

## Security headers

The dashboard responses carry:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store
```

`X-Frame-Options: DENY` means the dashboard **cannot** be embedded in an iframe. This is deliberate — embedding would open clickjacking vectors on approve/deny.

User-controlled strings (commands, paths, reasons) are rendered via `textContent` and an `esc()` helper, not `innerHTML`. A command like `<img src=x onerror=alert(1)>` in `command` will display as literal text.

---

## What the dashboard does NOT do

- **It does not auto-refresh the audit tab.** SSE delivers real-time check events; audit listing requires a page reload for the full historical window.
- **It does not let you edit policies.** Policy changes happen in YAML; hot-reload via `--watch`.
- **It does not show `/metrics`.** Use Prometheus/Grafana.
- **It does not provide user management.** There is one API key; everyone who has it has full access.

---

## Embedding or customizing

The dashboard HTML lives in `pkg/proxy/server.go` as `dashboardHTML` / `loginHTML`. It is deliberately vanilla HTML/JS with no bundler so builds stay dependency-free.

If you need a branded dashboard, serve your own at a different path (via your reverse proxy or a separate static server) and use `/api/stats`, `/api/pending`, `/api/stream`, `/v1/audit`, `/v1/approve/{id}`, `/v1/deny/{id}` as the backend API — they are documented in [`API.md`](API.md).

---

## Related docs

- [`docs/API.md`](API.md) — the endpoints the dashboard calls.
- [`docs/APPROVAL_WORKFLOW.md`](APPROVAL_WORKFLOW.md) — end-to-end flow that lands in the dashboard's Pending list.
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — cookie `Secure` flag, reverse proxy headers, CORS for cross-origin dashboard hosts.
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — login loops, SSE disconnects, silent logouts.
