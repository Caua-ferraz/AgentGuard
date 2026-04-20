# Deploying AgentGuard in Production

This guide covers the four decisions you **must** get right before exposing AgentGuard beyond `localhost`:

1. [Setting an API key](#1-always-set-an-api-key) (and what happens if you do not)
2. [Running behind a TLS-terminating reverse proxy](#2-behind-a-tls-terminating-reverse-proxy)
3. [Configuring CORS](#3-cors)
4. [Understanding the unauthenticated `/v1/check` endpoint](#4-v1check-is-intentionally-open)

Each section shows the exact flag/setting, the failure mode if you skip it, and a worked example.

> **TL;DR** — minimum safe flags for a production server behind an HTTPS proxy:
> ```bash
> agentguard serve \
>   --policy /etc/agentguard/policy.yaml \
>   --api-key "$AGENTGUARD_API_KEY" \
>   --base-url https://guard.example.com \
>   --allowed-origin https://app.example.com \
>   --tls-terminated-upstream \
>   --dashboard \
>   --audit-log /var/lib/agentguard/audit.jsonl \
>   --watch
> ```

---

## 1. Always set an API key

AgentGuard changes how it binds based on whether `--api-key` is set:

| `--api-key` | Bind address | Who can reach `/v1/approve`, `/v1/deny`, `/v1/audit`, `/api/*` |
|---|---|---|
| **unset** | `127.0.0.1:<port>` **only** | Processes on the same host (all gated endpoints become open) |
| **set** | `0.0.0.0:<port>` (all interfaces) | Anything with the Bearer token (or a valid session cookie) |

Source: `pkg/proxy/server.go:283-289`.

**Symptom if you forget:** agents running on a different host get `connection refused` or `connect: timed out`. The server log shows:

```
INFO: binding to 127.0.0.1:8080 (localhost only) — set --api-key to listen on all interfaces
```

**Fix:**

```bash
export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
agentguard serve --api-key "$AGENTGUARD_API_KEY" ...
```

The same key is used by `agentguard approve|deny|status|audit` (falls back to `AGENTGUARD_API_KEY` env; see `cmd/agentguard/main.go:256-261`) and by the Python / TypeScript SDKs (`AGENTGUARD_API_KEY` env var).

> **Note:** `/v1/check`, `/health`, `/metrics`, `/auth/login`, and `/auth/logout` are open by design even when `--api-key` is set. See [section 4](#4-v1check-is-intentionally-open).

---

## 2. Behind a TLS-terminating reverse proxy

Most production deployments terminate TLS at an nginx / HAProxy / ALB / Cloudflare edge and speak plaintext HTTP to AgentGuard on a private network. Two things break if you do not tell AgentGuard about this:

### 2a. Session cookies without `Secure` → login loop

`/auth/login` sets `ag_session` (HttpOnly) and `ag_csrf` cookies. The `Secure` attribute is decided at emit time by:

```go
Secure: r.TLS != nil || s.cfg.TLSTerminatedUpstream
```

(`pkg/proxy/auth.go:221, 231`.)

Modern browsers reject non-`Secure` cookies from `SameSite=Strict` origins served over HTTPS — so the cookie is set, **then silently dropped on the next request**, and `/dashboard` bounces back to the login form. Users see an infinite redirect loop.

**Fix:** pass `--tls-terminated-upstream`.

```bash
agentguard serve --tls-terminated-upstream ...
```

This forces `Secure=true` on session cookies regardless of `r.TLS`. Only use it when TLS is actually terminated upstream — marking cookies `Secure` over plaintext would make them unreadable.

### 2b. Approval links point at the wrong host

`approval_url` in `POST /v1/check` responses and in webhook/Slack notifications is built from `cfg.BaseURL`. If you do not set `--base-url`, AgentGuard defaults to `http://localhost:<port>` (`cmd/agentguard/main.go:154-156`) — Slack messages will link to `http://localhost:8080/...` which is useless to a human approver on their laptop.

**Fix:** set `--base-url` to the public URL the dashboard is reachable at:

```bash
agentguard serve --base-url https://guard.example.com ...
```

### 2c. nginx reference config

```nginx
server {
    listen 443 ssl http2;
    server_name guard.example.com;

    ssl_certificate     /etc/ssl/guard.example.com.crt;
    ssl_certificate_key /etc/ssl/guard.example.com.key;

    # AgentGuard uses Server-Sent Events on /api/stream — disable buffering.
    location /api/stream {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s;
    }
}
```

### 2d. Docker Compose reference

```yaml
services:
  agentguard:
    image: agentguard:latest
    restart: unless-stopped
    command: >
      serve
      --policy /etc/agentguard/default.yaml
      --audit-log /var/lib/agentguard/audit.jsonl
      --api-key ${AGENTGUARD_API_KEY}
      --base-url https://guard.example.com
      --allowed-origin https://app.example.com
      --tls-terminated-upstream
      --dashboard --watch
    environment:
      - AGENTGUARD_API_KEY
    volumes:
      - ./policy.yaml:/etc/agentguard/default.yaml:ro
      - agentguard-audit:/var/lib/agentguard
    expose:
      - "8080"
    networks: [internal]

  nginx:
    image: nginx:stable
    ports: ["443:443"]
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/ssl:/etc/ssl:ro
    depends_on: [agentguard]
    networks: [internal]

volumes:
  agentguard-audit:
networks:
  internal:
```

Mount your own policy over `/etc/agentguard/default.yaml` — **not** the whole `/etc/agentguard` directory, which would hide the image's baked-in default.

### 2e. Kubernetes stub

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: agentguard }
spec:
  replicas: 1   # ⚠ rate limits and session-cost accounting are per-instance; see docs/OPERATIONS.md
  template:
    spec:
      containers:
        - name: agentguard
          image: agentguard:0.4.1
          args:
            - serve
            - --api-key=$(AGENTGUARD_API_KEY)
            - --base-url=https://guard.example.com
            - --tls-terminated-upstream
            - --allowed-origin=https://app.example.com
            - --audit-log=/var/lib/agentguard/audit.jsonl
            - --dashboard
          env:
            - name: AGENTGUARD_API_KEY
              valueFrom: { secretKeyRef: { name: agentguard, key: api-key } }
          volumeMounts:
            - name: audit
              mountPath: /var/lib/agentguard
          readinessProbe:
            httpGet: { path: /health, port: 8080 }
      volumes:
        - name: audit
          persistentVolumeClaim: { claimName: agentguard-audit }
```

> **Warning — multi-instance:** rate-limit buckets and session-cost accumulators are in-memory and not shared across replicas. Running `replicas: > 1` lets an agent burst past per-scope limits by hitting different pods. See [`docs/OPERATIONS.md`](OPERATIONS.md) for mitigations.

---

## 3. CORS

`--allowed-origin` has two modes:

| Value | Behavior | Use when |
|---|---|---|
| **unset** (default) | **Permissive-localhost**: reflects any `http://localhost:*` or `http://127.0.0.1:*` origin. Everything else is rejected. | Local development, same-host deployments. |
| `https://app.example.com` (exact) | **Strict**: only the named origin gets `Access-Control-Allow-Origin` back. | Production, dashboard served from a known SPA origin. |

Source: `pkg/proxy/server.go:926-956`.

Permissive-localhost is safe because:

- Session cookies are `SameSite=Strict`, so cross-site pages cannot ride them.
- State-changing endpoints require a CSRF token (`X-CSRF-Token`) that a cross-origin page cannot read.
- Origins like `http://localhost.evil.com` are **rejected** — the trailing `:` on the localhost prefix blocks DNS-rebinding-style lookalikes.

For production, set the exact origin of whatever frontend calls the AgentGuard HTTP API directly. If the only consumer is agents (which speak HTTP, not browsers), you can leave `--allowed-origin` empty — agents do not send `Origin`.

---

## 4. `/v1/check` is intentionally open

Every other endpoint that accepts state-changing input (`/v1/approve`, `/v1/deny`, `/v1/audit`, all `/api/*`) requires either a Bearer token or a valid session + CSRF. `/v1/check` does **not**.

**Why this is safe by design:**

- `/v1/check` answers a policy question; it does not execute anything. The agent still has to perform the action itself after receiving `ALLOW`.
- The response (ALLOW / DENY / REQUIRE_APPROVAL + matched rule name) leaks nothing that a determined attacker could not also derive by reading the policy file.
- Requiring auth on `/v1/check` would force every guarded agent to hold a long-lived secret, which is a much larger attack surface than the policy decision itself.

**If your threat model requires L7 auth on `/v1/check` anyway** (e.g., a multi-tenant deployment where policy decisions must not leak between tenants), gate it at your reverse proxy:

```nginx
location = /v1/check {
    # Only allow requests from the agent subnet.
    allow 10.0.0.0/8;
    deny all;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

Or require a header set by an authenticating proxy (e.g., Cloudflare Access, oauth2-proxy) and reject at the edge.

---

## Related docs

- [`docs/OPERATIONS.md`](OPERATIONS.md) — audit log rotation, multi-instance caveats, capacity limits.
- [`docs/OBSERVABILITY.md`](OBSERVABILITY.md) — `/metrics`, alert rules, response-header timings.
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — symptom-keyed diagnostics for the footguns above.
- [`docs/CONFIG.md`](CONFIG.md) — policy-file tunables (`proxy.session.ttl`, body caps, audit query bounds).
