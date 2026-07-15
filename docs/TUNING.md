# Tuning Knobs

Every setting that changes AgentGuard's runtime behavior, grouped by how you change it. Ordered from safest to most surgical.

---

## Policy YAML (reload without restart when `--watch` is set)

These live in the policy file (`configs/*.yaml`) under the `proxy:` and `notifications:` top-level blocks, or per-scope rule blocks.

### `proxy.session`

```yaml
proxy:
  session:
    ttl: "1h"   # default; dashboard sessions expire this long after login
```

| Key | Default | Bounds |
|---|---|---|
| `ttl` | `1h` | Any `time.ParseDuration` value. Operator shift = `8h` is common. |

### `proxy.request`

```yaml
proxy:
  request:
    max_body_bytes: 1048576   # 1 MB
```

| Key | Default | Bounds |
|---|---|---|
| `max_body_bytes` | `1048576` (1 MB) | `>0`. Values over a few MB defeat the DoS guard — keep tight. |

### `proxy.audit`

```yaml
proxy:
  audit:
    default_limit: 50    # example override — used when /v1/audit omits ?limit
    max_limit: 200       # example override — ?limit=N above this is silently clamped
```

| Key | Default |
|---|---|
| `default_limit` | `100` |
| `max_limit` | `1000` |

### `notifications.dispatch_timeout`

```yaml
notifications:
  dispatch_timeout: "10s"   # per-target enqueue deadline
```

Default `10s`. Set short if you have a flaky notifier that stalls workers.

### Per-scope `rate_limit`

```yaml
rules:
  - scope: network
    rate_limit:
      max_requests: 60
      window: "1m"
```

Per-instance. See [`OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments) for multi-replica arithmetic.

### Per-scope `limits` (cost)

```yaml
rules:
  - scope: cost
    limits:
      max_per_action: "$0.25"
      max_per_session: "$15.00"
      alert_threshold: "$10.00"
```

- `max_per_action`: hard DENY above this.
- `max_per_session`: hard DENY when `sessionCosts[session_id] + est_cost` would exceed.
- `alert_threshold`: REQUIRE_APPROVAL (no reservation) when a single action exceeds.

---

## CLI flags (restart to apply)

```bash
agentguard serve \
  --policy /etc/agentguard/policy.yaml \
  --port 8080 \
  --api-key $KEY \
  --base-url https://guardrails.example \
  --allowed-origin https://app.example \
  --tls-terminated-upstream \
  --audit-log /var/lib/agentguard/audit.jsonl \
  --session-cost-ttl 24h \
  --session-cost-sweep-interval 1h \
  --data-dir /var/lib/agentguard \
  --audit-backend file \
  --watch \
  --dashboard
```

The v0.6 persistence knobs (`--persist`, `--store-dsn`, `--data-dir`, `--audit-backend`) are covered in [`CLI.md`](CLI.md#persistence--multi-tenancy-v06).

See [`CLI.md`](CLI.md) for the full list.

---

## Hardcoded constants (as of v0.9)

These are **not configurable** yet. Listed so you know what ceiling you're running against. Changing any of these requires a code change.

| Constant | Value | Source | Notes |
|---|---|---|---|
| `MaxPendingApprovals` | `10000` | `pkg/proxy/server.go` | Evicts resolved entries on pressure; at capacity `/v1/check` gets `503`. |
| `SSEChannelBufferSize` | `64` | `pkg/proxy/server.go` | Slow SSE consumer drops events. |
| `MaxSessions` | `1024` | `pkg/proxy/auth.go` | Oldest-by-expiry evicted; at cap `/auth/login` returns `503`. |
| `MaxBuckets` (rate limiter) | `10000` | `pkg/ratelimit/ratelimit.go` | Stale buckets evicted on insert pressure. |
| `DefaultWorkers` (notifier) | `8` | `pkg/notify/notify.go` | Goroutine pool for dispatch. |
| `DefaultQueueSize` (notifier) | `256` | `pkg/notify/notify.go` | Shared queue depth across notifiers. |
| Policy watch fallback poll interval | `2s` | `pkg/policy/watcher.go` | Reloads are fsnotify-driven (immediate); the 2 s `os.Stat().ModTime()` poll is the fallback when fsnotify is unavailable. |
| Histogram buckets (ms) | `0.25..10000` | `pkg/metrics/metrics.go` | Contract — re-bucketing invalidates historical Prometheus data. |
| Notifier histogram buckets (s) | `0.005..10` | `pkg/metrics/metrics.go` | Same contract note. |
| Audit scanner buffer | `1 MB` per line | `pkg/audit/logger.go` | Raised from stdlib default to tolerate long rows. |
| `absoluteMaxBufferBytes` (LLM proxy) | `64 MiB` | `pkg/llmproxy/streaming.go` | Hard safety ceiling on the streaming buffers. A `MaxBufferBytes` of `0` disables the operator cap (`--max-buffer-bytes` itself rejects `0`; only reachable by embedding the package) but this ceiling still applies — the stream is refused fail-closed past it. |

If you need any of these configurable in YAML, open an issue with the use case.

---

## Environment variables

| Var | Consumed by | Default |
|---|---|---|
| `AGENTGUARD_API_KEY` | CLI client subcommands | empty |
| `AGENTGUARD_URL` | Python + TypeScript SDKs | `http://localhost:8080` |

The server process does **not** read these. CLI-server flags are the source of truth on the server side.

---

## What you usually don't need to tune

- **Histogram buckets.** Re-bucketing breaks historical Prometheus data; prefer adding new histograms in code.
- **Body cap.** 1 MB is already 10× a typical `CheckRequest`; raising it weakens DoS protection.
- **Notifier workers.** Eight is plenty for most deployments — dropped events usually mean a slow *target*, not too few workers.
- **Rate-limit `MaxBuckets`.** 10k tracked agents per instance is enough for almost everyone.

---

## Related docs

- [`docs/CONFIG.md`](CONFIG.md) — YAML schema for `proxy.*` and `notifications.*` blocks.
- [`docs/OPERATIONS.md`](OPERATIONS.md) — what to do when a ceiling bites.
- [`docs/OBSERVABILITY.md`](OBSERVABILITY.md) — metrics to watch before you tune.
