# Operations Guide

Day-2 concerns for running AgentGuard in production: log rotation, scaling, capacity limits, and restart semantics. Read [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) first — this guide assumes you already have a correctly configured server.

---

## Audit log rotation

**AgentGuard does not rotate `audit.jsonl`.** The file is opened with `O_CREATE|O_WRONLY|O_APPEND` at mode `0600` and grows forever until you rotate it externally.

Two follow-on consequences:

1. **Disk usage** grows proportional to request volume. A busy deployment can produce hundreds of MB per day.
2. **Startup replay** re-reads the entire file. `NewServer` calls `Logger.Query({})` once at boot and replays every entry through `metrics.IncDecision` so `/metrics` and `/api/stats` survive restarts with accurate counters. A multi-GB log delays counter accuracy until the scan completes.

### Recommended pattern: external shipper + periodic truncate

The audit log is append-only JSON Lines with one decision per line (schema in [`docs/FILE_FORMATS.md`](FILE_FORMATS.md)). Any log shipper that handles newline-delimited JSON works — Vector, Fluent Bit, Filebeat, Datadog agent, etc.

Minimum safe rotation approach:

```bash
#!/usr/bin/env bash
# /usr/local/bin/rotate-agentguard-audit — cron nightly
set -euo pipefail

AUDIT=/var/lib/agentguard/audit.jsonl
ARCHIVE_DIR=/var/lib/agentguard/archive

mkdir -p "$ARCHIVE_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
cp -a "$AUDIT" "$ARCHIVE_DIR/audit-$stamp.jsonl"
gzip "$ARCHIVE_DIR/audit-$stamp.jsonl"

# Truncate in place so the open file descriptor keeps working.
: > "$AUDIT"
```

Key rules:

- **Truncate in place** (`: > file`) instead of renaming + recreating. AgentGuard holds an open file descriptor on the original inode; a rename-and-recreate breaks that handle and new writes go into the renamed file.
- **Archive first, truncate second.** If the machine crashes between the two, you have the archive and only lose the in-flight seconds.
- **Do not truncate during startup replay.** Run rotation during off-peak hours and give the process headroom.

If you need `logrotate`, use the `copytruncate` directive:

```
/var/lib/agentguard/audit.jsonl {
    daily
    rotate 14
    compress
    copytruncate
    missingok
    notifempty
    create 0600 agentguard agentguard
}
```

Keep `copytruncate` — the default `create`-based rotation breaks AgentGuard's open fd.

### Reducing startup replay time

If restart latency bothers you more than disk usage, archive aggressively:

- Keep `audit.jsonl` scoped to the last N hours of decisions.
- Ship everything older to external storage (S3, GCS, Datadog, etc.) where `/v1/audit` queries do not need to reach.

Historical audit queries then become a two-tier lookup: recent entries from the local file, older entries from the external store. `/v1/audit`'s `?offset=` + `?limit=` support pagination within the local file; cross-tier paging is your responsibility.

---

## Multi-instance deployments

Two in-memory state stores do **not** propagate across replicas:

### Rate-limit buckets (`pkg/ratelimit/ratelimit.go`)

- Key: `"<scope>:<agent_id>"`.
- An agent hitting two replicas round-robin gets up to `2 × max_requests` per window.
- `MaxBuckets = 10000` buckets per instance; stale buckets evicted on insertion pressure.

### Session-cost accumulators (`pkg/policy/engine.go` `sessionCosts`)

- Keyed by `session_id` from the incoming request.
- An agent session hitting two replicas sees `max_per_session` enforced against **each** replica's local total, not the global total.
- `--session-cost-ttl` evicts idle entries; it does not solve the sharing problem.

### Mitigations (from simplest to most involved)

1. **Run one replica.** Scale vertically. AgentGuard is a latency-sensitive sidecar, not a throughput bottleneck — one well-sized instance usually handles thousands of agents.
2. **Pin sessions.** Configure your load balancer for session affinity on `session_id` (header or cookie). Rate-limit buckets still drift across replicas for multi-session agents, but cost accounting becomes accurate.
3. **Divide limits by replica count.** If you run 3 replicas and want a global cap of 30 req/min, set `max_requests: 10`. Works only for steady-state traffic; burst behavior remains sloppy.
4. **Aggregate externally.** Have each replica emit `/metrics` to Prometheus; alert on aggregate drift between declared and observed rates. Treat AgentGuard rate limits as best-effort and backstop with an upstream rate limiter (the reverse proxy, a CDN, or an API gateway).

---

## Approval queue capacity

| Constant | Value | Source |
|---|---|---|
| `MaxPendingApprovals` | `10000` | `pkg/proxy/server.go` |
| Channel buffer per SSE subscriber | `64` | `pkg/proxy/server.go` |

Behavior at capacity:

- New approvals bulk-evict any **resolved** entries from the queue (`evictResolvedLocked`) before inserting. Unresolved pendings are never evicted.
- If every entry is unresolved, `/v1/check` calls that would require approval get `503 Service Unavailable` with `Retry-After: 5`.
- Approvals are **lost on restart.** There is no disk persistence. Agents polling `/v1/status/{id}` after a restart will poll forever (their SDK will hit its wall-clock timeout).

Operational guidance:

- **Resolve approvals fast.** A backlog >1k almost always means nobody is triaging.
- **Set SDK approval timeouts higher than your human SLA**, but not so high that a restart silently hangs agents. A practical rule: `timeout = expected_human_response_time + restart_budget`.
- **Avoid restarts during business hours.** Use rolling restarts with drained approval queues if at all possible.
- **Watch `agentguard_pending_approvals`** (gauge in `/metrics`). Sustained growth = triage is not keeping up.

---

## Session store limits

| Constant | Value | Source |
|---|---|---|
| `SessionTTL` | `1h` | `pkg/proxy/auth.go` (default, overridable via `policy.proxy.session.ttl`) |
| `MaxSessions` | `1024` | `pkg/proxy/auth.go` (hardcoded in v0.4.1) |

At capacity, the oldest-by-expiry session is evicted. Under pathological login bursts you can see `503` with `Retry-After: 5` from `/auth/login`.

Operational guidance:

- Most deployments never approach 1024 dashboard sessions. If you do, it is usually a bot probing `/auth/login` — firewall it.
- `MaxSessions` is not yet configurable via YAML. If you legitimately need more, open an issue with your use case.
- Session TTL **is** configurable:

  ```yaml
  proxy:
    session:
      ttl: "8h"   # dashboards stay logged in for an operator shift
  ```

---

## Notifier queue capacity

| Constant | Value | Source |
|---|---|---|
| `DefaultWorkers` | `8` | `pkg/notify/notify.go` |
| `DefaultQueueSize` | `256` | `pkg/notify/notify.go` |
| `DefaultNotifyDispatchTimeout` | `10s` | `pkg/policy/engine.go` |

Dispatch is **non-blocking**: `Dispatcher.Send(event)` enqueues one job per configured notifier. If the queue is full (a slow Slack webhook is the usual culprit), the event is dropped and counted:

- `agentguard_notify_events_dropped_total{notifier, reason}` — Prometheus counter.
- `notify.DroppedEvents` — atomic `uint64` for in-process Go consumers.
- `agentguard_notify_queue_depth{notifier}` — current queue depth.
- `agentguard_notify_dispatch_duration_seconds{notifier}` — histogram of per-target HTTP latency.

Tune by:

- Reducing notifier fanout (drop unused targets).
- Lowering per-target `timeout` so a flaky endpoint stalls fewer workers.
- Setting a lower per-target `timeout` on Slack while keeping webhook `timeout` long (use `notifications.dispatch_timeout` + per-target `timeout`).

---

## Session-cost sweeper

If your agents use long-lived `session_id`s, the `sessionCosts` map can grow unbounded. Two flags control eviction:

```bash
agentguard serve \
  --session-cost-ttl 24h \
  --session-cost-sweep-interval 1h \
  ...
```

- `--session-cost-ttl 0` (default): entries never expire, v0.4.0-compatible.
- `--session-cost-sweep-interval` defaults to `max(ttl/4, 1m)` if unset.

Eviction logs `INFO: session-cost sweeper evicted N entries (ttl=…)` when non-zero.

Trade-off: a short TTL resets session totals mid-run if an agent goes idle longer than the TTL. Pick `ttl` > your longest expected idle gap within a session.

---

## Backups

Two things are worth backing up:

1. **Policy files** (`configs/*.yaml`) — version control them. Every change should land through a commit and, if possible, a CI `agentguard validate` check.
2. **Audit log archive** — whatever your shipper lands in S3 / object storage. The local `audit.jsonl` is the working copy; the archive is truth. Retain per your compliance requirements.

Do **not** try to back up the approval queue or session store — they are ephemeral by design.

---

## Restart checklist

Before a scheduled restart in production:

- [ ] No approvals pending (`curl .../api/pending`) or acceptable to lose them.
- [ ] Agents are either idle or configured with a generous `wait_for_approval` / `waitForApproval` timeout.
- [ ] Audit log recently archived, so replay latency on boot is bounded.
- [ ] You know how to roll back the binary if the new version fails (`agentguard version`).

Graceful shutdown handles SIGINT and SIGTERM — the process drains in-flight requests up to `ShutdownTimeout` before exiting.

---

## Capacity sizing

For a single replica on modern hardware:

- CPU: 1 vCPU comfortably handles 500+ RPS of `/v1/check` (mostly spent in YAML policy evaluation and JSON decode).
- Memory: base ~50 MB; linear growth with audit log size during startup replay only.
- Disk: **audit log drives this**. Size for at least 2× your retention window.

For higher throughput, benchmark with your actual policy before scaling. The response headers `X-AgentGuard-Policy-Ms`, `X-AgentGuard-Audit-Ms`, `X-AgentGuard-Total-Ms` give you a per-request breakdown.

---

## Related docs

- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — reverse proxy, TLS, CORS, initial setup.
- [`docs/OBSERVABILITY.md`](OBSERVABILITY.md) — `/metrics`, alerts.
- [`docs/FILE_FORMATS.md`](FILE_FORMATS.md) — audit log schema and migration format.
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — symptom-keyed diagnostics.
- [`docs/CONFIG.md`](CONFIG.md) — YAML tunables (session TTL, audit limits, body caps).
