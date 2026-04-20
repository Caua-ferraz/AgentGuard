# Observability

Everything AgentGuard exposes for monitoring: the `/metrics` endpoint, `/api/stats`, response-header timings, and example Prometheus / alerting rules.

Source of truth: `pkg/metrics/metrics.go`.

---

## `/metrics` — Prometheus text format

- Unauthenticated, scrape-friendly.
- Always emits `HELP` and `TYPE` lines for every metric, including those with no observations yet.
- Zero external deps — lightweight hand-rolled exposition.

```bash
curl -s http://127.0.0.1:8080/metrics
```

### Counters

| Name | Labels | What it counts |
|---|---|---|
| `agentguard_checks_total` | — | All `/v1/check` requests processed (sum of all decisions including rate-limit denies). |
| `agentguard_allowed_total` | — | Decisions of `ALLOW`. |
| `agentguard_denied_total` | — | Decisions of `DENY`, including rate-limit denies. |
| `agentguard_approval_required_total` | — | Decisions of `REQUIRE_APPROVAL`. |
| `agentguard_rate_limited_total` | — | Subset of `_denied_total` where the denial came from the rate limiter. |
| `agentguard_request_rejected_total` | `reason` | Requests rejected **before** policy eval. Current reasons: `body_too_large`. |
| `agentguard_notify_events_dropped_total` | `notifier`, `reason` | Notification events never delivered. Notifier ∈ {`webhook`,`slack`,`console`,`log`,`unknown`}; reason currently `queue_full`. |
| `agentguard_approvals_evicted_total` | `reason` | Approval queue evictions. Reason ∈ {`lru_resolved`, `queue_full`}. |
| `agentguard_ratelimit_bucket_evictions_total` | `scope` | Rate-limit buckets evicted under capacity pressure (`MaxBuckets=10000`). |
| `agentguard_sse_events_dropped_total` | `reason` | SSE broadcasts dropped before reaching a subscriber. Reason currently `slow_consumer`. |
| `agentguard_audit_replay_entries_total` | — | Audit entries re-read at startup to seed counters. |
| `agentguard_audit_rotations_total` | — | Live audit file rotations triggered by size threshold. |
| `agentguard_audit_corrupt_lines_total` | — | Audit lines that failed JSON parse during `Query()` and were skipped. |
| `agentguard_deprecations_used_total` | `feature` | Times a deprecated feature was exercised. Keys match `docs/DEPRECATIONS.md`. |

### Gauges

| Name | Labels | What it reports |
|---|---|---|
| `agentguard_pending_approvals` | — | Current approval-queue depth. |
| `agentguard_ratelimit_buckets` | — | Currently tracked rate-limit token buckets. |
| `agentguard_sse_subscribers` | — | Live `/api/stream` subscribers. |
| `agentguard_notify_queue_depth` | — | Length of the shared notify dispatch queue (sampled at last enqueue). |
| `agentguard_audit_replay_duration_seconds` | — | Wall-clock duration of the most recent startup audit replay. |
| `agentguard_audit_migration_status` | `from`, `to`, `status` | 1 = current outcome of an audit-schema migration; 0 for non-current statuses of the same `(from, to)`. Status ∈ {`ran`,`skipped`,`failed`}. |

### Histograms

| Name | Unit | What it measures |
|---|---|---|
| `agentguard_request_duration_ms` | ms | End-to-end latency of `/v1/check`. |
| `agentguard_policy_eval_duration_ms` | ms | Time inside `Engine.Check` only. |
| `agentguard_audit_write_duration_ms` | ms | Time inside `Logger.Log` only. |
| `agentguard_notify_dispatch_duration_seconds` | seconds (labeled by `notifier`) | Time inside each `Notifier.Notify`. |

Duration bucket bounds (ms, shared across the three `_ms` histograms):

```
0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf
```

Notifier histogram buckets (seconds):

```
0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf
```

Bucket boundaries are treated as a stable contract. Re-bucketing invalidates historical Prometheus data — see `CHANGELOG.md` v0.4.1.

---

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: agentguard
    metrics_path: /metrics
    static_configs:
      - targets: ['agentguard.internal:8080']
    # /metrics is unauthenticated; gate at the network layer if needed.
    scrape_interval: 15s
    scrape_timeout: 10s
```

Behind a reverse proxy with path rewriting, keep `/metrics` un-prefixed (do not add auth headers — the endpoint is intentionally open).

---

## Example alert rules

```yaml
groups:
  - name: agentguard
    rules:
      # Sudden spike of denies: either an attack or a policy that's too strict.
      - alert: AgentGuardDeniedSpike
        expr: rate(agentguard_denied_total[5m]) > 5 * rate(agentguard_denied_total[1h] offset 1h)
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "DENY rate 5× its 1h baseline"

      # Human approvers falling behind.
      - alert: AgentGuardPendingApprovalsGrowing
        expr: agentguard_pending_approvals > 100
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "Approval queue > 100 for 15m; triage is not keeping up"

      # Approval queue saturation — approaching 503s.
      - alert: AgentGuardApprovalQueueCritical
        expr: agentguard_pending_approvals > 9000
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Approval queue near MaxPendingApprovals=10000"

      # Notifier events are being dropped — Slack/webhook probably slow.
      - alert: AgentGuardNotifierDrops
        expr: rate(agentguard_notify_events_dropped_total[5m]) > 0
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Notifier {{ $labels.notifier }} dropping events: {{ $labels.reason }}"

      # p99 policy eval > 50 ms sustained — policy is heavy or a reload is contending.
      - alert: AgentGuardSlowPolicyEval
        expr: histogram_quantile(0.99, sum by (le) (rate(agentguard_policy_eval_duration_ms_bucket[5m]))) > 50
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "p99 Engine.Check > 50 ms"

      # Audit replay on startup is becoming the slow path.
      - alert: AgentGuardSlowAuditReplay
        expr: agentguard_audit_replay_duration_seconds > 30
        labels: { severity: warning }
        annotations:
          summary: "Startup audit replay > 30s; consider rotating the audit log"

      # Agents bypassing per-instance rate limits via multi-replica fanout.
      - alert: AgentGuardRateLimitBucketEviction
        expr: rate(agentguard_ratelimit_bucket_evictions_total[5m]) > 1
        for: 15m
        labels: { severity: info }
        annotations:
          summary: "Rate-limit buckets evicting in scope {{ $labels.scope }}"
```

---

## `/api/stats` vs `/metrics`

| Endpoint | Auth | Use when |
|---|---|---|
| `/metrics` | open | Prometheus scraping, alerting, long-term trending. |
| `/api/stats` | Bearer or session | Dashboard fetches a single JSON blob once per page load and on SSE events. Cheap, O(1), atomic snapshot. |

Example `/api/stats` response:

```json
{
  "total_checks": 12034,
  "total_allowed": 10998,
  "total_denied":  842,
  "total_approvals": 194,
  "pending_count": 3
}
```

Do **not** poll `/api/stats` in a tight loop; use `/api/stream` (SSE) for real-time updates and fall back to one `/api/stats` on reconnect.

---

## Response-header timings

Every `/v1/check` response carries three timing headers (values in **ms**, 3-decimal precision). Useful for ad-hoc debugging without scraping `/metrics`.

| Header | What it measures |
|---|---|
| `X-AgentGuard-Policy-Ms` | Time in `Engine.Check`. |
| `X-AgentGuard-Audit-Ms` | Time in `Logger.Log`. |
| `X-AgentGuard-Total-Ms` | End-to-end server processing, including decode, rate-limit, policy, audit, notify enqueue. |

`Total - Policy - Audit` approximates the framework overhead (JSON decode/encode, rate limit lookup, notify dispatch enqueue).

---

## SSE event types on `/api/stream`

The dashboard and any external listener can subscribe. Events are JSON objects sent as:

```
data: {"type":"check","timestamp":"…","request":{…},"result":{…}}\n\n
```

| Type | Emitted when |
|---|---|
| `check` | `/v1/check` handled any decision. |
| `approval_required` | A `REQUIRE_APPROVAL` decision was stored in the queue. |
| `denied` | A `DENY` decision was returned (also fires `check`). |
| `resolved` | `/v1/approve/{id}` or `/v1/deny/{id}` resolved a pending entry. |

Slow consumers drop events; see `agentguard_sse_events_dropped_total{reason="slow_consumer"}`.

---

## Debug-quick-loop checklist

1. `curl -s localhost:8080/health` — is the server up?
2. `curl -s localhost:8080/metrics | head -80` — counters growing? pending gauge reasonable?
3. `curl -D- -X POST localhost:8080/v1/check -d '{"scope":"shell","command":"ls"}'` — check the `X-AgentGuard-*-Ms` headers.
4. `curl -s -H "Authorization: Bearer $KEY" localhost:8080/v1/audit?limit=20` — see the last 20 decisions.
5. `agentguard status` — health + pending approvals CLI-style.

---

## Related docs

- [`docs/OPERATIONS.md`](OPERATIONS.md) — notifier queue sizing, audit rotation, capacity limits.
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — exposing `/metrics` safely behind a reverse proxy.
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — keyed by symptom; most entries reference a metric to confirm.
- [`docs/DEPRECATIONS.md`](DEPRECATIONS.md) — feature keys for `agentguard_deprecations_used_total`.
