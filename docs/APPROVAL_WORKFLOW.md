# Approval Workflow — End to End

What happens from the moment a policy returns `REQUIRE_APPROVAL` to the moment the agent proceeds (or gives up). Useful when you're deciding approval timeouts, staffing a triage rotation, or wiring notifications.

---

## The 5-step lifecycle

```
 Agent               AgentGuard proxy            Human (dashboard / CLI / API)
 ─────               ──────────────────          ─────────────────────────────
  │                   │                           │
  │ 1. /v1/check ─────▶                           │
  │                   │ evaluate policy           │
  │                   │ → REQUIRE_APPROVAL        │
  │                   │ ApprovalQueue.Add         │
  │                   │ Notifier.Send ───────────▶│ (Slack / webhook / console)
  │ ◀───── 200 OK ────│   approval_id, approval_url
  │   decision=REQUIRE_APPROVAL                   │
  │                   │                           │ 2. opens dashboard / uses CLI
  │                   │                           │
  │ 3. poll /v1/status/{id}  (every 2 s)          │
  │  ──────────────▶  │                           │
  │  ◀─ resolved:false│                           │ 4. POST /v1/approve/{id}
  │  ──────────────▶  │ ◀─────────────────────────│  (Bearer or session+CSRF)
  │  ◀─ resolved:true │ Resolve(ALLOW)            │
  │       decision=ALLOW   broadcast "resolved"   │
  │                   │                           │
  │ 5. re-run /v1/check (same params)             │
  │  ──────────────▶  │ → ALLOW (cost reserves,   │
  │  ◀──────────────  │    audit entry written)   │
  │                   │                           │
```

Step numbering matches the sections below.

---

## 1. Policy returns REQUIRE_APPROVAL

Three policy paths lead here:

- **Explicit `require_approval:` rule match** in the relevant scope.
- **Cost alert threshold**: an `est_cost` above `alert_threshold` but not above `max_per_action` returns `require_approval:cost:alert_threshold`. Important: **no reservation** is made against `sessionCosts` at this point — the cost is only reserved when the approved action re-runs `/v1/check`.
- **(Future)** Condition-based approvals (e.g., `require_prior` not satisfied yielding approval instead of deny) — still not implemented as of v1.0.0.

The response body:

```json
{
  "decision": "REQUIRE_APPROVAL",
  "reason": "Matches approval rule in shell scope",
  "matched_rule": "require_approval:shell:<pattern>",
  "approval_id": "ap_1a2b3c4d5e6f7890abcdef1234567890",
  "approval_url": "http://localhost:8080/v1/approve/ap_1a2b..."
}
```

The `approval_url` is built from `--base-url` (or `http://localhost:<port>` if unset) and points at the **POST-only resolution endpoint** `/v1/approve/{id}` — it is for CLI/scripted resolution, not a browser page (humans approve in the dashboard, see step 4). Behind a reverse proxy, set `--base-url https://guardrails.example` so the URL in notifications points at the reachable host.

---

## 2. Notification fan-out

`Notifier.Send` redacts the event and enqueues one job per configured notifier. Each target dispatches **asynchronously** — a slow Slack webhook never blocks the request thread.

### Event payload (redacted before send)

```json
{
  "type": "approval_required",
  "timestamp": "2026-04-19T12:03:44Z",
  "agent_id": "researcher-01",
  "request": {
    "scope": "shell",
    "command": "sudo apt upgrade"
  },
  "result": {
    "decision": "REQUIRE_APPROVAL",
    "reason": "Matches approval rule in shell scope",
    "approval_id": "ap_1a2b…",
    "approval_url": "https://guardrails.example/v1/approve/ap_1a2b…"
  },
  "approval_url": "https://guardrails.example/v1/approve/ap_1a2b…"
}
```

Redactor (in `pkg/notify/notify.go` — `DefaultRedactor`) scrubs:
- `Bearer <token>`
- `AKIA[0-9A-Z]{16}` (AWS)
- `ghp_[A-Za-z0-9]{36,}` (GitHub PAT)
- `xox[baprs]-…` (Slack)
- `(secret|token|password|api_key)=<value>`

Redaction runs on `Command`, `Path`, `Domain`, `Action`, `URL`, `Reason`, and every `Meta` value.

### Slack payload (what approvers actually see)

`SlackNotifier` wraps the event in an attachment (`pkg/notify/notify.go`):

```json
{
  "attachments": [{
    "color": "#ecb22e",
    "text": ":warning: *REQUIRE_APPROVAL* | scope: `shell` | action: `sudo apt upgrade`\n>Matches approval rule in shell scope\n><https://guardrails.example/v1/approve/ap_1a2b…|Approve this action>",
    "footer": "AgentGuard",
    "ts": 1745064224,
    "mrkdwn_in": ["text"]
  }]
}
```

### Webhook payload

POST of the raw event JSON to the configured URL with `User-Agent: AgentGuard/1.0` and a 10 s timeout.

### Dropped events

If the notifier queue (`DefaultQueueSize=256`) is full, the event is dropped and counted:

```
agentguard_notify_events_dropped_total{notifier="slack",reason="queue_full"}
```

See [`OPERATIONS.md`](OPERATIONS.md#notifier-queue-capacity) for tuning.

---

## 3. Agent polls `/v1/status/{id}`

The SDKs wrap this in `wait_for_approval` (Python) / `waitForApproval` (TypeScript). Behavior:

- Poll every 2 s (`pollIntervalMs: 2_000` / `poll_interval=2`).
- Send the Bearer token on every poll — `/v1/status` is auth-gated.
- Stop on either `status: "resolved"` **or** wall-clock timeout.

### Timeouts

SDK defaults are **5 minutes**:

- Python: `guard.wait_for_approval(id, timeout=300, poll_interval=2)`
- TypeScript: `guard.waitForApproval(id, 300_000, 2_000)`

Tune to your human SLA:

- **5 minutes** — fine for always-on ops rotations.
- **30–60 minutes** — typical for non-urgent approvals.
- **8 hours** — operator shift; accepts the restart risk (see below).

On timeout the SDK returns:

```python
CheckResult(decision="DENY", reason="Approval timed out", approval_id="ap_...")
```

This is a logical deny, not a transport error — the `approval_id` is preserved so you can resolve it out-of-band.

### Restarts and in-flight approvals

Since v0.6 the approval queue is **persistent by default** (`--persist`, SQLite-backed — see [`CLI.md`](CLI.md#persistence--multi-tenancy-v06)): pending entries are rehydrated on boot, and agents polling `/v1/status/{id}` across a restart pick up where they left off. Two caveats:

1. The store flushes on a ≥1 s background tick — an approval created in the final moments before a hard crash may not have been written and is lost.
2. With `--persist=false` (the pre-v0.6 in-memory mode), a restart loses every pending entry; agents see `404` on `/v1/status/{id}` and eventually hit their SDK timeout, receiving the fail-deny response.

**Rule of thumb** still applies: `SDK timeout = expected_human_response_time + restart_budget` — even though state survives a restart, nobody can resolve approvals while the process is down.

---

## 4. Human resolves

Three resolution channels, all equivalent:

### a) Dashboard (most common)

Approver opens the dashboard at `<base-url>/dashboard`, which lists pending approvals in real time (SSE). Each item shows the request (scope, command, agent, reason) with **Approve** / **Deny** buttons; clicking posts `/v1/approve/{id}` or `/v1/deny/{id}` with the CSRF header. (The `approval_url` field in the check response is the POST-only API endpoint used by channels b and c below, not a dashboard deep-link.)

### b) CLI

```bash
AGENTGUARD_API_KEY=$KEY agentguard approve ap_1a2b…
# Action approve: approved

agentguard deny ap_1a2b… --url https://guardrails.example
```

Useful for scripted approvals (e.g., a runbook step) or when the dashboard is unreachable.

### c) HTTP API

```bash
curl -X POST -H "Authorization: Bearer $KEY" \
  https://guardrails.example/v1/approve/ap_1a2b…
# {"status":"approved"}
```

See [`API.md`](API.md#post-v1approveid--post-v1denyid--tenant-aware-mirrors).

### What happens server-side

`ApprovalQueue.Resolve(id, decision)`:

1. Locks; if the entry is already resolved, either no-ops (same decision —
   idempotent for retried requests) or rejects with a `409` conflict
   (opposite decision — resolutions are **write-once**; a DENY can never be
   flipped to ALLOW after the fact, or vice versa).
2. Otherwise flips `Resolved=true`, stamps `Decision`, `ResolvedAt`, and
   the actor (`resolved_via`: `bearer`/`session`/`open` + peer host).
3. Broadcasts a `resolved` SSE event (dashboard updates in real time) —
   exactly once per approval; retries do not re-broadcast.
4. Returns.

It does **not** unblock any waiter — the agent's SDK learns about the resolution on its next poll (within ≤ 2 s).

### One-shot consumption and validity

A resolved **ALLOW** is a single-use, time-boxed capability:

- The first `/v1/check` retry carrying the `approval_id` (and matching the
  original request shape) is honored with `matched_rule: "allow:approved"`
  and **consumes** the approval. Any further replay of the same id falls
  through to fresh policy evaluation and re-enters the approval flow under
  a new id — one human click authorizes at most one execution.
- Honoring is bounded by `--approval-validity` (default `5m`, matching the
  SDKs' `wait_for_approval` window; `0` disables): a resolution older than
  the window is no longer replayable.
- A resolved **DENY** stays sticky within the validity window (a retrying
  model gets an immediate deny instead of spawning fresh approval
  requests) and is never "consumed".
- `GET /v1/status/{id}` is read-only — SDK poll loops and dashboards never
  spend the capability.
- Refused replays are visible as
  `agentguard_approval_replay_refused_total{reason="consumed"|"expired"}`;
  a rising `consumed` count means something is trying to reuse one
  approval for multiple executions.
- Consumption survives restarts (persisted with the approval), so a
  restart cannot resurrect a spent ALLOW.
- **Multi-node (v1.0, PostgreSQL store):** all of the above holds
  cluster-wide, eventually — an approval resolved on one node is visible on
  every node within one `--reconcile-interval` (default 2s), and a consumed
  ALLOW is spent everywhere once its stamp reconciles. Inside that staleness
  window a replay racing to a node that has not yet reconciled can be honored
  once there; shrink `--reconcile-interval` if that window matters to your
  threat model. Conflicting resolutions across nodes always converge to
  **DENY**, and the shared store's merge is monotonic (a resolution is never
  un-resolved, a resolved DENY is never overwritten by a non-DENY, a
  consumption stamp is never cleared) — so neither restarts nor lagging
  replicas can resurrect a spent or denied approval.

---

## 5. Agent re-runs `/v1/check`

The SDK returns a `CheckResult` carrying the resolution. **The original `check()` call is not the one that "executes" — the agent must either:**

- Act on `result.allowed` directly (trusting the resolution), or
- Re-run `check()` with the same parameters so the cost reservation / rate-limit accounting fires.

For **cost scope** specifically, **you must re-run check()** — the approval does not reserve cost. The re-run will hit `checkCost` and reserve atomically against `sessionCosts[session_id]`.

For most other scopes, the approval is sufficient and you can execute the action directly.

### SDK convenience: `guarded` with `wait_for_approval=True`

Both SDKs let you opt into blocking-until-resolved:

```python
# Python
@guarded("cost", guard=guard, wait_for_approval=True, approval_timeout=300)
def expensive_call(prompt): ...
```

```typescript
// TypeScript
const gated = guarded(guard, 'cost', makeExpensiveCall, {
  waitForApproval: true,
  approvalTimeoutMs: 60_000,
});
```

The decorator/HOF internally: `check` → if REQUIRE_APPROVAL, `wait_for_approval` → on ALLOW resolution, re-run `check` (so cost reserves) → run the wrapped function. On DENY resolution or timeout, it raises `AgentGuardDenied` / `AgentGuardApprovalTimeout`.

---

## Operational guidance

### Sizing the approval queue

- `MaxPendingApprovals = 10000` (hardcoded).
- **Evicts resolved entries first**, so a healthy triage process never hits the cap.
- A backlog > 1000 almost always means **nobody is triaging** — alert on `agentguard_pending_approvals > 100 for 15m`.

### Choosing notifier targets

- **Slack / Discord / Teams**: best for human triage (interactive link, colored attachment).
- **Webhook**: for piping into your incident platform (PagerDuty, Opsgenie).
- **Console / log**: dev-only, or as a fallback when other targets are down.

### Auditability

Every resolution is recorded in the audit log with `decision: ALLOW` or `DENY` and `matched_rule: require_approval:*`. The follow-up re-run check is also recorded. You can reconstruct the full chain by querying `/v1/audit?agent_id=X` and following `approval_id` values.

---

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Approvers never see Slack/webhook notification | Queue dropped on slow endpoint, or filter mismatch in `notifications.approval_required` | Watch `agentguard_notify_events_dropped_total`; verify the notifier's `type` block in policy. |
| `approval_url` in Slack is `http://localhost:8080` behind a proxy | `--base-url` not set | Start server with `--base-url https://guardrails.example`. |
| Approval works in dashboard but `POST /v1/approve/{id}` from script returns 401 | Missing Bearer | Set `Authorization: Bearer $KEY`. |
| Approvals "stuck" after a restart | Running with `--persist=false`, or the entry was created inside the final store-sync window before a crash | Re-issue `check()` from the agent; resolving stale IDs is a no-op. |
| Agent sees ALLOW but action fails at cost check | Cost only reserves on `check()` re-run after approval | Either re-run check, or use the `guarded` wrapper with `wait_for_approval=True`. |

---

## Related docs

- [`docs/API.md`](API.md) — approve/deny/status endpoint shapes.
- [`docs/DASHBOARD.md`](DASHBOARD.md) — UI walkthrough for approvers.
- [`docs/OPERATIONS.md`](OPERATIONS.md#approval-queue-capacity) — queue sizing and restart behavior.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — when REQUIRE_APPROVAL fires.
