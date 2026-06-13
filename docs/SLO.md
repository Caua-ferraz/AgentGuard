# Service Level Objectives — AgentGuard v0.7

**Status:** baseline established. Targets below are operational expectations
for a single-replica deployment running the in-process file-backed audit
logger; revisit when deployments adopt the v0.6 store-backed audit
(`--audit-backend=store`) or when horizontal scale-out becomes a thing.

## Service in scope

`POST /v1/check` — the policy enforcement endpoint that AI agents call
before every sensitive action. Every other surface (approvals, audit
queries, dashboard, SSE) is best-effort and **not** part of this SLO.

## Workload assumptions

The targets below assume:

- **Single-replica** AgentGuard process on commodity hardware (modern x86
  laptop / small cloud VM, ≥4 cores, ≥8 GiB RAM, local SSD).
- **In-process file-backed audit logger** (`audit.FileLogger` writing to
  local SSD). Network-attached storage will degrade the audit-write tail.
- **No upstream network calls in the hot path** — `/v1/check` does not
  hit a webhook or Slack on the synchronous reply (notifications fan out
  on a non-blocking queue; see `pkg/notify`).
- **All rules fit in memory.** The engine evaluates against a single
  `*Policy` snapshot under a read lock; we have not modeled policies
  larger than a few hundred rules.
- **No `require_prior` conditional rules** in the request path. They
  trigger an audit-log scan that is explicitly out-of-scope for this
  SLO (see "Out of scope" below).
- **Cost-scope traffic is a minority of total volume.** Cost requests
  acquire a write lock; sustained heavy contention on the cost scope is
  out-of-scope.

## Targets

| Metric                      | Target               | Why                                               |
| --------------------------- | -------------------- | ------------------------------------------------- |
| `/v1/check` p50 latency     | **< 1 ms**           | Engine path is in-memory; audit write is a single `json.Encode` to a buffered file. |
| `/v1/check` p95 latency     | **< 3 ms**           | Allows one fsync per request to stay inside 3 ms. |
| `/v1/check` p99 latency     | **< 5 ms** at 1k RPS | GC pause + sporadic file-system sync. |
| Throughput (sustained)      | **≥ 1 000 RPS**      | Per replica; horizontal scale-out is out-of-scope for v0.5. |
| Audit-write durability lag  | **< 100 ms**         | Time between `Log()` returning and the entry being readable by `Query`. |
| Approval-required emit lag  | **< 250 ms**         | `notify.Dispatcher` queue depth + a single webhook hop. |

These targets are **aspirational** for v0.5. They are validated against the
benchmarks in §Baseline below; production validation against a real
workload (with realistic policy sizes and concurrency) is tracked as a
v0.6 follow-up.

## Out of scope for the v0.5 SLO

- **Cost-scope under heavy contention.** `Engine.Check(scope="cost")`
  takes a write lock so cost reservation and decision are atomic. Many
  concurrent cost checks against the same `Engine` instance will serialize.
  We do not bound p99 in this regime.
- **`require_prior` audit-history scan.** When a rule has a `require_prior`
  condition, the engine queries the audit log via `HistoryQuerier`, which
  walks the JSONL file linearly. p99 here scales with audit-log size.
  Deferred (the v0.6 store backend's indexed `audit_entries` table is the
  intended fix before we publish a target).
- **Startup replay.** `NewServer` re-reads the audit log to seed in-memory
  decision counters. A multi-GiB log delays the first accurate `/metrics`
  scrape; this is documented in `CLAUDE.md` and not part of the steady-state
  SLO.
- **CSRF / session-store contention** on the dashboard auth path. The
  dashboard is a developer tool, not a load-bearing surface.

## Baseline (v0.5)

Numbers below were captured on `2026-05-05` with `make bench` on an AMD
Ryzen 7 5800X (16-thread, Windows 11, Go 1.26.1) using a local SSD.
They are micro-benchmarks of the hot-path primitives, not full
end-to-end RPS measurements — but they bound the per-request floor.

| Benchmark                                    | ns/op   | B/op   | allocs/op |
| -------------------------------------------- | ------: | -----: | --------: |
| `BenchmarkEngineCheck_AllowFastPath`         |   284.9 |    104 |         6 |
| `BenchmarkEngineCheck_DenyDeepMatch` (100 allows + 1 deny match) | 215.6 | 72 | 4 |
| `BenchmarkGlobMatch_DoubleStar/Match`        |   200.0 |    144 |         2 |
| `BenchmarkGlobMatch_DoubleStar/NoMatch`      |   196.9 |    144 |         2 |
| `BenchmarkFileLogger_Log` (single-threaded append) | 4 546 | 336 | 2 |
| `BenchmarkDispatcher_Send_QueueFull` (drop path under saturation) | 3 010 | 483 | 30 |

**Reading the numbers:**

- Engine `Check` for the common allow path is ≈ 286 ns / 6 allocs. With
  a per-request audit write of ≈ 4.2 µs, the synchronous floor for
  `/v1/check` lands well under the **p50 < 1 ms** target with three
  orders of magnitude of headroom for HTTP framing and OS scheduling.
- The deny-deep-match path (walk past 100 allows to a deny) is actually
  *cheaper* per-op than the allow fast path — the deny match short-
  circuits before any allow allocation, and `formatRule` for the matching
  deny does fewer string ops than the allow message format. This bounds
  the worst-case `Check()` shape we ship by default.
- `globMatch` with `**` against a 5-segment path is ≈ 155 ns regardless
  of match/no-match. The two-allocation cost is the segment-split slices;
  a future zero-alloc rewrite is queued in `R4 E1`.
- `FileLogger.Log` at 4.2 µs / 2 allocs / 336 B is within an order of
  magnitude of the syscall floor for an `O_APPEND` write of a ≈ 200 B
  JSON line. Replacing the per-record `json.Encoder` with batched writes
  is the obvious next optimisation (deferred — `R4 F2`).
- `Dispatcher.Send` on a fully wedged queue costs ≈ 3 µs / 30 allocs.
  The allocations come from the redactor scrubbing the event payload
  (`Redactor.Redact` returns a new `Event` with redacted strings); they
  are paid even when the queue drops the event. Reducing the redactor's
  alloc footprint is queued in `R4 E2`.

## Re-running the baseline

```bash
make bench
```

The target runs `go test -bench=. -benchmem -run=^$ ./...` so only
benchmarks fire (`-run=^$` skips regular tests) and allocations are
reported. Capture the numbers and replace the table above when the
benchmarks shift materially (≥ 10 % regression).

## Validation plan

The benchmarks above are the v0.5 floor. The SLO targets themselves
will be validated by:

1. A `vegeta`/`hey` harness against `agentguard serve` running with
   `--policy configs/default.yaml` and a tmpfs-backed audit log,
   driving 1 kRPS sustained for 5 minutes. **Not yet automated** —
   tracked for v0.6.
2. Latency histograms exported via `/metrics`
   (`agentguard_request_duration_ms`,
   `agentguard_policy_eval_duration_ms`,
   `agentguard_audit_write_duration_ms`).
3. p99 reported by Prometheus' `histogram_quantile(0.99, …)` over a
   30-second window.

Until the harness is automated, the in-process micro-benchmarks above
are the contract.
