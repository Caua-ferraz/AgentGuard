# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] — 2026-07-21

> **The validated 1.0 — multi-node, and the additive-only guarantee goes hard.** This is the release the v0.9 surface-stabilization was the step before. Two things define it. First, AgentGuard now runs as **more than one replica** against a shared **PostgreSQL** backend, with approval / rate-limit / cost state converging across nodes through a background reconcile loop — **without touching the `/v1/check` hot path** (no synchronous DB call was added; the <3 ms p99 budget is preserved and gated in CI). Second, the pre-1.0 validation window is over: from 1.0 the **additive-only** rule in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) is a hard guarantee for the 1.x line, not an intent. A single-node deployment upgrades as a binary/SDK swap — multi-node is entirely opt-in behind a Postgres `--store-dsn`. This release also folds in the security, validation-hardening, and doc-honesty work done on the road to the 1.0 mark. Operators upgrading should read [`MIGRATION.md`](docs/MIGRATION.md) § v0.9.0 → v1.0.0 for the two behavior changes that matter (write-once / one-shot approvals).

### Added

- **PostgreSQL multi-node backend — shared state across replicas.** A Postgres `--store-dsn` (`postgres://…` / `postgresql://…`) selects a new `store.PostgresStore` (pgx v5, `database/sql` stdlib driver, pure-Go, mirroring `SQLiteStore`) behind the existing frozen `store.Store` interface. Approvals, rate-limit consumption, and cost accumulators are the shared durable tier; each node keeps its in-memory state authoritative and **converges in the background** via per-node-rows-summed consumption tables (`rate_consumption`, `cost_consumption`) and interval approval re-hydrate + merge. The zero-config single-node SQLite default is unchanged — the reconcile ticker never starts on SQLite. New exported surface for embedders: `store.NewPostgresStore`, the reconcile delta types (`ratelimit.BucketDelta`, `policy.CostDelta`, `store.RateConsumption`/`CostConsumption`), and the `ApprovalReplayRefusedTotal` / `IncApprovalReplayRefused` metric accessors. Design: [`docs/v1.0-multinode-PLAN.md`](docs/v1.0-multinode-PLAN.md); operator sizing: [`docs/OPERATIONS.md`](docs/OPERATIONS.md#multi-instance-deployments).
- **`--node-id` serve flag** (default: OS hostname) — stable identifier for this node in multi-node reconciliation. Each replica MUST have a distinct value; an empty value disables reconciliation. Additive; single-node deployments never need it.
- **`--reconcile-interval` serve flag** (default `2s`) — cadence of the background rate-limit/cost/approval reconciliation loop. **Takes effect only with a Postgres `--store-dsn`**; on the SQLite backend it is forced to `0` and the loop never starts. `0` disables reconciliation.
- **`--approval-validity` serve flag** (default `5m`) — how long a resolved ALLOW is honored by the `/v1/check` approval-id retry, measured from resolution. Past the window the retry re-enters the approval flow under a new id; `0` restores the unbounded pre-v1.0 window. The default matches the SDKs' `wait_for_approval` poll window.
- **`POST /v1/audit` (+ `/v1/t/{tenant}/audit`) — auth-gated, DENY-only central audit-ingest endpoint.** Backs the F1 audit-verdict fidelity fix (see *Fixed*): when a proxy forces a fail-closed refusal for a malformed streaming tool call, it now records the **forced `malformed_tool_call` DENY** centrally via `handleAuditRecord` (single-source-of-truth preserved — the proxy still writes no local audit) instead of letting the policy verdict stand in the audit trail. Additive `policy.AuditRecord` type + `Server.RecordForcedAudit` → `gate.RecordForcedAudit` → `gateclient.Caller.RecordForcedAudit` wiring; a nil hook falls back to the prior audit-via-`PolicyCheck` path. On a `POST /v1/audit` record failure (canonical case: a keyed central server but an unkeyed proxy → 401), the proxy best-effort falls back to the `/v1/check` audit path so a forced refusal is never left un-audited — **fidelity** degrades to the engine verdict but **coverage does not**; give the proxy `--api-key` when the central server is keyed for full fidelity.

### Changed

- **Approval lifecycle hardening, enforced cluster-wide.** Resolutions are now **write-once**: re-approving an approved id (or re-denying a denied one) stays an idempotent no-op, but a *conflicting* re-resolution returns `409 Conflict` with a structured body (`policy.ApprovalConflictError`) instead of silently flipping the decision — the last-write-wins hole is closed. A resolved ALLOW is **one-shot and time-boxed**: the first `/v1/check` retry carrying the `approval_id` consumes it (`consumed_at`), later replays re-enter the approval flow, and honoring is bounded by `--approval-validity`. Across nodes these properties are preserved by a **monotonic merge**: `ApprovalQueue.ApplyRemote` merges remote resolutions DENY-wins and never clobbers unflushed local pendings, and `UpsertApprovals` on **both** store backends is a monotonic upsert — never un-resolves, never flips DENY→non-DENY, never clears `consumed_at`. So one human click is honored **once per cluster**, and a Postgres restart never resurrects a spent ALLOW.
- **Distributed rate limiting is bounded-overshoot by design, not global-strict.** Because reconciliation is background-only (to hold the no-sync-DB-on-`/v1/check` invariant), a cluster's aggregate admissions may exceed a single global budget by up to **≈ `reconcile-interval` × peak-rate × replicas** before convergence. This is a deliberate, documented trade — global-strict limiting would require a synchronous cross-node check on the hot path, which the latency budget forbids. Single-node behavior is exactly as before (the reconcile path is a proven no-op). See [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md#topology).
- **Go toolchain pinned to `go1.25.12`** in `go.mod` (`toolchain` directive) — carries the stdlib fix for **GO-2026-5856** (crypto/tls Encrypted Client Hello privacy leak); go1.25.11 and earlier trip the CI govulncheck gate. See *Security*.
- **MCP Gateway protocol-coverage docs truthed-up (no behavior change to drop paths).** The gateway brokers `tools/*` only: `resources/*` and `prompts/*` capabilities are **masked** by `MergeCapabilities` (default dispatch is `MethodNotFound`), not "forwarded verbatim" as the old [`docs/MCP_GATEWAY.md`](docs/MCP_GATEWAY.md) § 3.3 / § 10 claimed. `notifications/cancelled` is documented as a latent no-op (host-space vs gateway-internal request-id spaces — § 8.4, which had overstated forward-to-upstream + cancel + audit). Server-initiated requests (`sampling/createMessage`, `roots/list`, `elicitation/create`) still drop, but a dropped frame carrying a `method` now logs at **Info** (was Debug) so operators see unsupported server→client requests. The README gained an "MCP brokers tools only" limitation bullet.
- **Contributor-facing `CLAUDE.md` now enumerates the latency hot path** — the exact packages/functions on the read-a-byte/forward path (`pkg/llmproxy` streaming/forward/parsers, `pkg/policy` `Engine.Check` & matchers, `pkg/proxy` `handleCheck`, `pkg/ratelimit` `Allow`, `pkg/internal/gateclient`), verified against code, so the "no sync DB / no blocking I/O / no per-request allocs on the hot path" rule is checkable rather than folklore.
- **v1.0 documentation-accuracy pass.** README, COMPATIBILITY, MIGRATION, and the current-state docs are corrected to describe the shipped 1.0 behavior — multi-node Postgres, the bounded-overshoot semantics, approval write-once/one-shot lifecycle, and the F1–F3 fixes below — replacing v0.9-era "single-node is the supported topology / Postgres is post-v1" wording.
- **Version set to 1.0.0** across all three binaries (`agentguard`, `agentguard-mcp-gateway`, `agentguard-llm-proxy`), both SDKs (`agentguardproxy` on PyPI, `@agentguard/sdk` on npm), and the docs' canonical version references.

### Fixed

- **F1 — malformed streaming tool calls now fail closed (was: silent audit gap + stuck accumulator).** A completed tool call whose assembled arguments were not valid JSON returned `Completed:true` with a parse error and hit `if ferr != nil && !isEOF { continue }`, which skipped the gating switch entirely: no fail-closed refusal, no audit entry, and the accumulator's `activeToolUseIndex` was never reset, so the stream stayed broken for the rest of the connection (buffered bytes were dropped at EOF — not a client bypass, but an audit-visible stream went dark). Both providers now emit a fail-closed synthetic refusal (`denyMalformedOpenAI` / `denyMalformedAnthropic`), reset the accumulator, and continue. The **happy path is byte-identical** — only the malformed-completion branch changed; the `Allow` path stays 0-alloc. The follow-up audit-verdict fidelity fix (the forced DENY reaches the audit trail, not the policy verdict) is the `POST /v1/audit` ingest endpoint under *Added*.
- **F3 — `globMatch` documentation corrected to match code + non-fatal policy-lint warning.** A path pattern containing `/` but no `**` (e.g. `/workspace/*`) falls through to unanchored `wildcardMatch`, where `*` crosses `/` and matches `/workspace/a/b/secret.env` — contradicting `globMatch`'s own documented "stable contract." Matching **semantics are unchanged** (tightening them would break the frozen policy contract); instead the contract doc is corrected and `serve`/policy load now emits a non-breaking lint **warning** for patterns that match more broadly than they appear to. Operators relying on `/prefix/*` to bound a single directory should switch to an explicit `**`-anchored pattern.
- **MCP Gateway drop-path observability** — see *Changed*; unsupported server-initiated requests are no longer invisible at production log levels.
- **Python SDK filesystem-`action` inference now matches the Go transports** — the adapters (`agentguard/adapters/_common.py`) inferred the filesystem `action` by **substring** with a narrower verb set, so `edit_file`/`append_file`/`copy_*`/`move_*`/`unlink`/`rm*`/`list_*`/`stat`/`cat`/`find`/`glob` sent **no** `action` through LangChain/CrewAI/MCP while the Go transports (`gateclient.InferFilesystemAction`) sent one — and substring matching also mis-fired on names like `set_target` (contains "get"). Inference is now the same **prefix-matched** verb groups shared with `gateclient.InferFilesystemAction`, pinned by a parity test that mirrors the Go table. Operators whose policies key on filesystem `action` may see new (correct) matches through the Python adapters — the same class of change the v0.7 cross-transport skew fix documented.
- **Audit flush workers now isolate panics from the underlying logger.** A panic inside `underlying.Log` (a store-driver panic, a custom `MarshalJSON`, a nil-handle close race) escaped the `BufferedAsyncLogger` worker goroutine unrecovered and aborted the whole process, violating "a flush worker crash must never block or crash the proxy loop." The worker now recovers the panic and routes the entry to the existing overflow path (durable on disk, drop-accounted) instead of crashing — mirroring the panic isolation `pkg/notify`'s dispatcher already had.

### Security

- **F2 — domain matching is now case-insensitive (was a true fail-open deny bypass).** `normalizeRequest` never lowercased the request domain and `matchRule` → `globMatch` compared case-sensitively, so a deny rule for `evil.com` did **not** match the DNS-equivalent request `EVIL.com` — the deny was skipped and the request fell through to allow. Both the request domain (in `normalizeRequest`) and rule domains (at load) are now lowercased. No measurable hot-path cost (p99 ≈ 0.75 µs, no benchmark regression). Policies that accidentally relied on case-sensitive domain rules are now evaluated case-insensitively.
- **pgx bumped v5.9.1 → v5.9.2 — GHSA-j88v-2chj-qfwx (SQL injection).** v5.9.1 was vulnerable to SQL injection via dollar-quoted placeholder confusion; the advisory is reachable through the new Postgres backend. Both the reachability-based `govulncheck` job and the cross-ecosystem `dep-audit` gate fired correctly; verified clean live against OSV.dev post-bump.
- **crypto/tls Encrypted Client Hello privacy leak — GO-2026-5856.** Resolved by pinning the build toolchain to `go1.25.12` (see *Changed*).

### Compatibility

- **The v1.x additive-only guarantee formally begins with this release.** As declared in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), no frozen field, route, flag, subcommand, scope, or schema version is removed, renamed, or repurposed across the 1.x line; only optional additive surface may be added, and consumers must tolerate unknown additive surface. A genuinely breaking change would be a major-version event behind a new identifier (`schema/v2`, audit `schema_version: 3`, a new route family), never a silent mutation. This release is **additive-only vs v0.9.0** — verified by diffing `go doc -short ./...` against the `v0.9.0` tag: **0 exported declarations removed**, and the only CLI-flag changes are the three additions above (`--approval-validity`, `--node-id`, `--reconcile-interval`).
- **One correction made under the pre-1.0 reserved right:** approval resolutions became write-once / one-shot (see *Changed*). This is the last-write-wins → write-once tightening documented in [`MIGRATION.md`](docs/MIGRATION.md#v090--v100); it is the reason the freeze is anchored at 1.0 rather than 0.9.
- **`/v1/check` request/response shapes, the audit format (`schema_version: 2`), and the policy schema (`version: "1"`) are byte-for-byte compatible with v0.9.**

### Migration

- **v0.9.0 → v1.0.0 is a binary/SDK swap for single-node deployments — no config or data changes required.** On first boot the SQLite/Postgres store applies an **additive, idempotent** schema migration (the `approvals` table gains `consumed_at` / `resolved_via` / `resolved_from`; the `rate_consumption` and `cost_consumption` tables are created); pre-v1.0 approvals load as unconsumed/unstamped and no rows are rewritten. `agentguard migrate` is not involved. Multi-node is opt-in: provision PostgreSQL, set `--store-dsn postgres://…` and a distinct `--node-id` per replica, and read the bounded-overshoot sizing note before setting `--reconcile-interval`. Rollback to v0.9.0 is supported (the extra columns/tables are ignored by the older binary), with two documented degradations. Full detail: [`MIGRATION.md`](docs/MIGRATION.md#v090--v100).

### Known limitations

- **A sustained multi-node soak against live PostgreSQL has not been run.** CI's `postgres-integration` job and the pg-gated tests cover multi-node **correctness** against a real Postgres 16, and the latency gates cover sustained single-process load, but a long-running, many-replica load test against a live shared Postgres is still outstanding and is recommended before production multi-node rollout.
- **Approval cross-node staleness is bounded by `--reconcile-interval` (default 2s).** The optional Postgres LISTEN/NOTIFY nudge to shrink this to sub-100 ms (`1-A-notify`) is not in 1.0; per-node deny remains fail-closed in the meantime.

## [0.9.0] — 2026-07-09

> **Surface-stabilization release — the step before a validated v1.0.** AgentGuard's public surface is now stabilized: all three enforcement paths (MCP Gateway, LLM API Proxy, SDK / `/v1/check`) are verified end-to-end, the test suite is green, and v0.9 locks in the surfaces it intends to freeze at 1.0 while correcting one honesty defect. There are **no new features** and **no breaking changes** — the `/v1/check` wire protocol and the audit JSONL are byte-compatible with v0.7 (no schema bump). See [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) for the stabilized surfaces and the additive-only intent (a hard guarantee from 1.0). v0.9 ships only after additional testing and validation.

### Added
- **[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — the surface-stabilization contract.** Declares the surfaces v0.9 stabilizes and intends to freeze at 1.0 — the policy YAML schema (`version: "1"`), the `/v1/check` + `/v1/t/{tenant}/...` wire protocol, the audit `schema_version: 2` format, and the CLI flags/subcommands — and the additive-only intent (no field, route, flag, or schema version removed or renamed; breaking changes would be a major-version event). Linked from the README docs table.
- **CI hot-path p99 latency gate.** New `TestEngineCheck_P99LatencyGate` (`pkg/policy`) runs `policy.Engine.Check` with the persistence syncer active and **fails if p99 crosses the 3 ms budget** (measured baseline ≪0.1 ms for the bare engine; ~0.53 ms for the full HTTP `/v1/check` path). Wired as a dedicated step in `.github/workflows/ci.yml` alongside the existing HTTP-path persistence-on latency check (`TestIntegration_HotPathLatencyWithPersistence`), so a regression that lands blocking I/O on the hot path breaks the build.

### Changed
- **Audit "tamper-evident" claim corrected (the one real defect).** The README and FAQ marketed the audit log as "tamper-evident," but the code provides an **append-only** JSON-Lines log with no cryptographic integrity chain. The wording is now accurate: AgentGuard writes an append-only audit trail, and **tamper-evidence is achieved by forwarding it to append-only / WORM storage** (S3 Object Lock, a SIEM, or syslog) — AgentGuard does not seal the log itself. No code or on-disk format changed; this is a documentation correction only. (Closes internal-audit finding **L4** by truth-up, not by crypto — in-process hash-chaining / Merkle checkpoints were evaluated and deferred out of core scope.)
- **`/v1/check` latency telemetry corrected.** `X-AgentGuard-Total-Ms` and the `agentguard_request_duration_ms` SLO histogram are now measured end-to-end (after the audit enqueue), matching their documented "end-to-end" definition; previously they were captured before the audit write and understated a slow audit backend. Response-header / metric change only — no wire-format or gating change.
- **Single-node posture stated plainly.** README Limitations now declares single-node (`replicas: 1`) the **supported, stable topology**, with PostgreSQL / multi-node explicitly a v1.0 requirement (post-v0.9). No behavior change.
- **Version set to 0.9.0** across all three binaries (`agentguard`, `agentguard-mcp-gateway`, `agentguard-llm-proxy`) and both SDKs (`agentguardproxy` on PyPI, `@agentguard/sdk` on npm).
- **Planning-doc cleanup.** The stale `docs/v0.8-DESIGN.md` (a rejected crypto/RBAC/Merkle plan) was removed. The v1.0 roadmap (Postgres/multi-node + validation hardening) is tracked in the README [Roadmap](README.md#roadmap), and the deferred RBAC / secret-redaction / audit-crypto work is recorded in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) under *Post-v1, only if a concrete need arises*.

### Compatibility
- **No migration required.** The `/v1/check` request/response shapes, the audit `schema_version: 2` JSONL format, the policy schema (`version: "1"`), and every CLI flag/subcommand are unchanged from v0.7. Upgrading is a binary/SDK swap. See [`MIGRATION.md`](docs/MIGRATION.md) § v0.7.0 → v0.9.0.

## [0.7.0] — 2026-06-12

> The consistency + durability release. Three workstreams land together (v0.6.0 was tagged but had no standalone release notes or CHANGELOG entry — its milestone is documented here):
>
> 1. **Persistent multi-tenant state** (the v0.6 milestone): `serve` is stateful by default — approvals, rate limits, and cost accumulators survive restarts via a zero-config SQLite store, and per-tenant policies are first-class (`agentguard tenant put`, isolated runtime state, tenant-scoped audit).
> 2. **Cross-transport verdict consistency**: the `/v1/check` gate client and check-param inference are now implemented once and shared by the MCP Gateway, LLM API Proxy, and Python adapters — the same tool call gets the same verdict on every integration path (this fixed real skews; see *Fixed*).
> 3. **Outage durability + operations**: fail-closed denials are auditable locally while the central server is down (`--fail-audit-log`), notification overflow spools to disk instead of dropping (`--notify-spool`), `/v1/health` reports `"degraded"` on real durability signals, and `agentguard check --watch` brings one-policy-load streaming verdicts to CI and local harnesses.
>
> Operator-facing summary: [`docs/releases/v0.7.0.md`](docs/releases/v0.7.0.md).

### Added
- **Local fallback audit on central-server outage** — both proxies' `--fail-mode fail-closed-with-audit` now appends each denial to `--fail-audit-log` (default `agentguard-fail-audit.jsonl`, canonical `audit.Entry` JSONL) while `/v1/check` is unreachable; the `_with_audit` suffix is no longer roadmap intent.
- **`agentguard check --watch <jsonl>`** — follow a JSONL file (tail -f) and verdict each appended request with one policy load for the whole stream (policy hot-reloads on edit); SIGINT returns the aggregate exit code.
- **Notify spool-to-disk (`--notify-spool`)** — notification events that overflow the dispatch queue spill to a JSONL spool and are redelivered by a recovery loop (including leftovers from a previous process) instead of being dropped. New counters `agentguard_notify_spooled_to_disk_total` / `agentguard_notify_despooled_total`.
- **MCP gateway forwards `notifications/tools/list_changed`** from upstreams to the host and now advertises `tools.listChanged: true`; hosts re-pull `tools/list` when an upstream's tool set changes.
- **Buffered-audit observability** — `agentguard_audit_buffered_dropped_to_overflow_total`, `agentguard_audit_buffered_drained_from_overflow_total`, and the `agentguard_audit_buffered_queue_depth` gauge.
- **Metrics-derived `/v1/health`** — corrupt audit lines and dropped notifications surface as warnings; an audit overflow backlog flips `status` to `"degraded"` (HTTP stays 200 so liveness probes don't flap).
- **LangChain stream re-gating** — `stream`/`astream` re-validate the policy decision every 10s (`STREAM_REGATE_SECONDS`) so a mid-stream revocation cuts the stream off instead of riding to completion.

- **Durable persistent state (v0.6).** `agentguard serve` is now stateful by default: the approval queue, rate-limit buckets, and cost accumulators survive a restart. New `pkg/store` (`Store` interface + `SQLiteStore`, pure-Go `modernc.org/sqlite`, WAL) and `pkg/persist` (write-behind syncer). On boot the syncer hydrates the in-memory maps from the store; a background ticker (hard ≥1 s floor) and graceful shutdown flush snapshots back. The store is a **cold-path** component — never read or written on the `/v1/check` request path, so the <3 ms p99 budget is preserved (measured p99 0.53 ms with persistence on). New `serve` flags: `--persist` (default `true`), `--store-dsn`, `--data-dir`, `--audit-backend=file|store`. `--persist=false` restores the legacy pure-in-memory behavior.
- **Multi-tenant policies (v0.6).** Tenants beyond `local` can be registered (store `policies` table + `policy.MultiTenantProvider`) and are evaluated against their **own** policy through the existing `/v1/t/<tenant>/...` routes, with isolated approvals, rate limits, cost accumulators, and audit. New `agentguard tenant put|list|rm` subcommand manages them. A tenant with no registered policy denies with `deny:tenant:not_found`; an infrastructure (store) failure denies with `deny:tenant:provider_error`. Non-local policies are parsed once and cached in memory, so per-tenant evaluation never hits the DB on the hot path.
- **Tenant-keyed runtime state + audit `tenant_id` (v0.6).** Every per-request store is partitioned by tenant: rate-limit bucket key `scope:tenant:agent`, session-cost accumulator `(tenant, session)`, and the approval queue's `Lookup`/`Resolve`/`List`/SSE scoped per tenant (a foreign tenant's id returns "not found" — no cross-tenant existence oracle). The audit schema gained an additive `tenant_id` field/column, and `/v1/t/<tenant>/audit` is now scoped to its tenant — **closing a cross-tenant audit-read leak**. Single-tenant (`local`) output stays byte-identical (the local tenant is stored as `""`), so the audit `schema_version` is unchanged.

### Fixed
- **Cross-transport policy-verdict skew** (gate/adapter consolidation) — the same tool call could produce different action-keyed rule matches depending on transport. CrewAI's adapter never sent the inferred filesystem `action` (LangChain's did); the MCP gateway didn't recognise `cat`/`find`/`glob` as read verbs (the LLM proxy did); the Python MCP adapter missed `create`→`write`. All transports now share one inference (`pkg/internal/gateclient.InferFilesystemAction`, `agentguard/adapters/_common.py`). Operators whose policies key on `action` may see new (correct) matches through CrewAI/MCP.
- **MCP gateway: unrecognised `/v1/check` decision strings** now deny with the stable `Rule="deny:gateway:invalid_response"` (parity with the LLM proxy's `deny:llm_api_proxy:invalid_response`) instead of passing the malformed verdict through bare. Add the new rule to outage/alerting dashboards.
- **`/v1/check` User-Agent version skew** — both proxies stamped a hard-coded `…/1.0` on the side-channel call while reporting the real build version elsewhere; they now report `BuildVersion`/`GatewayBuildVersion` consistently.
- **MCP gateway flag validation parity** — `--tenant-id` must be non-empty and `--guard-url` must be an http(s) URL, matching the LLM proxy.
- **Flaky concurrent-stream cap tests** — the three `TestServer_MaxConcurrentStreams_*` tests polled a real-time gauge against a wall-clock deadline and starved under full-suite parallel load. Replaced with a deterministic barrier: the test upstream signals once per admitted+forwarded stream, and the test drains N signals before asserting. No timing dependence.

- **Policy watcher transient-read race** (`pkg/policy/watcher.go`) — an atomic-replace policy edit (write-temp + rename) racing `reload` on Windows leaves the destination briefly locked after `MoveFileEx`, so the reload's open-for-read returns `ERROR_SHARING_VIOLATION`; that failed read was swallowed and, on the event-driven fsnotify path (no periodic tick), the change was lost until the next unrelated event. `reload` now retries transient `*fs.PathError` reads with a small bounded backoff (parse/validation errors surface immediately); the retry runs on the watcher's background goroutine, off the request path. Stabilizes the previously-flaky `TestATIntegration_ProviderReloadE2E` / `TestFilePolicyProvider_WatchCallbackPanicDoesNotKillWatcher` / `TestATFilePolicyProvider_RaceWatchGetMutate`.

### Changed
- **Internal consolidation (no wire-format change).** The `/v1/check` client, fail-mode translation, `Decision` type, and shared gate CLI flags now live once in `pkg/internal/gateclient` (both proxies re-export `Decision` via type alias — public APIs unchanged). Python adapters share `adapters/_common.py` for check-param extraction; the SDK split into `core.py`/`decorators.py` with the package root re-exporting everything (imports and mock-patch targets unchanged).
- **`pkg/metrics` is now a `Registry`** with package-level delegates to `Default`; exported raw counter vars became same-named accessor functions and the exported histograms became `Observe*Duration` functions (Go API change for direct importers; Prometheus exposition is byte-identical). `metrics.Reset()` added for test isolation.
- **Audit pipeline construction** extracted from `runServe` into `cmd/agentguard/audit_setup.go` with explicit shutdown ordering; the never-wired `audit.SQLiteLogger` prototype was removed (the store backend `--audit-backend=store` is the live SQLite path). File/store backend `QueryFilter` semantics are pinned by a parity test.
- **Repo hygiene:** `.gitattributes` forces LF for `*.go` (gofmt is meaningful on Windows checkouts); repo-wide gofmt pass.

- **`serve` is stateful by default.** A first run creates `agentguard.db` (+ `-wal`/`-shm` sidecars, now gitignored) in the working directory. This is additive — the wire contract (`schema_version: v1`, the `/v1/t/{tenant}/...` routes) is unchanged, and `--persist=false` reverts to the prior behavior.

## [0.5.2] — 2026-06-01

> Maintenance release. Toolchain refresh (Go 1.22→1.25, Alpine 3.19→3.22 — both EOL on the previous pin), TypeScript SDK majors (TS 5→6, Jest 29→30, Node floor 18→20 — Node 18 EOL), supply-chain monitoring (govulncheck on every push, SBOM SPDX+CycloneDX attached on release), and a real bug fix in the MCP gateway: the upstream `initialize` was emitting `capabilities` as omitempty/null, which the current `@modelcontextprotocol/server-filesystem` (the README's quickstart example) and any spec-conformant strict server reject. The README's headline MCP Gateway path is functional again.

### Fixed

- **MCP Gateway initialize spec compliance** (`pkg/mcpgw/protocol.go`, `pkg/mcpgw/transport.go`) — `params.capabilities` is REQUIRED by the MCP spec; v0.5.0/v0.5.1 emitted it `omitempty` and sent `null` when the host passed no caps. Strict upstreams (current `@modelcontextprotocol/server-filesystem`) reject this with `expected object, received undefined`. Tag is now plain `json:"capabilities"`, and the send site normalises nil → `map[string]interface{}{}` so the field always serialises as `{}`. The README quickstart works again.
- **Policy watcher modTime race** (`pkg/policy/watcher.go`) — fsnotify v1.10.1's faster event delivery exposed an existing race where a failed parse advanced `w.modTime` to the just-Stat'd mtime, then a subsequent good save whose mtime happened to fall *before* the advanced value (e.g. after a test bumped mtime to `now+2s`) was silently skipped. `modTime` now advances only on successful parse.
- **`test_guardedtool_batch_all_allowed`** (`plugins/python/tests/test_langchain.py`) — assertion compared `calls == ["a","b","c"]` (execution order on a concurrent `batch()`); passed by luck on Python 3.10–3.12 schedulers, failed on 3.13. Now compares `sorted(calls)` — same semantic ("all three inputs ran exactly once") without scheduler dependence.

### Changed

- **Go toolchain → 1.25.** `go.mod`, Dockerfile builder stage, all CI `go-version` slots. 1.22 went EOL when 1.24 landed; only 1.25/1.26 are upstream-supported now.
- **Docker runtime base → Alpine 3.22.** Dockerfile. 3.19 was EOL; 3.22 is supported through 2027-05.
- **TypeScript SDK majors.** `typescript ^5.3 → ^6`, `jest ^29 → ^30`, `@types/jest ^29 → ^30`, `@types/node ^20 → ^22`. `ts-jest` stays on `^29.4` (it versions independently of Jest and 29.4.x supports Jest 30 via peers; no v30 exists). Fallout fixes: explicit `"types": ["node", "jest"]` in `tsconfig.json` (TS 6 stopped auto-discovering `@types/*`); dropped the now-invalid two-generic `jest.fn<Ret, Args>(...)` signature across 9 call sites in `src/__tests__/index.test.ts` (Jest 30 unified to a single function-type generic).
- **Node floor → ≥20**, CI matrix `[18,20,22] → [20,22,24]`. Node 18 reached upstream EOL 2025-04-30; 24 is the current Active LTS.
- **golangci-lint v1.61 → v2.12.2**, action `@v6 → @v8`. v1 is end-of-life. New `.golangci.yml` configures v2's stricter default linter set: errcheck excluded on `_test.go` files entirely and on conventional cleanup-path Close/Fprint patterns (with allowlists for the project's audit `Logger`, `policy.PolicyProvider`, `policy.Engine`, and `*fsnotify.Watcher` types).
- **Python CI matrix gains 3.13** (`[3.10,3.11,3.12] → [3.10,3.11,3.12,3.13]`). The trove classifier already claimed 3.13; CI now actually exercises it.
- **Go modules refreshed via `go get -u && go mod tidy`** — `fsnotify v1.9.0 → v1.10.1` (legitimate; v1.10.1 checksum recorded in `go.sum`), `golang.org/x/sys v0.13.0 → v0.45.0`. `gopkg.in/yaml.v3` stays.

### Added

- **`vulncheck` CI job** — blocking, reachability-aware Go CVE scan via `govulncheck` on every push and pull request. Reachability filtering keeps it quiet on theoretical issues in unused transitive code; only fires on advisories whose vulnerable symbol is actually called from project code.
- **`release-sbom.yml` workflow** — on `release: published`, builds the binary with the same flags as the Dockerfile, runs `syft`, and attaches both SPDX-JSON and CycloneDX-JSON SBOMs to the GitHub release as downloadable assets. SPDX is the format auditors (SOC 2 / FedRAMP) ask for by name; CycloneDX is what most security scanners (Dependency-Track, Grype, Snyk) ingest natively.
- **`.golangci.yml`** — first project-level golangci-lint config; documents what's excluded and why so future linter bumps don't require re-discovering the rationale.

### Notes

- **fsnotify supply-chain advisory (May 2026).** A maintainer access/ownership dispute around `fsnotify` surfaced in May 2026. v1.10.1 itself is legitimate; its checksum is now pinned in `go.sum` and verified by Go's module proxy. Reviewers should still eyeball the `go.sum` diff. Detection layering (dependabot + govulncheck + SBOM) is the response — see the new supply-chain monitoring entries above.
- **MCP Gateway "examples" configs.** The five `examples/*-config.*` files reference `@modelcontextprotocol/server-filesystem` via `npx`. With the v0.5.2 gateway fix they work against the current published version; the gateway no longer requires pinning the filesystem-server.

## [0.5.1] — 2026-05-07

> Adapter hotfix + maintenance release. CrewAI 1.x + pydantic 2.12 and langgraph 1.0 + langchain_core 1.x both reject the v0.5.0 composition-wrapper adapters at framework boundaries (`isinstance(thing, BaseTool)` / `isinstance(thing, Runnable)` no longer honour `BaseTool.register()` virtual-subclass registrations). v0.5.1 ships hybrid subclass+override adapters that satisfy the framework's isinstance checks natively while preserving the policy-enforcement contract by overriding every dispatch entry point. All binaries (CLI, MCP Gateway, LLM API Proxy) bumped to v0.5.1 alongside the Python SDK. Python 3.9 dropped from the support matrix (upstream EOL October 2025); 3.10+ required.

### Fixed

- **Python SDK CrewAI adapter** (`agentguard.adapters.crewai.GuardedCrewTool`) — now subclasses `crewai.tools.BaseTool` directly. `Agent(tools=[GuardedCrewTool(...)])` no longer raises `pydantic_core.ValidationError` on CrewAI 1.x. Every gated dispatch path (`_run`, `run`, `invoke`, `ainvoke`, `_arun`, `arun`, `__call__`, `to_structured_tool`) is explicitly overridden so future framework additions surface in the canary integration test rather than silently bypassing the gate.
- **Python SDK LangChain adapter** (`agentguard.adapters.langchain.GuardedTool`) — now subclasses `langchain_core.tools.BaseTool`. `langgraph.prebuilt.create_react_agent(llm, tools=[GuardedTool(...)])` and `langchain.agents.create_agent(...)` both accept the wrapper directly; the v0.5.0 `Tool.from_function(func=lambda x: gt.invoke(x))` workaround is no longer required. ToolCall-shaped inputs (`{"name", "args", "id", "type": "tool_call"}`) are unwrapped to the underlying args dict before the gate runs.
- Both adapters now use `pydantic.PrivateAttr` for internal references (`_tool`, `_guard`, `_scope`); these fields are excluded from `model_dump()` output and kept off `model_fields`.
- **CI `python-test` job** — now installs `[dev,langchain,crewai,mcp]` so adapter unit tests can import the real framework packages. The previous lean `[dev]` install made ~50 tests fail with `ModuleNotFoundError` at collection time. `browser-use` remains excluded to keep the job lean (covered by the dedicated `integration-tests` matrix).

### Added

- **Best-effort update-notice on CLI invocation.** The `agentguard` binary asynchronously queries the GitHub Releases API at startup and prints a single stderr line if a newer version is published (`Notice: agentguard vX is deprecated, version vY available — …`). Bounded to 800 ms; errors and timeouts are silent. Disabled on `commit=dev` builds and via `AGENTGUARD_NO_UPDATE_CHECK=1`.
- **`scripts/test-all.sh` + `make test-all`.** Single entry point that runs all four suites (Go, policy YAML, Python SDK, TypeScript SDK) with `PASS/FAIL/SKIP` summary. Missing toolchains report `SKIP` (Go-only contributors aren't penalised); the script never stops on first failure so a full picture lands in one go.

### Changed

- The composition-era `__getattr__` allowlist (`_ALLOWED_PASSTHROUGH`) is removed from both adapters. Defense moves from "no parent attributes are exposed" to "every gated dispatch path is on this class, not inherited" — the canary integration tests (`tests/integration/test_at_real_crewai.py`, `tests/integration/test_at_real_langchain.py`) trip when upstream adds a new dispatch path that bypasses our overrides.
- **Python support floor raised to 3.10.** `pyproject.toml` is now `requires-python = ">=3.10"`; CI matrix runs `3.10 / 3.11 / 3.12`. 3.9 reached upstream EOL in October 2025 and the `mcp` PyPI extra requires `>=3.10` anyway — keeping 3.9 in the trove invited broken `pip install agentguardproxy[mcp]` resolutions.

### Removed

- **Python 3.9 from `python-test` matrix** and from the `Programming Language :: Python :: 3.9` trove classifier. Users on 3.9 should pin to v0.5.0 or upgrade.

## [0.5.0] — 2026-05-07

> The proxy heroes release. Two new wire-level binaries (`agentguard-mcp-gateway`, `agentguard-llm-proxy`) make AgentGuard a wire-level firewall for MCP-aware clients and OpenAI/Anthropic SDK callers. The SDK becomes the compatibility tier — still fully supported and hardened, but no longer the only integration path. ~92 of the v0.4.1 audit's findings closed. See [`docs/releases/v0.5.0.md`](docs/releases/v0.5.0.md) for the operator-facing summary.

### Added

- **MCP Gateway** (`agentguard-mcp-gateway` binary) — wire-level Model Context Protocol proxy that sits in front of one or more MCP servers and policy-checks every `tools/call`. Includes multi-upstream namespacing, capability merging, reconnect-with-backoff, and approval `_meta` round-trip. Operator-facing copy-paste configs for Claude Desktop, Cursor, Cline, Continue, and Zed under `examples/`.
- **LLM API Proxy** (`agentguard-llm-proxy` binary) — OpenAI/Anthropic-compatible base URL (`OPENAI_BASE_URL=http://…/v1`, `ANTHROPIC_BASE_URL=http://…`) so existing SDK clients flow through AgentGuard without code changes. Streaming pause/resume/rewrite, tool-call gating, provider-aware synthetic refusals, and tool→scope mapping.
- **`data` policy scope** — first-class scope for exfiltration / sensitive-payload checks; recognised by `pkg/policy/engine.go` and surfaced through both SDKs. Browser-use adapter's form-input check uses it.
- **`mcp_tool` policy scope** — dual-check counterpart used by the MCP Gateway alongside a mapped concrete scope.
- **`unmapped` LLM-proxy sentinel scope** — flags tool calls with no `tool_scope_map` entry. Gate-time only; rejected from operator policy by `validateToolScopeMap`. Operators write `scope: unmapped` rules to control the default-deny posture.
- **`tool_scope_map` policy YAML key** — operator override surface shared between MCP Gateway and LLM API Proxy. Each binary loads the same policy file so the mapping stays in lockstep.
- **`Entry.Transport string` audit field** — `sdk` / `mcp_gateway` / `llm_api_proxy`. Additive top-level field on the audit `Entry` struct (no `schema_version` bump). Pre-v0.5 entries have no transport tag and default to `sdk` for backward-compat consumers.
- **`?transport=` filter on `GET /v1/audit`** (and the `agentguard audit --transport` CLI flag) — filters by integration path.
- **`schema_version` wire field** on `/v1/check` request/response — defaults to `"v1"`; non-v1 values rejected with `400`.
- **`/v1/health` HTTP endpoint** — open, returns `{"status","version"}`. Mirrors `/health` but lives under the `/v1` family for tenant-aware URL builders.
- **`/v1/t/{tenant}/...` tenant-aware route family** — every operational endpoint mirrored under a tenant-aware path. v0.5 only recognises `local`; v0.6 swaps in a multi-tenant `PolicyProvider`.
- **`agentguard check` CLI subcommand** — one-shot policy check (or batch from JSONL stdin) against a local policy file without going through the HTTP server. Per-field flags, `--request '<json>'`, `--stdin`, `--batch`, `--output text|json`, structured exit codes (`0` allow, `1` deny, `2` approval, `3` error).
- **`--debug-pprof` / `--debug-pprof-port` serve flags** — expose Go pprof handlers on a separate localhost-only listener (default `127.0.0.1:6060`). Off by default; tunnel via `kubectl port-forward` or `ssh -L` for remote access.
- **`--audit-buffered`, `--audit-queue-size`, `--audit-workers`, `--audit-overflow-path` serve flags** — wire the `BufferedAsyncLogger` (Phase 2 A6) so the `/v1/check` hot path no longer waits on the audit mutex. On by default; `--audit-buffered=false` restores the synchronous v0.4.x path.
- **JSON-RPC error codes for the MCP Gateway**: `-32000` (`ErrCodePolicyDeny`), `-32001` (`ErrCodePolicyApproval`), `-32002` (`ErrCodeUpstreamUnavail`). Wire-protocol contract for MCP clients to branch on.
- **`--policy` flag on `agentguard-llm-proxy`** — loads the central policy YAML for `tool_scope_map` operator overrides.
- **`--policy` and `--policy-mode strict|fast` flags on `agentguard-mcp-gateway`** — `strict` (default) requires `--policy`; `fast` skips loading and uses bundled defaults.
- **LLM streaming buffer cap** — `--max-buffer-bytes` (default `1048576`, ceiling `MaxConfigurableBufferBytes = 64 MiB`) per tool-call accumulator.
- **Provider-aware synthetic refusal payloads** — `pkg/llmproxy/refusal.go` emits OpenAI-style assistant-text + `[DONE]` and Anthropic-style `content_block_*` shapes that match what each SDK expects.
- **New Prometheus metrics**: `agentguard_llmproxy_buffer_overflow_total`, `agentguard_llmproxy_active_streams` (process-local on the LLM proxy); central server gains the `transport` label on existing decision counters.

### Changed

- **Audit log rotation is wired by default.** Previously, the rotation primitives existed in `pkg/audit` but were not constructed by `runServe`; size-triggered rotation now runs out of the box. Defaults: `--audit-max-size-mb 100`, `--audit-max-backups 5`, `--audit-max-age-days 30`, `--audit-compress true`. Rotated files are gzipped and carry a `_meta.rotated_from` pointer so startup replay walks the rotation chain. Operators who relied on external rotation can disable the built-in rotator via `--audit-max-size-mb 0`.
- **`conditions.time_window` without `require_prior` is now a hard load error** (`errorTimeWindowOnlyConditions`). v0.4.x emitted only a WARNING; v0.5 promotes it to a load failure that aborts `serve` startup and hot-reload. Operators upgrading must remove time-window-only conditions from their policies first. `docs/MIGRATION.md` § v0.4.1 → v0.5 documents the upgrade path.
- **Python SDK drops Python 3.8 support.** `pyproject.toml` requires `>=3.9`; CI matrix runs 3.9 / 3.10 / 3.11 / 3.12. 3.8 reached upstream EOL in October 2024.

### Fixed

- (no v0.5-specific fixes beyond those rolled into the above; security findings tracked in the v0.5 audit reports.)

## [0.4.1] — 2026-04-22

> This release focuses on behavioral fixes and observability. Server behavior changes are opt-in or clearly surfaced; SDK and audit-log contracts remain backward-compatible with v0.4.0.
>
> **Operators upgrading from v0.4.0 should read `docs/MIGRATION.md`.** The audit log is migrated in place on first start; a byte-for-byte backup is preserved at `<audit-log>.v040-backup` so downgrade stays possible through v0.4.2.

### Added

- `docs/DEPRECATIONS.md` — single-source-of-truth table for features scheduled for removal, with `deprecated-in`, `removal-target`, and `migration-path` columns. New entries land in the same commit as the code that introduces them.
- `docs/FILE_FORMATS.md` — documents the `schema_version` convention for every on-disk artifact AgentGuard writes, plus non-version identifiers (User-Agent, MCP protocol) that deliberately do not track the release version.
- `pkg/deprecation` helper — `deprecation.Warn(feature, msg)` logs once per process per feature key and increments a counter exposed at `agentguard_deprecations_used_total{feature="..."}`. Scrape this before a planned removal release to see whether anyone is still using a feature.
- `agentguard migrate` subcommand — runs on-disk schema migrations with `--dry-run`, `--list`, `--id=<name>` (operator override to re-run a specific migration), and `--reset-checkpoint` (force next start to do a full replay).
- `pkg/migrate` framework — `Migration` interface and registry used by `RunStartup()` (auto at boot) and `RunCLI()` (via `agentguard migrate`). Each concrete migration lives under `pkg/migrate/vNNN_to_vMMM/`.
- `proxy.tls.terminated_upstream` config flag — when true, session cookies are issued with `Secure` regardless of `r.TLS`. Off by default; turn it on when AgentGuard is behind a TLS-terminating reverse proxy that does not pass `X-Forwarded-Proto`.
- `notify.redaction.extra_patterns` config — operator-supplied regexes appended to the built-in redactor defaults. Compiled and validated at startup.
- Python SDK `fail_mode` parameter (default `"deny"`) — matches the existing knob on the TypeScript SDK. v0.4.1 does not change defaults; v0.5.0 will align both SDKs explicitly on `"deny"` in release notes.
- Observability (Phase 3):
  - `agentguard_notify_events_dropped_total{notifier,reason}` — was an unexposed `notify.DroppedEvents` atomic.
  - `agentguard_notify_queue_depth{notifier}`, `agentguard_notify_dispatch_duration_seconds{notifier}`.
  - `agentguard_sse_events_dropped_total{client_id}`, `agentguard_sse_subscribers`.
  - `agentguard_ratelimit_buckets`, `agentguard_ratelimit_bucket_evictions_total{scope}`.
  - `agentguard_approvals_pending`, `agentguard_approvals_evicted_total{reason}`.
  - `agentguard_request_rejected_total{reason="body_too_large"}`.
  - `agentguard_audit_replay_duration_seconds`, `agentguard_audit_replay_entries_total`, `agentguard_audit_rotations_total`, `agentguard_audit_migration_status{from,to,status}`.
- Config keys (Phase 4) — new keys with safe defaults, all documented in `docs/CONFIG.md`:
  - `proxy.session.ttl` (default `1h`)
  - `proxy.request.max_body_bytes` (default `1048576`)
  - `proxy.audit.default_limit` (default `100`) and `proxy.audit.max_limit` (default `1000`)
  - `notify.dispatch_timeout` (global + per-notifier, default `10s`)

### Changed

- Audit log format bumped to `schema_version: 2`. A meta-record `{"_meta": {"schema_version": 2, ...}}` is now the first line of every audit file. Readers at v0.4.1+ accept v1 (headerless, written by v0.4.0) transparently — the `v040_to_v041` migration rewrites the file in place on first start and preserves a `.v040-backup` copy for downgrade. See `docs/MIGRATION.md`.
- Audit log rotation primitives landed in `pkg/audit` (size-triggered rotator, gzip + `_meta.rotated_from` chain). They are *not yet wired into the default `runServe` path* — the v0.5 release wires them by default. Operators on v0.4.1 should continue to rotate `audit.jsonl` externally.
- Audit replay is now checkpointed at `<audit-log-path>.replay-checkpoint`, so a restart no longer re-scans the whole history to seed counters. The checkpoint is written atomically (`write + rename`); a missing, corrupt, or stale (file-truncated) checkpoint silently triggers a full rescan on next boot. Run `agentguard migrate --reset-checkpoint` (or just delete the file) to force that explicitly.
- `/v1/audit` now honors `?limit` (clamped to `[1, 1000]`, default `100`) and `?offset`. Previously, `?limit` was silently ignored and hard-coded to `100`.
- `ApprovalQueue` eviction is LRU instead of "drop every resolved entry at once". When the queue is at capacity, the oldest resolved entry is evicted first; if none are resolved, new approvals are rejected with `503 Service Unavailable` and a `Retry-After` header rather than silently dropped.
- Session store: when the in-memory session cap (`MaxSessions = 1024`) is reached, new logins receive `503` with a clear message instead of silently evicting the oldest active session. Heavy dashboard users who previously hit the cap will notice a visible failure where there used to be a silent one.
- Policy watcher uses fsnotify to detect atomic-replace rewrites immediately, with a 2 s poll fallback when fsnotify is unavailable. No user-visible contract change.
- `sessionCosts` map has an opt-in TTL sweep goroutine (`--session-cost-ttl`, `--session-cost-sweep-interval`) so long-running servers do not accumulate per-session cost entries indefinitely. Defaults to disabled (`0`), preserving v0.4.0 behavior; sweep interval defaults to `max(ttl/4, 1m)` when only the TTL is set.
- Histogram buckets for `agentguard_*_duration_ms` extend past 1 s (new 2500 ms, 5000 ms, 10 000 ms buckets) to capture tail behavior under load. Not configurable: altering bucket boundaries later invalidates historical data.
- Webhook notifier honors the new `notify.dispatch_timeout`; the hard-coded 10 s falls away.

### Fixed

- Requests that exceed `MaxRequestBodySize = 1 MB` are now logged at WARN with `agent_id`, size, and limit, and increment `agentguard_request_rejected_total{reason="body_too_large"}`. Previously silent.
- Notification dispatcher queue-full drops are exposed via Prometheus (`agentguard_notify_events_dropped_total{notifier,reason}`); the `notify.DroppedEvents` atomic is no longer the only place you could see them.

### Deprecated

- `policy.time_window_without_require_prior` — rules that declare `conditions.time_window` without `require_prior` are a no-op today (v0.4.0 pass-through behavior). As of v0.4.1 they emit a deprecation warning on load and increment `agentguard_deprecations_used_total{feature="policy.time_window_without_require_prior"}`. **v0.5.0 will make this a load error.** Migration: pair `time_window` with `require_prior`, or remove `time_window` from the rule.
- `audit.migration.v040_to_v041` — the in-binary v0.4.0 → v0.4.1 migration is scheduled for removal in v0.4.3. Users upgrading past v0.4.2 must either have run through v0.4.1/v0.4.2 on the way, or use the standalone `agentguard-migrate` binary to convert headerless v1 audit files first.
- `audit.backup.v040` — `.v040-backup` rollback files are written by the migration and retained through v0.4.2 so operators can downgrade without tooling. v0.4.3 removes both the migration and the backup mechanism.

### Security

- Filesystem deny rules could be bypassed via path traversal (`../` segments). Request paths are now normalized with `filepath.Clean` before rule matching, and paths containing `..` after normalization are rejected outright. Policy files with `..` in filesystem rule patterns are also rejected at load time. _(Carried over from the unreleased entry above.)_

### Internal

- `pkg/migrate/v040_to_v041/removal_deadline_test.go` — fails once the server version reaches `0.4.3` while the migration package still exists. Forces the conversation on schedule; the deadline cannot slip silently.
- MCP adapter logs a WARN when a client requests a newer protocol than the pinned `2024-11-05`, still pinning our side. Actual version negotiation is a v0.5.0 design item.
