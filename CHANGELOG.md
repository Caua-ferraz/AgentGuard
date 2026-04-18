# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

_Nothing yet._

## [0.4.1] — unreleased

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
- Audit log rotation is enabled by default, size-triggered. Rotated files are compressed and carry the same schema-2 header with `_meta.rotated_from` pointing at the previous file. The startup replay walks the rotation chain via that header.
- Audit replay is now checkpointed at `<audit-dir>/.replay-checkpoint`, so a restart no longer re-scans the whole history. Corrupt checkpoint files cause a clear startup refusal with a pointer to `agentguard migrate --reset-checkpoint`.
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
