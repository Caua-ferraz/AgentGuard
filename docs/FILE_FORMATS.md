# On-Disk File Formats

AgentGuard persists state to disk in a handful of places. Every file it writes carries a schema version so that a reader of version `N` knows whether it is looking at data it understands, data from an older version it can still handle, or data from a newer version that it must refuse.

This document is the contract for those formats. If you add a new on-disk artifact, add it here in the same commit.

## Versioning rules

1. **Every file AgentGuard writes carries a `schema_version` field or header record.** There are no unversioned writes.
2. **Readers tolerate `N-1`.** A server at schema `N` must be able to read the previous major on-disk format. If it can, the upgrade is transparent; if the older format needs to be rewritten, the server runs the registered migration from `pkg/migrate/` before starting the rest of the boot sequence.
3. **Readers refuse `N+1` with a clear message.** If a newer server wrote the file, the older server exits with: `file <path> is schema_version <N+1>; this AgentGuard build supports up to <N>. Upgrade the binary before starting.` — no silent downgrade, no best-effort parse.
4. **Schema versions are monotonic integers.** They are not semver; `schema_version: 2` means "the second iteration of the on-disk format", independent of the release version that introduced it.
5. **Bumping a schema version is a deliberate act.** It requires: (a) a new migration under `pkg/migrate/vNNN_to_vMMM/`, (b) an entry in `docs/DEPRECATIONS.md` for the old format with a removal target, (c) a CHANGELOG note.

## Current on-disk artifacts

### `audit.jsonl` — audit log

Default path: `audit.jsonl` (CLI `--audit-log`). JSON-Lines, one record per line, append-only, mode `0600`.

| schema_version | release | shape |
|---|---|---|
| 1 (headerless) | v0.3.x, v0.4.0 | First line is an `audit.Entry` record. No header. |
| 2 | v0.4.1+ | First line is a meta-record: `{"_meta": {"schema_version": 2, "created_at": "...", "rotated_from": "<path or null>"}}`. Remaining lines are `audit.Entry` records, one per line. |

**Reader contract.** A v0.4.1+ reader peeks the first non-empty line:
- If it contains `_meta.schema_version == 2`, read normally.
- If it contains `_meta.schema_version >= 3`, refuse startup with the upgrade message above.
- If it does not contain `_meta`, assume schema 1 and invoke the `v040_to_v041` migration (see `pkg/migrate/`). Migration rewrites the file in place with a header and preserves the original at `<path>.v040-backup` for one minor release.

**Corrupt meta record.** If the first non-empty line parses as JSON but has neither `_meta` nor the shape of an `audit.Entry`, the server refuses startup. Corrupt lines **after** the first are silently skipped, as they are today.

**`Entry.Transport` field (v0.5+, additive — schema_version stays at 2).** Each `audit.Entry` written by a v0.5+ binary carries a top-level `transport` string identifying which integration path produced the entry:

| value | source |
|---|---|
| `"sdk"` | direct `/v1/check` callers — Python SDK, TypeScript SDK, framework adapters, hand-rolled HTTP clients |
| `"mcp_gateway"` | `agentguard-mcp-gateway` binary |
| `"llm_api_proxy"` | `agentguard-llm-proxy` binary |
| (omitted / empty string) | pre-v0.5 entries, or v0.5+ entries written before the writer was upgraded — readers should treat as `"sdk"` for filtering purposes |

The field is purely additive: schema_version remains `2`. Pre-v0.5 readers ignore unknown top-level keys without error. v0.5+ writers MUST set `Transport` on every new entry; the central server's `/v1/check` handler stamps it from `meta["transport"]` on the inbound request, defaulting to `"sdk"` when the field is absent. External audit consumers implementing against this format MUST tolerate the field's absence on legacy data and SHOULD preserve it round-trip when re-serialising entries.

### `.replay-checkpoint` — audit replay checkpoint

Default path: `<audit-dir>/.replay-checkpoint`. Single JSON record. Written after each successful `Logger.Log` flush.

| schema_version | release | shape |
|---|---|---|
| 1 | v0.4.1+ | `{"schema_version": 1, "file": {"inode": <int>, "path": "<abs path>"}, "offset": <byte offset>, "last_record_timestamp": "<RFC3339>"}` |

On boot the server uses the checkpoint to resume replay without re-scanning the whole audit file. Inode mismatch triggers rotation-chain following via the `rotated_from` header in each file. A corrupt checkpoint causes the server to refuse startup; recover with `agentguard migrate --reset-checkpoint` (which discards the checkpoint and forces a full replay) or by deleting the file manually.

### `<audit-dir>/audit-<timestamp>.jsonl[.gz]` — rotated audit files

#### Rotated file headers

Size-triggered rotation via the logger. Each rotated file carries the same schema-2 header as the live file, with `_meta.rotated_from` set to the path of the file whose tail rolled into it. Compression is applied to rotated files only; the live file stays uncompressed to keep appends cheap. Startup replay walks the chain backwards via `_meta.rotated_from` until it reaches the segment indexed by `.replay-checkpoint`.

### `.v040-backup` — one-time rollback artifact

Default path: `<audit-log-path>.v040-backup`. Created by the v0.4.0 → v0.4.1 migration with mode `0600`. A byte-for-byte copy of the pre-migration headerless audit file, kept so an operator can downgrade to v0.4.0 by restoring this file over the migrated one.

Lifecycle: written on migration and left untouched afterwards. The removal originally scheduled for v0.4.3 never shipped — the migration (and this backup convention) is still in the binary as of v1.0. Tracked in `docs/DEPRECATIONS.md` as `audit.backup.v040`. Operators who want to keep the backup long-term should still copy it off the server.

### `agentguard.db` (+ `-wal` / `-shm` sidecars) — durable runtime store (v0.6+)

Default path: `<data-dir>/agentguard.db` (CLI `--data-dir`, default `.`; or an explicit `--store-dsn`). SQLite in WAL mode, created automatically on first run unless `--persist=false`. Mode `0600` — the file and its sidecars are created owner-only, and files created looser by pre-fix versions are tightened on every open (audit 2026-06, M2).

Tables (`pkg/store/sqlite.go`): `approvals` (since v1.0 including the one-shot consumption stamp `consumed_at` and the resolution-actor columns `resolved_via` / `resolved_from`), `rate_buckets`, `session_costs`, `policies` — all tenant-keyed — plus `audit_entries` when running `--audit-backend=store`, and the v1.0 multi-node reconciliation tables `rate_consumption` / `cost_consumption` (per-node consumption rows; only populated on the PostgreSQL backend). A background syncer flushes in-memory state on a ≥1 s tick and rehydrates it on boot; the store is never on the `/v1/check` hot path.

Schema management differs from the JSONL artifacts above: there is no `_meta`/`schema_version` record — `SQLiteStore.Migrate` applies idempotent `CREATE TABLE IF NOT EXISTS` DDL at open, plus guarded additive `ALTER TABLE`s for columns introduced after a table first shipped (the v1.0 approval columns). Back up the file with the process stopped or via `sqlite3 .backup`; copying `agentguard.db` alone mid-write (without its `-wal` sidecar) can produce a torn snapshot.

**PostgreSQL variant (v1.0):** with `--store-dsn postgres://…` the same schema lives in PostgreSQL (`pkg/store/postgres.go`, dialect deltas only) and there is no local database file — back up with your normal PostgreSQL tooling. Multiple replicas share it; each writes its own rows into the consumption tables keyed by `--node-id`.

## Items intentionally NOT on disk

- **Session tokens.** Stored in memory only (`pkg/proxy/auth.go`). Server restart invalidates all dashboard sessions.

The approval queue, rate-limit buckets, and session-cost accounting were on this list before v0.6; they now live in `agentguard.db` (above) whenever `--persist` is on (the default). With `--persist=false` they revert to in-memory, per-process, lost on restart.

## Non-version identifiers that look like version strings

Not everything that looks like a version tracks the release version. Listed here so nobody bumps them by accident:

- **`pkg/notify/notify.go:174` — `User-Agent: AgentGuard/1.0`.** This is the HTTP client protocol identifier sent by the webhook notifier. It is pinned at `1.0` and represents the webhook payload contract, not the server release. It changes only when the outbound webhook payload shape changes in a way downstream consumers must distinguish — independent of AgentGuard's release cadence. Do not add this to `scripts/bump-version.sh`.
- **`plugins/python/agentguard/adapters/mcp.py:41` — `MCP_PROTOCOL_VERSION`.** Pinned at the MCP protocol version negotiated with clients (e.g. `"2024-11-05"`), not the AgentGuard release version. This is the Model Context Protocol spec version, and moves only when the MCP spec does. Do not add to `scripts/bump-version.sh`.

If you add another such identifier, list it here explicitly — future releases will grep for stray `X.Y.Z` strings and an undocumented one will look like a bug.
