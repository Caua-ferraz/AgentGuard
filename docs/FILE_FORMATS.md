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

### `.replay-checkpoint` — audit replay checkpoint

Default path: `<audit-dir>/.replay-checkpoint`. Single JSON record. Written after each successful `Logger.Log` flush.

| schema_version | release | shape |
|---|---|---|
| 1 | v0.4.1+ | `{"schema_version": 1, "file": {"inode": <int>, "path": "<abs path>"}, "offset": <byte offset>, "last_record_timestamp": "<RFC3339>"}` |

On boot the server uses the checkpoint to resume replay without re-scanning the whole audit file. Inode mismatch triggers rotation-chain following via the `rotated_from` header in each file. A corrupt checkpoint causes the server to refuse startup; recover with `agentguard migrate --reset-checkpoint` (which discards the checkpoint and forces a full replay) or by deleting the file manually.

### `<audit-dir>/audit-<timestamp>.jsonl[.gz]` — rotated audit files

Size-triggered rotation via the logger. Each rotated file carries the same schema-2 header as the live file, with `_meta.rotated_from` set to the path of the file whose tail rolled into it. Compression is applied to rotated files only; the live file stays uncompressed to keep appends cheap.

### `.v040-backup` — one-time rollback artifact

Default path: `<audit-log-path>.v040-backup`. Created by the v0.4.0 → v0.4.1 migration with mode `0600`. A byte-for-byte copy of the pre-migration headerless audit file, kept so an operator can downgrade to v0.4.0 by restoring this file over the migrated one.

Lifecycle: written on migration, left untouched during v0.4.1 and v0.4.2 operation, deleted alongside the migration code in v0.4.3. Tracked in `docs/DEPRECATIONS.md` as `audit.backup.v040`. Operators who want to keep the backup for longer should copy it off the server before upgrading past v0.4.2.

## Items intentionally NOT on disk

- **Session tokens.** Stored in memory only (`pkg/proxy/auth.go`). Server restart invalidates all sessions.
- **Approval queue.** In-memory; a restart loses pending approvals. This is documented and intentional.
- **Rate-limit buckets.** In-memory, per-process. Not shared across instances. No on-disk format to version.
- **Session cost accounting.** In-memory map in the engine. Volatile by design.

## Non-version identifiers that look like version strings

Not everything that looks like a version tracks the release version. Listed here so nobody bumps them by accident:

- **`pkg/notify/notify.go:174` — `User-Agent: AgentGuard/1.0`.** This is the HTTP client protocol identifier sent by the webhook notifier. It is pinned at `1.0` and represents the webhook payload contract, not the server release. It changes only when the outbound webhook payload shape changes in a way downstream consumers must distinguish — independent of AgentGuard's release cadence. Do not add this to `scripts/bump-version.sh`.
- **`plugins/python/agentguard/adapters/mcp.py:41` — `MCP_PROTOCOL_VERSION`.** Pinned at the MCP protocol version negotiated with clients (e.g. `"2024-11-05"`), not the AgentGuard release version. This is the Model Context Protocol spec version, and moves only when the MCP spec does. Do not add to `scripts/bump-version.sh`.

If you add another such identifier, list it here explicitly — future releases will grep for stray `X.Y.Z` strings and an undocumented one will look like a bug.
