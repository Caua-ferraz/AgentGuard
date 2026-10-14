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
| 2 | v0.4.1+ | First line is a meta-record: `{"_meta": {"schema_version": 2, "created_at": "...", "segment_id": "...", "rotated_from": "..."}}`. Remaining lines are `audit.Entry` records, one per line. |

**Meta-record fields.** `created_at` is when the file was created (RFC 3339, UTC). `segment_id` (v1.4+, additive) is 32 random hex characters that identify this file; files written before v1.4 don't have it. `rotated_from` is the **base name** of the archive this file succeeded (for example `audit.jsonl.20261010T120000Z.gz`), and is omitted on a file that starts a chain.

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
| `"claude_code"` | `agentguard hook claude-code`, Claude Code's hook (v1.3+) |
| `"cursor"` | `agentguard hook cursor`, Cursor's hooks |
| `"gemini_cli"` | `agentguard hook gemini-cli`, Gemini CLI's hook |
| `"codex_cli"` | `agentguard hook codex`, Codex CLI's hook |
| (omitted / empty string) | pre-v0.5 entries, or v0.5+ entries written before the writer was upgraded — readers should treat as `"sdk"` for filtering purposes |

The field is purely additive: schema_version remains `2`. Pre-v0.5 readers ignore unknown top-level keys without error. v0.5+ writers MUST set `Transport` on every new entry; the central server's `/v1/check` handler stamps it from `meta["transport"]` on the inbound request, defaulting to `"sdk"` when the field is absent. External audit consumers implementing against this format MUST tolerate the field's absence on legacy data and SHOULD preserve it round-trip when re-serialising entries.

**Sealed logs (v1.4+, additive — schema_version stays at 2).** With `agentguard server --audit-seal`, the log is a hash chain that `agentguard audit verify` can check. Sealing is not encryption: entries stay readable. With sealing off none of the fields below are written, and the files are byte-identical to those of earlier releases.

Each sealed entry ends with three fields, always last and in this order:

| field | meaning |
|---|---|
| `seq` | `1` for the first sealed entry, then one more per entry. It keeps counting across rotations and restarts. |
| `prev_hash` | The `hash` of the entry before it. Omitted on the first entry of a chain (`seq` 1). |
| `hash` | 64 lowercase hex characters, computed as below. |

`_meta` lines get four fields:

| field | meaning |
|---|---|
| `seal` | How the entries after this line are sealed: `{"alg":"hmac-sha256","key_id":"<16 hex>"}` with `--audit-seal-key-file`, `{"alg":"sha256"}` without. `key_id` is the hex of the first 8 bytes of SHA-256(key). It names the key without revealing it. |
| `chain_prev` | The `hash` of the last sealed entry before this line. In a header written at rotation, that is the last entry of the archive, which is what links the files. Omitted when there is none. |
| `chain_seq` | That entry's `seq`. |
| `node_id` | The writing server's `--node-id`. |

A `_meta` line can also appear in the middle of a file. The server appends one when it starts with sealing on and the live file already exists; it says how the entries after it are sealed. Readers skip `_meta` lines wherever they are. Entries already in the file when sealing is first turned on stay unsealed, and the chain starts at `seq` 1 after them. Turning sealing off and on again starts a new chain, which `verify` reports as broken.

**Hashing rule.** Take an entry line as written, without its newline. Remove the trailing `,"hash":"<64 hex>"}` and append `}`. The result is the body. `hash` is the hex of HMAC-SHA256(key, body), or of SHA-256(body) without a key. The key is the key file's content with surrounding whitespace removed. Nothing is re-encoded, so any language can check a line byte for byte.

Worked example, without a key. The line

```
{"timestamp":"2026-10-01T12:00:00Z","session_id":"s1","agent_id":"bot","request":{"scope":"shell","command":"ls"},"result":{"decision":"ALLOW","reason":"ok"},"duration_ms":1,"seq":1,"hash":"278a4467f2999e6ef5146da29743b304f7f309fde7f36676b5a976c5ba434c8d"}
```

has the body

```
{"timestamp":"2026-10-01T12:00:00Z","session_id":"s1","agent_id":"bot","request":{"scope":"shell","command":"ls"},"result":{"decision":"ALLOW","reason":"ok"},"duration_ms":1,"seq":1}
```

and `printf '%s' "$body" | sha256sum` prints `278a4467f2999e6ef5146da29743b304f7f309fde7f36676b5a976c5ba434c8d`. With a key, use `openssl dgst -sha256 -hmac "$(cat audit-seal.key)"` instead. The next entry carries `"seq":2,"prev_hash":"278a4467f2999e6ef5146da29743b304f7f309fde7f36676b5a976c5ba434c8d"`.

**Redacted values (v1.2+).** With `serve --audit-redact` (the default), secret-shaped substrings in request fields and the reason are replaced with `[REDACTED]` before an entry is written — see [OPERATIONS § Audit redaction](OPERATIONS.md#audit-redaction). The entry shape and `schema_version` don't change; files written before 1.2.0 are not rewritten.

### `<audit-log>.replay-checkpoint` — audit replay checkpoint

Default path: `<audit-log>.replay-checkpoint` — `audit.CheckpointSuffix` appended to the audit log path, e.g. `audit.jsonl.replay-checkpoint`. Single JSON record, written atomically (temp file + rename): by the server after the startup replay finishes, and — since v1.2.0, file audit backend — by the audit logger after every rotation (before old archives are pruned) and when it closes on shutdown. `agentguard migrate --reset-checkpoint` and the v0.4.0 → v0.4.1 migration delete this exact file; there is no schema-version envelope.

| release | shape |
|---|---|
| v0.4.1 – v1.0.0 | `{"offset": <bytes>, "audit_size": <bytes>}` |
| v1.1.0+ | `{"offset": <bytes>, "audit_size": <bytes>, "file_id": "<live file's identity>", "counts": {"total": N, "allow": N, "deny": N, "require_approval": N}}` |
| v1.4.0+, sealed logs | the v1.1.0 shape plus `"last_seq": N, "last_hash": "<hex>"` |

`last_seq` and `last_hash` (sealed logs only, omitted otherwise) are the head of the seal chain when the checkpoint was written. At startup the logger compares them with the end of the live file. A file that ends before them logs a `WARNING` (possible truncation) and increments `agentguard_audit_seal_tail_mismatch_total`; the server still starts.

`file_id` says which live file `offset` refers to; it is absent for headerless legacy files. Since v1.4 it is the file's `_meta.segment_id`. For a file written before v1.4, which has no `segment_id`, it is the file's `_meta.created_at`, as in v1.1–v1.3, so checkpoints written before an upgrade keep matching. (`created_at` alone could repeat: on a coarse clock, two files created in quick succession could share it, and replay then resumed inside the wrong file. A v1.3 binary reading a v1.4 checkpoint finds no matching file and replays everything still reachable, carrying `counts` forward.) `counts` is the lifetime decision tally as of `offset`: the next boot seeds `agentguard_checks_total` and its siblings from it and replays only the entries written afterwards, which is how the counters survive restarts. A v1.0.0 checkpoint (no `counts`) is still accepted and triggers one full replay of the live file to establish the tally. The tally starts at the first boot that wrote a checkpoint; archives that already existed before that boot are not scanned.

On boot: a matching `file_id` resumes at `offset`. A different one means the log rotated in between, and the seeder walks `_meta.rotated_from` back through the archives (gzip or plain) to the checkpointed segment, replaying it from `offset` and every newer segment from the start; if that segment was already pruned, everything still reachable is replayed and `counts` is carried forward. Because the logger rewrites the checkpoint at every rotation since v1.2.0, the checkpointed segment is always the current live file after a graceful shutdown, and at most one rotation old after a crash — pruning can no longer strand it. A missing, corrupt, or truncation-stale checkpoint never blocks startup — it triggers a full replay of the live file. Force that explicitly with `agentguard migrate --reset-checkpoint --audit-log <path>` or by deleting the file.

### `<audit-log>.<timestamp>[.gz]` — rotated audit files

#### Rotated file headers

Size-triggered rotation via the logger. Archives are named `<audit-log>.<timestamp>` using `20060102T150405Z`, so lexicographic order is chronological and pruning sorts names without parsing them. That format has one-second resolution, so a burst rotating more than once inside a second would compute the same name twice. Since v1.4 the rotator picks a name one second after the newest archive on disk whenever the clock reads that or earlier, so a name can read a little later than the instant it rotated, never lands on an existing archive, and never reuses a name pruning freed: name order is always write order, which `audit verify` relies on. (Before v1.4 a burst after pruning could reuse a freed, older name, and the next prune then deleted that newest archive.) Every file carries a schema-2 header. When the logger rotates, it renames the live file to the archive name and starts a new live file whose `_meta.rotated_from` holds that archive's base name, so each file points back at the one before it. Compression is applied to rotated files only; the live file stays uncompressed to keep appends cheap. Startup replay walks the chain backwards via `_meta.rotated_from` until it reaches the segment identified by the replay checkpoint's `file_id`. On a sealed log, the new header's `chain_prev` and `chain_seq` name the archive's last entry; `agentguard audit verify` follows `rotated_from` the same way and checks that each link holds. When pruning has removed the oldest files, the oldest file left still names the last pruned entry, and `verify` reports that the chain starts after it.

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
