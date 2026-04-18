# Migration Guide

This document tells operators what to expect when upgrading between AgentGuard releases. Every release that changes on-disk state, default behavior, or a contract operators may depend on gets a section here.

For a single-line summary of each change, see `CHANGELOG.md`. For deep-dive release notes, see `docs/releases/`. For the format-version contract, see `docs/FILE_FORMATS.md`.

---

## v0.4.0 → v0.4.1

### What happens automatically

On first start of a v0.4.1 binary against an audit file written by v0.4.0:

1. The `v040_to_v041` migration detects a headerless v1 audit file.
2. It writes a byte-for-byte backup to `<audit-log>.v040-backup` (mode `0600`).
3. It rewrites the live file in place with a `schema_version: 2` header record as the first line.
4. It verifies that the rewritten file parses cleanly and contains the same number of records as the backup.
5. Startup continues.

If any step fails, the server refuses to start, leaves the original file untouched, and prints a recovery path. No partial migration state is left behind.

### What you should do

**Nothing is required.** The migration runs on boot. But if you want to preview it:

```bash
agentguard migrate --dry-run --audit-log /var/lib/agentguard/audit.jsonl
```

This logs the intended actions without touching disk. Use this to confirm that the detected file matches what you expect.

### Rollback to v0.4.0

Supported through v0.4.2. Steps:

1. Stop the v0.4.1 server.
2. `cp <audit-log>.v040-backup <audit-log>` — the backup is exactly the file v0.4.0 wrote.
3. Replace the binary with v0.4.0.
4. Start.

v0.4.0 does not understand the schema-2 header and will refuse to read a migrated file; that is what the backup is for. If you deleted the backup deliberately, downgrade is not supported.

**The backup is removed in v0.4.3**, along with the migration itself. Operators who upgrade past v0.4.2 lose the downgrade-to-v0.4.0 path. If you want to retain the ability to downgrade indefinitely, copy `.v040-backup` off the server before upgrading past v0.4.2.

### Behavioral changes worth knowing about

- **Audit replay is checkpointed.** First start takes as long as it used to (one full replay). Subsequent starts are near-instant — the server resumes from `<audit-dir>/.replay-checkpoint`.
- **Audit rotation is now built in.** Default threshold and file count are safe; tune via config if your retention policy requires it. Rotated files are gzipped and carry a `_meta.rotated_from` pointer so replay follows the chain.
- **ApprovalQueue eviction is LRU**, not bulk-drop. Under extreme load with no resolved entries and a full queue, new approvals return `503` with `Retry-After`. The previous behavior was silent state loss. If you scrape `agentguard_approvals_evicted_total{reason}` you will see the events.
- **Session store rejects new logins at the cap** instead of silently evicting the oldest session. If you routinely run with more than ~1000 concurrent dashboard sessions you will see `503` on new logins; sign out idle tabs to free slots.
- **`/v1/audit?limit=` is honored** for the first time. The dashboard's existing `?limit=200` query now returns up to 200 entries (clamped to the new `proxy.audit.max_limit`, default `1000`). Scripts that relied on the hard-coded `100` will see up to the requested value.

### Deprecation warnings you may see on first load

- `WARN deprecation feature=policy.time_window_without_require_prior ...` — fix by pairing `time_window` with `require_prior` in the policy rule, or remove `time_window` entirely. v0.5.0 will reject the policy at load.

Check `/metrics` for `agentguard_deprecations_used_total` before upgrading to v0.5.0.

### Corrupt-checkpoint recovery

If the server refuses to start with a message about a corrupt replay checkpoint:

```bash
agentguard migrate --reset-checkpoint --audit-log <path>
```

This deletes the checkpoint. The next server start performs a full replay (as with v0.4.0) and writes a fresh checkpoint.

---

_Migration guides for prior releases live in the git history of this file._
