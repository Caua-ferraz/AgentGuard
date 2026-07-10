# Deprecations

This file is the single source of truth for features that are on the way out of AgentGuard. Every deprecation lands here in the same commit that introduces it.

## How this table is used

- **feature** — a stable identifier, also used as the key passed to `deprecation.Warn(...)` and exposed via `agentguard_deprecations_used_total{feature="..."}`.
- **deprecated-in** — the release that started emitting the warning.
- **removal-target** — the release where the feature becomes an error or is removed. Do not slip this silently; if the date moves, update this file and say why.
- **migration-path** — what users should do instead. Must link to code, docs, or a config snippet.
- **owner** — person or area responsible for following through on removal.

Before the removal release ships, check `agentguard_deprecations_used_total` in scraped metrics. If anyone is still using the feature, extend the timeline explicitly in this file — do not remove silently.

## Active deprecations

| feature | deprecated-in | removal-target | migration-path | owner |
|---|---|---|---|---|
| `audit.migration.v040_to_v041` | v0.4.1 | TBD (was v0.4.3 — that release never shipped; still in the binary as of v0.9.0) | Runs automatically on startup (registered via `pkg/migrate/v040_to_v041`, also invocable as `agentguard migrate`). Users still on headerless v1 audit files should migrate before the removal release, whenever it is rescheduled. | audit |
| `audit.backup.v040` | v0.4.1 | TBD (was v0.4.3 — that release never shipped; convention still active as of v0.9.0) | `.v040-backup` is created by the v0.4.0 → v0.4.1 migration to enable downgrade. Operators who want the backup retained long-term should archive it externally. It will be removed alongside the migration code. | audit |

## Removed (historical)

| feature | deprecated-in | removed-in | notes |
|---|---|---|---|
| `policy.time_window_without_require_prior` | v0.4.1 (WARNING log) | v0.5.0 (hard policy-load error) | `time_window` without `require_prior` was a silent no-op; policies containing it now fail to load. Pair `time_window` with `require_prior`, or remove it. See [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#footgun-time_window-without-require_prior). |

## Policy for removing entries from this table

An entry moves from "Active" to "Removed" only after:
1. The removal release has shipped.
2. The code path is gone from the main server binary.
3. The CHANGELOG entry for that release names the removal.

Otherwise the entry stays in "Active" with an updated `removal-target`.
