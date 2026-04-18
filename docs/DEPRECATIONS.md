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
| `policy.time_window_without_require_prior` | v0.4.1 | v0.5.0 | Pair `time_window` with `require_prior` in the conditional rule, or remove `time_window` entirely. See `pkg/policy/engine.go` (`matchConditions`). | policy |
| `audit.migration.v040_to_v041` | v0.4.1 | v0.4.3 | Automatic on startup in v0.4.1 and v0.4.2. After upgrading past v0.4.2, the in-binary migration is removed; users still on headerless v1 audit files must run the standalone `agentguard-migrate` binary before upgrading. | audit |
| `audit.backup.v040` | v0.4.1 | v0.4.3 | `.v040-backup` is created by the v0.4.0 → v0.4.1 migration to enable downgrade. Kept through v0.4.2 so operators can roll back without tooling. Removed in v0.4.3 alongside the migration code. Operators who want the backup retained should archive it externally before upgrading past v0.4.2. | audit |

## Removed (historical)

_None yet._

## Policy for removing entries from this table

An entry moves from "Active" to "Removed" only after:
1. The removal release has shipped.
2. The code path is gone from the main server binary.
3. The CHANGELOG entry for that release names the removal.

Otherwise the entry stays in "Active" with an updated `removal-target`.
