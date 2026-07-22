# Compatibility & Stability — the v1.0 freeze

**Status:** Stabilized as of **v0.9.0**; **frozen as of v1.0.0** — the
additive-only rule is now the hard guarantee.

This document declares the public surfaces AgentGuard froze at 1.0 (stabilized
through the v0.9 release, validated and hardened on the road to 1.0) and states
the backward-compatibility guarantee that holds across the 1.x line.

## The promise

**As of v0.9 these surfaces are stable, and from v1.0 every change to them is
additive-only.** Concretely:

- No frozen field, route, flag, subcommand, scope, or schema version is removed
  or renamed.
- No field's JSON name or type changes, and no flag's meaning changes.
- New **optional** fields, new routes, new flags, new subcommands, and new
  policy keys **may** be added. Consumers must tolerate unknown additive
  surface (ignore-and-pass-through) — the first-party SDKs and the Go decoders
  already do.
- A genuinely breaking change is a **major-version** event: it ships behind a new
  version identifier (`schema/v2`, audit `schema_version: 3`, a new route
  family), never as a silent mutation of a stabilized surface.

The pre-1.0 validation window is over: from **1.0** the additive-only rule is a
hard guarantee — a `go get -u` / `pip install -U` / `npm update` within the 1.x
line will not break you. (One correction made during that window, per the
reserved right: approval resolutions became write-once/one-shot — see
[`MIGRATION.md`](MIGRATION.md#v090--v100).)

---

## Frozen surface 1 — Policy YAML schema (`version: "1"`)

The policy file format is frozen at schema **`version: "1"`**.

- The top-level keys (`version`, `name`, `rules`, `agents`, `tool_scope_map`,
  `notifications`, …), the rule-precedence contract
  (`deny → require_approval → allow → default deny`), and the matching
  semantics (string-glob, `filepath.Clean` path normalization) do not change
  across the stabilized line.
- The built-in scopes are frozen: `shell`, `filesystem`, `network`, `browser`,
  `cost`, `data`, `mcp_tool`, plus the `unmapped` sentinel emitted by the LLM
  API Proxy. New scopes may be **added**; none of these is removed or
  repurposed.
- A v1 policy that loads on v0.9 loads on every later release.

Full schema and gotchas: [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md).

## Frozen surface 2 — Wire protocol (`schema_version: "v1"`)

The `/v1/check` request (`ActionRequest`) and response (`CheckResult`) shapes
are frozen at `schema_version: "v1"`, and the full `/v1/...` route family is
frozen, including its `/v1/t/{tenant}/...` tenant-aware mirrors:

| Route | Tenant-aware mirror |
|---|---|
| `POST /v1/check` | `POST /v1/t/{tenant}/check` |
| `POST /v1/approve/{id}` | `POST /v1/t/{tenant}/approve/{id}` |
| `POST /v1/deny/{id}` | `POST /v1/t/{tenant}/deny/{id}` |
| `GET /v1/status/{id}` | `GET /v1/t/{tenant}/status/{id}` |
| `GET /v1/audit` | `GET /v1/t/{tenant}/audit` |
| `GET /v1/health` | `GET /v1/t/{tenant}/health` |

Supporting endpoints frozen alongside them: `GET /health`, `GET /metrics`,
`POST /auth/login`, `POST /auth/logout`, `GET /api/pending`, `GET /api/stats`,
`GET /api/stream`, `GET /dashboard` (and their `/v1/t/{tenant}/api/...`
mirrors).

The wire freeze rules — never remove a field, never change a field's type or
JSON name, decision enum stays the closed set `{ALLOW, DENY, REQUIRE_APPROVAL}`,
new optional fields only — are spelled out in
[`WIRE_PROTOCOL.md`](WIRE_PROTOCOL.md). The machine-readable spec is
[`pkg/proxy/schema/v1/schema.json`](../pkg/proxy/schema/v1/schema.json), pinned
by a Go ↔ Python ↔ TypeScript cross-language contract test that fails CI on
drift.

## Frozen surface 3 — Audit log format (`schema_version: 2`)

The on-disk audit format is frozen at audit **`schema_version: 2`** (the
`{"_meta":{"schema_version":2,...}}` header line, followed by one JSON object
per decision).

- The `Entry` fields (`timestamp`, `tenant_id`, `session_id`, `agent_id`,
  `request`, `result`, `duration_ms`, `transport`) are stable. `tenant_id` and
  `transport` are `omitempty`, so single-tenant SDK output stays
  **byte-identical** to pre-v0.6 / pre-v0.5 files.
- The same `schema_version: 2` format is produced by both the `file` (JSONL)
  and `store` (SQLite `audit_entries`) backends; their `QueryFilter` semantics
  are pinned by a parity test.
- New optional `Entry` fields may be **added** without a bump (additive readers
  ignore unknown keys). A format change that is *not* backward-readable would
  bump to `schema_version: 3` with a migration, which is a v2.x-class event.

The audit log is **append-only**, not cryptographically sealed. For
tamper-evidence, forward it to append-only / WORM storage (S3 Object Lock, a
SIEM, or syslog); AgentGuard does not hash-chain or sign the log itself. Format
history and the `schema_version` convention: [`FILE_FORMATS.md`](FILE_FORMATS.md).

## Frozen surface 4 — CLI flags & subcommands

The `agentguard` subcommands (`serve`, `validate`, `check`, `approve`, `deny`,
`status`, `audit`, `tenant`, `migrate`, `version`) and their existing flags are
frozen: a flag's name, default, and meaning do not change across the stabilized line, and no
subcommand is removed. The same applies to the `agentguard-mcp-gateway` and
`agentguard-llm-proxy` flag sets. New flags and new subcommands may be added.

Full reference: [`CLI.md`](CLI.md) · [`MCP_GATEWAY.md`](MCP_GATEWAY.md) ·
[`LLM_API_PROXY.md`](LLM_API_PROXY.md).

---

## Explicitly *not* frozen

These may change without it being a compatibility break:

- **`CheckResult.reason` wording.** Human-readable; stable enough for log
  aggregation but not a contract. Switch on `decision` and `matched_rule`, not
  on `reason` text.
- **Prometheus metric set.** New series may be added and labels enriched;
  treat dashboards as best-effort across minor versions.
- **Dashboard HTML/CSS/JS** and the `/api/stream` SSE event payloads beyond the
  documented fields.
- **Internal Go package APIs** (anything under `pkg/internal/`, and unexported
  identifiers). Importers of internal packages are not covered by this freeze.
- **Default values that are not a wire/format contract** (e.g. tuning knobs),
  unless changing them would alter a frozen on-disk or wire shape.

## Topology

Two supported topologies as of v1.0:

- **Single-node (`replicas: 1`) — the default.** The approval queue, rate-limit
  buckets, and cost accumulators persist to a local SQLite store and survive
  restarts, but they are not shared across instances.
- **Multi-node on PostgreSQL.** Set `--store-dsn postgres://…` and a distinct
  `--node-id` per replica. Replicas share approval / rate-limit / cost state
  through background reconciliation (`--reconcile-interval`, default 2s) — the
  enforcement hot path never makes a synchronous database call. The documented
  semantics of the shared mode are part of the compatibility promise:
  distributed rate/cost limiting is **bounded-overshoot** (not globally
  strict), cross-node approval staleness is at most one reconcile interval,
  conflicting approval resolutions converge to **DENY**, and a consumed
  one-shot ALLOW is spent cluster-wide once reconciled — the shared store
  merge is monotonic (a resolution is never un-resolved, a resolved DENY is
  never overwritten by a non-DENY, a consumption stamp is never cleared).

The additive v1.0 surface on top of v0.9 — `--store-dsn` accepting
`postgres://`/`postgresql://`, `--node-id`, `--reconcile-interval`,
`--approval-validity`, and the write-once / one-shot approval lifecycle
(HTTP 409 on a conflicting re-resolution) — is frozen under the same rules as
the surfaces above.

## Post-v1, only if a concrete need arises

Out of scope and deliberately not on the stabilization: in-process
cryptographic audit sealing (hash-chaining / Merkle checkpoints — use external
WORM instead), RBAC / multi-key auth, and audit secret-redaction.
