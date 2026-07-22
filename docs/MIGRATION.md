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
- **Audit rotation primitives ship in `pkg/audit` but are not wired by default in v0.4.1.** Continue to rotate `audit.jsonl` externally on this release. Rotation will be wired by default in v0.5; the rotator gzips rotated files and carries a `_meta.rotated_from` pointer so startup replay follows the chain.
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

## v0.4.1 → v0.5.0

### What happens automatically

- The audit-log binary format is unchanged from v0.4.1 (`schema_version: 2`). No file rewrite runs.
- New audit entries written by v0.5+ binaries carry an additional top-level `transport` field (`"sdk"`, `"mcp_gateway"`, or `"llm_api_proxy"`). The field is purely additive — existing readers ignore unknown top-level keys, so the schema version does not bump.
- `runServe` constructs the rotating logger by default (`--audit-max-size-mb 100`, `--audit-max-backups 5`, `--audit-max-age-days 30`, `--audit-compress true`). On first restart after upgrade, the live `audit.jsonl` keeps appending; once it crosses the size threshold, the rotator kicks in and rotated files start to appear as `audit-YYYYMMDDTHHMMSSZ.jsonl.gz` (or `.jsonl` with `--audit-compress=false`) alongside the active file.

### What you should do

1. **Audit the audit log rotation chain.** If you currently run `logrotate` (or any other external rotator) against `audit.jsonl`, do **one** of:
   - **Recommended:** disable your external rotator. AgentGuard's built-in rotator handles size, age, and retention via flags.
   - **Or** keep `logrotate` and pass `--audit-max-size-mb 0` to disable AgentGuard's rotator. Use `copytruncate` in your `logrotate` config (see [`OPERATIONS.md`](OPERATIONS.md#audit-log-rotation)).

   **Do not run both at once** — the dual-rotator chain corrupts the `_meta.rotated_from` continuity and breaks startup replay's chain walk.

2. **Sweep your policy YAML for `time_window` without `require_prior`.** v0.5.0 promotes this from a WARNING to a load error. Find any rule with `conditions.time_window` and no sibling `conditions.require_prior` and either pair them up or drop `time_window` from the rule. v0.4.1's `agentguard_deprecations_used_total{feature="policy.time_window_without_require_prior"}` counter tells you whether your runtime hit the warning. If the counter is zero and your policy parses cleanly under v0.4.1, v0.5 will load it cleanly too.

3. **Decide on the new policy options:**
   - **`mcp_tool` scope** — if you use the MCP Gateway, write at least one rule for `scope: mcp_tool` (`configs/default.yaml` ships an example; see [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#mcp_tool-scope)). The gateway dual-checks `mcp_tool` AND the mapped concrete scope (e.g., `shell` or `network`), so omitting `mcp_tool` rules causes default-deny on every tool call.
   - **`tool_scope_map`** — operator override surface for the gateway and LLM proxy's tool→scope mapping. Optional; the bundled defaults work for most setups. Add overrides for tools your policy needs to gate at a different scope than the default.
   - **`unmapped` sentinel** — if you run the LLM API Proxy, decide your default-deny posture: write a `scope: unmapped` rule (deny or require-approval) for tool calls the proxy can't classify. The proxy returns synthetic refusal on `unmapped` denials.

4. **Deploy the new binaries** (optional but the headline feature):
   - `go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@v0.5.0`
   - `go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@v0.5.0`

   Both share the central server's policy file (mount the same `policy.yaml` into all three processes; `--watch` on the central server still hot-reloads).

5. **Update Python SDK installs** to Python 3.9+. v0.5 drops 3.8 (upstream EOL October 2024). The `pyproject.toml` floor is now `requires-python = ">=3.9"`.

### New flags worth knowing about (`agentguard serve`)

- `--audit-max-size-mb`, `--audit-max-backups`, `--audit-max-age-days`, `--audit-compress` — rotation knobs (see above).
- `--audit-buffered` (default `true`), `--audit-queue-size`, `--audit-workers`, `--audit-overflow-path` — buffered async audit logger. The hot path no longer blocks on the audit mutex; disk-overflow durability spills to `<audit-log>.overflow.jsonl` when the queue saturates. `--audit-buffered=false` restores the v0.4.x synchronous path.
- `--debug-pprof` and `--debug-pprof-port` (default `6060`) — localhost-only pprof listener. Off by default; tunnel via `kubectl port-forward` or `ssh -L` for remote profiling sessions.

### New CLI subcommand

- `agentguard check` — one-shot policy check (or batch from JSONL stdin) against a local policy file without going through the HTTP server. Useful for CI gates and pre-commit hooks. See [`CLI.md`](CLI.md#agentguard-check).

### Behavioral changes worth knowing about

- **The dashboard chips audit entries by `transport`.** SDK callers stay tagged `sdk`; MCP Gateway and LLM API Proxy entries carry `mcp_gateway` and `llm_api_proxy` respectively. Filter via `/v1/audit?transport=mcp_gateway` or `agentguard audit --transport mcp_gateway`.
- **`/v1/check` accepts `schema_version: "v1"` in the request body.** Omitting it still defaults to v1; non-v1 values are rejected with `400`. SDK clients on v0.4.1 already match the wire (the field is opaque to them); custom clients hand-rolling JSON should add it.
- **Histogram buckets for `agentguard_*_duration_ms` extend past 1 s** (new 2500 ms, 5000 ms, 10 000 ms buckets). Existing dashboards still work; histograms with new buckets coexist with old data points (Prometheus computes summaries across both).

### Rollback to v0.4.1

Supported with one caveat: audit entries written by v0.5 binaries carry a `transport` field that v0.4.1 readers ignore but the field is preserved on disk. Downgrading is therefore lossy only if you need the v0.5 binary to re-read those entries with the field intact (the v0.4.1 binary will emit them through `Logger.Query` with `Transport == ""`).

Steps:

1. Stop the v0.5 server, MCP gateway, and LLM API proxy.
2. Replace the central-server binary with v0.4.1.
3. If you turned on built-in rotation, delete or move any rotated `audit-*.jsonl[.gz]` files out of the audit directory before starting v0.4.1 — v0.4.1 does not know how to walk a rotation chain.
4. Restore your previous external rotation configuration if you turned it off.
5. Start the v0.4.1 server.

### Corrupt-checkpoint recovery

Same as v0.4.0 → v0.4.1: `agentguard migrate --reset-checkpoint --audit-log <path>` deletes the checkpoint. The next server start performs a full replay (now walking the rotation chain) and writes a fresh checkpoint.

---

## v0.5.0 → v0.5.1

### What happens automatically

- **Nothing on the server side.** No file rewrite, no policy schema change, no audit format change.
- The central server, MCP Gateway, and LLM API Proxy all bump to v0.5.1; existing v0.5.0 audit logs replay cleanly, existing v0.5.0 policies load unchanged.

### What you should do

1. **Bump Python ≥ 3.10.** v0.5.1 drops Python 3.9 (upstream EOL October 2025; the `mcp` extra already required >=3.10). `pyproject.toml` is now `requires-python = ">=3.10"`. Users still on 3.9 should pin to `agentguardproxy==0.5.0` or upgrade their interpreter.

   ```bash
   pip install --upgrade "agentguardproxy==0.5.1"   # 3.10+ only
   ```

2. **Update the framework adapters.** If you wrote v0.5.0 code that worked around the composition-wrapper isinstance issue (e.g., `Tool.from_function(func=lambda x: gt.invoke(x))` for LangChain, or skipped `Agent(tools=[GuardedCrewTool(...)])`), you can now pass the wrappers in directly. The v0.5.1 adapters subclass `langchain_core.tools.BaseTool` and `crewai.tools.BaseTool` natively. See [`ADAPTERS.md`](ADAPTERS.md).

3. **Optionally silence the new update notice.** Every subcommand of the `agentguard` binary asynchronously checks the GitHub Releases API at startup and prints a single stderr line if a newer release is published. Set `AGENTGUARD_NO_UPDATE_CHECK=1` in scripted environments where stderr noise is unwanted. See [`CLI.md`](CLI.md#update-notice-on-startup-v051).

### New surfaces

- **`AGENTGUARD_NO_UPDATE_CHECK`** environment variable — disables the v0.5.1 startup update-notice on all three binaries.
- **`make test-all` / `scripts/test-all.sh`** — single entry point for Go + policy YAML + Python SDK + TypeScript SDK suites with PASS / FAIL / SKIP summary. See [`CONTRIBUTING.md`](CONTRIBUTING.md#running-the-full-test-suite).

### Rollback to v0.5.0

Trivial. v0.5.1 introduces no on-disk state, no schema bumps, and no wire-protocol changes:

1. Reinstall v0.5.0 binaries (`go install …@v0.5.0`).
2. Reinstall the Python SDK at the v0.5.0 release: `pip install --upgrade "agentguardproxy==0.5.0"`.
3. Start. No data migration required either way.

The only behavioural difference an operator might notice: v0.5.0 Python SDK on CrewAI 1.x + pydantic 2.12 / langgraph 1.0 + langchain_core 1.x fails the framework's `isinstance(thing, BaseTool)` check — that's the bug v0.5.1 fixes. If you downgrade and run a recent framework, pin to the older `crewai<1.0` / `langchain<1.0` line.

---

## v0.5.x → v0.7.0 (includes the v0.6 milestone)

v0.5.2 was a maintenance release (toolchain refresh, no migration). The
v0.6 milestone (persistence + multi-tenancy) shipped without standalone
release notes and is documented under v0.7.0 — upgrading from any v0.5.x
directly to v0.7.0 is the supported path. Full detail:
[`releases/v0.7.0.md`](releases/v0.7.0.md).

### What happens automatically

- **`serve` becomes stateful by default.** First run creates
  `agentguard.db` (SQLite, WAL) in the working directory (`--data-dir`
  to relocate); approvals, rate-limit buckets, and cost accumulators now
  survive restarts. `--persist=false` restores the old pure-in-memory
  behaviour. No existing file is rewritten — the store is a new artifact.
- **No wire or format changes.** `schema_version: "v1"`, the `/v1/...`
  and `/v1/t/{tenant}/...` route families, and the audit JSONL
  (`schema_version: 2`) are backward-compatible.

### What you should do

1. **Give the process a writable `--data-dir`** (or run `--persist=false`
   deliberately) and add `agentguard.db` + `-wal`/`-shm` to your backup
   plan — see [`OPERATIONS.md`](OPERATIONS.md#backups).
2. **Review `action`-keyed filesystem rules.** Verdicts are now
   consistent across integration paths; CrewAI/MCP paths that previously
   omitted `action` now send it, so expect new (correct) matches.
3. **Optionally adopt the new operator surface:** `--fail-audit-log`
   (outage-window denial audit on both proxies), `--notify-spool`
   (notification overflow spool), `--audit-backend=store`,
   `agentguard tenant put|list|rm`, and `agentguard check --watch`.

### Rollback to v0.5.x

Reinstall the v0.5.x binaries. They ignore `agentguard.db` entirely
(delete it if you want a clean tree); pending approvals stored in it are
lost, matching v0.5.x's in-memory behaviour.

---

## v0.7.0 → v0.9.0

### What happens automatically

- **Nothing.** v0.9.0 is a stabilization release, not a feature or format change. There is no file rewrite, no policy-schema change, no wire-protocol change, and no audit-format change.
- The `/v1/check` request/response shapes, the audit log (`schema_version: 2` JSONL), the policy schema (`version: "1"`), and every CLI flag/subcommand are **byte-for-byte compatible** with v0.7. Existing audit logs replay cleanly; existing policies load unchanged; existing SDK clients and proxies interoperate without changes.

### What changed

- **The audit "tamper-evident" wording was corrected — documentation only.** The audit log was always an append-only JSON-Lines log with no cryptographic sealing, and that is now what the README and FAQ say. No code path or on-disk byte changed. If your compliance posture relied on the word "tamper-evident," achieve it the way the docs now describe: forward the audit log to append-only / WORM storage (S3 Object Lock, a SIEM, or syslog).
- **The v0.9 surface stabilization is now documented** in [`COMPATIBILITY.md`](COMPATIBILITY.md): the policy schema, wire protocol, audit format, and CLI are stabilized (the freeze targets for 1.0), with additive-only becoming the hard rule from 1.0. This is intent, not a behavior change.

### What you should do

1. **Swap the binaries and SDKs to 0.9.0.** No config or data changes are required.

   ```bash
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@v0.9.0
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@v0.9.0
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@v0.9.0
   pip install --upgrade "agentguardproxy==0.9.0"
   npm install @agentguard/sdk@0.9.0
   ```

2. **(Optional) Forward your audit log to WORM storage** if you want tamper-evidence — see the README audit bullet and [`COMPATIBILITY.md`](COMPATIBILITY.md).

### Rollback to v0.7.0

Trivial. v0.9.0 introduces no on-disk state, no schema bumps, and no wire-protocol changes — reinstall the v0.7.0 binaries/SDKs and start. No data migration is required either way.

---

## v0.9.0 → v1.0.0

### What happens automatically

- **Additive store-schema migration on first boot.** The `approvals` table
  gains three columns (`consumed_at`, `resolved_via`, `resolved_from` — the
  one-shot consumption stamp and resolution-actor fields) via guarded
  `ALTER TABLE`s, and two new tables (`rate_consumption`, `cost_consumption`)
  are created for multi-node reconciliation. Idempotent, additive-only, no
  rewrite of existing rows; pre-v1.0 approvals load as unconsumed/unstamped.
  No backup step is needed and `agentguard migrate` is not involved.
- Everything else is untouched: `/v1/check` request/response shapes, the
  audit format (`schema_version: 2`), and the policy schema (`version: "1"`)
  are byte-for-byte compatible with v0.9.

### Behavior changes worth knowing about

- **Approval resolutions are write-once.** Re-approving an already-approved
  id (or re-denying a denied one) stays an idempotent no-op, but a
  *conflicting* re-resolution now returns `409 Conflict` with a structured
  body instead of silently flipping the decision. Anything that relied on
  flip-by-re-POST must stop; that was the last-write-wins hole.
- **A resolved ALLOW is one-shot and time-boxed.** The first `/v1/check`
  retry carrying the `approval_id` consumes it; later replays re-enter the
  approval flow. Honoring is bounded by `--approval-validity` (default `5m`;
  `0` restores the unbounded pre-v1.0 window). Long-delayed retries that
  used to be honored will now come back as fresh approval requests.
- **Malformed streaming tool calls now fail closed.** The LLM API Proxy
  refuses (and audits) a completed tool call whose assembled arguments are
  not valid JSON, instead of silently dropping it and going dark for the
  rest of the stream.
- **Domain matching is case-insensitive.** A deny rule for `evil.com` now
  matches `EVIL.com`. Policies that (accidentally) relied on case-sensitive
  domain rules are evaluated case-insensitively.
- **Multi-node is opt-in.** Nothing changes unless you set
  `--store-dsn postgres://…`; the zero-config SQLite default behaves exactly
  as in v0.9 (the reconcile ticker stays off). See
  [`OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments).

### What you should do

1. **Swap the binaries and SDKs to 1.0.0.** No config or data changes are
   required for single-node deployments.

   ```bash
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@v1.0.0
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@v1.0.0
   go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@v1.0.0
   pip install --upgrade "agentguardproxy==1.0.0"
   npm install @agentguard/sdk@1.0.0
   ```
2. If you run (or plan to run) more than one replica: provision PostgreSQL,
   set `--store-dsn postgres://…` and a distinct `--node-id` per replica,
   and read the bounded-overshoot semantics in
   [`COMPATIBILITY.md`](COMPATIBILITY.md#topology) before sizing
   `--reconcile-interval`.

### Rollback to v0.9.0

Supported. The schema changes are additive: a v0.9.0 binary reads a
v1.0-touched SQLite store (the extra columns and tables are simply ignored).
Two things degrade on rollback: one-shot consumption stamps stop being
enforced (v0.9 predates them — previously-spent ALLOWs become replayable
within their retention window), and any Postgres-backed deployment must
return to single-node SQLite (v0.9 has no Postgres backend).

---

_Migration guides for prior releases live in the git history of this file._
