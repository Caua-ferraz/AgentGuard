# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

> Tracks work in flight on `master` post-v0.5.0. Items here are *not* in any tagged release yet.

## [0.5.0] — 2026-05-05

> Python SDK adapter hotfix. CrewAI 1.x + pydantic 2.12 and langgraph 1.0 + langchain_core 1.x both reject the v0.5.0 composition-wrapper adapters at framework boundaries (`isinstance(thing, BaseTool)` / `isinstance(thing, Runnable)` no longer honour `BaseTool.register()` virtual-subclass registrations). v0.5.0 ships hybrid subclass+override adapters that satisfy the framework's isinstance checks natively while preserving the policy-enforcement contract by overriding every dispatch entry point. Python-only release; the Go binaries, MCP Gateway, and LLM API Proxy stay at v0.5.0.

### Fixed

- **Python SDK CrewAI adapter** (`agentguard.adapters.crewai.GuardedCrewTool`) — now subclasses `crewai.tools.BaseTool` directly. `Agent(tools=[GuardedCrewTool(...)])` no longer raises `pydantic_core.ValidationError` on CrewAI 1.x. Every gated dispatch path (`_run`, `run`, `invoke`, `ainvoke`, `_arun`, `arun`, `__call__`, `to_structured_tool`) is explicitly overridden so future framework additions surface in the canary integration test rather than silently bypassing the gate.
- **Python SDK LangChain adapter** (`agentguard.adapters.langchain.GuardedTool`) — now subclasses `langchain_core.tools.BaseTool`. `langgraph.prebuilt.create_react_agent(llm, tools=[GuardedTool(...)])` and `langchain.agents.create_agent(...)` both accept the wrapper directly; the v0.5.0 `Tool.from_function(func=lambda x: gt.invoke(x))` workaround is no longer required. ToolCall-shaped inputs (`{"name", "args", "id", "type": "tool_call"}`) are unwrapped to the underlying args dict before the gate runs.
- Both adapters now use `pydantic.PrivateAttr` for internal references (`_tool`, `_guard`, `_scope`); these fields are excluded from `model_dump()` output and kept off `model_fields`.

### Changed

- The composition-era `__getattr__` allowlist (`_ALLOWED_PASSTHROUGH`) is removed from both adapters. Defense moves from "no parent attributes are exposed" to "every gated dispatch path is on this class, not inherited" — the canary integration tests (`tests/integration/test_at_real_crewai.py`, `tests/integration/test_at_real_langchain.py`) trip when upstream adds a new dispatch path that bypasses our overrides.

## [0.5.0] — 2026-05-05

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
