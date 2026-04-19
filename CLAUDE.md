# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

AgentGuard is a Go policy-enforcement and audit-logging proxy for autonomous AI agents. Agents call `POST /v1/check` before every sensitive action; AgentGuard evaluates the action against a YAML policy and returns `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. Decisions are persisted to a JSON-Lines audit log, emitted to webhooks/Slack/console, and surfaced on an embedded dashboard via Server-Sent Events. Python and TypeScript SDKs wrap the HTTP API; framework adapters plug the Guard into LangChain, CrewAI, browser-use, and MCP.

It is a **defensive-security / guardrails** tool — the opposite of malware. Integration is opt-in (the agent must call `guard.check`); AgentGuard does not transparently intercept syscalls.

## Build, Test, Run

```bash
make build                      # go build with -ldflags main.version/main.commit
make test                       # go test -v -race -coverprofile=coverage.out ./...
make lint                       # golangci-lint run ./...
make run                        # serve with configs/default.yaml, --dashboard, --watch
make validate                   # validate every YAML in configs/ and configs/examples/
make docker / make docker-run   # build + run container
make install-python-sdk         # pip install -e plugins/python[all]
make install-ts-sdk             # npm install && npm run build in plugins/typescript

# single Go test
go test -v -race -run TestEngineCheck ./pkg/policy/

# Python SDK
cd plugins/python && pip install -e ".[dev]" && pytest -v --cov=agentguard

# TypeScript SDK
cd plugins/typescript && npm install && npm run build && npm test

# CLI smoke
./agentguard serve --policy configs/default.yaml --dashboard --watch --api-key $KEY
./agentguard validate --policy configs/examples/research-agent.yaml
./agentguard approve <id>   # uses AGENTGUARD_API_KEY env or --api-key
./agentguard deny    <id>
./agentguard status         # /health + /api/pending
./agentguard audit --agent X --decision DENY --scope shell --limit 50
./agentguard version
```

No external Go deps beyond `gopkg.in/yaml.v3`. No Python runtime deps (stdlib `urllib`). No TypeScript runtime deps (native `fetch`).

## Request Lifecycle (`POST /v1/check`)

1. `withCORS` middleware reflects Origin. Two modes: **exact-match** if `--allowed-origin` is set; otherwise **permissive-localhost** (any `http://localhost:*` or `http://127.0.0.1:*`; the trailing `:` is mandatory to block `localhost.evil.com`). `Vary: Origin` always set. Options short-circuits 204.
2. `withLogging` records method/path/duration.
3. `handleCheck` (`pkg/proxy/server.go:213`) enforces `MaxRequestBodySize = 1 MB`, JSON-decodes into `policy.ActionRequest`.
4. Rate limit: `Engine.RateLimitConfig(scope, agentID)` returns the per-scope `RateLimitCfg` (respecting per-agent overrides). If present, `ratelimit.Limiter.Allow(key=scope:agentID, max, window)` consumes a token; exceeding → synthetic `DENY` with `Rule="deny:ratelimit:<scope>"` and `metrics.IncRateLimited()`.
5. `Engine.Check(req)` (`pkg/policy/engine.go:310`):
   - `normalizeRequest` strips C0 control bytes (keeps `\t`) from `Command/Action/Domain/URL`; on `Path`, also single-pass URL-decodes `%HH`. Fast path returns the input unchanged (no alloc) when already clean.
   - Lock: **write** lock when `scope == "cost"` (so ALLOW can atomically reserve against `sessionCosts[session_id]`); **read** lock otherwise.
   - `resolveRules(agentID)` merges `policy.Rules` with `policy.Agents[agentID].Override`. Override replaces base per-scope; scopes unique to the override are appended.
   - For each RuleSet matching `req.Scope`:
     - If `scope == "cost"` and `Limits != nil`: hand off to `checkCost` (see below).
     - If `scope == "filesystem"` and `req.Path != ""`: reject `..` segments after `filepath.Clean + ToSlash` → `DENY Rule="deny:filesystem:path_traversal"`.
     - Evaluate **deny → require_approval → allow**; first match returns. Match = `matchRule(rule, req) && matchConditions(rule, req)`.
   - Fall-through: `DENY "No matching allow rule (default deny)"`.
6. If decision is `REQUIRE_APPROVAL`, `ApprovalQueue.Add` generates a 16-byte `crypto/rand` hex ID (`ap_<32hex>`), stores a `PendingAction`, evicts all resolved entries if at `MaxPendingApprovals = 10000`. `approval_url` is built from `Config.BaseURL`. `Notifier.Send` dispatches an `approval_required` event.
7. If decision is `DENY`, `Notifier.Send` dispatches a `denied` event.
8. `logAndRespond` writes an `audit.Entry`, observes `PolicyEvalDuration`, `AuditWriteDuration`, `RequestDuration` histograms (ms), increments decision counters, sets response headers `X-AgentGuard-Policy-Ms`, `X-AgentGuard-Audit-Ms`, `X-AgentGuard-Total-Ms` (milliseconds, 3-decimal), broadcasts an `AuditEvent{Type:"check"}` to SSE watchers (non-blocking, drop on full), and JSON-encodes the `CheckResult`.

### Cost scope (`checkCost`, engine.go:460)
Order inside `checkCost` (all with write lock held):
1. `est_cost < 0` → `DENY deny:cost:negative_value`.
2. `max_per_action`, `max_per_session`, `alert_threshold` parsed via `parseDollar` (strips optional `$`); parse errors → `DENY deny:cost:invalid_config`.
3. `est_cost > max_per_action` → `DENY deny:cost:max_per_action`.
4. `sessionCosts[session_id] + est_cost > max_per_session` → `DENY deny:cost:max_per_session`.
5. `est_cost > alert_threshold` → `REQUIRE_APPROVAL require_approval:cost:alert_threshold` (no reservation — reservation happens when approved action re-runs `check`).
6. Otherwise: `sessionCosts[session_id] += est_cost` atomically, return `ALLOW allow:cost:within_limits`.

`Engine.RecordCost` and `RefundCost` exist for out-of-band accounting / rollback but are **not** wired into the proxy — the proxy relies on the atomic reserve inside `checkCost`.

### Pattern matching (`globMatch`, engine.go:725)
- If pattern has **no `**`**, dispatches to `wildcardMatch` (anchored `*` = any chars incl. `/`, `?` = single char).
- If pattern has `**`, dispatches to `doubleStarMatch` which splits both pattern and value on `/` (preserving leading empty segment for absolute paths) and runs `matchSegments` — an iterative backtracking matcher where `**` consumes zero or more whole segments and each other segment is matched via `wildcardMatch`. Security property: `**/secret/**` never matches `/notsecret/x` (no substring bypass).
- `matchRule` matches `Pattern` vs `Command`, or `Action==req.Action` with optional `Paths` (each path and `req.Path` cleaned with `filepath.Clean + ToSlash`), or `Domain` vs `req.Domain`.

### Conditional rules (`matchConditions`, engine.go:828)
- `require_prior`: queries `HistoryQuerier.RecentActions(agentID, scope, since=now-time_window)`. A prior `ALLOW` whose `Action`/`Command` equals or glob-matches `require_prior` satisfies the condition. The querier is the `auditHistoryAdapter` around `Logger.Query` (wired in `NewServer`).
- `time_window` **without** `require_prior`: no-op (always satisfied). `LoadFromFile` emits a `WARNING` log line naming the rule. This preserves v0.4.0 pass-through behavior.
- No querier wired (or query errors) → condition fails (rule does not match).

### Policy load (`LoadFromFile`, engine.go:103)
- Requires `version` and `name` fields.
- Rejects `..` segments (after `filepath.Clean + ToSlash`) in `filesystem` rule `paths` — policy-author traversal guard.
- Warns on time-window-only conditions across base rules and per-agent overrides.

### Policy hot-reload (`pkg/policy/watcher.go`)
`WatchFile(path, callback)` polls `os.Stat(path).ModTime()` every `DefaultPollInterval = 2s`. On a newer mtime, re-invokes `LoadFromFile`; success → `callback(pol)` (wired to `engine.UpdatePolicy` which takes the write lock and swaps the pointer). Parse errors log but don't stop the watcher. `Close()` closes the `done` channel.

## HTTP Surface (`pkg/proxy/server.go`, `auth.go`)

| Method | Path | Auth (when `--api-key` set) | Notes |
|---|---|---|---|
| POST | `/v1/check` | **Open by design** | Main policy query; 1 MB body cap |
| POST | `/v1/approve/{id}` | Bearer **or** session + CSRF | `Resolve(id, ALLOW)`; broadcasts `resolved` SSE |
| POST | `/v1/deny/{id}` | Bearer **or** session + CSRF | `Resolve(id, DENY)` |
| GET | `/v1/status/{id}` | Bearer **or** session | Poll for approval resolution |
| GET | `/v1/audit` | Bearer **or** session | Query params: `agent_id, session_id, decision, scope, limit, offset`. `limit` is bounded by `s.auditDefaultLimit` / `s.auditMaxLimit` (clamped silently above the ceiling; `<1` or non-integer → 400). `offset ≥ 0`. |
| POST | `/auth/login` | Open (validates API key) | Issues `ag_session` (HttpOnly) + `ag_csrf` (JS-readable) cookies; returns `{csrf_token, expires_at}` |
| POST | `/auth/logout` | Open | Destroys session, expires both cookies |
| GET | `/health` | Open | `{status, version}` |
| GET | `/metrics` | Open | Prometheus text format |
| GET | `/dashboard` | Renders `loginHTML` or `dashboardHTML` based on session | Sets `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| GET | `/api/pending` | Bearer **or** session | JSON list of unresolved actions |
| GET | `/api/stream` | Bearer **or** session | Server-Sent Events; flushes headers on connect so `EventSource.onopen` fires immediately |
| GET | `/api/stats` | Bearer **or** session | In-memory atomic counter snapshot (O(1)) |

When `--api-key` is **unset**:
- A WARNING is logged.
- The server binds to `127.0.0.1:<port>` only (not `0.0.0.0`) to prevent network-adjacent abuse.
- Auth middleware pass-through: every gated endpoint becomes open.

When `--api-key` is **set**:
- `requireAuthOrSession` (auth.go:230) accepts **either** `Authorization: Bearer <key>` (constant-time compare) **or** a valid `ag_session` cookie. For state-changing endpoints (`requireCSRF=true`), the session path additionally requires `X-CSRF-Token` to equal the session value (double-submit cookie; constant-time compare).
- `/auth/login` uses `subtle.ConstantTimeCompare` on the submitted key; sets `Secure` cookies when `r.TLS != nil` (so behind a TLS-terminating proxy without `X-Forwarded-Proto` parsing, cookies are emitted without Secure — functionally safe because the proxy enforces HTTPS).
- `SessionTTL = 1h`, `MaxSessions = 1024` (hardcoded). Oldest-by-expiry evicted when at cap.

### ApprovalQueue (server.go:69–640)
- `pending map[string]*PendingAction`, guarded by `sync.RWMutex`.
- `Add` uses `crypto/rand` (returns 500 if that fails — approvals must be cryptographically unguessable).
- `Resolve` flips `Resolved=true`, stamps `Decision`, broadcasts a `resolved` event. It does **not** block/unblock any waiter — clients poll `/v1/status/{id}`.
- `PendingCount()` walks the map without allocating (used in `/metrics`).
- `Subscribe()` creates a buffered (`SSEChannelBufferSize = 64`) channel appended to `watchers`. `Unsubscribe` removes and closes it.
- `Broadcast` is non-blocking: `select { case ch <- event: default: }` — slow consumers drop events.
- Eviction: when `len(pending) >= MaxPendingApprovals = 10000`, `Add` calls `evictResolvedLocked` which deletes every resolved entry (bulk, not LRU).

### SSE `/api/stream`
Sets `text/event-stream`, `X-Accel-Buffering: no`, writes headers + flushes immediately, then loops over the subscribed channel and `r.Context().Done()`. Events are JSON-marshaled into `data: ...\n\n`.

### Embedded dashboard (`dashboardHTML`, `loginHTML` at the bottom of server.go)
- Loads `/api/stats`, `/api/pending`, `/v1/audit?limit=200`, subscribes `/api/stream`.
- Pulls CSRF from `document.cookie['ag_csrf']` and echoes it as `X-CSRF-Token` on approve/deny fetches.
- Escapes decision values and user input via `textContent`/an `esc()` helper before rendering (no `innerHTML` with user data).
- `agFetch` redirects to `/dashboard` on 401/403, forcing re-login.
- Login form POSTs `{api_key: ...}` to `/auth/login`; cookies are set by the server, JS then `location.href = '/dashboard'`.

## Audit Logging (`pkg/audit/logger.go`)

- `FileLogger` opens with `O_CREATE|O_WRONLY|O_APPEND`, mode `0600`. Writes serialize through `sync.Mutex`; encoding is `json.NewEncoder` (writes a trailing `\n`, JSON-Lines).
- `Query` captures the file path under the lock, opens a **separate read handle**, scans without holding the write mutex (append writes are atomic on POSIX for small records, so concurrent writes are not blocked by long queries). Scanner buffer bumped from 64 KB default to 1 MB max line.
- Corrupt lines (non-JSON) are silently skipped.
- Filters: `AgentID`, `SessionID`, `Decision`, `Scope`, `Since`, `Limit` (stop after N matches).
- `startup counter seed`: `NewServer` calls `Logger.Query({})` once at boot and replays every entry through `metrics.IncDecision` so `/metrics` and `/api/stats` are accurate across restarts. **This scans the entire audit file at startup.**
- `SQLiteLogger` (`sqlite_logger.go`) is a **dormant** alternative implementation — full WAL-mode schema and indexed query code — that is **not** wired in `main.go`. To activate, add `modernc.org/sqlite` as an import side-effect and construct `audit.NewSQLiteLogger(path)` in `runServe`.

## Notifier (`pkg/notify/notify.go`)

- `NewDispatcher(cfg)` = `NewDispatcherWithOpts(cfg, workers=DefaultWorkers=8, queueSize=DefaultQueueSize=256)`.
- Spawns `workers` goroutines pulling `dispatchJob{notifier, event}` off a bounded channel.
- `Dispatcher.Send(event)` runs `Redactor.Redact` (regex-replace for Bearer tokens, AWS `AKIA...`, GitHub `ghp_...`, Slack `xox[baprs]-...`, and generic `(secret|token|password|api_key)=value` — scrubs `Command`, `URL`, `Reason`, and all `Meta` values) then **non-blocking** enqueues one job per notifier. Queue-full drops increment the package-level `notify.DroppedEvents` atomic **and** the Prometheus counter `agentguard_notify_events_dropped_total{notifier,reason}`; queue depth is exposed as `agentguard_notify_queue_depth{notifier}` and per-notifier dispatch latency as `agentguard_notify_dispatch_duration_seconds{notifier}`.
- Notifiers by `type`:
  - `webhook` → `WebhookNotifier` POSTs JSON with `User-Agent: AgentGuard/1.0`, 10 s timeout.
  - `slack` → `SlackNotifier` formats a color-coded attachment payload (green/yellow/red by event type) with the approval link inline.
  - `console` → `ConsoleNotifier` prints a single line to stdout.
  - `log` → `LogNotifier` goes through the stdlib `log` package.
  - Unknown type falls back to `LogNotifier{Level: "warn"}`.
- Each notifier has a `Filter` string (`"approval_required"` or `"denied"`) and silently no-ops on mismatch. Filters come from the policy section (`notifications.approval_required` vs `notifications.on_deny`).
- `Dispatcher.Close()` closes `done` — workers exit. Called from `runServe` via `defer`.

## Rate Limiter (`pkg/ratelimit/ratelimit.go`)

- Token bucket per string key (proxy uses `"<scope>:<agent_id>"`).
- `Allow(key, maxRequests, window)`: first call creates a bucket with `tokens = maxRequests - 1`. On refill, advances `lastRefill` by whole `window` periods (`periods := int(elapsed / window)`) and resets tokens to `max`. Consumes one token per allowed request.
- Eviction: when `len(buckets) >= MaxBuckets = 10000`, `evictStaleLocked` drops any bucket whose window has fully elapsed.
- `ParseWindow(s)` → `time.ParseDuration(s)` with an empty-string error.
- In-memory only, not shared across instances.

## Metrics (`pkg/metrics/metrics.go`)

Zero external deps; writes the Prometheus text exposition format.

Counters (atomic `uint64`):
- `agentguard_checks_total`
- `agentguard_allowed_total`, `agentguard_denied_total`, `agentguard_approval_required_total`
- `agentguard_rate_limited_total`

Gauge:
- `agentguard_pending_approvals` (recomputed on every `/metrics` scrape via `ApprovalQueue.PendingCount`)

Histograms (buckets `[0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000]` ms + `+Inf`):
- `agentguard_request_duration_ms` (end-to-end `/v1/check`)
- `agentguard_policy_eval_duration_ms` (`Engine.Check` only)
- `agentguard_audit_write_duration_ms` (`Logger.Log` only)

`Histogram.Observe` locks a mutex (not atomics on `[]uint64`) — fine at hundreds of RPS; a known hotspot at much higher load.

## SDKs

### Python (`plugins/python/agentguard/__init__.py`)
- `Guard(base_url, agent_id, timeout=5, api_key)` — falls back to `AGENTGUARD_URL` / `AGENTGUARD_API_KEY` env vars.
- `check(scope, *, action, command, path, domain, url, session_id, est_cost, meta)` uses `urllib.request` POST; `urllib.error.URLError` → **fail-closed** `CheckResult(decision=DENY, reason="AgentGuard unreachable: ...")`.
- `approve(id)`, `deny(id)`, `wait_for_approval(id, timeout=300, poll_interval=2)` — polls `/v1/status/{id}` until `resolved`; sends Bearer header on every poll (required because the endpoint is auth-gated).
- `@guarded(scope, guard=None, **kwargs)` decorator; raises `PermissionError` on deny/approval (**approval is not awaited** by the decorator).

Adapters (`plugins/python/agentguard/adapters/`):
- `langchain.py`: `GuardedTool` wraps a LangChain tool's `run`/`arun`; `GuardedToolkit` builds wrappers for a list and auto-infers a default scope from the tool's `name + description` keywords (http/api → network, file/path → filesystem, browser → browser, shell → shell). `_infer_scope` in the wrapper upgrades scope to `network`/`filesystem` if the input contains `url`/`domain`/`path` keys.
- `crewai.py`: Same shape (`GuardedCrewTool`) but hooks both `run` and `_run` (CrewAI calls `_run` internally). `guard_crew_tools(tools, ...)` convenience factory.
- `browseruse.py`: `GuardedBrowser.check_navigation(url)`, `check_action(action, target)`, `check_form_input(url, field, value)` (uses the `"data"` scope), and `wrap_page(page)` → `GuardedPage` that guards async `goto()` — raises `PermissionError` on deny/approval.
- `mcp.py`: `GuardedMCPServer` — an MCP-over-stdio JSON-RPC server implementing `initialize`, `tools/list`, `tools/call`, and the `notifications/initialized` notification. Tool calls are guarded via `_infer_check_params` (maps `command`/`cmd`, `url`, `path`/`file_path` and upgrades scope accordingly) and return MCP content blocks with `isError: true` on deny/approval. `MCP_PROTOCOL_VERSION = "2024-11-05"`. Entry point `python -m agentguard.adapters.mcp --guard-url ...` runs an empty server (tools registered via code).

### TypeScript (`plugins/typescript/src/index.ts`)
- `AgentGuard(baseUrlOrOptions)` — dual constructor: string URL or `AgentGuardOptions { baseUrl, agentId, apiKey, timeout=5000, failMode: 'deny'|'allow' }`.
- `check(scope, options)` — converts camelCase to snake_case (`sessionId → session_id`, `estCost → est_cost`) in the JSON body; drops `estCost === 0`. Uses `fetch` with `AbortController` timeout. On any exception, returns the configured `failMode` decision (default DENY) — not DENY-only like Python.
- `CheckResult` exposes `allowed / denied / needsApproval` getters via `CheckResultImpl`.
- `approve`, `deny`, `waitForApproval(id, timeoutMs=300_000, pollIntervalMs=2_000)` mirror Python; send Bearer on every poll.
- `guarded(guard, scope, fn, getCheckOptions?)` HOF wraps an async function; default extracts `command: String(args[0])`. Throws `Error` on deny/approval (not a specific error class).

## CI (`.github/workflows/`)

- `ci.yml` triggers on push and pull_request to any branch (`branches: ['**']`). Five jobs:
  1. **test**: `go build ./...` → `go test -v -race -coverprofile=coverage.out ./...` → upload coverage artifact → `go run ./cmd/agentguard validate` on `configs/default.yaml` + every `configs/examples/*.yaml`.
  2. **lint**: `golangci-lint-action@v4` at `version: latest`.
  3. **python-test** (matrix 3.9 & 3.12): builds the Go binary (required — `tests/test_end_to_end_real_server.py` spawns the real binary), `pip install -e ".[dev]"`, runs `pytest --cov`, then re-runs the E2E file alone and **asserts `PASSED >= 10`** to catch silent-skip regressions.
  4. **typescript-build**: Node 20, `npm install && npm run build` (tsc).
  5. **docker**: builds image tagged `agentguard:ci`, runs it with `--api-key ci-smoke-key` and `--dashboard`, polls `/health` up to 20×1 s, dumps container logs on failure, then `docker rm -f`.
- `publish-pypi.yml`: triggered on GitHub `release: published` (or manual `workflow_dispatch`). Uses `twine upload` with `TWINE_USERNAME=__token__` and `secrets.PYPI_API_TOKEN`.

## Docker (`Dockerfile`)

Multi-stage: `golang:1.22-alpine` → `alpine:3.19`. Build flags `CGO_ENABLED=0 GOOS=linux -ldflags="-s -w"`. Runtime adds `ca-certificates`, creates uid `10001:10001` `agentguard` user, bakes `configs/default.yaml` at `/etc/agentguard/default.yaml`, creates writable `/var/lib/agentguard` (volume mount target for the audit log), exposes 8080. Default CMD enables the dashboard and writes to `/var/lib/agentguard/audit.jsonl`. No `--api-key` in the default CMD — supply one via runtime args in production or the server binds to localhost-only inside the container.

## Version Bumping (`scripts/bump-version.sh`)

Reads the current version from `cmd/agentguard/main.go` (`version = "..."`), validates the new value matches `^[0-9]+\.[0-9]+\.[0-9]+$`, and `sed -i` replaces across six files:
`cmd/agentguard/main.go`, `plugins/python/pyproject.toml`, `plugins/python/agentguard/adapters/mcp.py` (`SDK_VERSION`), `plugins/typescript/package.json`, `Makefile`, `docs/SETUP.md`. Post-replacement it greps the old string and fails if it still appears. Never edit versions by hand — a mismatch breaks release tagging and the PyPI publish workflow.

## Common Edit Points

| Task | Where |
|------|-------|
| Add a policy scope (e.g. `database`) | `pkg/policy/engine.go`: add dedicated handling in `Engine.Check` if needed, otherwise generic rules already match by `Pattern`/`Action`+`Paths`/`Domain`. |
| Change rule evaluation / precedence | `pkg/policy/engine.go:310` `Engine.Check` |
| Cost limits / session accounting | `pkg/policy/engine.go:460` `checkCost` + `sessionCosts` map |
| New path-matching semantics | `pkg/policy/engine.go:725` `globMatch` / `doubleStarMatch` / `matchSegments` |
| New condition type | `pkg/policy/engine.go:828` `matchConditions` + `HistoryQuerier` |
| Add a REST endpoint | `pkg/proxy/server.go` `NewServer` mux + handler (+ `requireAuthOrSession` if gated) |
| Auth / sessions / CSRF | `pkg/proxy/auth.go` |
| Dashboard UI | `pkg/proxy/server.go` `dashboardHTML` / `loginHTML` |
| Audit backend | `pkg/audit/logger.go` — implement the `Logger` interface or wire `SQLiteLogger` from `sqlite_logger.go` (add `modernc.org/sqlite` import) in `cmd/agentguard/main.go` |
| Notifier target | `pkg/notify/notify.go` — add a new `Notifier` impl + `type` case in `targetToNotifier` |
| New redaction pattern | `pkg/notify/notify.go` `DefaultRedactor` |
| Rate-limit semantics | `pkg/ratelimit/ratelimit.go` |
| New metric | `pkg/metrics/metrics.go` — atomic counter / histogram + case in `WritePrometheus` |
| CLI flag | `cmd/agentguard/main.go` `serveCmd` etc. |
| New Python framework adapter | `plugins/python/agentguard/adapters/<name>.py` |
| Update all versions | `./scripts/bump-version.sh <x.y.z>` |

## Known Behaviors / Gotchas

- **`/v1/check` is intentionally unauthenticated.** Only approve/deny/status/audit and dashboard API routes require the API key. Gate `/v1/check` behind a reverse proxy if you need network-level auth.
- **No API key ⇒ localhost-only bind** (`127.0.0.1:<port>`). Expected for dev; a gotcha if you wonder why remote clients can't connect.
- **Approvals are poll-based, not blocking.** `Resolve` sets `Resolved=true`; SDK `wait_for_approval` / `waitForApproval` polls `/v1/status/{id}`. There is no blocking channel on `PendingAction`.
- **`/v1/audit` honors `?limit` and `?offset`** (v0.4.1). `limit` is bounded by `s.auditDefaultLimit` / `s.auditMaxLimit`; values above the ceiling are silently clamped, non-integers or values `<1` return 400. The dashboard's `limit=200` is therefore clamped to the server's configured ceiling rather than being ignored.
- **Startup replay**: the entire audit log is re-read on boot to seed counters. A multi-GB log stalls `/metrics` accuracy until the scan completes.
- **CORS permissive-localhost** is the default and accepts any `http://localhost:*` / `http://127.0.0.1:*`. Safe because session cookies are `SameSite=Strict` and all state-changing endpoints require CSRF. Set `--allowed-origin https://app.example` for strict single-origin mode.
- **Cookie `Secure` flag is driven by `r.TLS`**, not `X-Forwarded-Proto`. Behind a TLS-terminating proxy, cookies are issued without `Secure` — safe on the wire (the proxy enforces HTTPS) but a lint failure on pedantic audits.
- **`SessionTTL = 1h` and `MaxSessions = 1024` are hardcoded** in `auth.go`. No CLI flag yet.
- **`conditions.time_window` without `require_prior`** is a deliberate no-op preserved for v0.4.0 policy backward compat. `LoadFromFile` logs a warning.
- **Pattern `*`** in wildcard mode crosses `/` boundaries. That's intentional for shell commands (`"rm -rf *"` matches `"rm -rf /home/user"`). For path patterns prefer `**`.
- **`globMatch` for domains** uses the same wildcard semantics. `*.foo.com` matches `api.foo.com`; it does **not** match `foo.com`.
- **Audit log has no rotation.** `audit.jsonl` grows unbounded with mode `0600`. Ship to external log aggregator in production.
- **`notify.DroppedEvents` is an `atomic uint64`** retained for Go consumers; drop events are also exposed via Prometheus as `agentguard_notify_events_dropped_total{notifier,reason}`.
- **`SQLiteLogger` is unused.** Wiring requires adding `modernc.org/sqlite` as an import side-effect and swapping the logger in `runServe`.
- **Python SDK and TypeScript SDK differ on failure mode**: Python is always fail-closed (DENY); TypeScript honors `failMode: 'deny' | 'allow'` (default `deny`).
- **The approval ID generator aborts the request with 500** if `crypto/rand` returns an error — intentional, since a non-random ID would be guessable.
- **`Logger.Log` serializes on one mutex.** Hot path; replace with batched writes or `SQLiteLogger` if audit I/O dominates p99.

## Project Conventions

- Go module path: `github.com/Caua-ferraz/AgentGuard`. Do **not** rename without updating imports + Docker + CI.
- One external Go dep (`gopkg.in/yaml.v3`) — adding dependencies requires a conscious justification.
- Python SDK core must stay stdlib-only. Framework integrations go under `plugins/python/agentguard/adapters/` as optional extras in `pyproject.toml`.
- TypeScript SDK must stay on native `fetch`/`AbortController` — no polyfills.
- Standard Go conventions (`gofmt`, `go vet`, table-driven tests). Prefer explicit error returns over panics.
- Keep `--api-key` handling in CLI subcommands consistent: explicit `--api-key` flag wins over `AGENTGUARD_API_KEY` env.
- Security report contact: `security@agentguard.dev` (see `docs/CONTRIBUTING.md`). Do not open public issues for vulnerabilities.