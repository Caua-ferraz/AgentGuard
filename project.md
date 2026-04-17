# AgentGuard — Project Documentation

## Project Overview

AgentGuard is a **policy enforcement and audit-logging proxy for autonomous AI agents**. It acts as a firewall between an AI agent and the real world: before an agent executes any sensitive action (run a shell command, write a file, call an API, browse the web), it must first ask AgentGuard for permission. AgentGuard evaluates the request against a declarative YAML policy, then returns `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. All decisions are logged to an audit trail.

**Core problems it solves:**
- Prevent AI agents from taking destructive or unauthorized actions
- Provide a human-in-the-loop approval workflow for risky operations
- Give operators full auditability of what agents did and why

---

## Tech Stack

| Layer | Technology |
|---|---|
| Policy engine & proxy server | Go 1.22 |
| Policy format | YAML (gopkg.in/yaml.v3) |
| Python SDK | Python 3.8+, stdlib only (urllib) |
| TypeScript SDK | TypeScript 5.3+, native fetch API |
| Dashboard | Embedded HTML/JS (Server-Sent Events) |
| Audit log | JSON Lines flat file |
| Container | Docker (multi-stage, alpine) |
| CI | GitHub Actions |
| Future DB (declared, unused) | SQLite (mattn/go-sqlite3) |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         AI Agent                             │
│  (uses Python SDK / TypeScript SDK / direct HTTP)            │
└──────────────────────────┬──────────────────────────────────┘
                           │  POST /v1/check
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  AgentGuard Proxy (Go)                       │
│                                                              │
│  ┌────────────────┐    ┌──────────────────────────────────┐ │
│  │  HTTP Server   │───▶│  Policy Engine (engine.go)       │ │
│  │  (server.go)   │    │  Deny → RequireApproval → Allow  │ │
│  └────────────────┘    │  → Default Deny                  │ │
│         │              └──────────────────────────────────┘ │
│         │  Decision                                          │
│         ▼                                                    │
│  ┌────────────────┐    ┌──────────────────────────────────┐ │
│  │  Audit Logger  │    │  Approval Queue (in-memory)      │ │
│  │  (logger.go)   │    │  + SSE broadcast to dashboard    │ │
│  │  JSON Lines    │    └──────────────────────────────────┘ │
│  └────────────────┘                                         │
└─────────────────────────────────────────────────────────────┘
           ▲                          ▲
           │                          │
   Policy YAML file           Human operator
   (hot-reloaded every 2s)    POST /v1/approve/{id}
                              or /v1/deny/{id}
                              via Dashboard UI
```

### Request lifecycle

```
Agent SDK                 Proxy                      Human
────────                  ─────                      ─────
check("shell",         →  matchRule()
 command="rm -rf /")      Deny rules first
                          RequireApproval rules
                          Allow rules
                          Default: DENY
                       ←  CheckResult{DENY, reason}

check("shell",         →  matchRule()
 command="sudo apt")      Matches require_approval
                          Enqueue PendingAction
                          Broadcast to SSE clients  → Dashboard shows
                       ←  CheckResult{REQUIRE_APPROVAL,
                            approval_id, approval_url}
                                                      POST /v1/approve/{id}
wait_for_approval()    ←  Resolve(id, ALLOW)
```

---

## Directory Structure

```
agentguard/
├── cmd/
│   └── agentguard/
│       └── main.go              # CLI entry point (serve / validate / version)
│
├── pkg/
│   ├── policy/
│   │   ├── engine.go            # Core policy evaluation logic
│   │   ├── engine_test.go       # Table-driven tests for all decision paths
│   │   ├── engine_agent_test.go # Per-agent override tests
│   │   └── watcher.go           # Hot-reload: polls policy file every 2s
│   ├── audit/
│   │   ├── logger.go            # JSON Lines file logger + query interface
│   │   └── logger_test.go       # Tests for log/query/persistence
│   ├── metrics/
│   │   └── metrics.go           # Prometheus-compatible counters + histograms
│   ├── notify/
│   │   └── notify.go            # Webhook/Slack/console/log notification dispatcher
│   ├── proxy/
│   │   └── server.go            # HTTP server, approval queue, SSE, dashboard HTML
│   └── ratelimit/
│       ├── ratelimit.go         # Token-bucket rate limiter
│       └── ratelimit_test.go    # Rate limiter tests
│
├── configs/
│   ├── default.yaml             # Restrictive defaults (dev/sandbox)
│   └── examples/
│       ├── research-agent.yaml  # Permissive read, restricted write
│       └── trading-bot.yaml     # Financial API whitelist, cost limits
│
├── plugins/
│   ├── python/
│   │   ├── pyproject.toml       # Package metadata (v0.2.3, Python 3.8+)
│   │   └── agentguard/
│   │       ├── __init__.py      # Guard class, CheckResult, @guarded decorator
│   │       └── adapters/
│   │           ├── langchain.py # GuardedTool / GuardedToolkit for LangChain
│   │           ├── crewai.py    # GuardedCrewTool / guard_crew_tools for CrewAI
│   │           ├── browseruse.py# GuardedBrowser / GuardedPage for browser-use
│   │           └── mcp.py       # GuardedMCPServer for Anthropic MCP
│   └── typescript/
│       ├── package.json         # @agentguard/sdk package
│       └── src/
│           └── index.ts         # AgentGuard class, CheckResult, guarded() HOF
│
├── examples/
│   └── quickstart.py            # Standalone demo (shell/network/filesystem checks)
│
├── docs/
│   └── CONTRIBUTING.md          # Dev setup, style guide, contribution areas
│
├── .github/
│   └── workflows/
│       └── ci.yml               # Build → test (race) → lint → docker
│
├── Dockerfile                   # Multi-stage build: golang:1.22-alpine → alpine:3.19
├── Makefile                     # build / test / lint / run / validate / docker
├── go.mod                       # Go module dependencies
└── README.md                    # Full user-facing documentation
```

---

## Core Modules

### `pkg/policy/engine.go` — Policy Engine
The heart of AgentGuard. Implements `Engine.Check(ActionRequest) CheckResult`.

**Evaluation order (strict priority):**
1. DENY rules — first match immediately returns DENY
2. REQUIRE_APPROVAL rules — first match queues for human review
3. ALLOW rules — first match permits the action
4. Default DENY — no matching rule → denied

**Pattern matching (`globMatch`):**
- Wildcard match for non-path patterns (shell commands, domains). `*` matches any run of characters including spaces/dots; anchored to both ends.
- Segment-based matching for patterns containing `**` — splits on `/` and matches path components. `**` consumes zero or more whole segments. Example: `**/secret/**` matches `/home/user/secret/data` but **not** `/notsecret/x` (substring bypass fixed).
- Domain globs use the same wildcard semantics (e.g., `*.googleapis.com`).

**Thread safety:** `sync.RWMutex` — multiple concurrent checks are safe; policy hot-swap uses an exclusive write lock.

**Key types:**
- `ActionRequest` — what the agent wants to do: `{scope, action, command, path, domain, url, agent_id}`
- `CheckResult` — the decision: `{decision, reason, rule, approval_id, approval_url}`
- `Policy` — parsed YAML: `{rules []RuleSet, agents map, notifications}`
- `RuleSet` — grouped by scope: `{scope, allow, deny, require_approval, rate_limit}`

### `pkg/proxy/server.go` — HTTP Proxy
Exposes the REST API agents call. Also manages the approval queue and dashboard.

**Endpoints:**
| Method | Path | Purpose | Auth when `--api-key` set |
|---|---|---|---|
| POST | `/v1/check` | Main policy enforcement | open |
| POST | `/v1/approve/{id}` | Approve a pending action | Bearer OR session+CSRF |
| POST | `/v1/deny/{id}` | Deny a pending action | Bearer OR session+CSRF |
| GET | `/v1/status/{id}` | Poll approval status | Bearer OR session |
| GET | `/v1/audit` | Query audit log (filtered) | Bearer OR session |
| POST | `/auth/login` | Exchange API key for session cookie | open |
| POST | `/auth/logout` | Destroy the current session | open |
| GET | `/health` | Health check | open |
| GET | `/metrics` | Prometheus metrics | open |
| GET | `/dashboard` | Web dashboard UI (or login page) | session |
| GET | `/api/pending` | List pending approvals | Bearer OR session |
| GET | `/api/stream` | SSE stream of new pending actions | Bearer OR session |
| GET | `/api/stats` | Aggregate counter snapshot | Bearer OR session |

Session auth uses a **double-submit cookie**: `/auth/login` sets a HttpOnly `ag_session` cookie plus a JS-readable `ag_csrf` cookie (same token). State-changing requests must echo the CSRF token in the `X-CSRF-Token` header. The API key is never embedded in the dashboard HTML.

**ApprovalQueue:** In-memory `map[string]*PendingAction`. Each pending action has a `response chan policy.Decision` that blocks `Resolve()` callers. SSE watchers are notified on `Add()`.

### `pkg/audit/logger.go` — Audit Logger
Writes every policy decision to a JSON Lines file. `Log()` is append-only with a mutex. `Query()` re-opens the file from the start and filters line-by-line (sequential scan — not suitable for large logs; see known limitations).

### `pkg/policy/watcher.go` — Policy Hot-Reload
Goroutine that polls the policy file's mtime every 2 seconds. On change, re-parses and calls `Engine.UpdatePolicy()`. Errors are logged but don't stop the watcher.

### `plugins/python/agentguard/__init__.py` — Python SDK
- `Guard` class: HTTP client using stdlib `urllib` only (no external deps)
- `CheckResult` dataclass with `.allowed`, `.denied`, `.needs_approval` properties
- `@guarded` decorator: wraps functions to auto-check before execution
- Fail-safe: returns DENY if AgentGuard proxy is unreachable

### `plugins/python/agentguard/adapters/langchain.py` — LangChain Adapter
- `GuardedTool`: wraps a LangChain `BaseTool`, intercepts `_run()` / `_arun()`
- `GuardedToolkit`: convenience wrapper for a list of tools
- Auto-detects scope from tool name/description keywords

### `plugins/typescript/src/index.ts` — TypeScript SDK
- `AgentGuard` class: async HTTP client using native `fetch` with `AbortController` timeout
- `guarded()` HOF: wraps async functions with a pre-check
- `failMode: 'deny' | 'allow'` — configurable behavior when proxy is unreachable (default: deny)

---

## Data Flow

### Happy path (ALLOW)
```
Agent code
  → Guard.check("network", domain="api.openai.com")
  → POST http://localhost:8080/v1/check
  → server.handleCheck()
  → Engine.Check(req)
    → matchRule(allow_rule, req) → true
    → return CheckResult{ALLOW, ...}
  → audit.Log(entry)
  → HTTP 200 {decision: "ALLOW"}
  → result.allowed == true
  → Agent proceeds
```

### Approval path (REQUIRE_APPROVAL)
```
Agent code
  → Guard.check("shell", command="sudo apt install ...")
  → POST /v1/check
  → Engine.Check → REQUIRE_APPROVAL
  → ApprovalQueue.Add() → PendingAction{id: "ap_<crypto_rand_hex>"}
  → SSE broadcast to all /api/stream subscribers
  → HTTP 200 {decision: "REQUIRE_APPROVAL", approval_id: "ap_...", approval_url: "..."}
  → Agent calls Guard.wait_for_approval("ap_...")
    → Polls GET /v1/status/ap_... every 2s
  → Human opens Dashboard → sees pending action
  → Human POSTs /v1/approve/ap_...
  → ApprovalQueue.Resolve("ap_...", ALLOW)
  → Next poll returns {status: "resolved", decision: "ALLOW"}
  → Agent proceeds
```

### Policy hot-reload
```
watcher goroutine (every 2s):
  → stat(policy_file)
  → if mtime changed: LoadFromFile()
  → Engine.UpdatePolicy(newPolicy)
  → next Check() uses new policy atomically
```

---

## Key Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `gopkg.in/yaml.v3` | v3.0.1 | YAML policy parsing |
| Python stdlib (`urllib`, `json`) | Built-in | Python SDK HTTP calls |
| Browser `fetch` API | Web standard | TypeScript SDK HTTP calls |

---

## Common Edit Points

| Task | File(s) to edit |
|---|---|
| Add a new policy scope (e.g., `database`) | `pkg/policy/engine.go` — add case in `matchRule()` |
| Change how rules are evaluated | `pkg/policy/engine.go:163-215` — `Engine.Check()` |
| Add a new API endpoint | `pkg/proxy/server.go` — add handler + register in `NewServer()` |
| Tweak auth / sessions | `pkg/proxy/auth.go` (`requireAuthOrSession`, `SessionStore`, login/logout handlers) |
| Tighten CORS | `pkg/proxy/server.go` — `withCORS` middleware (exact-origin match) |
| Swap audit backend (file → DB) | `pkg/audit/logger.go` — implement `Logger` interface |
| Add rate limiting enforcement | `pkg/policy/engine.go` — consume `RuleSet.RateLimit` in `Check()` |
| Add a new framework adapter (Python) | `plugins/python/agentguard/adapters/` — new file, implement wrapping |
| Change default policy | `configs/default.yaml` |
| Modify CLI flags | `cmd/agentguard/main.go` |
| Update dashboard UI | `pkg/proxy/server.go:336-392` — `dashboardHTML` variable |

---

## Known Limitations and TODOs

### Performance TODOs
- Audit `Query()` does a full file scan on every call — replace with a database-backed implementation. A SQLite logger (`pkg/audit/sqlite_logger.go`) exists and is SQL-injection-safe but is not wired in by default.
- Startup counter seeding scans the full audit log — should persist counters separately for servers with very large existing logs.

### Operational TODOs
- Approval queue is in-memory only — lost on restart; needs persistence.
- No audit log rotation or retention policy — ship the log to an external system in production.
- Module path is `github.com/Caua-ferraz/AgentGuard`.

### Resolved (v0.4.0 / v0.4.1)
- ✔ `globMatch` now supports multi-`**` patterns with segment-based matching (no more substring bypass).
- ✔ `conditions.require_prior` + `time_window` are enforced at check time. For v0.4.1, rules with only `time_window` (no `require_prior`) log a load-time warning but pass (restored backward-compat; the engine cannot satisfy a `time_window` without something to time-bound).
- ✔ `max_per_session` is enforced with atomic check-and-reserve inside `Engine.Check` — concurrent requests on the same session cannot collectively exceed the budget (TOCTOU fix). `Engine.RefundCost` is available to roll back a reservation.
- ✔ Rate limiter has TTL-based eviction of stale buckets when at capacity.
- ✔ Dashboard no longer embeds the API key in HTML. Login flow issues an HTTP-only session cookie; double-submit CSRF token on writes.
- ✔ Notifier dispatcher uses a bounded worker pool with an event queue; excess events are dropped with a counter (`notify.DroppedEvents`).
- ✔ Input normalization (strip NUL/C0 controls, single-pass URL-decode for paths) runs before policy matching.
- ✔ CLI subcommands (`approve`, `deny`, `status`, `audit`) accept `--api-key` or read `AGENTGUARD_API_KEY`.
- ✔ `--allowed-origin` CLI flag on `serve`. CORS default with no `--allowed-origin` remains permissive-localhost for backward compat (safe now: session cookies are SameSite=Strict, CSRF double-submit is required for state-changing requests, API key is never in HTML).

---

## v0.5.0 — Planned Fixes

These items are deliberately deferred. They are performance or defense-in-depth improvements that do not block v0.4.1; the current behavior is safe and correct.

### Security hardening
- **Rate limit `/auth/login`**: brute-force a short API key is trivial. Either add a per-IP rate limiter on the login endpoint or document a minimum key length (≥32 random chars) in the deployment guide.
- **CSP header on `/dashboard` and `/auth/login`**: add `Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'`. `ag_csrf` is JS-readable by design (double-submit pattern) — CSP hardens the dashboard against XSS concentrations of risk.
- **Trust-proxy / `X-Forwarded-Proto` handling**: when AgentGuard sits behind a TLS-terminating reverse proxy, `r.TLS` is nil, so `Secure` is not set on cookies. Functionally safe (proxy enforces HTTPS) but wrong on the wire. Consume `X-Forwarded-Proto` under an opt-in `--trust-proxy` flag.

### Configurability
- **`SessionTTL` as a Config field** (currently hardcoded 1 hour in `pkg/proxy/auth.go`). Expose via `--session-ttl` on `serve`.
- **`MaxSessions` as a Config field** (currently 1024). Expose similarly.

### Performance
- **`resolveRules` allocation caching**: per-call `[]RuleSet` allocation for agents with overrides. Cache on `(policy-version-counter, agent_id)`; invalidate on `UpdatePolicy`.
- **`FileLogger.Log` batching / SQLite wire-up**: single mutex per write serializes audit writes. Either batch and flush periodically or wire `sqlite_logger.go` behind an `--audit-backend=sqlite` flag.
- **Histogram `Observe` lock-free**: `sync.Mutex` in `pkg/metrics/metrics.go:82-93` is fine at hundreds of RPS, a bottleneck higher. Convert bucket counts to `[]uint64` with `atomic.AddUint64`.
- **Notifier `Redactor` regex cost**: 5 regexes × 3 fields per event. Negligible today; precompile once (done) and consider a single combined pattern under heavy notification load.
- **Startup audit replay full-file scan**: servers restarting against a multi-GB audit log stall on boot. Persist counter state separately (sidecar file or SQLite table) and seed from it.

### Observability & docs
- **Verify line-number references in `project.md` "Common Edit Points"**: file lengths changed since the last sweep; the `dashboardHTML` pointer in particular is stale.
- **Metric for `notify.DroppedEvents`**: currently a package-level `uint64`, not wired into the Prometheus exporter.
- **Per-rule deny-rate + approval-latency metrics**.
