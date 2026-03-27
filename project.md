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
│   │   └── watcher.go          # Hot-reload: polls policy file every 2s
│   ├── audit/
│   │   ├── logger.go            # JSON Lines file logger + query interface
│   │   └── logger_test.go       # Tests for log/query/persistence
│   └── proxy/
│       └── server.go            # HTTP server, approval queue, SSE, dashboard HTML
│
├── configs/
│   ├── default.yaml             # Restrictive defaults (dev/sandbox)
│   └── examples/
│       ├── research-agent.yaml  # Permissive read, restricted write
│       └── trading-bot.yaml     # Financial API whitelist, cost limits
│
├── plugins/
│   ├── python/
│   │   ├── setup.py             # Package metadata (v0.1.0, Python 3.8+)
│   │   └── agentguard/
│   │       ├── __init__.py      # Guard class, CheckResult, @guarded decorator
│   │       └── adapters/
│   │           └── langchain.py # GuardedTool / GuardedToolkit for LangChain
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
- Standard glob via `filepath.Match` (e.g., `rm -rf *`, `*.txt`)
- Double-star `**` for recursive path matching (e.g., `/etc/**`)
- Domain matching supports wildcards (e.g., `*.googleapis.com`)

**Thread safety:** `sync.RWMutex` — multiple concurrent checks are safe; policy hot-swap uses an exclusive write lock.

**Key types:**
- `ActionRequest` — what the agent wants to do: `{scope, action, command, path, domain, url, agent_id}`
- `CheckResult` — the decision: `{decision, reason, rule, approval_id, approval_url}`
- `Policy` — parsed YAML: `{rules []RuleSet, agents map, notifications}`
- `RuleSet` — grouped by scope: `{scope, allow, deny, require_approval, rate_limit}`

### `pkg/proxy/server.go` — HTTP Proxy
Exposes the REST API agents call. Also manages the approval queue and dashboard.

**Endpoints:**
| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/check` | Main policy enforcement |
| POST | `/v1/approve/{id}` | Approve a pending action |
| POST | `/v1/deny/{id}` | Deny a pending action |
| GET | `/v1/audit` | Query audit log (filtered) |
| GET | `/health` | Health check |
| GET | `/dashboard` | Web dashboard UI |
| GET | `/api/pending` | List pending approvals |
| GET | `/api/stream` | SSE stream of new pending actions |

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
  → ApprovalQueue.Add() → PendingAction{id: "ap_<nanoseconds>"}
  → SSE broadcast to all /api/stream subscribers
  → HTTP 200 {decision: "REQUIRE_APPROVAL", approval_id: "ap_...", approval_url: "..."}
  → Agent calls Guard.wait_for_approval("ap_...")
    → Polls GET /v1/check/ap_... every 2s (NOTE: endpoint does not exist — bug)
  → Human opens Dashboard → sees pending action
  → Human POSTs /v1/approve/ap_...
  → ApprovalQueue.Resolve("ap_...", ALLOW)
  → Agent eventually times out and gets DENY (due to polling bug)
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
| `github.com/gorilla/mux` | v1.8.1 | **Declared but unused** |
| `github.com/gorilla/websocket` | v1.5.1 | **Declared but unused** |
| `github.com/mattn/go-sqlite3` | v1.14.22 | **Declared but unused** (planned for audit DB) |
| Python stdlib (`urllib`, `json`) | Built-in | Python SDK HTTP calls |
| Browser `fetch` API | Web standard | TypeScript SDK HTTP calls |

---

## Common Edit Points

| Task | File(s) to edit |
|---|---|
| Add a new policy scope (e.g., `database`) | `pkg/policy/engine.go` — add case in `matchRule()` |
| Change how rules are evaluated | `pkg/policy/engine.go:163-215` — `Engine.Check()` |
| Add a new API endpoint | `pkg/proxy/server.go` — add handler + register in `NewServer()` |
| Add authentication | `pkg/proxy/server.go` — add auth middleware, wire in `NewServer():80` |
| Swap audit backend (file → DB) | `pkg/audit/logger.go` — implement `Logger` interface |
| Add rate limiting enforcement | `pkg/policy/engine.go` — consume `RuleSet.RateLimit` in `Check()` |
| Add a new framework adapter (Python) | `plugins/python/agentguard/adapters/` — new file, implement wrapping |
| Change default policy | `configs/default.yaml` |
| Modify CLI flags | `cmd/agentguard/main.go` |
| Update dashboard UI | `pkg/proxy/server.go:336-392` — `dashboardHTML` variable |

---

## Known Limitations and TODOs

### Bugs
- **`wait_for_approval` polls a non-existent endpoint:** Both Python (`__init__.py:153`) and TypeScript (`index.ts:200`) poll `GET /v1/check/{id}`, but no such endpoint exists on the server. Approval waiting is silently broken — agents always time out and receive DENY. The server needs a `GET /v1/status/{id}` endpoint, or the SDKs should use `GET /api/pending` to check resolution status.
- **`~/.ssh/**` deny rule never matches:** `filepath.Match` does not expand `~`. The shell home-directory deny rules in `configs/default.yaml:21` are ineffective on all platforms.
- **Broad allow patterns can be bypassed:** `python *` in shell scope allows arbitrary Python one-liners (e.g., `python -c "import os; os.system('rm -rf /')`).

### Security TODOs
- No authentication on `/v1/approve` and `/v1/deny` endpoints (anyone on the network can approve)
- CORS is `Access-Control-Allow-Origin: *` — any browser script can call the API
- Approval IDs use nanosecond timestamps (guessable); should use `crypto/rand` UUIDs
- No request body size limit (DoS vector via oversized payloads)
- XSS in dashboard: `data.request.scope/command/path` inserted via `innerHTML` without sanitization

### Features Parsed but Not Enforced
- `rate_limit` in RuleSet — parsed from YAML, never evaluated in `Engine.Check()`
- `conditions` in Rule (`require_prior`, `time_window`) — parsed, never enforced
- `cost` scope — policy structure exists, no evaluation logic
- `notifications` targets (`webhook` type) — parsed, never dispatched

### Performance TODOs
- Audit `Query()` does a full file scan on every call — replace with SQLite (dependency already declared in `go.mod`)
- Policy watcher re-parses YAML on every 2-second tick even when file hasn't changed — should check mtime before parsing

### Operational TODOs
- Approval queue is in-memory only — lost on restart; needs persistence
- No audit log rotation or retention policy
- Unused Go dependencies (`gorilla/mux`, `gorilla/websocket`, `go-sqlite3`) should be removed or used
- Module path is `github.com/Caua-ferraz/AgentGuard`
