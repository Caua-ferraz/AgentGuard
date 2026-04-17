# Local Setup Guide

Get AgentGuard running on your machine in under 5 minutes.

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Go | 1.22+ | `go version` |
| Git | any | `git --version` |
| Python (optional) | 3.8+ | `python --version` |
| Node.js (optional) | 18+ | `node --version` |
| Docker (optional) | any | `docker --version` |

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/Caua-ferraz/AgentGuard.git
cd AgentGuard
go build -o agentguard ./cmd/agentguard
```

On Windows:
```powershell
go build -o agentguard.exe ./cmd/agentguard
```

### 2. Validate the Default Policy

```bash
./agentguard validate --policy configs/default.yaml
# Output: VALID: default-sandbox — 18 rules across 4 scopes
```

### 3. Start the Server

```bash
# Basic
./agentguard serve --policy configs/default.yaml

# With dashboard and live policy reload
./agentguard serve --policy configs/default.yaml --dashboard --watch

# Custom port
./agentguard serve --policy configs/default.yaml --port 9090 --dashboard
```

### 4. Verify It's Running

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"0.4.0"}
```

Open `http://localhost:8080/dashboard` in your browser to see the live dashboard.

### 5. Test a Policy Check

```bash
# This should be ALLOWED (ls is in the allow list)
curl -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope": "shell", "command": "ls -la", "agent_id": "test"}'

# This should be DENIED (fork bomb)
curl -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope": "shell", "command": ":(){ :|:& };:", "agent_id": "test"}'

# This should REQUIRE_APPROVAL (sudo)
curl -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope": "shell", "command": "sudo apt install vim", "agent_id": "test"}'

# Filesystem scope — DENIED because /etc is not in the allow list
curl -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope": "filesystem", "action": "write", "path": "/etc/passwd", "agent_id": "test"}'

# Network scope — ALLOWED (api.openai.com is whitelisted)
curl -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope": "network", "domain": "api.openai.com", "agent_id": "test"}'
```

---

## Authentication

By default (`--api-key` not set) the server binds to `127.0.0.1` only — safe
for local dev, but approve/deny/audit/status are unauthenticated. For
anything beyond local dev, set an API key:

```bash
./agentguard serve \
  --policy configs/default.yaml \
  --api-key YOUR_SECRET \
  --dashboard

# Or via environment (server + CLI both read this):
export AGENTGUARD_API_KEY=YOUR_SECRET
./agentguard serve --policy configs/default.yaml --dashboard
```

With an API key configured:

| Endpoint | Who can call it |
|---|---|
| `POST /v1/check` | Anyone — the policy answer isn't sensitive. |
| `POST /v1/approve/{id}`, `POST /v1/deny/{id}` | Bearer token **or** dashboard session + `X-CSRF-Token`. |
| `GET /v1/status/{id}`, `GET /v1/audit` | Bearer token **or** dashboard session. |
| `GET /dashboard`, `GET /api/*` | Dashboard session only (serves login page otherwise). |
| `POST /auth/login`, `POST /auth/logout` | Unauthenticated (login validates the key; logout destroys the session). |
| `GET /health`, `GET /metrics` | Unauthenticated. |

### Dashboard login flow

1. Visit `http://<server>/dashboard` — if not logged in, you get a login form.
2. Enter the API key — the server issues an HTTP-only `ag_session` cookie
   plus a JS-readable `ag_csrf` cookie (same token, double-submit pattern).
3. Approve/deny buttons now work; the dashboard JS attaches `X-CSRF-Token`
   automatically. The API key is **never** embedded in the HTML.
4. `POST /auth/logout` destroys the session.

### From `curl` with Bearer auth

```bash
export AGENTGUARD_API_KEY=YOUR_SECRET

# Approve an action
curl -X POST "http://localhost:8080/v1/approve/ap_abc123" \
  -H "Authorization: Bearer $AGENTGUARD_API_KEY"

# Query the audit log
curl "http://localhost:8080/v1/audit?agent_id=my-bot&limit=20" \
  -H "Authorization: Bearer $AGENTGUARD_API_KEY"
```

### From `curl` with session cookies

```bash
# 1. Login — capture cookies into a jar.
curl -c /tmp/cj -X POST "http://localhost:8080/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"api_key\": \"$AGENTGUARD_API_KEY\"}"

# 2. Use cookies on subsequent calls. Writes also need X-CSRF-Token
#    (same value as the ag_csrf cookie).
CSRF=$(awk '/ag_csrf/ {print $7}' /tmp/cj)
curl -b /tmp/cj -X POST "http://localhost:8080/v1/approve/ap_abc123" \
  -H "X-CSRF-Token: $CSRF"
```

### CORS for browser clients on other origins

By default (no `--allowed-origin`), AgentGuard accepts CORS requests from
any `http://localhost:*` or `http://127.0.0.1:*` origin. For production
deployments where a specific frontend needs to talk to AgentGuard:

```bash
./agentguard serve --api-key YOUR_SECRET \
  --allowed-origin https://console.your-company.com
```

Exact-match only — no wildcards, no subdomains.

---

## Using the Python SDK

### Install

```bash
# From PyPI
pip install agentguardproxy

# With framework adapters
pip install agentguardproxy[langchain]
pip install agentguardproxy[crewai]
pip install agentguardproxy[browser-use]
pip install agentguardproxy[all]

# Or from source (editable / development)
cd plugins/python
pip install -e ".[dev]"
```

### Basic Usage

```python
from agentguard import Guard

# Both `base_url` and `api_key` fall back to environment variables if not
# passed explicitly:
#   AGENTGUARD_URL      → base_url (default: http://localhost:8080)
#   AGENTGUARD_API_KEY  → api_key  (required when the server has --api-key)
guard = Guard("http://localhost:8080", agent_id="my-agent", api_key="YOUR_SECRET")

# --- Plain check ---
result = guard.check("shell", command="ls -la")
print(result.decision)  # "ALLOW"
print(result.allowed)   # True

# --- Approval flow ---
result = guard.check("shell", command="rm -rf /tmp/data")
if result.needs_approval:
    print(f"Visit {result.approval_url} or approve via CLI/SDK")

    # Block until a human resolves it (or timeout → DENY).
    resolved = guard.wait_for_approval(
        result.approval_id, timeout=300, poll_interval=2,
    )
    if resolved.allowed:
        run(command)

# --- Programmatic approve / deny (needs api_key) ---
guard.approve("ap_abc123")   # → True on success
guard.deny("ap_abc123")      # → True on success

# --- Cost guardrails ---
r = guard.check(
    "cost",
    command="llm-call",
    session_id="user-123",
    est_cost=0.42,   # $0.42 for this action
)
# Engine atomically reserves the cost against max_per_session when allowed.

# --- Auto-check every invocation with the @guarded decorator ---
from agentguard import guarded

@guarded("shell", guard=guard)
def run_command(cmd: str):
    os.system(cmd)

run_command("ls -la")      # allowed → executes
run_command("rm -rf /")    # denied → raises PermissionError
```

### LangChain Integration

```python
from langchain.agents import create_react_agent
from agentguard.adapters.langchain import GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="research-bot",
)

agent = create_react_agent(llm, toolkit.tools, prompt)
# All tool calls now flow through AgentGuard
```

### CrewAI Integration

```python
from crewai import Agent, Task, Crew
from agentguard.adapters.crewai import guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)

agent = Agent(role="Researcher", tools=guarded_tools)
```

### browser-use Integration

```python
from agentguard.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080")

# Check before navigating
result = browser.check_navigation("https://example.com")
if result.allowed:
    await page.goto("https://example.com")
```

### MCP Integration

Add to your MCP client config (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python",
      "args": ["-m", "agentguard.adapters.mcp", "--guard-url", "http://localhost:8080"]
    }
  }
}
```

---

## Using the TypeScript SDK

### Install

```bash
cd plugins/typescript
npm install
npm run build
```

### Usage

```typescript
import { AgentGuard, guarded } from '@agentguard/sdk';

const guard = new AgentGuard({
  baseUrl: 'http://localhost:8080',
  agentId: 'my-bot',
  apiKey: process.env.AGENTGUARD_API_KEY,
  // failMode: 'deny' (default) — if the server is unreachable, check()
  // returns DENY. Set to 'allow' only if you know what you're doing.
});

// Plain check
const result = await guard.check('shell', { command: 'ls -la' });
if (result.allowed) { /* proceed */ }

// Approval flow
const r = await guard.check('shell', { command: 'sudo restart' });
if (r.needsApproval) {
  const resolved = await guard.waitForApproval(r.approvalId!, 300_000, 2_000);
  if (resolved.allowed) { /* proceed */ }
}

// Programmatic approve / deny (needs apiKey)
await guard.approve('ap_abc123');
await guard.deny('ap_abc123');

// Cost guardrails
await guard.check('cost', {
  command: 'llm-call',
  sessionId: 'user-123',
  estCost: 0.42,
});

// Higher-order wrapper — every invocation goes through AgentGuard
const safeExec = guarded(guard, 'shell', (cmd: string) => execAsync(cmd));
await safeExec('ls -la');    // allowed → resolves
await safeExec('rm -rf /');  // denied  → throws
```

---

## Using the CLI

```bash
# Start the server
agentguard serve --policy configs/default.yaml --dashboard --watch

# With authentication (also reads AGENTGUARD_API_KEY from the environment)
agentguard serve --policy configs/default.yaml --api-key YOUR_SECRET --dashboard

# Validate policy files (no server needed)
agentguard validate --policy configs/default.yaml

# Approve / deny — accept --api-key or AGENTGUARD_API_KEY env var.
agentguard approve --api-key YOUR_SECRET ap_abc123def456
AGENTGUARD_API_KEY=YOUR_SECRET agentguard deny ap_abc123def456

# Check server status and pending approvals (auth required if server is gated)
agentguard status --api-key YOUR_SECRET

# Query the audit log with filters
agentguard audit --agent my-bot --decision DENY --limit 20 --api-key YOUR_SECRET

# Print version
agentguard version
```

### `serve` flags reference

| Flag | Default | Purpose |
|---|---|---|
| `--policy` | `configs/default.yaml` | Policy YAML file. |
| `--port` | `8080` | Listen port. |
| `--dashboard` | off | Enable `/dashboard` + `/api/*`. |
| `--watch` | off | Hot-reload the policy on mtime change. |
| `--audit-log` | `audit.jsonl` | JSON-lines audit log path. In Docker, defaults to `/var/lib/agentguard/audit.jsonl`. |
| `--api-key` | unset (`AGENTGUARD_API_KEY` env) | Bearer token gating approve/deny/audit/status/dashboard. |
| `--base-url` | `http://localhost:<port>` | External URL used to build `approval_url` values (e.g. when behind a reverse proxy). |
| `--allowed-origin` | unset | Exact CORS origin to allow. Empty = permissive-localhost. |

---

## Using Docker

### Build

```bash
docker build -t agentguard:latest .
```

### Run

```bash
# With default policy (baked into the image). Mount a named volume for the
# audit log so it survives container restarts.
docker run -d -p 8080:8080 --name agentguard \
  -v agentguard-audit:/var/lib/agentguard \
  agentguard:latest

# With a custom policy — mount your YAML over the baked-in default file.
# Do NOT mount the whole /etc/agentguard directory; that hides the default.
docker run -d -p 8080:8080 --name agentguard \
  -v $(pwd)/configs/my-policy.yaml:/etc/agentguard/default.yaml:ro \
  -v agentguard-audit:/var/lib/agentguard \
  agentguard:latest

# The container runs as the non-root user agentguard (uid 10001). If you
# bind-mount a host directory for the audit log, make sure it's writable
# by uid 10001:
#   sudo chown -R 10001:10001 /path/on/host
```

---

## Configuration

### Policy Files

Policies are YAML files in `configs/`. See the included examples:

| File | Use Case |
|------|----------|
| `configs/default.yaml` | Safe sandbox defaults |
| `configs/examples/research-agent.yaml` | Permissive research agent |
| `configs/examples/trading-bot.yaml` | Strict financial trading agent |

### Policy Hot-Reload

Start with `--watch` to reload policies on file change without restarting:

```bash
agentguard serve --policy configs/default.yaml --watch
```

### Per-Agent Overrides

Define agent-specific rules in your policy file:

```yaml
agents:
  research-bot:
    extends: "default"
    override:
      - scope: network
        allow:
          - domain: "scholar.google.com"
          - domain: "*.arxiv.org"
```

### Notifications

Configure webhook/Slack notifications in your policy:

```yaml
notifications:
  approval_required:
    - type: slack
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    - type: console
  on_deny:
    - type: webhook
      url: "https://your-server.com/alerts"
    - type: log
      level: warn
```

### Rate Limiting

Rate limits are enforced per-scope per-agent:

```yaml
rules:
  - scope: network
    rate_limit:
      max_requests: 60
      window: "1m"
```

### Cost Guardrails

The cost scope evaluates `est_cost` from the request:

```yaml
rules:
  - scope: cost
    limits:
      max_per_action: "$0.50"
      max_per_session: "$10.00"
      alert_threshold: "$5.00"
```

---

## Running Tests

```bash
# Go tests with race detection
go test -v -race ./...

# Go coverage
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Python SDK tests
cd plugins/python
pip install -e ".[dev]"
pytest -v --cov=agentguard
```

---

## Project Structure

```
agentguard/
├── cmd/agentguard/          # CLI entry point
│   └── main.go
├── pkg/
│   ├── policy/              # Policy engine (YAML parsing, rule evaluation)
│   │   ├── engine.go
│   │   ├── engine_test.go
│   │   ├── engine_agent_test.go
│   │   └── watcher.go
│   ├── proxy/               # HTTP proxy server + dashboard
│   │   └── server.go
│   ├── audit/               # Audit logging (JSON lines)
│   │   ├── logger.go
│   │   └── logger_test.go
│   ├── notify/              # Webhook/Slack/console notifications
│   │   └── notify.go
│   └── ratelimit/           # Token-bucket rate limiter
│       ├── ratelimit.go
│       └── ratelimit_test.go
├── plugins/
│   ├── python/              # Python SDK + adapters
│   │   ├── agentguard/
│   │   │   ├── __init__.py
│   │   │   └── adapters/
│   │   │       ├── langchain.py
│   │   │       ├── crewai.py
│   │   │       ├── browseruse.py
│   │   │       └── mcp.py
│   │   ├── pyproject.toml
│   │   └── README.md
│   └── typescript/          # TypeScript SDK
│       ├── src/index.ts
│       ├── package.json
│       └── tsconfig.json
├── configs/                 # Policy files
│   ├── default.yaml
│   └── examples/
├── docs/                    # Documentation
├── Dockerfile
├── Makefile
└── README.md
```
