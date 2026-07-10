# Local Setup Guide

Get AgentGuard running on your machine in under 5 minutes.

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Go | 1.25+ | `go version` |
| Git | any | `git --version` |
| Python (optional, for the SDK) | 3.10+ | `python --version` |
| Node.js (optional, for the TS SDK) | 20+ | `node --version` |
| Docker (optional) | any | `docker --version` |

## What you're setting up

AgentGuard is the **wire-level checkpoint** that sits between your agent and everything it touches. It runs as one or more of three enforcement layers, plus the AgentGuard server that owns policy + audit + approvals.

| Layer | Binary | Use for | Code change |
|---|---|---|---|
| MCP traffic | `agentguard-mcp-gateway` | Claude Desktop, Cursor, Cline, Continue, Zed | None |
| LLM API calls | `agentguard-llm-proxy` | OpenAI / Anthropic SDK code | One env var |
| Direct calls | Python / TypeScript SDK + adapters | Custom code, framework integrations | Per-call `guard.check(...)` |

Layer-specific quickstarts: [`QUICKSTART_MCP.md`](QUICKSTART_MCP.md) · [`QUICKSTART_LLM_PROXY.md`](QUICKSTART_LLM_PROXY.md). The rest of this guide covers building the binaries, running the server, and using the SDK.

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/Caua-ferraz/AgentGuard.git
cd AgentGuard

# Central server (always needed)
go build -o agentguard ./cmd/agentguard

# MCP Gateway (only if you're integrating MCP clients)
go build -o agentguard-mcp-gateway ./cmd/agentguard-mcp-gateway

# LLM API Proxy (only if you're proxying OpenAI / Anthropic SDK traffic)
go build -o agentguard-llm-proxy ./cmd/agentguard-llm-proxy
```

On Windows append `.exe` to each `-o` target. Or install everything from a remote tag:

```bash
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest
```

### 2. Validate the Default Policy

```bash
./agentguard validate --policy configs/default.yaml
# Output: VALID: default-sandbox — 54 rules across 5 scopes  (numbers vary as the default ships more rules)
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
# {"status":"ok","version":"0.9.0"}
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

Which endpoints the key gates (and which stay open), the dashboard
login/CSRF flow, Bearer-vs-session `curl` recipes, and CORS
(`--allowed-origin`) are documented once in
[`DEPLOYMENT.md`](DEPLOYMENT.md) with the endpoint table in
[`API.md`](API.md).

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

# base_url / api_key fall back to AGENTGUARD_URL / AGENTGUARD_API_KEY.
guard = Guard("http://localhost:8080", agent_id="my-agent", api_key="YOUR_SECRET")

result = guard.check("shell", command="ls -la")
if result.allowed:
    run_it()
```

That's the whole core loop. The rest of the SDK surface — the approval
flow (`wait_for_approval`), programmatic approve/deny, cost guardrails,
the `@guarded` decorator, failure modes, and testing recipes — is
documented once in [`SDK_PYTHON.md`](SDK_PYTHON.md). The framework
adapters (LangChain, CrewAI, browser-use, MCP) with their scope-inference
rules and per-framework gotchas live in [`ADAPTERS.md`](ADAPTERS.md).

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
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard({
  baseUrl: 'http://localhost:8080',
  agentId: 'my-bot',
  apiKey: process.env.AGENTGUARD_API_KEY,
  // failMode: 'deny' (default) — server unreachable ⇒ check() returns DENY.
});

const result = await guard.check('shell', { command: 'ls -la' });
if (result.allowed) { /* proceed */ }
```

The TypeScript surface mirrors the Python one — `waitForApproval`,
`approve`/`deny`, cost checks, and the `guarded` higher-order wrapper.
See the package README in
[`plugins/typescript/`](../plugins/typescript/) for the full API.

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

The full `serve` flag table (persistence, audit rotation, buffered async
logger, session-cost TTL, base-url/CORS) lives in
[`CLI.md`](CLI.md#agentguard-serve); `agentguard serve -h` prints the same
list.

### Wire-level enforcement points

Two additional binaries enforce at the wire. Both need `--guard-url` pointing at `agentguard serve`, and both read `AGENTGUARD_API_KEY` for authenticated server calls.

- **`agentguard-mcp-gateway`** — sits between an MCP client and one or more MCP servers. Quickstart with copy-paste configs: [`QUICKSTART_MCP.md`](QUICKSTART_MCP.md). Reference: [`MCP_GATEWAY.md`](MCP_GATEWAY.md).
- **`agentguard-llm-proxy`** — sits between OpenAI / Anthropic SDK code and the providers. Quickstart: [`QUICKSTART_LLM_PROXY.md`](QUICKSTART_LLM_PROXY.md). Reference: [`LLM_API_PROXY.md`](LLM_API_PROXY.md).

---

## Using Docker

```bash
docker build -t agentguard:latest .

# Default policy is baked in; mount a named volume so the audit log
# survives container restarts.
docker run -d -p 8080:8080 --name agentguard \
  -v agentguard-audit:/var/lib/agentguard \
  agentguard:latest
```

Custom-policy mounts, the non-root uid-10001 volume-permission gotcha,
Compose, and Kubernetes manifests are in
[`DEPLOYMENT.md`](DEPLOYMENT.md).

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

### Everything else in the policy file

Per-agent overrides (`agents:`), notifications (Slack / webhook /
console), per-scope rate limits, cost guardrails, conditional rules, and
the `tool_scope_map` are all part of the policy YAML — the schema with
examples for each lives in
[`POLICY_REFERENCE.md`](POLICY_REFERENCE.md); server-side tunables
(session TTL, body caps, audit query limits) in [`CONFIG.md`](CONFIG.md).

---

## Running Tests

The fastest path is `make test-all`, which runs all four suites (Go, policy YAML validation, Python SDK, TypeScript SDK) in sequence and prints a PASS / FAIL / SKIP summary. Missing toolchains (no `python`, no `npm`) report SKIP cleanly so Go-only contributors aren't penalised. See [`CONTRIBUTING.md`](CONTRIBUTING.md#running-the-full-test-suite).

```bash
make test-all                   # everything
# or, narrow:
./scripts/test-all.sh --skip-ts
./scripts/test-all.sh --no-race      # drop the Go race detector for speed
```

Per-suite manual invocations:

```bash
# Go tests with race detection + coverage
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Policy YAML validation (every example)
make validate

# Python SDK tests (adapter unit tests need framework extras)
cd plugins/python
pip install -e ".[dev,langchain,crewai,mcp]"
pytest -v --cov=agentguard

# TypeScript SDK tests
cd plugins/typescript && npm install && npm run build && npm test
```

---

## Project Structure

```
agentguard/
├── cmd/
│   ├── agentguard/                  # Central server CLI (serve / validate / check / migrate / …)
│   │   ├── main.go
│   │   ├── check_cmd.go
│   │   └── update_check.go
│   ├── agentguard-mcp-gateway/      # v0.5 MCP Gateway binary
│   │   └── main.go
│   └── agentguard-llm-proxy/        # v0.5 LLM API Proxy binary
│       └── main.go
├── pkg/
│   ├── policy/                      # Policy engine (YAML parsing, rule evaluation, providers)
│   ├── proxy/                       # Central HTTP server + dashboard + approval queue
│   ├── audit/                       # Audit logging (JSON lines + rotation + buffered async)
│   ├── notify/                      # Webhook / Slack / console notifications
│   ├── ratelimit/                   # Token-bucket rate limiter
│   ├── mcpgw/                       # MCP Gateway core (upstream multiplexing, namespacing)
│   ├── llmproxy/                    # LLM API Proxy core (OpenAI / Anthropic stream gating)
│   └── migrate/                     # On-disk schema migrations (audit / checkpoint format)
├── plugins/
│   ├── python/                      # Python SDK + framework adapters
│   │   ├── agentguard/
│   │   │   ├── __init__.py          # Guard, @guarded, exception hierarchy
│   │   │   └── adapters/
│   │   │       ├── langchain.py     # GuardedTool, GuardedToolkit (subclasses BaseTool)
│   │   │       ├── crewai.py        # GuardedCrewTool (subclasses crewai BaseTool)
│   │   │       ├── browseruse.py    # GuardedBrowser / Page / Frame
│   │   │       └── mcp.py           # GuardedMCPServer + Python MCP gateway
│   │   ├── pyproject.toml
│   │   └── README.md
│   └── typescript/                  # TypeScript SDK
│       ├── src/index.ts
│       └── package.json
├── configs/                         # Policy files
│   ├── default.yaml
│   └── examples/
├── examples/                        # MCP-client + SDK config snippets ready to copy
├── docs/                            # Documentation
├── Dockerfile                       # Image shipping the `agentguard` server binary
├── Makefile                         # build / test / test-all / docker / …
└── README.md
```
