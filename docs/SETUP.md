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
# {"status":"ok","version":"0.2.3"}
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
```

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

guard = Guard("http://localhost:8080", agent_id="my-agent")

result = guard.check("shell", command="ls -la")
print(result.decision)  # "ALLOW"
print(result.allowed)   # True

result = guard.check("shell", command="rm -rf /")
print(result.decision)  # "REQUIRE_APPROVAL"
print(result.approval_url)  # http://localhost:8080/v1/approve/ap_...
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
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard('http://localhost:8080');

const result = await guard.check('shell', { command: 'ls -la' });
if (result.allowed) {
  // proceed
}
```

---

## Using the CLI

```bash
# Start the server
agentguard serve --policy configs/default.yaml --dashboard --watch

# Validate policy files
agentguard validate --policy configs/default.yaml

# Approve a pending action
agentguard approve ap_abc123def456

# Deny a pending action
agentguard deny ap_abc123def456

# Check server status and pending approvals
agentguard status

# Query the audit log
agentguard audit --agent my-bot --decision DENY --limit 20

# Print version
agentguard version
```

---

## Using Docker

### Build

```bash
docker build -t agentguard:latest .
```

### Run

```bash
# With default policy
docker run -d -p 8080:8080 --name agentguard agentguard:latest

# With custom policy
docker run -d -p 8080:8080 \
  -v $(pwd)/configs:/etc/agentguard \
  agentguard:latest \
  serve --policy /etc/agentguard/default.yaml --dashboard
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
