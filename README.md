<p align="center">
  <img src="docs/assets/banner.svg" alt="AgentGuard" width="720" />
</p>

<p align="center">
  <strong>The firewall for AI agents.</strong><br/>
  Policy enforcement, real-time oversight, and full audit logging for autonomous AI systems.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why-agentguard">Why AgentGuard</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#policy-engine">Policy Engine</a> •
  <a href="#dashboard">Dashboard</a> •
  <a href="#adapters">Adapters</a> •
  <a href="docs/SETUP.md">Setup Guide</a> •
  <a href="docs/CONTRIBUTING.md">Contributing</a>
</p>


## The Problem

Every trending AI project is giving agents more autonomy — running shell commands, browsing the web, calling APIs, moving money, even performing penetration tests. But **nobody is building the guardrails.**

Right now, most teams deploying AI agents are just... hoping they behave.

**AgentGuard** fixes that.

## Why AgentGuard

| Without AgentGuard | With AgentGuard |
|---|---|
| Agent runs `rm -rf /` — you find out later | Policy blocks destructive commands before execution |
| Agent calls production API with no oversight | Action paused, you get a Slack/webhook notification to approve |
| No record of what the agent did or why | Full audit trail with timestamps, reasoning, and decisions |
| "It worked on my machine" debugging | Query any agent session from the audit log |
| One policy for all agents | Per-agent, per-environment, per-tool permission scoping |

## Quickstart

### Prerequisites

- **Go 1.22+** — `go version`
- **Git** — `git --version`
- **Python 3.8+** (optional, for SDK) — `python --version`

### Install

```bash
# From source
git clone https://github.com/Caua-ferraz/AgentGuard.git
cd AgentGuard
go build -o agentguard ./cmd/agentguard

# Or via Go install
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest

# Or Docker
docker run -d -p 8080:8080 -v ./configs:/etc/agentguard agentguard:latest
```

### Define a Policy

Create `configs/default.yaml` (a ready-to-use default is included in the repo):

```yaml
# AgentGuard Policy File
version: "1"
name: "development-sandbox"
description: "Safe defaults for development agents"

rules:
  # File system access
  - scope: filesystem
    allow:
      - action: read
        paths: ["./workspace/**", "/tmp/**"]
      - action: write
        paths: ["./workspace/**"]
    deny:
      - action: delete
        paths: ["**"]
        message: "File deletion is not permitted"
      - action: write
        paths: ["/etc/**", "/usr/**", "~/.ssh/**"]

  # Shell commands
  - scope: shell
    require_approval:
      - pattern: "sudo *"
      - pattern: "curl * | bash"
      - pattern: "rm -rf *"
    deny:
      - pattern: ":(){ :|:& };:"
        message: "Fork bomb detected"
    allow:
      - pattern: "ls *"
      - pattern: "cat *"
      - pattern: "grep *"
      - pattern: "python *"

  # API / Network calls
  - scope: network
    allow:
      - domain: "api.openai.com"
      - domain: "api.anthropic.com"
      - domain: "*.slack.com"
    deny:
      - domain: "*.production.internal"
        message: "Production access requires elevated policy"
    rate_limit:
      max_requests: 100
      window: "1m"

  # Cost guardrails
  - scope: cost
    limits:
      max_per_action: "$0.50"
      max_per_session: "$10.00"
      alert_threshold: "$5.00"

# Per-agent overrides
agents:
  research-bot:
    extends: "default"
    override:
      - scope: network
        allow:
          - domain: "scholar.google.com"
          - domain: "arxiv.org"

notifications:
  approval_required:
    - type: slack
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    - type: console
  on_deny:
    - type: log
      level: warn
```

### Start the Server

```bash
# Start AgentGuard with the default policy
agentguard serve --policy configs/default.yaml --port 8080

# With the dashboard enabled
agentguard serve --policy configs/default.yaml --port 8080 --dashboard

# Watch mode (live policy reloading)
agentguard serve --policy configs/default.yaml --watch --dashboard
```

### Authentication

When deploying AgentGuard beyond localhost, set an API key to protect the privileged endpoints. You can pass it as a flag or via the `AGENTGUARD_API_KEY` environment variable (server and CLI both read it):

```bash
agentguard serve --policy configs/default.yaml --api-key YOUR_SECRET --dashboard
# or
AGENTGUARD_API_KEY=YOUR_SECRET agentguard serve --policy configs/default.yaml --dashboard
```

Without `--api-key`, the server binds to `127.0.0.1` only. With an API key set, it binds to all interfaces (`0.0.0.0`) and gates the privileged surface.

**What's gated when an API key is set:**

| Endpoint | Access |
|---|---|
| `POST /v1/check` | Open (the policy answer itself is not sensitive) |
| `POST /v1/approve/{id}`, `POST /v1/deny/{id}` | Bearer token **or** session cookie + `X-CSRF-Token` header |
| `GET /v1/status/{id}`, `GET /v1/audit` | Bearer token **or** session cookie |
| `GET /dashboard`, `GET /api/*` | Session cookie (served a login page otherwise) |
| `GET /health`, `GET /metrics` | Open |

**Dashboard login flow.** Opening `/dashboard` without a session serves a login form. POST your API key to `/auth/login` — the server sets an HTTP-only `ag_session` cookie and a JS-readable `ag_csrf` cookie (same token, double-submit pattern). The dashboard JS attaches `X-CSRF-Token` on approve/deny. The API key is **never** embedded in the HTML. `POST /auth/logout` destroys the session.

**SDKs.** The Python and TypeScript SDKs attach the Bearer token automatically on approve/deny/status/audit when configured:

```python
# Python — explicit or AGENTGUARD_API_KEY env var
guard = Guard("http://your-server:8080", api_key="YOUR_SECRET")
```

```typescript
// TypeScript
const guard = new AgentGuard({ baseUrl: 'http://your-server:8080', apiKey: 'YOUR_SECRET' });
```

**CLI subcommands** (`approve`, `deny`, `status`, `audit`) accept `--api-key` or read `AGENTGUARD_API_KEY` from the environment.

**CORS.** When you want a browser-based app on a different origin to call AgentGuard, set `--allowed-origin https://your-app.example` (exact match only — no localhost-wildcard default).

### Connect Your Agent

```bash
# Install the Python SDK
pip install agentguardproxy
```

```python
# Python — wrap any agent framework
from agentguard import Guard

guard = Guard("http://localhost:8080", agent_id="my-bot")

# Before executing any action, check it
result = guard.check("shell", command="rm -rf ./old_data")
# result.decision = "REQUIRE_APPROVAL"
# result.reason = "Matches pattern: rm -rf *"
# result.approval_url = "http://localhost:8080/v1/approve/ap_..."

if result.allowed:
    execute(command)

# Cost-scope guardrails: attach session_id + est_cost so the engine can
# enforce max_per_session. Each ALLOWed call atomically reserves the cost.
r = guard.check(
    "cost",
    command="llm-call",
    session_id="user-123",
    est_cost=0.42,
)
```

```typescript
// TypeScript / Node.js
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard({ baseUrl: 'http://localhost:8080', agentId: 'my-bot' });

const result = await guard.check('network', {
  url: 'https://api.production.internal/deploy',
});
// result.decision = "DENY"
// result.reason = "Production access requires elevated policy"

// Cost-scope guardrails:
await guard.check('cost', {
  command: 'llm-call',
  sessionId: 'user-123',
  estCost: 0.42,
});
```

## Architecture

```
┌─────────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│   AI Agent      │────▶│   AgentGuard Proxy        │────▶│  Target     │
│  (any framework)│◀────│                            │◀────│  (tools,    │
│                 │     │  ┌──────────────────────┐  │     │   APIs,     │
│  • LangChain    │     │  │  Policy Engine       │  │     │   shell)    │
│  • CrewAI       │     │  ├──────────────────────┤  │     └─────────────┘
│  • browser-use  │     │  │  Rate Limiter        │  │
│  • Claude (MCP) │     │  ├──────────────────────┤  │     ┌─────────────┐
│  • Custom       │     │  │  Approval Queue      │  │────▶│  Dashboard  │
│                 │     │  ├──────────────────────┤  │     │  (web UI)   │
│                 │     │  │  Notifier (Slack/WH) │  │     └─────────────┘
│                 │     │  ├──────────────────────┤  │
│                 │     │  │  Audit Logger         │  │     ┌─────────────┐
│                 │     │  └──────────────────────┘  │────▶│  Audit Log  │
└─────────────────┘     └──────────────────────────┘     │  (JSON)     │
                                                          └─────────────┘
```

### Core Components

**Policy Engine** — Evaluates every agent action against your YAML policy rules. Supports glob patterns (`*`, `**`, `?`), per-agent overrides, and cost evaluation. Rule precedence: deny → require_approval → allow → default deny.

**Rate Limiter** — Token-bucket rate limiting per scope, per agent. Prevents runaway agents from burning through API quotas.

**Audit Logger** — Records every action attempt with full context: what was requested, which rule matched, what decision was made, and wall-clock timestamps. Outputs to JSON lines.

**Approval Queue** — When an action hits a `require_approval` rule, it's held in a queue. You get notified via webhook/Slack/console, and can approve or deny from the dashboard or CLI.

**Notifier** — Sends alerts to Slack webhooks, generic webhooks, console, or the log when actions are denied or require approval.

## Policy Engine

Policies are declarative YAML files with a simple mental model:

```
For each action → check deny rules → check require_approval → check allow rules → default deny
```

### Rule Scopes

| Scope | Controls | Example |
|---|---|---|
| `filesystem` | File read/write/delete | Block writes to system dirs |
| `shell` | Command execution | Require approval for `sudo` |
| `network` | HTTP/API calls | Whitelist specific domains |
| `browser` | Web automation | Block navigation to banking sites |
| `cost` | Spend limits | Cap per-action API costs |

### Per-Agent Overrides

```yaml
agents:
  research-bot:
    extends: "default"
    override:
      - scope: network
        allow:
          - domain: "scholar.google.com"
          - domain: "arxiv.org"

  deploy-bot:
    extends: "default"
    override:
      - scope: shell
        require_approval:
          - pattern: "*"  # Everything needs approval
```

### Rate Limiting

```yaml
rules:
  - scope: network
    rate_limit:
      max_requests: 60
      window: "1m"
```

### Cost Guardrails

Send `est_cost` in the check request to trigger cost evaluation:

```yaml
rules:
  - scope: cost
    limits:
      max_per_action: "$0.50"      # Deny if exceeded
      max_per_session: "$10.00"
      alert_threshold: "$5.00"     # Require approval if exceeded
```

### Notifications

```yaml
notifications:
  approval_required:
    - type: slack
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    - type: webhook
      url: "https://your-server.com/agentguard-events"
    - type: console
  on_deny:
    - type: log
      level: warn
```

## Dashboard

The web dashboard gives you real-time visibility into what your agents are doing.

```bash
agentguard serve --dashboard
# → http://localhost:8080/dashboard
```

<p align="center">
  <img src="docs/assets/dashboard.svg" alt="AgentGuard Dashboard — live action feed with allow/deny/pending entries and one-click approval sidebar" width="900" />
</p>

**Features:**
- **Live action feed** — Every check streams in real time via SSE, color-coded by decision (green = ALLOW, red = DENY, yellow = REQUIRE_APPROVAL)
- **One-click approvals** — Pending actions appear in the sidebar with Approve / Deny buttons; no CLI needed
- **Stats bar** — Running totals of total checks, allowed, denied, and pending approval counts
- **Connection indicator** — LIVE badge turns red if the SSE stream drops
- **Agent context** — Each entry shows the agent ID, scope, action, matched rule reason, and timestamp

## Adapters

AgentGuard works with any agent framework through adapters:

| Framework | Status | Install |
|---|---|---|
| LangChain | Ready | `pip install agentguardproxy[langchain]` |
| CrewAI | Ready | `pip install agentguardproxy[crewai]` |
| browser-use | Ready | `pip install agentguardproxy[browser-use]` |
| Anthropic MCP | Ready | `pip install agentguardproxy[mcp]` |
| TypeScript/Node.js | Ready | `npm install @agentguard/sdk` |
| Custom / HTTP | Ready | Any HTTP client |
| AutoGPT | Planned | — |
| OpenAI Agents SDK | Planned | — |

### LangChain Example

```python
from langchain.agents import create_react_agent
from agentguard.adapters.langchain import GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="research-bot"
)

agent = create_react_agent(llm, toolkit.tools, prompt)
# All tool calls now flow through AgentGuard automatically
```

### CrewAI Example

```python
from agentguard.adapters.crewai import guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)
```

### MCP Integration

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

## CLI Reference

```bash
agentguard serve      # Start the proxy server
agentguard validate   # Validate policy files
agentguard approve    # Approve a pending action from CLI
agentguard deny       # Deny a pending action from CLI
agentguard status     # Show server health and pending approvals
agentguard audit      # Query the audit log
agentguard version    # Print version
```

## Limitations & Threat Model

AgentGuard is a policy enforcement layer, not a sandbox. Understanding what it does and does not protect against is important for safe deployment.

**Shell scope uses string-glob matching, not semantic analysis.** A deny rule for `rm -rf *` matches literal strings. An agent can trivially bypass it with equivalent commands (`find / -delete`, `perl -e 'unlink...'`, base64-encoded payloads, etc.). Shell rules reduce accidental damage from well-behaved agents; they do not stop a determined or adversarial agent. For strong shell isolation, combine AgentGuard with OS-level sandboxing (containers, seccomp, AppArmor).

**AgentGuard is opt-in, not a transparent proxy.** The agent (or its framework) must call `/v1/check` before acting. If the agent bypasses the SDK and acts directly, AgentGuard has no way to intercept it. It is an advisory gate, not an enforcement boundary.

**Audit log is append-only JSON lines.** There is no built-in log rotation, retention policy, or tamper detection. For production use, ship the log to an external system.

**Approval queue is in-memory.** Pending approvals are lost on server restart. There is no persistence layer for the approval queue.

**Rate limiter state is in-memory.** Rate limit buckets reset on restart and are not shared across instances.

## Roadmap

### Implemented
- [x] Core policy engine with YAML rules (deny -> require_approval -> allow -> default deny)
- [x] Audit logging (JSON lines)
- [x] Shell, filesystem, network, browser, cost scopes (string-glob matching — see [Limitations](#limitations--threat-model))
- [x] Approval queue with Slack/webhook/console notifications (in-memory, not persisted)
- [x] Web dashboard (live SSE feed, stats, interactive approve/deny)
- [x] Token-bucket rate limiting per scope per agent (in-memory)
- [x] Per-agent policy overrides via `agents:` config
- [x] Cost guardrails — per-action limits, alert thresholds, and session-level cost tracking
- [x] Conditional rules — `require_prior` and `time_window` conditions evaluated at check time
- [x] Python SDK + adapters: LangChain, CrewAI, browser-use, MCP
- [x] TypeScript/Node.js SDK
- [x] Full CLI: serve, validate, approve, deny, status, audit, version
- [x] Docker support with multi-stage build
- [x] Policy hot-reload via `--watch`

### Planned
- [ ] Data exfiltration detection / `data` scope (PII scanning)
- [ ] SQLite/PostgreSQL audit backend
- [ ] Persistent approval queue
- [ ] Policy-as-code (test policies in CI/CD)
- [ ] Multi-agent session correlation
- [ ] Session replay in dashboard
- [ ] Policy editor in dashboard
- [ ] AutoGPT adapter
- [ ] OpenAI Agents SDK adapter
- [ ] SOC 2 / compliance report generation
- [ ] VS Code extension for policy authoring

## Contributing

We'd love your help. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

Priority areas:
- **Adapters** — Add support for more agent frameworks
- **Policy rules** — New scope types and matching strategies
- **Dashboard** — UI improvements and new visualizations
- **Documentation** — Guides, examples, and tutorials

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Stop hoping your agents behave. Start knowing.</strong>
</p>
