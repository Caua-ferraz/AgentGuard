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
  <a href="docs/CONTRIBUTING.md">Contributing</a>
</p>

---
## ⚠️ Attention

Some features of this project are not yet fully implemented and are currently under active development.


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
| "It worked on my machine" debugging | Replay any agent session action-by-action |
| One policy for all agents | Per-agent, per-environment, per-tool permission scoping |

## Quickstart

### Install

```bash
# From source
git clone https://github.com/Caua-ferraz/agentguard.git
cd agentguard
go build -o agentguard ./cmd/agentguard

# Or via Go
go install github.com/Caua-ferraz/agentguard/cmd/agentguard@latest

# Or Docker
docker run -d -p 8080:8080 -v ./policies:/etc/agentguard agentguard/agentguard
```

### Define a Policy

Create `policies/default.yaml`:

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

notifications:
  approval_required:
    - type: webhook
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    - type: console
  on_deny:
    - type: log
      level: warn
```

### Start the Proxy

```bash
# Start AgentGuard with the default policy
agentguard serve --policy policies/default.yaml --port 8080

# With the dashboard enabled
agentguard serve --policy policies/default.yaml --port 8080 --dashboard

# Watch mode (live policy reloading)
agentguard serve --policy policies/default.yaml --watch
```

### Connect Your Agent

```python
# Python — wrap any agent framework
from agentguard import Guard

guard = Guard("http://localhost:8080")

# Before executing any action, check it
result = guard.check("shell", command="rm -rf ./old_data")
# result.decision = "REQUIRE_APPROVAL"
# result.reason = "Matches pattern: rm -rf *"
# result.approval_url = "http://localhost:8080/approve/abc123"

if result.allowed:
    execute(command)
```

```typescript
// TypeScript / Node.js
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard('http://localhost:8080');

const result = await guard.check('network', {
  method: 'POST',
  url: 'https://api.production.internal/deploy',
});
// result.decision = "DENIED"
// result.reason = "Production access requires elevated policy"
```

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────┐
│   AI Agent      │────▶│   AgentGuard Proxy    │────▶│  Target     │
│  (any framework)│◀────│                        │◀────│  (tools,    │
│                 │     │  ┌──────────────────┐  │     │   APIs,     │
│  • LangChain    │     │  │  Policy Engine   │  │     │   shell)    │
│  • CrewAI       │     │  ├──────────────────┤  │     └─────────────┘
│  • browser-use  │     │  │  Audit Logger    │  │
│  • AutoGPT      │     │  ├──────────────────┤  │     ┌─────────────┐
│  • Custom       │     │  │  Rate Limiter    │  │────▶│  Dashboard  │
│                 │     │  ├──────────────────┤  │     │  (web UI)   │
│                 │     │  │  Approval Queue  │  │     └─────────────┘
│                 │     │  └──────────────────┘  │
└─────────────────┘     └──────────────────────┘     ┌─────────────┐
                                │                     │  Audit Log  │
                                └────────────────────▶│  (JSON/DB)  │
                                                      └─────────────┘
```

### Core Components

**Policy Engine** — Evaluates every agent action against your YAML policy rules. Supports glob patterns, regex matching, and contextual rules (e.g., "allow writes only if the agent has read the file first").

**Audit Logger** — Records every action attempt with full context: what was requested, which rule matched, what decision was made, the agent's stated reasoning, and wall-clock timestamps. Outputs to JSON lines, SQLite, or PostgreSQL.

**Approval Queue** — When an action hits a `require_approval` rule, it's held in a queue. You get notified via webhook/Slack/email, and can approve or deny from the dashboard or CLI.

**Rate Limiter** — Token-bucket rate limiting per scope, per agent, or globally. Prevents runaway agents from burning through API quotas or flooding services.

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
| `cost` | Spend limits | Cap per-session API costs |
| `data` | Data exfiltration | Block sending PII to external APIs |

### Advanced Policies

```yaml
# Context-aware rules
rules:
  - scope: shell
    allow:
      - pattern: "git push *"
        conditions:
          - require_prior: "git diff"  # Must have reviewed changes
          - time_window: "5m"          # Within the last 5 minutes

# Per-agent overrides
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

### Policy Composition

```bash
# Layer multiple policies (last wins on conflict)
agentguard serve \
  --policy policies/base.yaml \
  --policy policies/team-overrides.yaml \
  --policy policies/agent-specific.yaml
```

## Dashboard

The web dashboard gives you real-time visibility into what your agents are doing.

**Features:**
- **Live feed** — Watch agent actions stream in real time
- **Session replay** — Step through any past session action by action
- **Approval queue** — Approve or deny pending actions with one click
- **Policy editor** — Edit and hot-reload policies from the browser
- **Analytics** — Action counts, denial rates, approval latency, cost tracking
- **Alerts** — Configure thresholds and notification channels

```bash
# Open the dashboard
agentguard serve --dashboard
# → http://localhost:8080/dashboard
```

## Adapters

AgentGuard works with any agent framework through adapters:

| Framework | Status | Install |
|---|---|---|
| LangChain | ✅ Ready | `pip install agentguard[langchain]` |
| CrewAI | ✅ Ready | `pip install agentguard[crewai]` |
| browser-use | ✅ Ready | `pip install agentguard[browser-use]` |
| AutoGPT | 🚧 In Progress | — |
| OpenAI Agents SDK | 🚧 In Progress | — |
| Anthropic MCP | ✅ Ready | `pip install agentguard[mcp]` |
| Custom / HTTP | ✅ Ready | Any HTTP client |

### LangChain Example

```python
from langchain.agents import create_react_agent
from agentguard.adapters.langchain import GuardedToolkit

# Wrap your tools with AgentGuard
toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="research-bot"
)

agent = create_react_agent(llm, toolkit.tools, prompt)
# All tool calls now flow through AgentGuard automatically
```

### MCP Integration

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard",
      "args": ["mcp-server", "--policy", "policies/default.yaml"]
    }
  }
}
```

## CLI Reference

```bash
agentguard serve      # Start the proxy server
agentguard validate   # Validate policy files
agentguard replay     # Replay a recorded session
agentguard audit      # Query the audit log
agentguard approve    # Approve a pending action from CLI
agentguard deny       # Deny a pending action from CLI
agentguard status     # Show connected agents and active sessions
```

## Roadmap

- [x] Core policy engine with YAML rules
- [x] Audit logging (JSON lines + SQLite)
- [x] Shell and filesystem scope
- [x] Network scope with domain whitelisting
- [x] Approval queue with webhook notifications
- [x] Web dashboard (live feed + session replay)
- [x] LangChain, CrewAI, browser-use adapters
- [ ] Cost tracking with LLM API price awareness
- [ ] Data exfiltration detection (PII scanning)
- [ ] Policy-as-code (test policies in CI/CD)
- [ ] Multi-agent session correlation
- [ ] Terraform/Pulumi provider for policy management
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
