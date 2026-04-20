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
  <a href="#production">Production</a> •
  <a href="#documentation">Docs</a> •
  <a href="docs/CONTRIBUTING.md">Contributing</a>
</p>

## The Problem

Every trending AI project is giving agents more autonomy — running shell commands, browsing the web, calling APIs, moving money, even performing penetration tests. But **nobody is building the guardrails.**

Right now, most teams deploying AI agents are just... hoping they behave. **AgentGuard** fixes that.

## Why AgentGuard

| Without AgentGuard | With AgentGuard |
|---|---|
| Agent runs `rm -rf /` — you find out later | Policy blocks destructive commands before execution |
| Agent calls production API with no oversight | Action paused, you get a Slack/webhook notification to approve |
| No record of what the agent did or why | Full audit trail with timestamps, reasoning, and decisions |
| "It worked on my machine" debugging | Query any agent session from the audit log |
| One policy for all agents | Per-agent, per-environment, per-tool permission scoping |

## Quickstart

### Install

```bash
# From source
git clone https://github.com/Caua-ferraz/AgentGuard.git
cd AgentGuard && go build -o agentguard ./cmd/agentguard

# Or via Go install
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest

# Or Docker
docker run -d -p 8080:8080 \
  -v agentguard-audit:/var/lib/agentguard \
  agentguard:latest
```

Prerequisites: Go 1.22+, Python 3.8+ (optional, for the SDK). See [`docs/SETUP.md`](docs/SETUP.md) for details.

### Minimal policy

`configs/default.yaml` — a ready-to-use default ships in the repo. A minimal example:

```yaml
version: "1"
name: "development-sandbox"
rules:
  - scope: shell
    require_approval:
      - pattern: "sudo *"
      - pattern: "rm -rf *"
    allow:
      - pattern: "ls *"
      - pattern: "cat *"
  - scope: network
    allow:
      - domain: "api.openai.com"
      - domain: "api.anthropic.com"
```

Full schema (filesystem, cost, per-agent overrides, rate limits, conditional rules, notifications): [`docs/POLICY_REFERENCE.md`](docs/POLICY_REFERENCE.md).

### Start the server

```bash
agentguard serve --policy configs/default.yaml --dashboard --watch
```

CLI flags and subcommands: [`docs/CLI.md`](docs/CLI.md).

### Connect your agent

```bash
pip install agentguardproxy
```

```python
from agentguard import Guard

guard = Guard("http://localhost:8080", agent_id="my-bot")

result = guard.check("shell", command="rm -rf ./old_data")
# result.decision = "REQUIRE_APPROVAL"
# result.approval_url = "http://localhost:8080/v1/approve/ap_..."

if result.allowed:
    execute(command)
```

TypeScript/Node.js:

```typescript
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard({ baseUrl: 'http://localhost:8080', agentId: 'my-bot' });
const result = await guard.check('network', { url: 'https://api.production.internal/deploy' });
```

Polling for approval, decorators/HOFs, cost guardrails, framework adapters (LangChain, CrewAI, browser-use, MCP): [`docs/SDK_PYTHON.md`](docs/SDK_PYTHON.md) • [`docs/ADAPTERS.md`](docs/ADAPTERS.md).

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

Rule precedence: `deny → require_approval → allow → default deny`. Scopes: `filesystem`, `shell`, `network`, `browser`, `cost`. See [`docs/POLICY_REFERENCE.md`](docs/POLICY_REFERENCE.md).

## Dashboard

<p align="center">
  <img src="docs/assets/dashboard.svg" alt="AgentGuard Dashboard — live action feed with allow/deny/pending entries and one-click approval sidebar" width="900" />
</p>

Live SSE action feed, one-click approve/deny, running totals, agent context. Start with `--dashboard` and open `http://localhost:8080/dashboard`. Walkthrough: [`docs/DASHBOARD.md`](docs/DASHBOARD.md).

## Production

> **Running AgentGuard in production?** The four most common misconfigurations — no API key (→ localhost-only bind), missing `--tls-terminated-upstream` behind an HTTPS proxy, wrong `--base-url`, and unrotated audit log — all have one-line fixes. Work through the checklist below before exposing AgentGuard beyond localhost.

- [ ] **Set `--api-key`** (or `AGENTGUARD_API_KEY`). Without it, AgentGuard binds to `127.0.0.1` only.
- [ ] **Set `--base-url`** to the public URL. Otherwise Slack/webhook approval links point at `http://localhost:8080`.
- [ ] **Pass `--tls-terminated-upstream`** if TLS is terminated upstream, or the dashboard login loops.
- [ ] **Set `--allowed-origin`** to your frontend's exact origin.
- [ ] **Mount a writable volume** for the audit log — no mount, log lost on restart.
- [ ] **Plan audit log rotation** externally (AgentGuard does not rotate `audit.jsonl`).
- [ ] **Stay on `replicas: 1`** — rate-limit buckets and session-cost accumulators are per-instance.

Full reference configs (nginx + Docker Compose + Kubernetes), auth/CORS/TLS details, and day-2 operations: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) • [`docs/OPERATIONS.md`](docs/OPERATIONS.md) • [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## Limitations & Threat Model

AgentGuard is a policy enforcement layer, not a sandbox.

- **Shell scope uses string-glob matching, not semantic analysis.** A deny rule for `rm -rf *` matches literal strings; determined agents can bypass with equivalents (`find / -delete`, base64 payloads, etc.). Combine with OS-level sandboxing (containers, seccomp, AppArmor) for strong isolation.
- **AgentGuard is opt-in, not a transparent proxy.** The agent must call `/v1/check` before acting. It is an advisory gate, not an enforcement boundary.
- **Audit log is append-only JSON lines.** No built-in rotation, retention, or tamper detection.
- **Approval queue and rate-limiter state are in-memory.** Both reset on restart and are not shared across instances.

## Documentation

| Topic | Doc |
|---|---|
| Getting started | [`docs/SETUP.md`](docs/SETUP.md) |
| Policy YAML schema + gotchas | [`docs/POLICY_REFERENCE.md`](docs/POLICY_REFERENCE.md) |
| HTTP API | [`docs/API.md`](docs/API.md) |
| CLI reference | [`docs/CLI.md`](docs/CLI.md) |
| Python SDK | [`docs/SDK_PYTHON.md`](docs/SDK_PYTHON.md) |
| Framework adapters (LangChain, CrewAI, browser-use, MCP) | [`docs/ADAPTERS.md`](docs/ADAPTERS.md) |
| Dashboard walkthrough | [`docs/DASHBOARD.md`](docs/DASHBOARD.md) |
| Approval workflow end-to-end | [`docs/APPROVAL_WORKFLOW.md`](docs/APPROVAL_WORKFLOW.md) |
| Deployment / TLS / CORS | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) |
| Day-2 operations | [`docs/OPERATIONS.md`](docs/OPERATIONS.md) |
| Metrics + alerting | [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) |
| Tunable knobs | [`docs/TUNING.md`](docs/TUNING.md) |
| Troubleshooting | [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) |
| FAQ | [`docs/FAQ.md`](docs/FAQ.md) |
| Config schema | [`docs/CONFIG.md`](docs/CONFIG.md) |
| File formats + migrations | [`docs/FILE_FORMATS.md`](docs/FILE_FORMATS.md) |
| Deprecations | [`docs/DEPRECATIONS.md`](docs/DEPRECATIONS.md) |
| Contributing | [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) |

## Roadmap

### Implemented
- [x] Core policy engine with YAML rules (deny → require_approval → allow → default deny)
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

See [CONTRIBUTING.md](docs/CONTRIBUTING.md). Priority areas: adapters for more agent frameworks, new scope types and matching strategies, dashboard UI, documentation.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Stop hoping your agents behave. Start knowing.</strong>
</p>
