<p align="center">
  <img src="docs/assets/banner.svg" alt="AgentGuard" width="720" />
</p>

<p align="center">
  <strong>The firewall for AI agents.</strong><br/>
  Every tool call, every API call — gated by policy, logged, and routed for human approval. No opt-out path.
</p>

<p align="center">
  <a href="https://github.com/Caua-ferraz/AgentGuard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Caua-ferraz/AgentGuard/ci.yml?branch=master&label=CI" alt="CI status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Caua-ferraz/AgentGuard" alt="License" /></a>
  <a href="https://github.com/Caua-ferraz/AgentGuard/releases"><img src="https://img.shields.io/github/v/release/Caua-ferraz/AgentGuard?include_prereleases&sort=semver" alt="Latest release" /></a>
  <a href="https://pkg.go.dev/github.com/Caua-ferraz/AgentGuard"><img src="https://pkg.go.dev/badge/github.com/Caua-ferraz/AgentGuard.svg" alt="Go reference" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/Caua-ferraz/AgentGuard"><img src="https://img.shields.io/ossf-scorecard/github.com/Caua-ferraz/AgentGuard?label=OpenSSF%20Scorecard" alt="OpenSSF Scorecard" /></a>
  <a href="https://pypi.org/project/agentguardproxy/"><img src="https://img.shields.io/pypi/v/agentguardproxy?label=PyPI%20%28agentguardproxy%29" alt="PyPI version" /></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why-agentguard">Why AgentGuard</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#limitations--threat-model">Limitations &amp; Threat Model</a> •
  <a href="#production">Production</a> •
  <a href="#documentation">Docs</a> •
  <a href="docs/CONTRIBUTING.md">Contributing</a>
</p>

## AgentGuard Cloud (preview)

AgentGuard Cloud is the hosted, multi-tenant version — same policy engine, same audit log, run for you. **Currently in design.** Join the waitlist at [https://agentguard.dev/cloud](https://agentguard.dev/cloud) (placeholder URL — sign-up form goes live alongside the v0.5 release). The self-hosted Apache-2.0 build in this repo will always remain fully featured.

## The Problem

Every trending AI project is giving agents more autonomy — running shell commands, browsing the web, calling APIs, moving money, even performing penetration tests. But **nobody is building the guardrails.**

Right now, most teams deploying AI agents are just... hoping they behave. **AgentGuard** fixes that.

## Why AgentGuard

AgentGuard is the wire-level checkpoint that sits between your agent and everything it touches:

- **Policy-gated tool calls.** Every shell command, file write, network call, browser action, or model spend evaluated against a YAML policy before it runs.
- **Human-in-the-loop approvals.** Risky actions pause, ping Slack/webhooks, surface on a live dashboard, and resume only after a human says yes.
- **Tamper-evident audit trail.** JSON-Lines log of every decision with agent ID, scope, command, timestamp, and reasoning — queryable by CLI, dashboard, or Prometheus metrics.
- **Per-agent, per-environment, per-tool scoping.** One policy file, finely overridable for each agent identity.

## Quickstart

AgentGuard ships in v0.5 with **three integration paths**, listed from "no code change" to "deepest control":

### 1. MCP Gateway

For Claude Desktop and any MCP-aware client (Cursor, Cline, Continue, Zed), point your config at `agentguard-mcp-gateway` and every `tools/call` from the model is policy-checked before reaching the real MCP server:

```bash
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-mcp-gateway@latest
```

Then add to `claude_desktop_config.json` (macOS path: `~/Library/Application Support/Claude/claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard-mcp-gateway",
      "args": [
        "--upstream", "fs:npx -y @modelcontextprotocol/server-filesystem /tmp",
        "--guard-url", "http://127.0.0.1:8080",
        "--api-key", "$AGENTGUARD_API_KEY",
        "--policy", "/etc/agentguard/policy.yaml",
        "--policy-mode", "strict",
        "--fail-mode", "deny"
      ],
      "env": { "AGENTGUARD_API_KEY": "<your-key-or-source-from-shell>" }
    }
  }
}
```

90-second walkthrough: [`docs/QUICKSTART_MCP.md`](docs/QUICKSTART_MCP.md). Wire-format design + client-integration gotchas: [`docs/MCP_GATEWAY.md`](docs/MCP_GATEWAY.md). Ready configs for Cursor, Cline, Continue, Zed: [`examples/`](examples/).

### 2. LLM API Proxy

For any code that already uses the OpenAI / Anthropic SDKs, set one environment variable and your existing client flows through AgentGuard:

```bash
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest

agentguard-llm-proxy \
    --listen 127.0.0.1:8081 \
    --policy configs/default.yaml \
    --guard-url http://127.0.0.1:8080 \
    --api-key "$AGENTGUARD_API_KEY" &

export OPENAI_BASE_URL=http://127.0.0.1:8081/v1
# Anthropic SDK: ANTHROPIC_BASE_URL=http://127.0.0.1:8081 (no /v1 suffix)
```

Tool calls inside the response stream are intercepted, gated against your policy, and either flushed to your code byte-identically (ALLOW), rewritten as a synthetic refusal (DENY), or surfaced for human approval (REQUIRE_APPROVAL). The OpenAI / Anthropic SDKs do not need to know the proxy exists.

90-second walkthrough: [`docs/QUICKSTART_LLM_PROXY.md`](docs/QUICKSTART_LLM_PROXY.md). Wire-format design + client-integration gotchas: [`docs/LLM_API_PROXY.md`](docs/LLM_API_PROXY.md). Ready scripts for the OpenAI SDK, Anthropic SDK, LangChain, and CrewAI: [`examples/`](examples/).

### 3. SDK (compatibility tier)

The Python and TypeScript SDKs remain fully supported for direct callers and for code paths where the proxy isn't practical (offline tools, embedded scripts, custom transports). They opt in via an explicit `Guard.check(...)` call:

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

The SDKs are not deprecated. They are the right answer when you control the agent's source and want explicit, scope-tagged check points. Polling for approval, decorators/HOFs, cost guardrails, framework adapters (LangChain, CrewAI, browser-use, MCP): [`docs/SDK_PYTHON.md`](docs/SDK_PYTHON.md) • [`docs/ADAPTERS.md`](docs/ADAPTERS.md).

### Install the server

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

Prerequisites: Go 1.22+, Python 3.9+ (optional, for the SDK; v0.5 dropped 3.8 — upstream EOL October 2024). See [`docs/SETUP.md`](docs/SETUP.md) for details.

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

Rule precedence: `deny → require_approval → allow → default deny`. The seven policy scopes are `shell`, `filesystem`, `network`, `browser`, `cost`, `data`, and `mcp_tool` (plus the `unmapped` sentinel emitted by the LLM API Proxy when a tool call has no `tool_scope_map` entry). See [`docs/POLICY_REFERENCE.md`](docs/POLICY_REFERENCE.md).

## Limitations & Threat Model

AgentGuard is a policy enforcement and audit layer. It is **not** an OS sandbox. Read this before you trust it as your last line of defense.

- **v0.5 makes the firewall wire-level.** Both proxy heroes are on `master`: the **MCP Gateway** (Phase 4B) is the primary integration path for MCP-aware clients (Claude Desktop, Cursor, Cline, Continue, Zed), and the **LLM API Proxy** (Phase 4C) extends the same boundary to OpenAI / Anthropic SDK calls (`OPENAI_BASE_URL=http://127.0.0.1:8081/v1` and the Anthropic equivalent). The agent reaches its tools only through AgentGuard, so there is no opt-out short of pointing the client at a different MCP server or ignoring the SDK's base-URL configuration. Operators who control the agent's environment (env vars, network egress, MCP client config) get an enforcement boundary, not just an advisory one.
- **The SDK is a compatibility tier.** It remains supported and tested for direct callers — but it is opt-in by design: the agent must call `guard.check(...)`. That makes it an *advisory* gate. Use it when the proxy is impractical (offline scripts, custom transports), and pair it with the proxy whenever both are available.
- **AgentGuard does not sandbox the host or intercept syscalls.** A determined agent that controls its own runtime can bypass the proxy by ignoring `OPENAI_BASE_URL`, talking to a different MCP server, or shelling out directly. Combine AgentGuard with OS-level isolation (containers, seccomp, AppArmor, network egress rules) when the threat model includes a hostile agent.
- **Pattern matching is string-glob, not semantic.** A deny rule for `rm -rf *` matches literal strings; an agent (or a creative human) can substitute equivalents (`find / -delete`, base64 payloads, etc.). Treat policies as a high-signal first filter, not a complete authorization model.
- **Approval queue and rate-limiter state are in-memory.** Both reset on restart and are not shared across instances. Run `replicas: 1` until persistent state lands.

## Dashboard

<p align="center">
  <img src="docs/assets/dashboard.svg" alt="AgentGuard Dashboard — live action feed with allow/deny/pending entries and one-click approval sidebar" width="900" />
</p>

Live SSE action feed, one-click approve/deny, running totals, agent context. Start with `--dashboard` and open `http://localhost:8080/dashboard`. Walkthrough: [`docs/DASHBOARD.md`](docs/DASHBOARD.md).

## Production

> **Running AgentGuard in production?** The four most common misconfigurations — no API key (→ localhost-only bind), missing `--tls-terminated-upstream` behind an HTTPS proxy, wrong `--base-url`, and unmounted audit volume — all have one-line fixes. Work through the checklist below before exposing AgentGuard beyond localhost.

- [ ] **Set `--api-key`** (or `AGENTGUARD_API_KEY`). Without it, AgentGuard binds to `127.0.0.1` only.
- [ ] **Set `--base-url`** to the public URL. Otherwise Slack/webhook approval links point at `http://localhost:8080`.
- [ ] **Pass `--tls-terminated-upstream`** if TLS is terminated upstream, or the dashboard login loops.
- [ ] **Set `--allowed-origin`** to your frontend's exact origin.
- [ ] **Mount a writable volume** for the audit log — no mount, log lost on restart.
- [ ] **Stay on `replicas: 1`** — rate-limit buckets and session-cost accumulators are per-instance.

Full reference configs (nginx + Docker Compose + Kubernetes), auth/CORS/TLS details, and day-2 operations: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) • [`docs/OPERATIONS.md`](docs/OPERATIONS.md) • [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

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
| Migration guide | [`docs/MIGRATION.md`](docs/MIGRATION.md) |
| Deprecations | [`docs/DEPRECATIONS.md`](docs/DEPRECATIONS.md) |
| Contributing | [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) |

## Roadmap

### Implemented
- [x] Core policy engine with YAML rules (deny → require_approval → allow → default deny)
- [x] Audit logging (JSON lines) with size-triggered rotation, retention, and gzip compression — wired by default *(v0.5)*
- [x] Shell, filesystem, network, browser, cost, `data`, and `mcp_tool` scopes (string-glob matching — see [Limitations](#limitations--threat-model))
- [x] Approval queue with Slack/webhook/console notifications (in-memory, not persisted)
- [x] Web dashboard (live SSE feed, stats, interactive approve/deny)
- [x] Token-bucket rate limiting per scope per agent (in-memory)
- [x] Per-agent policy overrides via `agents:` config
- [x] Cost guardrails — per-action limits, alert thresholds, and session-level cost tracking
- [x] Conditional rules — `require_prior` and `time_window` conditions evaluated at check time
- [x] Python SDK + adapters: LangChain, CrewAI, browser-use, MCP
- [x] TypeScript/Node.js SDK
- [x] Full CLI: serve, validate, check, approve, deny, status, audit, migrate, version
- [x] Docker support with multi-stage build
- [x] Policy hot-reload via `--watch`
- [x] **Data scope** — first-class `data` scope for exfiltration / sensitive-payload checks, wired through policy engine and SDKs *(v0.5)*
- [x] **MCP Gateway** — wire-level Model Context Protocol proxy with multi-upstream namespacing, capability merging, reconnect-with-backoff, and approval `_meta` round-trip; ships as the `agentguard-mcp-gateway` binary with copy-paste configs for Claude Desktop, Cursor, Cline, Continue, and Zed *(v0.5)*
- [x] **LLM API Proxy** — drop-in OpenAI / Anthropic-compatible base URL with streaming pause/resume/rewrite, tool-call gating, provider-aware synthetic refusals, and tool→scope mapping; ships as the `agentguard-llm-proxy` binary with copy-paste examples for the OpenAI SDK, Anthropic SDK, LangChain, and CrewAI *(v0.5)*

### Planned
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
