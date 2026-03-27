# Contributing to AgentGuard

Thanks for your interest in making AI agents safer. Here's how to get involved.

## Development Setup

```bash
git clone https://github.com/Caua-ferraz/AgentGuard.git
cd AgentGuard
go build ./...
go test -race ./...
```

For the full local setup guide, see [SETUP.md](SETUP.md).

## Project Structure

```
cmd/agentguard/     CLI entry point
pkg/policy/         Policy engine (YAML parsing, rule evaluation, per-agent overrides)
pkg/proxy/          HTTP proxy server + embedded dashboard
pkg/audit/          Audit logging (JSON lines)
pkg/notify/         Webhook/Slack/console notifications
pkg/ratelimit/      Token-bucket rate limiter
plugins/python/     Python SDK + framework adapters (LangChain, CrewAI, browser-use, MCP)
plugins/typescript/ TypeScript SDK
configs/            Policy files and examples
docs/               Documentation
```

## Priority Areas

1. **Adapters** — Adding support for more agent frameworks (AutoGPT, OpenAI Agents SDK, etc.)
2. **Policy rules** — New scope types, matching strategies, and contextual conditions
3. **Dashboard** — Session replay, policy editor, richer analytics
4. **Audit backends** — SQLite/PostgreSQL storage for audit logs
5. **Documentation** — Tutorials, integration guides, example policies

## Pull Request Process

- Fork the repo, create a feature branch
- Write tests for new functionality
- Run `go test -race ./...` before submitting
- Keep PRs focused — one feature or fix per PR
- Update documentation if behavior changes

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep packages small and focused
- Prefer explicit error handling over panics
- Write table-driven tests where possible

## Policy Contributions

We welcome community-contributed policy templates in `configs/examples/`. Include a clear description of the use case and what the policy protects against.

## Reporting Security Issues

If you find a security vulnerability in AgentGuard, please email security@agentguard.dev instead of opening a public issue. We take security seriously — it's literally our whole thing.
