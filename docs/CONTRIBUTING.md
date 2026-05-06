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

## Releasing a New Version

All version strings are kept in sync across 6 files. Use the bump script before tagging — never edit them by hand.

```bash
./scripts/bump-version.sh 0.4.1
```

This updates:

| File | Field |
|------|-------|
| `cmd/agentguard/main.go` | `version = "..."` |
| `plugins/python/pyproject.toml` | `version = "..."` |
| `plugins/python/agentguard/adapters/mcp.py` | `SDK_VERSION = "..."` |
| `plugins/typescript/package.json` | `"version": "..."` |
| `Makefile` | `VERSION=...` |
| `docs/SETUP.md` | health endpoint example |

Then commit, tag, and push — the PyPI publish workflow triggers automatically on a GitHub release:

```bash
git add -p
git commit -m "Bump version to 0.4.1"
git tag v0.4.1
git push && git push --tags
```
### How to define your version

Version format: `MAJOR.MINOR.PATCH` → `0.0.0`

- **MAJOR** → breaking changes (things stop working with older versions)
- **MINOR** → new features (backward-compatible)
- **PATCH** → bug fixes or small improvements

> If the version starts with `0` (e.g. `0.4.1`), the project is still in development and may change at any time.

> **PyPI note:** Never re-use a version number. PyPI permanently rejects duplicate uploads even after deletion. Always bump before publishing.

## Testing Metrics

The `/metrics` endpoint exposes Prometheus-compatible counters and histograms. When working on the hot path (`handleCheck`, policy engine, audit logger), verify your changes don't regress latency:

```bash
# 1. Start the server
agentguard serve --policy configs/default.yaml --port 8080

# 2. Send a few test checks
curl -s -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope":"shell","command":"ls -la","agent_id":"test"}'

# 3. Inspect per-phase timing headers on a single request
curl -si -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{"scope":"shell","command":"ls -la","agent_id":"test"}' \
  | grep -i x-agentguard
# X-AgentGuard-Policy-Ms: 0.143
# X-AgentGuard-Audit-Ms:  0.891
# X-AgentGuard-Total-Ms:  1.034

# 4. Scrape all metrics (counters + histograms)
curl -s http://localhost:8080/metrics
```

Key metrics to watch when contributing:

| Metric | What it measures |
|--------|-----------------|
| `agentguard_policy_eval_duration_ms` | Time in `Engine.Check` — policy rule matching |
| `agentguard_audit_write_duration_ms` | Time in `Logger.Log` — disk I/O |
| `agentguard_request_duration_ms` | End-to-end `/v1/check` latency |
| `agentguard_denied_total` | Cumulative deny count (sanity check for policy tests) |
| `agentguard_pending_approvals` | Current approval queue depth |

Histogram buckets go from 0.25 ms to 1000 ms. A healthy server at low load should show p99 `request_duration_ms` below 5 ms.

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
