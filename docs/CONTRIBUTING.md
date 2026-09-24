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
cmd/agentguard/              CLI and policy server (serve, check, validate, status, ...)
cmd/agentguard-mcp-gateway/  MCP Gateway binary
cmd/agentguard-llm-proxy/    LLM API Proxy binary
cmd/internal/buildinfo/      Version and commit reporting shared by the three binaries
pkg/policy/                  Policy engine (YAML parsing, rule evaluation, per-agent overrides)
pkg/proxy/                   HTTP policy server + embedded dashboard
pkg/mcpgw/                   MCP Gateway (stdio bridge, upstream processes, dual-check)
pkg/llmproxy/                LLM API Proxy (OpenAI / Anthropic parsers, streaming rewrite)
pkg/internal/gateclient/     Shared /v1/check client used by both proxies
pkg/audit/                   Audit logging (JSON lines, rotation, async buffering)
pkg/store/                   Durable store (SQLite, PostgreSQL)
pkg/persist/                 Write-behind sync between in-memory state and the store
pkg/migrate/                 On-disk schema migrations
pkg/notify/                  Webhook/Slack/console notifications
pkg/ratelimit/               Token-bucket rate limiter
pkg/metrics/                 In-process metrics with Prometheus text output
pkg/depaudit/                Dependency safety auditor
pkg/deprecation/             Warnings for features scheduled for removal
plugins/python/              Python SDK + framework adapters (LangChain, CrewAI, browser-use, MCP)
plugins/typescript/          TypeScript SDK
configs/                     Policy files and examples
docs/                        Documentation
```

## Priority Areas

1. **Adapters** — Adding support for more agent frameworks (AutoGPT, OpenAI Agents SDK, etc.)
2. **Policy rules** — New scope types, matching strategies, and contextual conditions
3. **Dashboard** — Session replay, policy editor, richer analytics
4. **Documentation** — Tutorials, integration guides, example policies

## Releasing a New Version

The version string appears in 15 files. Use the bump script before tagging — never edit them by hand.

```bash
./scripts/bump-version.sh 1.2.0     # whatever the new version is
```

This updates:

| File | Field |
|------|-------|
| `cmd/agentguard/main.go` | `version = "..."` |
| `cmd/agentguard-mcp-gateway/main.go` | `version = "..."` (v0.5+) |
| `cmd/agentguard-llm-proxy/main.go` | `version = "..."` (v0.5+) |
| `plugins/python/pyproject.toml` | `version = "..."` under `[project]` |
| `plugins/python/agentguard/adapters/mcp.py` | `SDK_VERSION = "..."` |
| `plugins/typescript/package.json` | `"version": "..."` |
| `plugins/typescript/package-lock.json` | top-level + root-package `"version"` (committed; CI installs with `npm ci`) |
| `Makefile` | `VERSION=...` |
| `docs/SETUP.md` | `/health` curl example |
| `docs/API.md` | `/health` and `/v1/health` response examples |
| `docs/MCP_GATEWAY.md` | `serverInfo` version in the `initialize` example |
| `docs/PROXY_ARCHITECTURE.md` | `/health` response example |
| `docs/POLICY_REFERENCE.md` | self-label `as of **vX.Y.Z**` |
| `docs/DEPLOYMENT.md` | Compose and Kubernetes example image tags |
| `docs/CLI.md` | `agentguard version` example output |

The script then checks that no file still carries the old version in its canonical spot, and exits non-zero if one does. It doesn't touch `CHANGELOG.md`, `docs/releases/`, or `SECURITY.md`, so before you commit the bump, also:

- Add the release's section to `CHANGELOG.md` and write `docs/releases/vX.Y.Z.md`.
- On a **minor or major** bump, update the Supported Versions table and the "currently X.Y.x" line in `SECURITY.md`, which support only the latest minor line.

Then commit, tag, and push — the publish workflows trigger when you **publish a GitHub Release** (not on the tag push alone):

```bash
git add -p
git commit -m "release: v1.2.0"
git tag v1.2.0
git push && git push --tags

# Then: GitHub UI → Releases → Draft a new release → Tag: v1.2.0 → Publish
# That fires .github/workflows/publish-pypi.yml (uploads agentguardproxy==1.2.0)
# and .github/workflows/publish-npm.yml (publishes @lictorate/agentguard@1.2.0).
```

The publish workflows only trigger on `release: [published]` events or via manual `workflow_dispatch`. Pushing the tag alone does **not** trigger them. (This caught v0.5.1 — the tag was pushed but the release was never drafted, so PyPI stayed on v0.5.0 until the operator pressed Publish.)

`publish-npm.yml` uses npm trusted publishing, so there's no npm token to store or rotate. On npmjs.com, `@lictorate/agentguard`'s trusted publisher names the repository `Caua-ferraz/AgentGuard` and the workflow file `publish-npm.yml`. If you rename the workflow file, update that setting too, or publishing fails. The workflow refuses to publish when the release tag doesn't match `plugins/typescript/package.json`'s version, and skips a version that's already on npm. npm attaches provenance to each version it publishes.

### How to define your version

Version format: `MAJOR.MINOR.PATCH` → `0.0.0`

- **MAJOR** → breaking changes (things stop working with older versions)
- **MINOR** → new features (backward-compatible)
- **PATCH** → bug fixes or small improvements

> If the version starts with `0` (e.g. `0.4.1`), the project is still in development and may change at any time.

> **PyPI note:** Never re-use a version number. PyPI permanently rejects duplicate uploads even after deletion. Always bump before publishing.

## Running the Full Test Suite

Before opening a PR, run all four test suites at once with the `test-all` script:

```bash
make test-all
# or
./scripts/test-all.sh
```

This runs, in order:

| Suite | What it does |
|-------|--------------|
| `go` | `go test -race -coverprofile=coverage.out ./...` |
| `policy` | builds the binary, runs `agentguard validate --strict` on every YAML in `configs/` and `configs/examples/` |
| `python` | `pip install -e ".[dev]"` + `pytest -v --cov=agentguard` in `plugins/python` |
| `ts` | `npm install` + `npm run build` + `npm test` in `plugins/typescript` |

The script does **not** stop on the first failure — every suite runs so you see the full picture in one go. Suites whose toolchain is missing (no `python`, no `npm`) are reported as `SKIP` rather than `FAIL`, so Go-only contributors aren't penalised on a partial setup. Final exit code is the number of failed suites (0 if all passed).

Useful flags:

- `--skip-go` / `--skip-policy` / `--skip-python` / `--skip-ts` — narrow the run
- `--no-race` — drop the Go race detector for a faster Go suite
- `-h`, `--help` — full usage

Cross-platform: works under Git Bash on Windows, macOS, and Linux. The script auto-detects `agentguard.exe` vs `agentguard` based on the OS.

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

Histogram buckets go from 0.25 ms to 10,000 ms, plus `+Inf`. A healthy server at low load should show p99 `request_duration_ms` below 5 ms.

## Latency budget

AgentGuard sits in front of every tool call, so the enforcement hot path has a hard budget: **p99 < 3 ms** for a `/v1/check` decision. The hot path is:

- `pkg/proxy` — `handleCheck`
- `pkg/policy` — `Engine.Check` and the rule matchers
- `pkg/ratelimit` — `Allow`
- `pkg/llmproxy` — the streaming, forwarding and parser code on the read-a-byte / forward path
- `pkg/internal/gateclient` — the `/v1/check` client both proxies use

On that path, don't add a synchronous database call, blocking I/O, or new per-request allocations. That's why persistence, multi-node reconciliation and (by default) audit writes run in the background.

CI enforces the budget in the `latency-gate` job, which runs without `-race` because the race detector distorts timing. Run the same gates locally before sending a hot-path change:

```bash
go test ./pkg/policy/ -run TestEngineCheck_P99LatencyGate -v -count=1
go test ./pkg/persist/ -run TestIntegration_HotPathLatencyWithPersistence -v -count=1
AGENTGUARD_SOAK_P99_GATE=1 go test ./pkg/persist/ -run TestIntegration_ConcurrentHotPathLatencyWithPersistence -v -count=1
make bench   # compare allocations per op before and after your change
```

## Pull Request Process

- Fork the repo, create a feature branch
- Write tests for new functionality
- Run `make test-all` before submitting (or `go test -race ./...` for a Go-only quick check)
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

If you find a security vulnerability in AgentGuard, please email cauaferrazp@gmail.com instead of opening a public issue. We take security seriously — it's literally our whole thing.
