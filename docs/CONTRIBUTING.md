# Contributing to AgentGuard

Thanks for your interest in making AI agents safer. Here's how to get involved.

## Development Setup

```bash
git clone https://github.com/Caua-ferraz/agentguard.git
cd agentguard
go build ./...
go test ./...
```

## Priority Areas

1. **Adapters** — Adding support for more agent frameworks (AutoGPT, OpenAI Agents SDK, etc.)
2. **Policy rules** — New scope types, matching strategies, and contextual conditions
3. **Dashboard** — Improved UI, better session replay, richer analytics
4. **Documentation** — Tutorials, integration guides, example policies

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

We welcome community-contributed policy templates in `configs/community/`. Include a clear description of the use case and what the policy protects against.

## Reporting Security Issues

If you find a security vulnerability in AgentGuard, please email security@agentguard.dev instead of opening a public issue. We take security seriously — it's literally our whole thing.
