# FAQ

Questions that come up often in issues and conversations. For symptom-keyed debugging see [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

---

### Is AgentGuard a sandbox?

No. It is a **policy-enforcement proxy**. Agents call `/v1/check` before sensitive actions; AgentGuard decides `ALLOW` / `DENY` / `REQUIRE_APPROVAL`. It does not intercept syscalls, containerize processes, or prevent an agent that bypasses the SDK from acting. For strong isolation, pair AgentGuard with OS-level sandboxing (seccomp, AppArmor, containers, gVisor).

### Do I need to modify my agent code?

Yes — the integration is **opt-in**. Either:
- Call `guard.check(...)` from the Python or TypeScript SDK before each sensitive action, or
- Wrap your framework's tools with the adapters in [`ADAPTERS.md`](ADAPTERS.md) (LangChain, CrewAI, browser-use, MCP).

There is no transparent-proxy mode — an agent that bypasses the SDK bypasses AgentGuard entirely.

### Why is `/v1/check` unauthenticated?

So agents can call it with zero per-request setup. The only authenticated endpoints are approve/deny/status/audit and the dashboard. If your threat model requires `/v1/check` to be authenticated, gate it at the reverse proxy (allowlist source IPs or require a second header) — see [`DEPLOYMENT.md`](DEPLOYMENT.md).

### My agents can't connect remotely, but `curl localhost:8080/health` works.

You're running without `--api-key`. Without it, the server binds to `127.0.0.1` only. Set `--api-key` (or `AGENTGUARD_API_KEY`) and the server will bind `0.0.0.0`.

### Do I have to run it behind a reverse proxy?

For production yes — TLS termination, connection pooling, static IP, and buffering tuning all belong at the edge. AgentGuard has no built-in TLS. See [`DEPLOYMENT.md`](DEPLOYMENT.md) for nginx/Docker Compose/K8s examples.

### Can I run multiple replicas?

Technically yes, practically be careful. Rate-limit buckets and session-cost accumulators are **per-instance** — they do not share state. A load-balanced agent can burst past limits. Mitigations: pin sessions via load-balancer affinity, divide limits by replica count, or stick to one replica (usually plenty — AgentGuard handles 500+ RPS per vCPU). See [`OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments).

### My approval queue is empty after a restart. Where did the approvals go?

The approval queue is **in-memory**. Restart loses every pending entry — by design. Agents polling across a restart will eventually hit their SDK timeout and receive a fail-deny response. Set SDK `wait_for_approval` timeouts shorter than the restart-to-timeout window if this matters.

### Does the audit log rotate?

No — it grows forever. `audit.jsonl` is opened with `O_APPEND` and never renamed or truncated by AgentGuard. **You must rotate externally.** See [`OPERATIONS.md`](OPERATIONS.md#audit-log-rotation) for the truncate-in-place pattern. Also note the startup replay: the entire log is re-read on boot to seed counters, so letting it grow to multi-GB delays `/metrics` accuracy.

### Why does `*.foo.com` not match `foo.com`?

Standard glob semantics — `*.foo.com` requires at least one character + `.` before `foo.com`. Matches `api.foo.com`, not the apex. Add both explicitly if you want both:

```yaml
- domain: "foo.com"
- domain: "*.foo.com"
```

See [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md#wildcards) for the full pattern table.

### Can I use `time_window` without `require_prior`?

You can, but it's a **no-op**. `time_window` only means something as a modifier on a `require_prior` condition (i.e., "only match if the prior action happened within this window"). v0.4.1 emits a `WARNING` log line at policy load; v0.5.0 will make it a hard error. See [`DEPRECATIONS.md`](DEPRECATIONS.md).

### Python fail-closed vs TypeScript failMode — which should I use?

Both SDKs default to **fail-closed** (proxy unreachable → `DENY`). This matches the usual security posture: if the guard is down, don't act.

- Python: `Guard(fail_mode="allow")` opts into fail-open.
- TypeScript: `new AgentGuard({ failMode: 'allow' })` opts into fail-open.

Use fail-open only when AgentGuard is advisory (e.g., you have another enforcement layer downstream).

### Is the SQLite audit backend ready?

It's implemented (`pkg/audit/sqlite_logger.go`) but **not wired in v0.4.1**. Activation requires adding `modernc.org/sqlite` as an import side-effect and constructing `audit.NewSQLiteLogger(path)` in `cmd/agentguard/main.go`. It's on the roadmap, not in production.

### Where's the admin API for managing approvers / RBAC?

There isn't one. v0.4.1 has **one API key** — anyone with it has full access. Multi-user and RBAC are planned. For now, treat the API key like a root password.

### Can I edit policies from the dashboard?

No. Policies are YAML files; edit them on disk and use `--watch` for hot-reload (2 s mtime poll). A dashboard-side policy editor is on the roadmap.

### Does AgentGuard support streaming responses / LLM output filtering?

No — AgentGuard decides on discrete actions (shell commands, HTTP calls, file writes), not on streaming LLM tokens. For content filtering at generation time, use a different layer (e.g., a prompt-filtering library or an output-scanning middleware). AgentGuard is about what the agent *does*, not what it *says*.

### How do I test my policy without a live agent?

Two ways:

1. **CLI validate** — syntax + load-time checks: `agentguard validate --policy configs/my-policy.yaml`.
2. **Direct curl** — semantics:
   ```bash
   curl -X POST http://localhost:8080/v1/check \
     -H 'Content-Type: application/json' \
     -d '{"agent_id":"test","scope":"shell","command":"rm -rf /"}'
   ```

Scripted coverage in CI is on the roadmap (P2 item: policy-as-code testing).

### How much does running AgentGuard cost in overhead?

Typical policy evaluation is sub-millisecond. End-to-end `/v1/check` runs in single-digit ms on a modern vCPU. At 500 RPS the service uses ~1 vCPU and ~50 MB RAM (no audit log). Memory grows linearly with audit log size during the startup replay only.

### Can I use it as a library, not a proxy?

The Go policy engine (`pkg/policy`) and audit logger (`pkg/audit`) are importable. The proxy is a thin wrapper around them. But the SDK/adapter story assumes an HTTP proxy — in-process embedding is uncommon and unsupported.

### Why YAML and not JSON / HCL / Rego?

YAML is human-friendly for rule lists with comments. JSON is too noisy for nested rules; HCL/Rego add external runtime deps. The policy engine is small enough that swapping languages is possible, but YAML covers every observed use case. If you want programmable policies, wrap the YAML generation in your own tool.

### I think I found a security issue. Where do I report?

Email `security@agentguard.dev`. Do **not** open a public issue. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the disclosure policy.

---

## Related docs

- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — symptom-keyed diagnostics.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — exact policy schema.
- [`docs/OPERATIONS.md`](OPERATIONS.md) — day-2 operational concerns referenced above.
