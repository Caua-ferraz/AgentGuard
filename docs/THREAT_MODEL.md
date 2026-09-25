# Threat Model

This document states who AgentGuard defends against, what it trusts, and what it deliberately does not attempt. It is written from the code: every defence named below points at the function that implements it, and every non-goal is one the README or a design decision already records. Treat it as binding — a change that moves an actor across a boundary is a security decision, not a refactor.

Related: [`README.md` § Limitations & Threat Model](../README.md#limitations--threat-model) (the short form), [`SECURITY.md`](../SECURITY.md) (reporting, out-of-scope list), [`DEPLOYMENT.md`](DEPLOYMENT.md) (the flags that move the boundaries).

## What AgentGuard is

A policy enforcement and audit layer at two protocol boundaries — the MCP stdio gateway and the OpenAI/Anthropic HTTP proxy — plus an advisory SDK layer. Every gated action becomes a `/v1/check` question to the central server, which answers `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` from in-memory policy state and writes an append-only audit entry.

## Actors, from most to least trusted

### Operator and approver — trusted

Owns the policy file, the API key, the process environment, and the approve/deny decision. Control-plane endpoints (`/v1/approve`, `/v1/deny`, `/v1/status`, `/v1/audit`, `/api/*`) require a Bearer token or a session cookie plus CSRF header (`pkg/proxy/auth.go`, constant-time comparison). Without an API key the server binds `127.0.0.1` only (`pkg/proxy/server.go`, `NewServer`) and prints a startup warning; exposing it further is an explicit operator act.

A compromised operator host is out of scope: whoever can edit the policy file or read the API key can disable enforcement.

### Embedder — trusted, fallible

Go code that imports `pkg/proxy`, `pkg/llmproxy`, or `pkg/mcpgw` directly. The packages are nil-safe rather than fail-closed on missing wiring: a nil `PolicyCheck` hook allows every call with an identifiable rule string (audit B5, `local_fixes/STATUS.md`), and the legacy `HistoryQuerier` answers `require_prior` without a tenant filter behind a one-time warning. Both shipped binaries wire every hook; an embedder must do the same.

### Co-tenants — mutually untrusted

Tenants share one process and one store. Every enforcement key carries the tenant: rate-limit buckets (`scope:tenant:agent`), session-cost accumulators (`{tenant, session}`), the approval queue (`tenantsMatch` on every lookup, resolve, and status read), the `require_prior` index (`{tenant, agent, scope}`), audit queries, and every store function (`tenant_id` is a required explicit parameter; `ErrTenantRequired` otherwise). Tenant-aware routes validate the tenant before dispatch (`pkg/proxy/tenant.go`, `withTenant`). Cross-tenant reads are a bug even in tests.

Metrics are process-wide and carry no tenant label by design: aggregate counters leak nothing tenant-specific, and per-tenant series would make `/metrics` cardinality client-controlled. The one client-influenced label, `agentguard_ratelimit_bucket_evictions_total{scope}`, is bounded by the union of policy scope names.

### The agent and its model — untrusted

Prompt injection is assumed. Everything the agent emits is attacker-controlled input: tool-call arguments, scope strings, `agent_id`, `session_id`, `meta`, and any `approval_id` it presents. Defences:

- **Approval replay is shape-bound and one-shot.** An `approval_id` is honoured only when the retry's operationally-meaningful fields match the original request (`matchesOriginalRequest`), only within `--approval-validity`, and only once for an ALLOW (`ConsumeResolved`, compare-and-consume under the write lock). Mismatches fall through to fresh evaluation rather than a 4xx, so the endpoint is not an oracle. Counted in `agentguard_approval_replay_mismatch_total` and `agentguard_approval_replay_refused_total`.
- **Duplicate JSON keys in tool arguments are a hard deny** (`pkg/llmproxy/streaming.go`, `runPolicyCheck`). The gate projects a Go map (last-wins) while the ALLOW path replays the raw bytes; a first-wins executor would act on a different value than the one gated. This deny is not subject to `--fail-mode allow`.
- **Secrets in requests are masked before they are stored or shown** (`server --audit-redact`, default on since v1.2.0): the audit trail, `GET /v1/audit`, the SSE stream, the dashboard and the pending list see `[REDACTED]` for keys, tokens and passwords an agent puts in a command. The approval store keeps the original request for replay matching. See [OPERATIONS § Audit redaction](OPERATIONS.md#audit-redaction).
- **Input normalisation before matching** (`pkg/policy/engine.go`, `normalizeRequest`): control bytes stripped, domains lower-cased, paths cleaned — so `EVIL.com` cannot slip past a `evil.com` deny.
- **Malformed tool-call JSON at completion is refused fail-closed** and audited as a forced `malformed_tool_call` deny (`denyMalformedOpenAI` / `denyMalformedAnthropic`), never forwarded.
- **Shell commands are split before matching** (`pkg/policy/shell_segments.go`, since v1.2.0). Chained commands, substitutions, subshells, line breaks and redirections are evaluated one command at a time, so an allow rule for the first command can't carry the rest; redirection targets are checked as filesystem access; anything that can't be split safely is denied (`deny:shell:unparseable_command`). See [POLICY_REFERENCE § Compound shell commands](POLICY_REFERENCE.md#compound-shell-commands).
- **Glob matching is string matching.** An agent can express the same action differently (`find / -delete` for `rm -rf`), and a single allowed command can run others through its arguments (`find -exec`, `git -c core.sshCommand=…`). Policies are a high-signal filter, not a semantic authorisation model — pair with OS isolation (README).

Anything the agent does outside the gated transport — shelling out directly, pointing itself at a different MCP server or base URL — is out of scope. AgentGuard is not a sandbox.

### The upstream LLM provider — semi-trusted

The provider is trusted for the *content* of its answers but **not for the structure of its stream**. A non-conformant or hostile stream is in scope, and three fail-closed defences exist for exactly this actor:

| Defence | Where | What it refuses |
|---|---|---|
| Interleaved second `tool_use` block | `anthropic_parser.go` (`FeedEvent`, audit H1) | A second block opening while one is still buffering would be flushed ungated when the first cycle resets. The whole stream is refused. |
| Start-seeded input plus streamed deltas | `anthropic_parser.go` (audit H2) | Two argument sources would concatenate into invalid JSON and the gate would evaluate a truncated view. Refused. |
| First-wins function name | `openai_parser.go` (audit M1) | A second, different name for the same `tool_calls[i]` would make the gate evaluate a different call than the client executes. The first name wins, matching client SDKs. |

Each refusal is a synthetic refusal to the client, counted in `agentguard_llmproxy_protocol_violation_total{provider}`, and the buffered bytes are discarded. Oversized argument accumulation is capped by `--max-buffer-bytes` with a built-in 64 MiB ceiling. Still open and priced in `local_fixes/STATUS.md`: B6, B17, B18, B21+B7.

### The downstream MCP server — untrusted for framing and liveness

Its frames are untrusted bytes: oversized frames are skipped per-frame with the reader resynchronised (`pkg/mcpgw/framing.go`), a wedged reader is killed and the supervisor respawns it, explicit `"id": null` is answered with an error, and server-initiated requests (`sampling/createMessage`, `roots/list`, `elicitation/create`) are dropped, never forwarded to the host. Its **tool results** are not inspected — data exfiltration through a result payload is a non-goal (see `#data-pii` in `TODO.md`).

### The MCP host or client application — trusted for framing, untrusted for intent

The host speaks JSON-RPC to the gateway over stdio and is assumed well-formed, but the tool-call arguments it forwards originate from the model and are treated as agent input above.

### Anyone who can reach `/v1/check` or `/metrics` — untrusted, by design reachable

Both endpoints are unauthenticated ([`DEPLOYMENT.md` §4](DEPLOYMENT.md#4-v1check-is-intentionally-open), [`OBSERVABILITY.md`](OBSERVABILITY.md)). A network peer can:

- consume rate-limit budget for any scope and agent id it names,
- fill the approval queue (bounded at 10 000; refused with 503 and `Retry-After` when full, resolved entries evicted first),
- learn policy decisions for requests it composes, and read aggregate counters and policy scope names from `/metrics`.

It cannot approve, deny, read the audit trail, or reuse an approval it did not obtain the id for without also matching the original request shape. Volumetric abuse is delegated to the network layer (`SECURITY.md`). Gate `/v1/check` at a reverse proxy when the threat model needs L7 auth.

### Outbound connections

The enforcement server initiates only the connections the operator configured: the PostgreSQL store (`--store-dsn`) and the policy's notifiers. `agentguard server` performs no update check and sends no telemetry. The interactive `agentguard` subcommands query the GitHub Releases API once at startup unless `AGENTGUARD_NO_UPDATE_CHECK` is set. CI, not the binaries, talks to OSV.dev, PyPI, npm, and the Go module proxy (`pkg/depaudit`). The MCP gateway reaches `--guard-url` and the MCP servers it spawns; the LLM proxy reaches `--guard-url` and the configured provider. Each of these peers is a trust decision the operator made; AgentGuard does not verify GitHub's answer beyond parsing a tag name and never executes anything based on it.

### Supply chain — checked in CI

`govulncheck` (reachability-based) and `pkg/depaudit` (live OSV.dev per pinned version plus a curated performance-regression registry) gate every push. Python extras are version ranges and Go pseudo-versions are not point-queryable, so those are registry-only; transitive npm packages are covered only by the advisory `npm audit` job. See `pkg/depaudit/advisories.md`.

## Trust boundaries in one picture

```
   untrusted            semi-trusted             trusted
 ┌──────────┐  stream  ┌──────────────┐          ┌────────────┐
 │ LLM      │ ───────► │ LLM proxy    │ /v1/check│ agentguard │ ◄── operator
 │ provider │ ◄─────── │ (gate)       │ ───────► │ serve      │ ◄── approver
 └──────────┘          └──────────────┘          │ (policy,   │
 ┌──────────┐  frames  ┌──────────────┐          │  approvals,│ ◄── store (--store-dsn)
 │ MCP      │ ◄──────► │ MCP gateway  │ ───────► │  audit)    │ ──► notifiers
 │ server   │          │ (gate)       │          └────────────┘
 └──────────┘          └──────────────┘               ▲
 ┌──────────┐   guard.check(...)                      │ advisory — the agent
 │ agent    │ ────────────────────────────────────────┘ process decides to call
 │ (model)  │  ── shells out / other base URL ──► out of scope (OS sandboxing)
 └──────────┘
```

Enforcement is only as strong as the operator's control over the agent's environment (`OPENAI_BASE_URL`, MCP client config, network egress). The SDK layer is opt-in and therefore advisory; it exists for offline scripts and custom transports and should be paired with a wire-level layer whenever both apply.

## Fail-open versus fail-closed

- Central server unreachable: both proxies default to `--fail-mode deny` (`deny:<gateway>:fail_closed`), with `fail-closed-with-audit` writing the denial to a local fallback file. `allow` is an explicit, logged opt-in for trusted development environments.
- `/v1/check` answers 2xx with an unparseable or unknown decision: hard deny (`InvalidResponseRule`), regardless of `--fail-mode`.
- SDKs: fail-closed by default; `fail_mode="allow"` / `failMode: 'allow'` is an explicit opt-in.
- Audit backend saturated: entries spill to a durable overflow file and the request is still answered — the audit path never blocks or fails the decision.
- Approval queue full: 503, not a silent allow.

## Explicit non-goals

These are documented decisions, not gaps:

- **OS sandboxing or syscall interception.** Use containers, seccomp, AppArmor, egress rules.
- **Semantic understanding of commands.** Matching is glob on strings; a single `*` crosses `/` (see `POLICY_REFERENCE.md`).
- **Cryptographic audit sealing.** The audit log is append-only JSONL; tamper-evidence comes from forwarding it to WORM storage (v0.9 decision).
- **RBAC or multi-key auth.** One bearer key; capability-scoped keys are post-v1.
- **PII or secret detection in data flows.** Deferred (`#data-pii`) — a weak classifier would create false confidence.
- **MCP resources, prompts, sampling, elicitation, cancellation.** Masked out of the handshake or dropped; tools only.
- **Global strictness across replicas.** Multi-node limiting is bounded-overshoot by design (≈ `reconcile-interval × peak rate` per extra replica).
- **A compromised operator host or a hostile embedder.**

## Keeping this document true

When a change adds an outbound connection, a new unauthenticated endpoint, a new actor whose bytes reach a parser, or relaxes one of the defences in the table above, update this file in the same change. `cmd/agentguard/docs_consistency_test.go` pins the claims that are cheap to check mechanically.
