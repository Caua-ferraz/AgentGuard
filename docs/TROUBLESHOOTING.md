# Troubleshooting

Symptom-first reference. If something is wrong, skim the headers below for the one that matches what you are seeing.

---

## Agents get `connection refused` / `connect: timed out`

**Likely cause:** `--api-key` is not set, so the server is bound to `127.0.0.1:<port>` only. Agents running on any other host cannot reach it.

**Confirm:** the server log on startup will show:

```
INFO: binding to 127.0.0.1:8080 (localhost only) — set --api-key to listen on all interfaces
```

**Fix:** set a Bearer token.

```bash
export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
agentguard serve --api-key "$AGENTGUARD_API_KEY" ...
```

Details: [`docs/DEPLOYMENT.md` §1](DEPLOYMENT.md#1-always-set-an-api-key).

---

## Dashboard login loops back to the login page

**Likely cause:** you are running behind an HTTPS-terminating reverse proxy, but AgentGuard is issuing session cookies without `Secure`. The browser sets them, then refuses to send them back on the next HTTPS request.

**Confirm:** in browser devtools (Application → Cookies), `ag_session` is present but `Secure` column is blank.

**Fix:** add `--tls-terminated-upstream`.

```bash
agentguard serve --tls-terminated-upstream ...
```

Details: [`docs/DEPLOYMENT.md` §2a](DEPLOYMENT.md#2a-session-cookies-without-secure--login-loop).

---

## Slack / webhook approval links point at `localhost`

**Likely cause:** `--base-url` is not set, so `approval_url` falls back to `http://localhost:<port>`.

**Fix:**

```bash
agentguard serve --base-url https://guard.example.com ...
```

---

## Policy edits do not take effect

**Likely cause (a):** `--watch` is not enabled. Without it, the policy is loaded once at startup and never re-read.

```bash
agentguard serve --watch ...
```

**Likely cause (b):** the file's mtime did not change. The watcher polls `os.Stat(path).ModTime()` every 2s (`pkg/policy/watcher.go` `DefaultPollInterval`). If you edited through a tool that preserves mtime, touch the file:

```bash
touch configs/default.yaml
```

**Likely cause (c):** your edit is syntactically invalid. Parse errors are logged but do **not** halt the watcher — the old policy keeps serving. Check the server log for `WatchFile: reload failed:` and run `agentguard validate --policy configs/default.yaml` to pinpoint the error.

---

## Rate limit works locally but gets bypassed in production

**Likely cause:** you are running more than one AgentGuard replica. Rate-limit buckets are in-memory per instance (`pkg/ratelimit/ratelimit.go`); an agent can burst past the cap by hitting different pods / VMs round-robin.

**Mitigations:**

- Divide per-scope `max_requests` by the replica count when writing the policy.
- Pin agents to a single AgentGuard instance via session affinity.
- Keep `replicas: 1` and scale vertically.

Details: [`docs/OPERATIONS.md`](OPERATIONS.md).

---

## Approvals disappeared after a restart

**Cause:** the approval queue is in-memory only (`pkg/proxy/server.go` `ApprovalQueue`). Pending actions are lost on any process restart and polling SDKs will eventually time out.

**Mitigations:**

- Set SDK `wait_for_approval(timeout=...)` to a realistic human SLA — long enough to survive a short restart, short enough to free the agent if approval never comes.
- Use systemd / a process supervisor that minimizes restart windows.
- For mission-critical flows, have the calling agent checkpoint its state so it can re-issue the `check` and get a fresh approval ID.

---

## `/metrics` or `/api/stats` are slow / inaccurate right after startup

**Cause:** on boot, AgentGuard replays the entire audit log through `metrics.IncDecision` to seed decision counters so `/metrics` survives restarts with accurate totals. For a multi-GB `audit.jsonl`, this scan can take seconds to minutes.

**Fix:**

- Rotate the audit log regularly (AgentGuard does not auto-rotate).
- Ship historical audit data to an external aggregator and truncate the local file during scheduled maintenance.

Details: [`docs/OPERATIONS.md`](OPERATIONS.md).

---

## Webhook / Slack events are missing

**Cause:** the notification dispatcher has a bounded queue (`DefaultQueueSize = 256`). If notifiers are slow or the queue is full, `Dispatcher.Send` drops the event and increments `agentguard_notify_events_dropped_total{notifier, reason}`.

**Confirm:**

```bash
curl -s http://127.0.0.1:8080/metrics | grep notify_events_dropped_total
```

**Mitigations:**

- Increase notifier timeouts in the policy file (`notifications.dispatch_timeout`).
- Reduce notifier fanout (remove unused targets).
- Shard to multiple webhook endpoints if a single Slack channel is a bottleneck.
- Watch `agentguard_notify_queue_depth{notifier}` — steady growth means the worker cannot drain.

---

## Python SDK always returns `DENY` in tests

**Cause:** the Python SDK **defaults to fail-closed** on any network error (`urllib.error.URLError`, `OSError`, or a non-JSON response body → synthetic `DENY` with reason `"AgentGuard unreachable (deny): ..."`). If your test environment cannot reach the proxy URL, every call fails closed.

**Confirm:** inspect `result.reason` — it will contain `"AgentGuard unreachable"`.

**Fixes:**

- Point the test `Guard(base_url=...)` at a running test server, or use `httpretty` / `responses` to stub `urllib`.
- For tests that need fail-open behavior, pass `fail_mode="allow"` explicitly (Python v0.4.1+). Do **not** flip this in production unless your threat model treats AgentGuard as advisory — the `"deny"` default is what keeps agents safe when the proxy is down.

---

## `*.foo.com` does not match `foo.com`

**Not a bug.** AgentGuard uses standard glob semantics: `*.foo.com` requires at least one character before the dot. Similarly, `*` does not cross `/` boundaries unless you use `**`.

**Fix:** add both patterns explicitly.

```yaml
allow:
  - domain: "foo.com"
  - domain: "*.foo.com"
```

Details: [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md).

---

## Condition has `time_window` but it is being ignored

**Cause:** `time_window` without `require_prior` was a v0.4.0-compat no-op that **errors out at policy load as of v0.5.0**. `LoadFromFile` returns the validation error; the server refuses to boot until the policy is fixed. Either remove the orphan `time_window` or add a `require_prior` clause. See [`DEPRECATIONS.md`](DEPRECATIONS.md).

**Confirm:** look for a line like:

```
WARNING: rule "..." has time_window without require_prior — condition will be ignored
```

**Fix:** add a `require_prior` (the pattern/action that must have been allowed within the window), or remove the orphan `time_window`.

Details: [`docs/DEPRECATIONS.md`](DEPRECATIONS.md) and [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md).

---

## Dashboard shows a red LIVE badge

**Cause:** the SSE connection on `/api/stream` dropped — either the server restarted, the network hiccupped, or your reverse proxy buffered the stream shut (nginx default is `proxy_buffering on`).

**Fixes:**

- Refresh the page. The dashboard does **not** auto-reconnect today.
- If behind nginx, set `proxy_buffering off` on `/api/stream`. See [`docs/DEPLOYMENT.md` §2c](DEPLOYMENT.md#2c-nginx-reference-config).

---

## I see `503 Service Unavailable` on `/v1/approve` or `/v1/deny`

**Cause:** the in-memory session store or approval queue is full.

- Session store: `MaxSessions = 1024` (hardcoded in `pkg/proxy/auth.go`). Oldest-by-expiry are evicted, but under burst login load you can hit `Retry-After: 5`.
- Approval queue: `MaxPendingApprovals = 10000`. Resolved entries are bulk-evicted when the queue fills.

**Mitigation:** resolve outstanding approvals faster, or rotate API keys / force logouts to shrink the session table.

---

## CORS preflight fails from a production frontend

**Cause:** `--allowed-origin` is unset, so AgentGuard is in **permissive-localhost** mode — any non-localhost `Origin` is rejected.

**Fix:** set the exact frontend origin.

```bash
agentguard serve --allowed-origin https://app.example.com ...
```

Details: [`docs/DEPLOYMENT.md` §3](DEPLOYMENT.md#3-cors).

---

## Docker: audit log is empty after container restart

**Cause:** the audit log is written inside the container at `/var/lib/agentguard/audit.jsonl`. Without a volume mount, the filesystem is destroyed when the container is removed.

**Fix:**

```bash
docker run -d -p 8080:8080 \
  -v agentguard-audit:/var/lib/agentguard \
  agentguard:latest
```

---

## MCP Gateway / LLM API Proxy issues (v0.5+)

### MCP client shows zero tools after pointing at `agentguard-mcp-gateway`

The gateway started but no `--upstream` is wired, or the upstream subprocess crashed at boot. Run the gateway in the foreground and watch for `WARN mcpgw upstream <name> spawn failed: ...`. Verify the upstream command runs standalone. Details: [`MCP_GATEWAY.md`](MCP_GATEWAY.md).

### LLM API Proxy: SDK hangs / `unexpected end of stream`

The proxy was killed mid-stream and the buffered tool-call payload was never flushed. Give it a 30 s graceful-shutdown window (`TimeoutStopSec=30s` / `terminationGracePeriodSeconds: 30`).

### LLM API Proxy: agent sees `502 Bad Gateway`

The proxy couldn't reach `--guard-url` or the bearer token is wrong. `curl -sf <guard-url>/health` to confirm reachability, then verify `AGENTGUARD_API_KEY` matches on both sides. With `--fail-mode=deny` (production default), in-flight calls return synthetic refusals until the server comes back.

### Proxy rejects every incoming connection

It bound to `127.0.0.1`. If your agent runs in a separate container or host, the loopback bind blocks it. Change to `--listen 0.0.0.0:<port>` **only on a trusted network** — proxy inbound is not authenticated.

### Tool calls flow through the LLM API Proxy but never reach the AgentGuard server

The client's `OPENAI_BASE_URL` is missing the `/v1` suffix, or the request is a plain chat completion (intentionally passthrough). Check `agentguard_llmproxy_tool_calls_total` — if it's not incrementing, no tool call was produced. Set `OPENAI_BASE_URL=http://127.0.0.1:8081/v1` (include `/v1`); for Anthropic use `ANTHROPIC_BASE_URL=http://127.0.0.1:8081` (no `/v1`). Details: [`QUICKSTART_LLM_PROXY.md`](QUICKSTART_LLM_PROXY.md).

---

## Still stuck?

- Run `agentguard status` — shows `/health` reachability and the pending queue.
- Check `/metrics` on the central server AND on each proxy — counters, gauges, histograms, dispatch drops.
- Response headers on `/v1/check`: `X-AgentGuard-Policy-Ms`, `X-AgentGuard-Audit-Ms`, `X-AgentGuard-Total-Ms` (timings in ms, 3 decimals).
- Version skew: all three binaries report their version via `agentguard version` / `agentguard-mcp-gateway --version` / `agentguard-llm-proxy --version`. Mismatch is the most common ops-time bug after a partial upgrade.
- Open an issue with: versions of all binaries, sanitized policy snippet, and the relevant log lines from both the proxy and the central server. Security-sensitive reports go to `cauaferraz@lictorate.com` — not the issue tracker.
