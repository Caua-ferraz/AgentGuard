# CLI Reference

Every AgentGuard subcommand, every flag, every env-var fallback. Source of truth: `cmd/agentguard/main.go`.

```
agentguard <command> [flags]

Commands:
  serve       Start the AgentGuard proxy server
  validate    Validate a policy file
  approve     Approve a pending action by ID
  deny        Deny a pending action by ID
  status      Show server health + pending approvals
  audit       Query the audit log
  migrate     Run on-disk schema migrations
  version     Print version information

Run 'agentguard <command> -h' for per-command flag help.
```

Global conventions:
- All subcommands use Go's stdlib `flag` package. Flags must precede positional args (`agentguard approve --api-key $K <id>`, **not** `agentguard approve <id> --api-key $K`).
- `--api-key` on client subcommands (`approve`, `deny`, `status`, `audit`) falls back to the `AGENTGUARD_API_KEY` env var.
- Exit code `0` = success; `1` = any failure.

---

## `agentguard serve`

Start the proxy server. This is the only subcommand that runs a server process.

| Flag | Default | Description |
|---|---|---|
| `--policy <path>` | `configs/default.yaml` | Path to policy YAML. Rejected at startup if missing or invalid. |
| `--port <int>` | `8080` | TCP port. See bind behavior below. |
| `--dashboard` | off | Serve `/dashboard` HTML + `/api/stream` SSE. Required for human approval UI. |
| `--watch` | off | Poll the policy file every 2 s; hot-reload on mtime change. No restart needed. |
| `--audit-log <path>` | `audit.jsonl` | Append-only JSON Lines file. Mode `0600`. Grows forever — see [`OPERATIONS.md`](OPERATIONS.md#audit-log-rotation). |
| `--api-key <key>` | *(empty)* | Bearer token for gated endpoints. **If empty, the server binds to `127.0.0.1` only** (localhost-only). |
| `--base-url <url>` | `http://localhost:<port>` | External URL used when constructing `approval_url` in check responses. Set this behind a reverse proxy. |
| `--allowed-origin <url>` | *(empty)* | Exact CORS origin. Empty = permissive-localhost (accepts any `http://localhost:*` or `http://127.0.0.1:*`). Set to `https://app.example` for strict single-origin. |
| `--tls-terminated-upstream` | off | Issue session cookies with `Secure` even when `r.TLS == nil`. Set when behind a TLS-terminating proxy that does not forward `X-Forwarded-Proto`. See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| `--session-cost-ttl <dur>` | `0` (never expire) | Evict idle session-cost accumulator entries. Example: `24h`. Zero keeps v0.4.0 behavior. |
| `--session-cost-sweep-interval <dur>` | `max(ttl/4, 1m)` | Sweeper cadence. Ignored when `--session-cost-ttl 0`. |

### Bind behavior

- `--api-key` **set**: binds on `0.0.0.0:<port>` (all interfaces).
- `--api-key` **unset**: binds on `127.0.0.1:<port>` only. A WARNING is logged at startup. Remote agents cannot connect. This is the #1 source of "connection refused" for new users.

### Examples

```bash
# Local dev — localhost-only, dashboard on, hot-reload.
agentguard serve --policy configs/default.yaml --dashboard --watch

# Production behind a reverse proxy.
agentguard serve \
  --policy /etc/agentguard/policy.yaml \
  --audit-log /var/lib/agentguard/audit.jsonl \
  --api-key "$AGENTGUARD_API_KEY" \
  --base-url https://guardrails.example \
  --allowed-origin https://app.example \
  --tls-terminated-upstream \
  --session-cost-ttl 24h \
  --dashboard
```

### Signals

`SIGINT`/`SIGTERM` → graceful shutdown (drains in-flight requests up to the internal shutdown timeout, closes audit logger and notifier).

---

## `agentguard validate`

Load a policy file and report rule count / scope count. Exits `1` on parse error, load-time validation failure (e.g., `..` in a filesystem path), or missing required fields (`version`, `name`).

| Flag | Default | Description |
|---|---|---|
| `--policy <path>` | `configs/default.yaml` | Policy file to validate. |

```bash
agentguard validate --policy configs/examples/trading-bot.yaml
# VALID: trading-bot-policy — 14 rules across 4 scopes

agentguard validate --policy /tmp/broken.yaml
# INVALID: yaml: unmarshal errors: line 4: cannot unmarshal !!int into string
```

Use in CI:

```bash
for f in configs/*.yaml configs/examples/*.yaml; do
  agentguard validate --policy "$f" || exit 1
done
```

---

## `agentguard approve <id>` / `agentguard deny <id>`

POST to `/v1/approve/{id}` or `/v1/deny/{id}`. Used by humans or scripts to resolve `REQUIRE_APPROVAL` decisions.

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | `http://localhost:8080` | Server URL. |
| `--api-key <key>` | `$AGENTGUARD_API_KEY` | Bearer token. Required if the server was started with `--api-key`. |

```bash
agentguard approve ap_1a2b3c4d5e6f7890abcdef1234567890
# Action approve: approved

AGENTGUARD_API_KEY=$KEY agentguard deny ap_deadbeef… --url https://guardrails.example
# Action deny: denied
```

Exit `1` on network error, non-2xx response, or invalid approval ID. Approval IDs are `ap_<32hex>` as returned by `/v1/check`.

---

## `agentguard status`

Quick human-readable health + pending list. Hits `/health` (unauthenticated) then `/api/pending` (authenticated).

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | `http://localhost:8080` | Server URL. |
| `--api-key <key>` | `$AGENTGUARD_API_KEY` | Bearer token. |

```bash
agentguard status
# AgentGuard server: OK (http://localhost:8080)
# Pending approvals: 2
#   [ap_123…] scope=shell action="rm -rf ./old_data" agent=researcher-01
#   [ap_456…] scope=cost  action=""                   agent=trading-bot
```

If the server is running without `--api-key`, pending approvals appear unauthenticated. If you set `--api-key` on the server but not here, the pending list shows "unauthorized".

---

## `agentguard audit`

Query `/v1/audit` for recent decisions. All filters are optional and AND-combined.

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | `http://localhost:8080` | Server URL. |
| `--agent <id>` | *(none)* | Filter by exact `agent_id`. |
| `--decision <D>` | *(none)* | `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. |
| `--scope <name>` | *(none)* | `shell`, `filesystem`, `network`, `browser`, `cost`, `data`, etc. |
| `--limit <int>` | `50` | Max entries. Server clamps above configured ceiling (default 200). |
| `--api-key <key>` | `$AGENTGUARD_API_KEY` | Bearer token. |

```bash
agentguard audit --decision DENY --scope shell --limit 20
# Showing 20 audit entries:
#
#   2026-04-19T12:03:44Z  DENY                scope=shell         agent=researcher-01     rm -rf /
#     reason: Matches deny rule in shell scope
#   ...
```

The CLI uses `/v1/audit?limit=N` directly — pagination (`?offset=`) is supported on the HTTP API but not exposed as a CLI flag yet; use `curl` for paginated exports.

---

## `agentguard migrate`

Run registered on-disk audit-schema migrations. Each migration has a `Detect()` step — it only runs if the on-disk format matches. See [`FILE_FORMATS.md`](FILE_FORMATS.md) for the schema history.

| Flag | Default | Description |
|---|---|---|
| `--audit-log <path>` | `audit.jsonl` | Audit log to migrate in place. |
| `--checkpoint <path>` | `<audit-dir>/.replay-checkpoint` | Replay checkpoint used by the boot seeding path. |
| `--backup-dir <path>` | `<audit-dir>` | Where rollback copies are written. |
| `--dry-run` | off | Log intended actions without writing. |
| `--list` | off | Print registered migrations and exit. |
| `--id <name>` | *(none)* | Run only the named migration, even if `Detect()` returns false (operator override). |
| `--reset-checkpoint` | off | Delete the replay checkpoint first (forces full replay on next server start). |

```bash
agentguard migrate --list
agentguard migrate --dry-run
agentguard migrate --audit-log /var/lib/agentguard/audit.jsonl
```

Startup migrations run automatically inside `agentguard serve` before the audit logger opens — the `migrate` subcommand is for operator-driven out-of-band runs.

---

## `agentguard version`

```bash
agentguard version
# agentguard 0.4.1 (abc1234)
```

The `version` string is baked in at build time via `-ldflags "-X main.version=... -X main.commit=..."` (see `Makefile`).

---

## Environment variables

| Var | Consumed by | Default |
|---|---|---|
| `AGENTGUARD_API_KEY` | `approve`, `deny`, `status`, `audit` (when `--api-key` unset) | empty |
| `AGENTGUARD_URL` | SDKs (not the CLI) | `http://localhost:8080` |

The CLI does **not** read `AGENTGUARD_URL` — pass `--url` explicitly. Only the Python/TypeScript SDKs honor that env var.

---

## Related docs

- [`docs/SETUP.md`](SETUP.md) — getting a server running in 10 minutes.
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — reverse proxy, TLS, CORS, bind behavior.
- [`docs/API.md`](API.md) — HTTP surface the CLI calls.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — what `validate` checks.
