# CLI Reference

Every AgentGuard subcommand, every flag, every env-var fallback. Source of truth: `cmd/agentguard/main.go`.

```
agentguard <command> [flags]

Commands:
  serve       Start the AgentGuard proxy server
  validate    Validate a policy file
  check       Run a one-shot policy check against a local policy file
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

## `agentguard check`

Run a single policy check (or a batch from stdin) against a local policy file **without going through the HTTP server**. Useful in CI pipelines, pre-commit hooks, and one-shot scripts that want a deterministic verdict on a candidate action.

### Synopsis

```
agentguard check [flags]
```

### Input modes (mutually exclusive)

Exactly one of these selects how requests enter the subcommand. Specifying more than one returns exit code `3`.

| Mode | How |
|---|---|
| Per-field flags (default) | `--scope`, `--command`, `--path`, `--domain`, `--url`, `--action`, `--agent-id`, `--session-id`, `--est-cost`, `--meta` |
| `--request '<json>'` | One JSON object inline on the command line |
| `--stdin` | One JSON object read from stdin |
| `--batch` | JSON Lines (one request per line) read from stdin |

### Flags

| Flag | Default | Description |
|---|---|---|
| `--policy <path>` | *(required)* | Policy YAML to evaluate against. Validated at startup; missing or malformed → exit 3. |
| `--tenant-id <id>` | `local` | Tenant identifier. v0.5 only recognises `local`; any other value resolves to a synthetic `DENY` with `matched_rule="deny:tenant:not_found"`. |
| `--request <json>` | *(empty)* | Single check from a JSON string. Mutually exclusive with `--stdin`/`--batch`. |
| `--stdin` | off | Read a single JSON request object from stdin. |
| `--batch` | off | Read JSONL (one request per line) from stdin. |
| `--output <fmt>` | `text` | Output format: `text` (human-friendly) or `json` (one JSON object per request, matching the `/v1/check` response shape). |
| `--scope <name>` | *(empty)* | Required for the per-field flag mode. `shell`, `filesystem`, `network`, `cost`, `data`, etc. |
| `--command <str>` | *(empty)* | Shell command to evaluate (shell scope). |
| `--action <name>` | *(empty)* | Action name (`read`, `write`, `delete`, ...) — typically paired with `--path`. |
| `--path <p>` | *(empty)* | Filesystem path. |
| `--domain <d>` | *(empty)* | Network domain. |
| `--url <u>` | *(empty)* | Request URL. |
| `--agent-id <id>` | *(empty)* | Agent identifier (drives per-agent overrides in the policy). |
| `--session-id <id>` | *(empty)* | Session identifier (cost accumulator key). |
| `--est-cost <f>` | `0` | Estimated cost (cost scope). |
| `--meta <pairs>` | *(empty)* | Comma-separated `k=v` pairs (e.g. `team=ml,prio=high`). For metadata containing commas/quotes, use `--request '{"meta":{}}'` instead. |

### Exit codes

The subcommand returns a structured exit code so shell pipelines can branch on the outcome.

| Code | Meaning |
|---|---|
| `0` | ALLOW — single mode; or every entry ALLOW in batch mode. |
| `1` | DENY — single mode; or any entry DENY in batch mode. |
| `2` | REQUIRE_APPROVAL — single mode; or any approval and no deny in batch mode. |
| `3` | Error — missing/invalid policy, malformed JSON, flag misuse, mutually exclusive modes. |

Severity precedence in batch mode is **error > deny > approval > allow**, regardless of numeric exit-code ordering. (`exitDeny=1` numerically precedes `exitApproval=2`, but a deny still dominates because a deny is operationally more severe than an approval request.)

### Examples

```bash
# Per-field flag mode — the simplest form.
agentguard check --policy configs/default.yaml \
  --scope shell --command "rm -rf ./old_data" --agent-id my-bot

# Single check via inline JSON request.
agentguard check --policy configs/default.yaml \
  --request '{"scope":"shell","command":"ls","agent_id":"my-bot"}'

# Single check via stdin.
echo '{"scope":"shell","command":"ls","agent_id":"my-bot"}' | \
  agentguard check --policy configs/default.yaml --stdin

# Batch mode (JSONL via stdin).
cat <<EOF | agentguard check --policy configs/default.yaml --batch
{"scope":"shell","command":"ls","agent_id":"bot1"}
{"scope":"shell","command":"rm -rf /","agent_id":"bot1"}
{"scope":"network","domain":"api.openai.com","agent_id":"bot1"}
EOF

# JSON output for downstream tooling.
agentguard check --policy configs/default.yaml \
  --request '{"scope":"shell","command":"ls"}' --output json
# {"schema_version":"v1","decision":"DENY","reason":"...","matched_rule":"..."}
```

### CI gate example

Fail the pipeline if any deploy command would be denied:

```bash
# deploy_actions.jsonl contains one ActionRequest per line.
if ! agentguard check --policy ci-policy.yaml --batch --output json \
       < deploy_actions.jsonl > /tmp/check_out.jsonl; then
  echo "Policy violation in deploy plan; see /tmp/check_out.jsonl"
  exit 1
fi
```

### Behavior notes

- The subcommand is **one-shot** — no policy hot-reload. Each invocation reloads the policy. Long-running pipelines that re-invoke `check` per action pay the load cost each time. (`--watch <jsonl-file>` for streaming evaluation is tracked as a v0.6 follow-up.)
- The decoder rejects unknown JSON fields. A typo like `"actions":"read"` (instead of `"action":"read"`) returns exit `3`, so silent default-deny on a malformed request is impossible.
- Cost-scope evaluations DO reserve session cost into the in-memory accumulator for the lifetime of the process, but the accumulator is discarded on exit. Two consecutive `agentguard check` calls do not see each other's reservations — that's a server feature, not a CLI feature.

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
