# CLI Reference

Every `agentguard` (central server) subcommand, every flag, every env-var fallback. Source of truth: `cmd/agentguard/main.go` and `cmd/agentguard/cli.go`.

> **Scope:** this page documents the `agentguard` binary — the central server that owns the policy engine, audit log, approval queue, and dashboard. For the v0.5 wire-level proxy binaries see [`MCP_GATEWAY.md`](MCP_GATEWAY.md) (`agentguard-mcp-gateway`) and [`LLM_API_PROXY.md`](LLM_API_PROXY.md) (`agentguard-llm-proxy`).

```
agentguard <command> [flags]

Set up and run:
  setup       Set up, update or remove AgentGuard on this computer (a menu)
  server      Start AgentGuard: policy engine, approvals, audit log, dashboard

Policies:
  validate    Check that a policy file loads
  check       Evaluate one action against a policy file (no server needed)
  tenant      Manage per-tenant policies in the store (put|list|rm)

Work with a running server:
  status      Show server health and pending approvals
  approve     Approve a pending action by ID
  deny        Deny a pending action by ID
  audit       Query the audit log

Other:
  migrate     Upgrade the audit log's format (the server does this at startup)
  version     Print version information (also: --version)
  help        Show help for a command

Get started:
  agentguard setup
      Set AgentGuard up to run at login, with a policy and an API key
  agentguard server --dashboard
      Or start the server yourself, then open http://localhost:8080/dashboard
  agentguard check --scope shell --command "rm -rf /"
      Try the policy on one action, no server needed

Also installed:
  agentguard-mcp-gateway   Guards the tools of an MCP client (Claude Desktop,
                           Cursor, …)
  agentguard-llm-proxy     Guards tool calls in OpenAI / Anthropic SDK code

Run 'agentguard help <command>' (or 'agentguard <command> -h') for its flags.
```

Every command's help (`agentguard help <command>`) has examples and says what its exit codes mean; the full list also shows the environment variables and a link to this page for the installed version.

Global conventions:
- `agentguard serve` is the same command as `agentguard server` and keeps working for the whole 1.x line ([`COMPATIBILITY.md`](COMPATIBILITY.md#frozen-surface-4--cli-flags--subcommands)).
- Flags can go before or after positional arguments: `agentguard approve <id> --url <url>` and `agentguard approve --url <url> <id>` are the same. A `--` ends the flags; everything after it is an argument.
- `agentguard help`, `-h` and `--help` print help on stdout and exit `0`; so do `agentguard help <command>` and `agentguard <command> -h`. A mistyped command or flag gets a suggestion: `agentguard: unknown command "--serve". Did you mean 'agentguard server'?`
- `--api-key` on `server` and on the client subcommands (`approve`, `deny`, `status`, `audit`) falls back to the `AGENTGUARD_API_KEY` env var; `--url` on the client subcommands falls back to `AGENTGUARD_URL`; `--policy` on `server`, `validate` and `check` is found automatically when not given (see [Policy file](#policy-file)).
- Exit code `0` = success, `1` = failure, `2` = the command line was wrong (unknown command or flag, missing or extra argument). `check` has its own codes — see below.

---

## `agentguard setup`

Set AgentGuard up on this computer, keep it current and remove it, from a menu: move with ↑/↓, choose with Enter, go back with Esc. It has no flags; every action is a menu item. It needs a terminal: scripts use the [one-line installers](SETUP.md#1-install), which install, update and uninstall too.

**Set up** (the first run) asks two questions — start AgentGuard at login? protect it with an API key? — then does this, skipping what's already there:

| Step | Linux / macOS | Windows |
|---|---|---|
| Starter policy (an existing one is kept) | `~/.config/agentguard/default.yaml` | `%APPDATA%\agentguard\default.yaml` |
| Data folder: audit log, state database, server log | `~/.local/share/agentguard` | `%LOCALAPPDATA%\AgentGuard\data` |
| API key, readable only by you | `~/.config/agentguard/api-key` | `%APPDATA%\agentguard\api-key` |
| Start at login, without admin rights | systemd user service `agentguard.service` / LaunchAgent `com.lictorate.agentguard` | Task Scheduler task `AgentGuard`, at your logon |

The service runs `agentguard server --policy … --data-dir … --audit-log … --port 8080 --bind 127.0.0.1 --dashboard --api-key-file …`, on the next free port when 8080 is taken. The key goes in as a file, so it never appears in the service definition or the process list. `XDG_CONFIG_HOME` and `XDG_DATA_HOME` move the Linux and macOS folders.

**Later runs** show whether the server is running and offer: open the dashboard (the API key goes to the clipboard for its login), update, start or restart the server, connection details (the URL, where the key is, the lines for the SDKs, and a Claude Desktop block with no secret in it), open the policy file, change settings, and — last, under a divider — uninstall.

**Update** installs the newest release (or `AGENTGUARD_VERSION`) for this OS and CPU, from GitHub or from `AGENTGUARD_DOWNLOAD_URL`, like the installers. It checks the archive against the release's `checksums.txt`, swaps the three binaries in place — a running server keeps going until it restarts — and restarts the service. A `go install` copy gets the `go install` command instead; a source build and the container image don't update themselves.

**Uninstall** offers, in this order: stop the server and don't start it at login; uninstall and keep the policy, key and data; uninstall everything; cancel. It removes the login service and the three binaries — on Windows also the installer's PATH entry, and the running `.exe` right after setup exits — works offline, and prints a link for feedback. Nothing is sent.

Opening the menu checks GitHub for a newer release unless `AGENTGUARD_NO_UPDATE_CHECK` is set; the menu then offers "Check for updates". setup refuses to run as root (it sets AgentGuard up for your own user; for a system-wide server see [`DEPLOYMENT.md`](DEPLOYMENT.md)) and inside the container image.

---

## `agentguard server`

Start the AgentGuard server. This is the only subcommand that runs a long-lived process. `agentguard serve` is the same command.

`agentguard server -h` prints the flags below grouped by topic (network, security, policy, audit log, storage, multi-node, notifications, debugging).

| Flag | Default | Description |
|---|---|---|
| `--policy <path>` | found automatically | Path to policy YAML. When not given, see [Policy file](#policy-file). Rejected at startup if missing or invalid; the startup log names the file it loaded. |
| `--port <int>` | `8080` | TCP port. See bind behavior below. |
| `--bind <host>` | *(empty)* | **(v1.2)** Host or IP to listen on, e.g. `127.0.0.1` behind a same-host reverse proxy. Empty keeps the default bind behavior below. A non-loopback `--bind` without `--api-key` is refused at startup (exit 2). |
| `--dashboard` | off | Serve `/dashboard` HTML + `/api/stream` SSE. Required for human approval UI. |
| `--watch` | off | Log a line each time the policy file is reloaded. The reload itself always happens, with or without this flag (fsnotify events, with a 2 s mtime poll as fallback); no restart needed after policy edits. |
| `--audit-log <path>` | `audit.jsonl` | Append-only JSON Lines file. Mode `0600`. Rotation is on by default; configurable via `--audit-max-size-mb`, `--audit-max-backups`, `--audit-max-age-days`, `--audit-compress`. Operators following older guidance should NOT also configure logrotate against `audit.jsonl` — the dual-rotator chain corrupts the rotation index. See [`OPERATIONS.md`](OPERATIONS.md#audit-log-rotation). |
| `--api-key <key>` | `$AGENTGUARD_API_KEY` | Bearer token for gated endpoints. **If empty, the server binds to `127.0.0.1` only** (localhost-only). |
| `--api-key-file <path>` | *(empty)* | Read the API key from the first line of this file instead of the command line, where other users of the machine could see it. `--api-key` wins over it; it wins over `AGENTGUARD_API_KEY`. The server refuses to start when the file can't be read or is empty, rather than run unprotected. `agentguard setup` uses it. |
| `--base-url <url>` | `http://localhost:<port>` | External URL used when constructing `approval_url` in check responses. Set this behind a reverse proxy. |
| `--allowed-origin <url>` | *(empty)* | Exact CORS origin. Empty = permissive-localhost (accepts any `http://localhost:*` or `http://127.0.0.1:*`). Set to `https://app.example` for strict single-origin. |
| `--tls-terminated-upstream` | off | Issue session cookies with `Secure` even when `r.TLS == nil`. Set when behind a TLS-terminating proxy that does not forward `X-Forwarded-Proto`. See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| `--session-cost-ttl <dur>` | `0` (never expire) | Evict idle session-cost accumulator entries. Example: `24h`. Zero keeps v0.4.0 behavior. |
| `--session-cost-sweep-interval <dur>` | `max(ttl/4, 1m)` | Sweeper cadence. Ignored when `--session-cost-ttl 0`. |
| `--approval-validity <dur>` | `5m` | How long a resolved approval is honored by the `/v1/check` approval-id retry, measured from resolution. Past the window the retry re-enters the approval flow under a new id. `0` disables the bound. Default matches the SDKs' `wait_for_approval` poll window. Resolved ALLOWs are additionally **one-shot** regardless of this flag — see [`APPROVAL_WORKFLOW.md`](APPROVAL_WORKFLOW.md#one-shot-consumption-and-validity). |
| `--audit-max-size-mb <int>` | `100` | Rotate when the live audit file reaches this MiB. `0` disables rotation entirely (v0.4.x behavior — unbounded growth). See [`OPERATIONS.md`](OPERATIONS.md#audit-log-rotation). |
| `--audit-max-backups <int>` | `5` | Maximum number of rotated archives to retain. `0` keeps all archives indefinitely. |
| `--audit-max-age-days <int>` | `30` | Maximum age (days) of archived audit files. Older archives pruned at rotation time. `0` disables age-based pruning. |
| `--audit-compress` | `true` | gzip-compress rotated archives. Disable for plain JSONL siblings. |
| `--audit-redact` | `true` | **(v1.2)** Mask secrets (API keys, tokens, passwords, private keys, credential headers — see [OPERATIONS § Audit redaction](OPERATIONS.md#audit-redaction)) in requests before they reach the audit log, `GET /v1/audit`, the SSE stream, the dashboard and the pending-approvals list. The policy's `notifications.redaction.extra_patterns` apply too. `false` stores requests verbatim and logs a startup warning. |
| `--audit-buffered` | `true` | Wrap the audit logger in a bounded async queue with disk-overflow durability so `/v1/check` no longer waits on the audit mutex. Disable to write straight to FileLogger (v0.4.x behavior). |
| `--audit-queue-size <int>` | `1024` | Bounded queue size for the buffered async logger. Ignored unless `--audit-buffered`. |
| `--audit-workers <int>` | `4` | Worker goroutines draining the buffered audit queue. Ignored unless `--audit-buffered`. |
| `--audit-overflow-path <path>` | `<audit-log>.overflow.jsonl` | Disk-overflow spill file used when the buffered queue saturates. Ignored unless `--audit-buffered`. |
| `--notify-spool <path>` | *(empty)* | *(v0.7)* JSONL spool file for notification events that overflow the dispatch queue — spooled events are redelivered by a recovery loop (including leftovers from a previous process) instead of dropped. Empty disables (drop-on-full). |
| `--debug-pprof` | off | Expose Go pprof handlers on a **separate localhost-only** listener (`--debug-pprof-port`). Off by default; enable for performance investigations only. Tunnel via `kubectl port-forward` / `ssh -L` to access remotely — this listener never binds beyond `127.0.0.1`. |
| `--debug-pprof-port <int>` | `6060` | Port for the localhost-only pprof listener. Ignored unless `--debug-pprof`. |
| `--persist` | `true` | **(v0.6)** Persist runtime state (approvals, rate-limit buckets, cost accumulators) to a durable store so it survives restarts. Zero-config: auto-creates `agentguard.db` (SQLite). Set `false` for pure in-memory (pre-v0.6 behavior). The store is **never** on the `/v1/check` hot path — a background syncer flushes snapshots on a ≥1 s tick and hydrates memory on boot. See [Persistence & multi-tenancy](#persistence--multi-tenancy-v06). |
| `--store-dsn <dsn>` | *(empty)* | **(v0.6)** Durable store location. Empty ⇒ zero-config SQLite at `<data-dir>/agentguard.db`; a SQLite file path is also accepted. **(v1.0)** A `postgres://` / `postgresql://` DSN selects the PostgreSQL backend — required for [multi-node deployments](OPERATIONS.md#multi-instance-deployments). Ignored when `--persist=false`. |
| `--data-dir <path>` | `.` | **(v0.6)** Directory for the zero-config SQLite database (`agentguard.db` + its `-wal`/`-shm` sidecars). Ignored when `--store-dsn` is set or `--persist=false`. |
| `--node-id <id>` | *(hostname)* | **(v1.0)** This replica's identity in the shared PostgreSQL store. Must be distinct per replica (two processes on one host need explicit values; in Kubernetes pass the pod name). No effect on the SQLite backend. |
| `--reconcile-interval <dur>` | `2s` | **(v1.0)** Cadence of the background reconcile that merges other nodes' rate/cost consumption and approval state into this node's in-memory view (and publishes this node's). Postgres-only: forced off on the SQLite backend. Smaller ⇒ tighter rate-limit overshoot bound and fresher cross-node approvals, more store traffic. Never touches the `/v1/check` hot path. |
| `--audit-backend <file\|store>` | `file` | **(v0.6)** Where the audit trail lives. `file` = JSONL (rotation + migration, the default). `store` = the durable store's indexed `audit_entries` table (one-file deployment, indexed `/v1/audit` queries). `store` requires `--persist` and always runs buffered (async) — a synchronous DB write per request would break the <3 ms budget, so buffering is forced. |

### Policy file

When `--policy` is not given, `server`, `validate` and `check` use the first of:

1. `$AGENTGUARD_POLICY`.
2. `configs/default.yaml` in the current folder (the flag's default, so running from a checkout works as before).
3. The starter policy the [installer](SETUP.md#1-install) writes: `$XDG_CONFIG_HOME/agentguard/default.yaml` (else `~/.config/agentguard/default.yaml`, on macOS too), then `/etc/agentguard/default.yaml` (a root install, and the container image). On Windows, `%APPDATA%\agentguard\default.yaml`.

If none exists, the command stops and lists where it looked. `validate` and `check` print `Using policy file <path> (…)` on stderr when the file wasn't named with `--policy`; the server's startup log always names it (`Loaded policy: <name> from <path> …`).

### Bind behavior

- `--api-key` **set**: binds on `0.0.0.0:<port>` (all interfaces).
- `--api-key` **unset**: binds on `127.0.0.1:<port>` only. An INFO line is logged at startup. Remote agents cannot connect. This is the #1 source of "connection refused" for new users.
- `--bind <host>` **(v1.2)**: binds on `<host>:<port>` instead. With `--api-key` any address is accepted; without one only a loopback address (`127.0.0.1`, `::1`, `localhost`) is, and anything else exits 2 before listening. Use `--bind 127.0.0.1` with `--api-key` when a reverse proxy on the same host is the only client.

### Persistence & multi-tenancy (v0.6)

By default `server` is **stateful**: runtime state survives a restart. On a clean run `agentguard server` creates `agentguard.db` in the working directory (override with `--data-dir`) and:

- **hydrates** the in-memory approval queue, rate-limit buckets, and cost accumulators from the store on boot, then
- **write-behind syncs** them back on a background ticker (≥ 1 s) and on graceful shutdown.

The store is a *cold-path* component — it is never read or written on the `/v1/check` request path, so the <3 ms p99 budget is unaffected. Disable with `--persist=false` for the legacy pure-in-memory behavior.

**Multi-node (v1.0).** With `--store-dsn postgres://…`, every replica shares the same durable tier and additionally reconciles its in-memory state with the other nodes every `--reconcile-interval` (default 2s), identified by `--node-id`. Memory stays authoritative per node — reconciliation is background-only, so distributed rate/cost limiting is bounded-overshoot rather than globally strict, and cross-node approval staleness is at most one interval. Semantics and sizing guidance: [`OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments).

**Tenancy.** The `local` tenant's policy comes from `--policy`. Additional tenants are registered in the store with [`agentguard tenant`](#agentguard-tenant-v06) and addressed via the `/v1/t/<tenant>/...` route family; each tenant is evaluated against its **own** policy, with isolated approvals, rate limits, cost accumulators, and audit. A tenant that has no registered policy is rejected over HTTP with `404 {"error":"tenant not found"}` (see [`API.md`](API.md#url-families-legacy-vs-tenant-aware-v05)); the offline [`agentguard check --tenant-id`](#agentguard-check) path returns a synthetic DENY with `matched_rule="deny:tenant:not_found"`.

### Examples

```bash
# Local dev — localhost-only, dashboard on, a log line per policy reload.
agentguard server --policy configs/default.yaml --dashboard --watch

# After the one-line installer: the starter policy is found automatically.
agentguard server --dashboard

# Production behind a reverse proxy.
agentguard server \
  --policy /etc/agentguard/policy.yaml \
  --audit-log /var/lib/agentguard/audit.jsonl \
  --api-key "$AGENTGUARD_API_KEY" \
  --base-url https://guardrails.example \
  --allowed-origin https://app.example \
  --tls-terminated-upstream \
  --session-cost-ttl 24h \
  --dashboard

# Multi-node (v1.0) — every replica points at the same PostgreSQL and
# carries its own --node-id (here: the pod name).
agentguard server \
  --policy /etc/agentguard/policy.yaml \
  --store-dsn "postgres://agentguard:$PGPASS@pg.internal:5432/agentguard" \
  --node-id "$POD_NAME" \
  --reconcile-interval 2s \
  --api-key "$AGENTGUARD_API_KEY"
```

### Signals

`SIGINT`/`SIGTERM` → graceful shutdown (drains in-flight requests up to the internal shutdown timeout, closes audit logger and notifier).

---

## `agentguard validate`

Load a policy file and report rule count / scope count. Give the file as an argument (`agentguard validate policy.yaml`) or with `--policy`; with neither, it validates the file the server would load (see [Policy file](#policy-file)). Exits `1` on parse error, load-time validation failure (e.g., `..` in a filesystem path), or missing required fields (`version`, `name`).

Non-fatal warnings go to stderr as `WARN: …` lines and don't change the exit code unless you pass `--strict`: a scope that appears in more than one block (the blocks are merged), a scope name one or two edits away from a built-in one (`shel` → "did you mean `shell`?"), and a path pattern whose single `*` crosses `/`. See [POLICY_REFERENCE § Load-time validation](POLICY_REFERENCE.md#load-time-validation).

| Flag | Default | Description |
|---|---|---|
| `--policy <path>` | found automatically | Policy file to validate. Same as giving it as an argument; passing both is an error. |
| `--strict` | `false` | **(v1.2)** Exit `1` if the policy loads with any warning. |

```bash
agentguard validate configs/examples/trading-bot.yaml
# VALID: trading-bot-policy — 14 rules across 4 scopes

agentguard validate /tmp/broken.yaml
# INVALID: yaml: unmarshal errors: line 4: cannot unmarshal !!int into string

agentguard validate /tmp/typo.yaml --strict
# WARN: policy: rules[1] scope "shel" is not a built-in scope — did you mean "shell"? …
# INVALID (--strict): my-policy loads, but with 1 warning(s)
```

Use in CI:

```bash
for f in configs/*.yaml configs/examples/*.yaml; do
  agentguard validate --strict "$f" || exit 1
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
| `--watch <file>` | *(v0.7)* Follow a JSONL file (tail -f) and verdict each appended request — one policy load for the whole stream, policy hot-reloads on edit. Runs until SIGINT/SIGTERM, then exits with the aggregate code |

### Flags

| Flag | Default | Description |
|---|---|---|
| `--policy <path>` | found automatically | Policy YAML to evaluate against. When not given, see [Policy file](#policy-file); nothing found → exit 3. Validated at startup; missing or malformed → exit 3. |
| `--tenant-id <id>` | `local` | Tenant identifier. The offline `check` command evaluates against the supplied policy file only — an unknown tenant resolves to a synthetic `DENY` with `matched_rule="deny:tenant:not_found"`. |
| `--request <json>` | *(empty)* | Single check from a JSON string. Mutually exclusive with `--stdin`/`--batch`. |
| `--stdin` | off | Read a single JSON request object from stdin. |
| `--batch` | off | Read JSONL (one request per line) from stdin. |
| `--watch <file>` | *(empty)* | Follow a JSONL file and verdict each appended request. Mutually exclusive with `--request`/`--stdin`/`--batch`. Only newline-terminated lines are processed (a torn mid-append write is buffered until completed); a malformed line aborts with exit 3. |
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
| `3` | Error — missing/invalid policy, malformed JSON, flag misuse (including an unexpected argument), mutually exclusive modes. |

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

# Watch mode: follow a JSONL file and verdict requests as they are
# appended (one policy load for the whole stream; Ctrl-C to stop and
# get the aggregate exit code).
agentguard check --policy configs/default.yaml --watch actions.jsonl

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

- Without `--watch`, the subcommand is **one-shot** — no policy hot-reload. Each invocation reloads the policy, so pipelines that re-invoke `check` per action pay the load cost each time; `--watch <jsonl-file>` streams requests through a single policy load instead.
- The decoder rejects unknown JSON fields. A typo like `"actions":"read"` (instead of `"action":"read"`) returns exit `3`, so silent default-deny on a malformed request is impossible.
- Cost-scope evaluations DO reserve session cost into the in-memory accumulator for the lifetime of the process, but the accumulator is discarded on exit. Two consecutive `agentguard check` calls do not see each other's reservations — that's a server feature, not a CLI feature.

---

## `agentguard approve <id>` / `agentguard deny <id>`

POST to `/v1/approve/{id}` or `/v1/deny/{id}`. Used by humans or scripts to resolve `REQUIRE_APPROVAL` decisions.

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | `$AGENTGUARD_URL`, else `http://localhost:8080` | Server URL. Must include the scheme (`http://` or `https://`). |
| `--guard-url <url>` | | Same as `--url` (the name the MCP gateway and LLM proxy use). |
| `--api-key <key>` | `$AGENTGUARD_API_KEY` | Bearer token. Required if the server was started with `--api-key`. |

```bash
agentguard approve ap_1a2b3c4d5e6f7890abcdef1234567890
# Approved ap_1a2b3c4d5e6f7890abcdef1234567890

AGENTGUARD_API_KEY=$KEY agentguard deny ap_deadbeef… --url https://guardrails.example
# Denied ap_deadbeef…
```

Exit `1` when the server can't be reached or answers with an error, each with a message that says what to do: `Cannot connect to AgentGuard at … (connection refused). Is 'agentguard server' running there?`, `the server requires an API key (HTTP 401)`, `no pending approval ap_… (…)`, `ap_… was already approved`. Exit `2` for a missing or extra argument. Approval IDs are `ap_<32hex>` as returned by `/v1/check`.

---

## `agentguard status`

Quick human-readable health + pending list. Hits `/health` (unauthenticated) then `/api/pending` (authenticated).

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | `$AGENTGUARD_URL`, else `http://localhost:8080` | Server URL. |
| `--guard-url <url>` | | Same as `--url`. |
| `--api-key <key>` | `$AGENTGUARD_API_KEY` | Bearer token. |

```bash
agentguard status
# AgentGuard server: OK (http://localhost:8080)
# Pending approvals: 2
#   [ap_123…] scope=shell action="rm -rf ./old_data" agent=researcher-01
#   [ap_456…] scope=cost  action=""                   agent=trading-bot
```

If the server is running without `--api-key`, pending approvals appear unauthenticated. If you set `--api-key` on the server but not here, the pending list shows "unauthorized". `/api/pending` exists only when the server runs with `--dashboard`; without it the line reads `Pending approvals: unavailable (the server was started without --dashboard)`. The exit code is `1` only when the server can't be reached.

---

## `agentguard audit`

Query `/v1/audit` for recent decisions. All filters are optional and AND-combined.

| Flag | Default | Description |
|---|---|---|
| `--url <url>` | `$AGENTGUARD_URL`, else `http://localhost:8080` | Server URL. |
| `--guard-url <url>` | | Same as `--url`. |
| `--agent <id>` | *(none)* | Filter by exact `agent_id`. |
| `--decision <D>` | *(none)* | `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. |
| `--scope <name>` | *(none)* | `shell`, `filesystem`, `network`, `browser`, `cost`, `data`, `mcp_tool`. |
| `--transport <name>` | *(none)* | Filter by audit `transport` tag. One of `sdk`, `mcp_gateway`, `llm_api_proxy`. Pre-v0.5 entries are excluded when set. |
| `--limit <int>` | `50` | Max entries. Server clamps silently above configured ceiling (default 1000). |
| `--order <desc\|asc>` | `desc` | **(v1.2)** `desc` shows the newest entries first; `asc`, the oldest (the order before v1.2, when `--limit` returned the first entries in the log rather than the latest). |
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

## `agentguard tenant` (v0.6)

Manage per-tenant policies in the durable store. Operates directly on the store database (the server need not be running — SQLite WAL permits a concurrent writer, and a running server picks up a new tenant on its next lookup). Requires persistence (the store); these commands open it directly.

```
agentguard tenant put <tenant-id> --policy <file.yaml> [--store-dsn <dsn>] [--data-dir <dir>]
agentguard tenant list                                 [--store-dsn <dsn>] [--data-dir <dir>]
agentguard tenant rm  <tenant-id>                      [--store-dsn <dsn>] [--data-dir <dir>]
```

| Subcommand | Description |
|---|---|
| `put <id> --policy <f>` | Validate `<f>` (same checks as `validate`) and register it as tenant `<id>`'s policy. Re-running replaces it. A malformed policy is rejected and never stored. The tenant ID can come before or after the flags. |
| `list` | List every registered tenant id (the `local` tenant is served from `--policy`, not the store, so it is not listed). |
| `rm <id>` | Remove a tenant's policy. Reports whether a row existed. |

`--store-dsn` / `--data-dir` resolve the database exactly like [`server`](#agentguard-server) (empty DSN ⇒ `<data-dir>/agentguard.db`).

```bash
# Register a tenant, then check it via its tenant-aware route.
agentguard tenant put acme --policy acme-policy.yaml
agentguard tenant list
#   Registered tenants (1):
#     acme
curl -s -X POST localhost:8080/v1/t/acme/check \
  -H 'Content-Type: application/json' \
  -d '{"scope":"shell","command":"deploy app"}'
# → evaluated against acme's policy, independently of the local tenant
```

> A tenant added while the server is running is loaded lazily on its first `/v1/t/<id>/...` request (one store read, then cached). Tenants present at boot are eager-loaded.

---

## `agentguard migrate`

Run registered on-disk audit-schema migrations. Each migration has a `Detect()` step — it only runs if the on-disk format matches. See [`FILE_FORMATS.md`](FILE_FORMATS.md) for the schema history.

| Flag | Default | Description |
|---|---|---|
| `--audit-log <path>` | `audit.jsonl` | Audit log to migrate in place. |
| `--checkpoint <path>` | `<audit-log>.replay-checkpoint` | The replay checkpoint `agentguard server` reads at boot — `audit.CheckpointSuffix` appended to the audit log path, i.e. the very file the startup seeder writes. |
| `--backup-dir <path>` | `<audit-dir>` | Where rollback copies are written. |
| `--dry-run` | off | Log intended actions without writing. |
| `--list` | off | Print registered migrations and exit. |
| `--id <name>` | *(none)* | Run only the named migration, even if `Detect()` returns false (operator override). |
| `--reset-checkpoint` | off | Delete the replay checkpoint first (forces a full replay on the next server start). Prints `checkpoint removed (<path>)` when a file was deleted and `no checkpoint found at <path>` otherwise — it never reports success for a file that was not there. |

```bash
agentguard migrate --list
agentguard migrate --dry-run
agentguard migrate --audit-log /var/lib/agentguard/audit.jsonl
```

Startup migrations run automatically inside `agentguard server` before the audit logger opens — the `migrate` subcommand is for operator-driven out-of-band runs.

---

## `agentguard version`

`agentguard --version` (or `-version`) is the same command since v1.2, matching the MCP gateway and LLM proxy flags.

```bash
agentguard version
# agentguard 1.2.0 (abc1234)
```

The version comes from the source; the part in parentheses identifies the build:

| Built with | Shows |
|---|---|
| `make build` (`-ldflags "-X main.commit=…"`) | the git short hash, e.g. `abc1234` |
| `go install …/cmd/agentguard@vX.Y.Z` or `@latest` | `module vX.Y.Z` (from Go build info) |
| `go build` in a git checkout | the short VCS revision, with `-dirty` if the tree had local changes |
| `make docker` (`--build-arg COMMIT=…`) | the git short hash |
| any build with neither ldflags nor VCS information | `dev` |

### Update notice on startup (v0.5.1+)

The interactive subcommands (`check`, `validate`, `approve`, `deny`, `status`, `audit`, `migrate`, `tenant`, `version`) kick off an async best-effort check against the GitHub Releases API at startup (800 ms wait budget, 1.5 s HTTP timeout). If a newer release exists, one line lands on stderr before subcommand output; otherwise silent.

```
Notice: AgentGuard v1.3.0 is available (you have v1.2.0). Update: agentguard setup — what's new: https://github.com/Caua-ferraz/AgentGuard/releases/latest
```

The command it names depends on how this copy was installed:

| Installed with | Update command in the notice |
|---|---|
| The one-line installer or a release archive | `agentguard setup` (choose Update); re-running the installer works too |
| `go install …@vX.Y.Z` / `@latest` | `go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest` |
| The container image (it sets `AGENTGUARD_DISTRIBUTION=container`) | `docker pull ghcr.io/caua-ferraz/agentguard:latest`, then recreate the container |

Both replace the binaries and keep your policy, and say whether they updated or downgraded (with a warning). See [`SETUP.md`](SETUP.md#update).

`server` never performs the check (nor does `serve`, the same command): the enforcement server opens no outbound connection the operator did not configure (see [`THREAT_MODEL.md`](THREAT_MODEL.md#outbound-connections)). The check is also skipped for development builds — a version string containing `dev`, or no `-ldflags` commit (`commit=dev`) *and* no tagged release version in the Go build info, as with `go build` on an untagged or modified checkout. `go install …@vX.Y.Z` and `@latest` builds record the release tag, so they do check. It is also skipped when `AGENTGUARD_NO_UPDATE_CHECK` is set to any value other than `0`, or when the HTTP request fails. It is not run for `agentguard help` or a mistyped command either. Never touches stdout, never affects exit codes. Only the `agentguard` binary has the check; the MCP gateway and LLM proxy never had one.

---

## Environment variables

| Var | Consumed by | Default |
|---|---|---|
| `AGENTGUARD_API_KEY` | `server`, `approve`, `deny`, `status`, `audit` (when `--api-key` unset); the MCP gateway and LLM proxy; the SDKs | empty |
| `AGENTGUARD_URL` | `approve`, `deny`, `status`, `audit` (when `--url` unset); the MCP gateway and LLM proxy (when `--guard-url` unset); the SDKs | `http://localhost:8080` (CLI, SDKs), `http://127.0.0.1:8080` (gateway, proxy) |
| `AGENTGUARD_POLICY` | `server`, `validate`, `check` (when `--policy` unset) — see [Policy file](#policy-file) | unset |
| `AGENTGUARD_NO_UPDATE_CHECK` | Every subcommand except `server` (which never checks) — disables the GitHub Releases startup check when set to any value other than `0` | unset |

A flag always wins over its environment variable. When no key is given at all, `approve`, `deny`, `status`, `audit`, the MCP gateway and the LLM proxy use the key [`agentguard setup`](#agentguard-setup) saved (`~/.config/agentguard/api-key`, `%APPDATA%\agentguard\api-key`). The server never picks that file up by itself — a key changes which interfaces it listens on — only through `--api-key-file`.

---

## Related docs

- [`docs/SETUP.md`](SETUP.md) — getting a server running in 10 minutes.
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — reverse proxy, TLS, CORS, bind behavior.
- [`docs/API.md`](API.md) — HTTP surface the CLI calls.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — what `validate` checks.
- [`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md) — flags and configuration for the `agentguard-mcp-gateway` binary.
- [`docs/LLM_API_PROXY.md`](LLM_API_PROXY.md) — flags and configuration for the `agentguard-llm-proxy` binary.
