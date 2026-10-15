# Policy Reference

Canonical reference for the AgentGuard policy YAML format as of **v1.3.0**.

Source of truth: `pkg/policy/engine.go` (types) and `pkg/policy/engine.go:Engine.Check` (evaluation). Examples here are the shapes the Go YAML decoder accepts — unknown keys are silently ignored.

---

## Table of contents

- [Top-level document](#top-level-document)
- [Rule sets and scopes](#rule-sets-and-scopes)
- [Rule fields](#rule-fields)
- [Conditions](#conditions)
- [Rate limits](#rate-limits)
- [Cost guardrails](#cost-guardrails)
- [Data scope](#data-scope)
- [MCP tool scope (`mcp_tool`)](#mcp_tool-scope)
- [`tool_scope_map`](#tool_scope_map)
- [LLM API Proxy tool scope mapping](#llm-api-proxy-tool-scope-mapping)
- [Per-agent overrides](#per-agent-overrides)
- [Notifications](#notifications)
- [Proxy tunables](#proxy-tunables)
- [Evaluation order](#evaluation-order)
- [Compound shell commands](#compound-shell-commands)
- [Pattern matching semantics (read this)](#pattern-matching-semantics-read-this)
- [Load-time validation](#load-time-validation)
- [Testing policies](#testing-policies)

---

## Top-level document

```yaml
version: "1"                       # required — free-form string
name: "development-sandbox"        # required — shown in logs
description: "…"                   # optional

rules: [...]                       # optional — array of RuleSets, see below
agents: {...}                      # optional — per-agent overrides
notifications: {...}               # optional — Slack / webhook / console targets
proxy: {...}                       # optional — server-side tunables
```

Both `version` and `name` are required. Absence returns `policy missing required '<field>' field` at load.

---

## Rule sets and scopes

A `RuleSet` groups rules that share a scope. Scopes are free strings — AgentGuard ships with dedicated handling for a few and treats everything else generically.

```yaml
rules:
  - scope: shell
    allow: [...]
    deny: [...]
    require_approval: [...]
    rate_limit: { max_requests: 30, window: "1m" }
    limits: { max_per_action: "$1.00", ... }   # only meaningful for scope: cost
```

| Scope | Dedicated handling | Typical fields on each rule |
|---|---|---|
| `shell` | a command with shell syntax is checked one command at a time — see [compound shell commands](#compound-shell-commands) | `pattern`, optional `conditions` |
| `filesystem` | `..` path-traversal guard at load + at request time | `action`, `paths` |
| `network` | none | `domain` or `pattern` |
| `browser` | none | `domain` |
| `cost` | dedicated `checkCost` evaluator; `limits` block | no rule fields — driven entirely by `limits` and `est_cost` on the request |
| `data` | none (generic) | `pattern`, `action` (`form_input`), `domain` — see [data scope](#data-scope) |
| `mcp_tool` | none (generic) | `pattern` matched against `<namespace>:<tool>` — see [mcp_tool scope](#mcp_tool-scope) |
| *any other string* | none | generic; `pattern`/`action`/`domain` all still work — a custom scope applies to requests that send exactly that scope string. A name one or two edits from a built-in one is flagged at load as a likely typo |

**One rule set per scope.** If a scope appears in more than one block of `rules:` (or of one agent's `override:`), the blocks are merged at load, in file order: their `deny`, `require_approval` and `allow` rules are combined, so deny → require_approval → allow precedence holds across them. `agentguard validate` prints a `WARN` line for each merge. A `rate_limit` or `limits` set in more than one of the merged blocks must be identical, or the policy is rejected. Before v1.2.0 the first block that decided won, and a `deny` in a later block for the same scope never applied.

### Scope field reference

- `scope` (**required**) — the scope string. Must match the `scope` field on the incoming `POST /v1/check` request for the RuleSet to apply.
- `allow` / `deny` / `require_approval` — arrays of `Rule`s.
- `rate_limit` — optional `{max_requests, window}`. Applied before rule evaluation; exceeding the bucket returns synthetic `DENY` with `matched_rule = "deny:ratelimit:<scope>"`.
- `limits` — optional `{max_per_action, max_per_session, alert_threshold}`. Only interpreted when `scope: cost`.

---

## Rule fields

All fields are optional; you combine them to describe what matches.

| Field | Type | Meaning |
|---|---|---|
| `action` | string | Exact match against `ActionRequest.Action` (e.g., `"read"`, `"write"`, `"delete"`). |
| `pattern` | string | Glob match against `ActionRequest.Command` (or URL for `network`). See [pattern semantics](#pattern-matching-semantics-read-this). |
| `paths` | string array | One or more glob patterns matched against `ActionRequest.Path`. Each path **and** `req.Path` are passed through `filepath.Clean + ToSlash` first. |
| `domain` | string | Glob match against `ActionRequest.Domain` (or the host of `ActionRequest.URL` if `Domain` is empty). |
| `message` | string | Human-readable reason returned in `CheckResult.Reason` and shown in the dashboard. Defaults to a generic string. |
| `conditions` | `[]Condition` | Contextual constraints. See [Conditions](#conditions). All listed conditions must be satisfied for the rule to match. |

Minimum example:

```yaml
- scope: filesystem
  allow:
    - action: read
      paths: ["./workspace/**", "/tmp/**"]
  deny:
    - action: write
      paths: ["/etc/**", "/usr/**", "~/.ssh/**"]
      message: "system paths are read-only"
```

---

## Conditions

```yaml
- pattern: "git push *"
  conditions:
    - require_prior: "git status"
      time_window: "10m"
```

| Field | Type | Meaning |
|---|---|---|
| `require_prior` | string | A prior `ALLOW`ed action (matched by exact equality **or** glob) that must have been logged for this `agent_id` + `scope` within `time_window`. |
| `time_window` | string | Go duration string (e.g., `"10m"`, `"1h"`). Interpreted relative to `now` at the time of the check. |

**Backed by an in-memory index of the audit log.** The server keeps a `PriorActionIndex` (`pkg/policy/history_index.go`) of the newest `ALLOW` per tenant, `agent_id`, scope and action or command. It is seeded from the audit log at startup and updated on every `ALLOW`, so a condition check is a map lookup, not a log scan. The index has a TTL and size caps; history older than the TTL, or dropped at a cap, cannot satisfy a condition. Embedders that only set a `HistoryQuerier` get the older log-scan path, with a one-time warning.

### Footgun: `time_window` without `require_prior`

Setting only `time_window` is rejected at policy load — `LoadFromFile` fails with:

```
rules[0]("…").conditions[0]: time_window without require_prior is rejected; pair time_window with require_prior or remove it
```

In v0.4.x this was a silent no-op that only logged a WARNING; it **became a hard policy-load error in v0.5.0** (see [`DEPRECATIONS.md`](DEPRECATIONS.md)). Either remove the orphan `time_window` or add a `require_prior` clause.

To test a `require_prior` rule without a server, give the case `prior:` actions; see [Testing policies](#testing-policies).

### Footgun: no audit history → condition fails

If the `HistoryQuerier` is not wired (it is by default in `NewServer`), or the audit query returns an error, the condition is treated as **unsatisfied** and the rule does not match. This is fail-closed for `allow` rules and fail-open for `deny`/`require_approval` — review any condition-bearing rules with that in mind.

---

## Rate limits

```yaml
- scope: shell
  rate_limit:
    max_requests: 30
    window: "1m"
  allow: [...]
```

| Field | Type | Meaning |
|---|---|---|
| `max_requests` | int | Tokens per bucket. First call initializes the bucket at `max_requests - 1` (one consumed for the allowed request). |
| `window` | string | Go duration string (e.g., `"1s"`, `"30s"`, `"1m"`). On refill, `int(elapsed / window)` full periods advance the bucket and reset tokens to `max_requests`. |

**Key is `<scope>:<agent_id>`.** Per-agent, per-scope.

**In-memory; per-instance on the default SQLite store.** Multi-replica deployments on SQLite do not share buckets — agents can burst past the nominal cap by hitting different pods. With the v1.0 PostgreSQL backend, replicas share consumption via background reconcile (bounded-overshoot: brief bursts can still exceed the cap by ≈ `reconcile-interval × peak rate` per extra replica). See [`docs/OPERATIONS.md`](OPERATIONS.md#multi-instance-deployments).

A rate-limit denial produces `CheckResult{Decision: DENY, Rule: "deny:ratelimit:<scope>"}` and increments `agentguard_rate_limited_total`.

---

## Cost guardrails

Applies only when `scope: cost`. The incoming request must carry a numeric `est_cost`.

```yaml
- scope: cost
  limits:
    max_per_action: "$1.00"
    max_per_session: "$50.00"
    alert_threshold: "$5.00"
```

| Field | Type | Parsed via | Meaning |
|---|---|---|---|
| `max_per_action` | string | `parseDollar` (strips optional `$`) | Single-call ceiling. |
| `max_per_session` | string | `parseDollar` | Running total per `session_id` on the request. |
| `alert_threshold` | string | `parseDollar` | If `est_cost > alert_threshold`, the call is paused for human approval (no reservation is made). |

### Cost evaluation order (inside `checkCost`)

1. `est_cost < 0` → `DENY deny:cost:negative_value`.
2. Any `limits` field fails to parse → `DENY deny:cost:invalid_config`.
3. `est_cost > max_per_action` → `DENY deny:cost:max_per_action`.
4. `sessionCosts[session_id] + est_cost > max_per_session` → `DENY deny:cost:max_per_session`.
5. `est_cost > alert_threshold` → `REQUIRE_APPROVAL require_approval:cost:alert_threshold` (no reservation; the approved action re-runs `check` and reserves then).
6. Otherwise → atomic `sessionCosts[session_id] += est_cost`, `ALLOW allow:cost:within_limits`.

### Caveats

- `sessionCosts` is in-memory only. Restart loses all session totals.
- `--session-cost-ttl` evicts idle sessions so the map does not grow forever. Default `0` = never.
- `Engine.RecordCost` / `RefundCost` exist for out-of-band accounting but are still **not** wired into the HTTP request path as of v0.5.1 — call them from custom Go embeddings if you need pre-reserved cost accounting outside of `/v1/check`.

---

## Data scope

The `data` scope gates **form inputs and browser data submissions** so operators can write rules against the value being submitted (PII, credentials, credit-card-shaped strings) and the destination URL — independently of the broader `browser` scope which only sees navigation and clicks. The browser-use adapter (`plugins/python/agentguard/adapters/browseruse.py`) routes every `GuardedPage.fill`, `GuardedPage.type`, `GuardedFrame.fill`, and `GuardedBrowser.check_form_input` call through `scope: data`; framework adapters that wrap form-completion tools should follow the same convention.

### Request fields

| Field | Source | Notes |
|---|---|---|
| `command` | the value being submitted | Redacted by the SDK before the wire — see below. |
| `action` | always `"form_input"` | Use this in rules keyed on `action:` to gate the entire form-input surface. |
| `url` | optional | Full URL of the page hosting the form. |
| `domain` | optional | Hostname extracted from `url` (or sent directly). |
| `meta.field` | the form field's name/selector | Pass-through, NOT redacted. Operators rely on it for "never submit a value to a field named 'password'" rules. |

### Pattern matching

Standard glob matching applies (see [pattern semantics](#pattern-matching-semantics-read-this)). Examples:

```yaml
- scope: data
  deny:
    # Explicit PII markers in the value
    - pattern: "*ssn:*"
      message: "SSN values must not leave this agent"
    # Credit-card-shaped (13-19 digit groups). Loose heuristic.
    - pattern: "*[0-9][0-9][0-9][0-9] *[0-9][0-9][0-9][0-9]*"
    # Field-name based gate — the field name lands in command via the adapter
    # when the form-input action is dispatched.
  allow:
    - domain: "*.internal.local"
```

### Domain matching

Standard domain glob matching applies against `req.URL` / `req.Domain`. `*.foo.com` matches `api.foo.com` but not `foo.com` itself (same gotcha as `network` and `browser`).

### Operator note: redaction is upstream of the audit log

The Python SDK applies a redactor (mirrored from `pkg/notify.DefaultRedactor`) to the form value **before** it leaves the SDK process:

- Empty / whitespace values pass through unchanged.
- Values longer than **256 chars** are replaced with `<redacted; len=N>` so audit logs never carry paste-buffer-sized PII.
- Shorter values run through the regex redactor, which has the same patterns as the server's (Bearer tokens, AWS `AKIA…`, GitHub and Slack tokens, `secret=…`, and from v1.2.0 `sk-…` and Google keys, JWTs, PEM keys and credential headers).

Since v1.2.0 the server also masks secrets in every request before it reaches the audit trail (`serve --audit-redact`, on by default — see [OPERATIONS § Audit redaction](OPERATIONS.md#audit-redaction)), so a value that reaches the server unredacted is masked there too.

The field NAME (in `meta.field`) is NOT redacted — operators need it stable for rule authoring. Raw values do not land in the audit log unless they survive the redactor cleanly. Future deferred work (`v0.6, #data-pii`): regex / classifier-based PII detection baked into a built-in rule library so operators don't have to spell out SSN/CC formats themselves.

### Default-deny still applies

A `data`-scoped request that matches no allow rule receives `DENY "No matching allow rule (default deny)"` — same as every other scope. If you wire the browser-use adapter and forget to add `data` rules, every form submission will deny. This is intentional: a permissive default would silently leak PII the moment an agent encountered an unfamiliar page.

---

## `mcp_tool` scope

The `mcp_tool` scope is the primary scope the [AgentGuard MCP Gateway](./MCP_GATEWAY.md) (`agentguard-mcp-gateway`) checks every host `tools/call` against. The gateway sits between an MCP host (Claude Desktop, Cursor, IDE plugins) and one or more downstream MCP servers; on every `tools/call` it runs `Engine.Check` with `scope: "mcp_tool"` and `command: "<namespace>:<tool>"`.

In `--policy-mode strict` (the gateway's default) it also fires a **second** `Engine.Check` against the **mapped existing scope** (filesystem / network / shell / browser / data) per the [`tool_scope_map`](#tool_scope_map) — so existing rules apply to MCP traffic without duplication. Either DENY denies; either REQUIRE_APPROVAL requires approval.

### Request fields

The gateway populates an `ActionRequest` with:

| Field | Source |
|---|---|
| `scope` | `"mcp_tool"` |
| `command` | `"<namespace>:<tool>"`, e.g. `"fs:read_file"` |
| `agent_id` | `"mcp-gateway:<clientName>"` from MCP `clientInfo.name` |
| `session_id` | derived from clientInfo (one per host) |
| `meta.namespace` | the configured upstream namespace |
| `meta.tool_name` | un-prefixed tool name |
| `meta.transport` | `"mcp_gateway"` |
| `meta.arg_<key>` | best-effort serialised arguments |
| `meta.approval_id` | echoed back from `_meta.dev.agentguard/approval_id` on retry |

Rules match on `pattern` against the namespaced `command`:

```yaml
- scope: mcp_tool
  deny:
    - pattern: "github:delete_*"          # destructive github actions
    - pattern: "fs:write_file"            # never write via MCP
  require_approval:
    - pattern: "*:execute_*"              # any execute_* tool, any namespace
    - pattern: "github:*"                 # all github tool calls
  allow:
    - pattern: "fs:read_*"
    - pattern: "fs:list_*"
    - pattern: "everything:*"             # MCP "everything" sample server
```

### Cross-namespace patterns

`*:execute_*` matches `shell:execute_command`, `runner:execute_script`, etc. — useful for blanket "any execute-style tool needs approval" rules without enumerating every namespace. Because `*` is character-greedy in command/pattern matching (it crosses `:`), be explicit when you want to scope to a single namespace (e.g., `"github:*"` not `"git*:*"`).

### Default-deny still applies

A `mcp_tool` request that matches no allow rule receives `DENY "No matching allow rule (default deny)"`. The gateway's default behaviour (no `mcp_tool` rules in policy) is therefore **deny everything** — operators must add at least one allow rule for the gateway to be useful. See `configs/default.yaml` for a commented template.

---

## `tool_scope_map`

`tool_scope_map` declares the dual-check mapping the MCP Gateway uses when `--policy-mode strict` is in effect. It is a top-level YAML key at the same level as `rules:`, not a sub-key of any RuleSet.

```yaml
tool_scope_map:
  - pattern: "fs:read_file"
    scope: filesystem
  - pattern: "fs:write_file"
    scope: filesystem
  - pattern: "fs:*"
    scope: filesystem
  - pattern: "fetch:*"
    scope: network
  - pattern: "*:execute_*"
    scope: shell
  - pattern: "*:run_command"
    scope: shell
```

| Field | Type | Meaning |
|---|---|---|
| `pattern` | string | Glob over `<namespace>:<tool>`. Same matcher as rule patterns (`*`, `?`, `**`). |
| `scope` | string | One of `shell`, `filesystem`, `network`, `browser`, `data`, `cost`, `mcp_tool`. Other values are rejected at policy load. |

**First match wins.** YAML list order is significant — operators put more specific patterns first. The gateway iterates the list in declared order and stops on the first glob match.

### Field projection per mapped scope

When the dual-check fires, the gateway projects the tool-call arguments into the right `ActionRequest` fields for the mapped scope:

| Mapped scope | Argument projection |
|---|---|
| `filesystem` | `Path` ← first non-empty of `path`/`file_path`/`filepath`/`target_path`/`destination`/`src`/`dst`. `Action` ← inferred from tool-name verb (`read`/`write`/`delete`). |
| `network` | `URL` ← `url` arg. `Domain` ← the URL's host when there is a `url` arg (empty for a relative or malformed URL, so the call is denied); otherwise the `domain`/`host`/`hostname` arg. **(v1.2)** A `domain`/`host`/`hostname` arg no longer overrides the URL's host: the model writes the arguments and could pair an allow-listed domain with a URL on another host. |
| `browser` | `URL` + `Domain` as for network; `Action` ← un-prefixed tool name. |
| `shell` | `Command` ← first non-empty of `command`/`cmd`/`script`. Falls back to `<ns>:<tool>` + serialised `args`. |
| `data` | `Command` ← first non-empty of `value`/`content`/`text`/`data`. `Action` ← `"form_input"`. `URL`/`Domain` projected as for network. |

Rules in the mapped scope (`filesystem`, `network`, etc.) match on these fields exactly as they would for an SDK or proxy request — there is no MCP-specific matching path.

**Map a tool only if its arguments carry what the mapped scope checks.** A tool mapped to `network` with no `url`/`domain`/`host`/`hostname` argument projects an empty `Domain`, so domain allow rules such as `api.github.com` never match and every call falls through to default deny. GitHub's MCP server is the common case (its tools take `owner`/`repo`), which is why `configs/default.yaml` leaves `github:*` unmapped and gates it with an `mcp_tool` `require_approval` rule instead.

### Why the list form, not an inline map

A YAML map (`fs:read_file: filesystem`) would be more compact, but Go map iteration is non-deterministic and the dual-check is first-match-wins. Operators write a few extra lines per entry; the gateway guarantees the same scope for the same tool name on every host regardless of YAML library quirks.

### Without a `tool_scope_map`

`--policy-mode strict` requires the gateway to load a policy file via `--policy <path>`. If `tool_scope_map` is absent (or no entry matches the tool), the gateway runs only the `mcp_tool` check — equivalent to fast mode for that specific tool.

`--policy-mode fast` skips the second `Engine.Check` entirely and never consults `tool_scope_map`. The gateway still runs the `mcp_tool` check via the central server.

See [`docs/MCP_GATEWAY.md`](./MCP_GATEWAY.md) for the gateway's full wire format, approval round-trip, and reconnect strategy.

---

## LLM API Proxy tool scope mapping

The LLM API Proxy (`agentguard-llm-proxy`) inspects upstream model responses for `tool_calls` and gates each call against operator policy **using the same `tool_scope_map:` section** the MCP Gateway uses. There is no separate `llm_tool_scope_map:` key — the bare tool names emitted by chat-style models (`bash`, `read_file`, `web_search`) and the namespaced names emitted by MCP servers (`fs:read_text_file`, `github:list_issues`) occupy disjoint regions of the pattern space, so a single mapping table covers both transports without ambiguity.

### Bundled defaults

The proxy binary ships with a built-in mapping for common tool names so operators do not have to enumerate every LangChain / CrewAI / browser-use tool by hand. Source of truth: `pkg/llmproxy/scope_map.go` (`DefaultLLMToolScopeMap`). Categories:

| Scope | Default tool names |
|---|---|
| `shell` | `bash`, `sh`, `shell`, `run_command`, `execute_command`, `cmd`, `system`, `exec`; Claude Code's `Bash`, `PowerShell` |
| `filesystem` | `read_file`, `write_file`, `list_directory`, `list_files`, `file_read`, `file_write`, `edit_file`, `delete_file`, `create_directory`, `ls`, `cat`, `find`, `glob`; Claude Code's `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep` |
| `network` | `web_search`, `fetch_url`, `http_request`, `http_get`, `http_post`, `search`, `fetch`, `url_request`; Claude Code's `WebFetch` |
| `browser` | `playwright_*`, `browser_*`, `chrome_*`, `firefox_*`, `selenium_*`, `navigate`, `click`, `screenshot` |
| `data` | (no defaults) — operators map `fill_form` / `submit_form` here for PII gating |
| `cost` | (no defaults) — model-cost gating uses SDK `est_cost`, not tool-name mapping |

Tool names are matched case-sensitively, which is why Claude Code's capitalised names have entries of their own. (Claude Code is better guarded by its hook, which needs no proxy: see [`CODING_AGENTS.md`](CODING_AGENTS.md).)

Wildcard patterns (`playwright_*`, etc.) match the family conventions used by Anthropic's computer-use models and the popular browser-use / Playwright agents.

### Operator overrides and extensions

Entries declared in `tool_scope_map:` are merged with the bundled defaults so that **operator entries beat defaults on collision** (operator entries appear first in the merged list, and the matcher is first-match-wins). The merge does not mutate the policy snapshot — the live `Provider.Watch` callback can swap `Policy.ToolScopeMap` atomically without race-prone slice aliasing.

```yaml
tool_scope_map:
  # Override a default: the LLM tool named `read_file` actually
  # carries form data in this deployment, so route it to the `data`
  # scope (where PII rules live) instead of `filesystem`.
  - pattern: "read_file"
    scope: data

  # Add a tool not in the defaults.
  - pattern: "deploy_to_prod"
    scope: shell
  - pattern: "send_email"
    scope: network
```

### The `unmapped` sentinel

Tools not matched by any entry — neither operator nor default — are routed to scope `unmapped` at gate time. The policy engine has **no built-in `unmapped` rules**, so the default behaviour is fail-closed (DENY: "No matching allow rule (default deny)"). Operators who want unknown LLM tools to pass through must write an explicit `scope: unmapped` rule. The recommended baseline is `require_approval: [{pattern: "*"}]` so a human inspects the tool name + arguments before the call runs.

```yaml
rules:
  # Catch-all for tool names the proxy doesn't recognise. Without
  # this section the proxy denies every unmapped tool — by design.
  - scope: unmapped
    require_approval:
      - pattern: "*"
```

### End-to-end example

```yaml
version: "1"
name: my-policy

# Map tool names → scopes. Patterns merged with the bundled LLM
# defaults; operator entries win on collision.
tool_scope_map:
  - pattern: "deploy_*"
    scope: shell             # any LLM tool named deploy_<X>
  - pattern: "send_email"
    scope: network

# Rules that apply to mapped scopes. The same rules apply to SDK
# callers, MCP gateway traffic, and LLM API Proxy traffic.
rules:
  - scope: shell
    deny:
      - pattern: "rm -rf *"
    require_approval:
      - pattern: "deploy_*"  # all deploy_* tool calls need a human

  - scope: network
    allow:
      - domain: "company-internal.com"
    require_approval:
      - pattern: "*"

  # Catch-all for unknown tool names. Leave unwritten and unknown
  # tools fail closed (DENY); write `require_approval` if you trust
  # your LLM tools enough to let humans rubber-stamp them.
  - scope: unmapped
    require_approval:
      - pattern: "*"
```

See [`docs/LLM_API_PROXY.md`](./LLM_API_PROXY.md) for the proxy's full wire format, request/response handling, and refusal-rewriting strategy.

---

## Per-agent overrides

```yaml
agents:
  research-bot:
    override:
      - scope: network
        allow:
          - domain: "arxiv.org"
          - domain: "*.arxiv.org"
      - scope: shell
        deny:
          - pattern: "*"
            message: "shell access disabled for this agent"
```

Merge semantics (`resolveRules` in `pkg/policy/engine.go`):

- If the incoming request's `agent_id` matches a key under `agents:`, its `override` RuleSets replace the base RuleSets **per scope**.
- Scopes that appear **only** in the override (not in the base `rules:`) are appended.
- Scopes in the base that the override does **not** mention are unchanged.
- If `agent_id` is empty or does not match any key, the base `rules:` apply unchanged.

The `extends` field is reserved but not currently used by the engine — do not rely on it.

---

## Notifications

```yaml
notifications:
  dispatch_timeout: "10s"            # applied to webhook + slack (per-target `timeout` wins)
  approval_required:
    - type: slack
      url: "https://example.invalid/REPLACE_ME_BEFORE_DEPLOY"
      timeout: "5s"
  on_deny:
    - type: webhook
      url: "https://logs.example.com/agentguard"
    - type: console
  redaction:
    extra_patterns:
      - "MY_ORG_TOKEN_[A-Z0-9]{24}"
```

- `approval_required` → fired when a rule matches `REQUIRE_APPROVAL`.
- `on_deny` → fired when a rule matches `DENY`.
- `redaction.extra_patterns` → Go `regexp` (RE2) patterns appended to the built-in redactor list (bearer tokens and credential headers, `AKIA…`, GitHub `gh?_…`/`github_pat_…`, `xox?-…`, `sk-…`, `AIza…`, JWTs, PEM private keys, `secret=`/`token=`/`password=`/`api_key=`). Applied to `Command`, `Path`, `Domain`, `URL`, `Action`, `Reason`, and every `Meta` value before dispatch — and, since v1.2.0, before the request reaches the audit trail, SSE stream and pending list (`serve --audit-redact`; the `--policy` file's patterns only). Invalid regex → policy load fails.
- `dispatch_timeout` — Go duration; default `10s`. Per-target `timeout` overrides it.

| `type` | Purpose | Honors `timeout` |
|---|---|---|
| `webhook` | POST JSON to a URL | yes |
| `slack` | Post an attachment to a Slack incoming webhook | yes |
| `console` | Single line to stdout | no (synchronous) |
| `log` | Stdlib `log` package | no |

Unknown types fall back to `log` with `level: "warn"`.

---

## Proxy tunables

All under the optional `proxy:` block. Absent values fall back to the defaults in `pkg/policy/engine.go:54-60`.

```yaml
proxy:
  session:
    ttl: "1h"                   # dashboard session cookie lifetime (default 1h)
  request:
    max_body_bytes: 1048576     # POST /v1/check body cap (default 1 MiB)
  audit:
    default_limit: 100          # default ?limit= on /v1/audit (default 100)
    max_limit: 1000             # hard ceiling on ?limit= (default 1000, values above are clamped silently)
```

See [`docs/CONFIG.md`](CONFIG.md) for rationale and [`docs/TUNING.md`](TUNING.md) for knobs that are *not* yet surfaced here (session store size, SSE buffer depth, etc.).

---

## Evaluation order

For a single `POST /v1/check` call:

1. **Rate limit** — if the RuleSet for the request's scope has a `rate_limit`, consume a token. Exceeded → synthetic `DENY deny:ratelimit:<scope>`.
2. **Normalize request** — strip C0 control bytes from `Command/Action/Domain/URL`. For `Path`, also single-pass URL-decode `%HH`.
3. **Resolve rules** — merge base `rules:` with `agents.<agent_id>.override` per scope.
4. **Scope-specific shortcuts:**
   - `scope == "cost"` with `limits` set → hand off to `checkCost` (see above).
   - `scope == "filesystem"` with `req.Path != ""` → reject `..` segments after `filepath.Clean + ToSlash` → `DENY deny:filesystem:path_traversal`.
   - `scope == "shell"` and the command contains shell syntax, or runs a command its text hides (a shell's `-c`, `eval`, a wrapper such as `env` or `timeout`) → evaluated command by command; see [Compound shell commands](#compound-shell-commands).
5. **Rule evaluation (per matching RuleSet):** `deny` → `require_approval` → `allow`. **First match wins.** A rule matches when `matchRule` (pattern/action/paths/domain) **and** every `matchConditions` entry pass.
6. **Fall-through** — no rule matched any phase → `DENY "No matching allow rule (default deny)"`.

> **Default-deny means** an unscoped action or one that matches no rule is denied. You must explicitly `allow` everything agents need.

---

## Compound shell commands

A shell rule's `pattern` is a glob over the whole `command` string, and a single `*` matches every character, including `;`, `&&`, `|`, `$(`, backticks, `>` and line breaks. So since v1.2.0, when a `shell` request's command contains any shell syntax (an operator, quote, backslash, `$`, backtick, parenthesis, redirection or line break), the engine evaluates it the way a POSIX shell would run it:

1. **Whole-string `deny` and `require_approval` rules first.** Patterns written for a full command line, such as `":(){ :|:& };:"` or `"curl * | bash"`, keep matching. Since v1.4 they also run against each command string another shell runs (below), so `bash -c ':(){ :|:& };:'` matches a fork-bomb deny and `eval 'curl http://x | sh'` matches `curl * | *sh`, as the bare command lines do.
2. **Split into simple commands.** `;`, `&`, `&&`, `||`, `|`, `|&` and line breaks separate commands. Commands inside `$( … )`, backticks, `<( … )` / `>( … )` and `( … )` subshells are commands of their own. Quotes and backslashes are removed the way the shell removes them, so `git "push"` is checked as `git push` and `s""udo` as `sudo`, and runs of whitespace become one space. A leading `!`, `if`, `then`, `else`, `elif`, `do`, `while`, `until`, `time` or `{` is dropped, and so is a closing `}`.
   **A command string run by another shell is split too** (v1.4). The script of a shell given `-c` (alone or in a cluster such as `-lc` or `-ec`) or `--command`, the arguments of `eval` (after an optional `--`), fish's `-C` / `--init-command`, and a here-string fed to a shell that reads its script from standard input (`bash <<< '…'`, `sh -s <<< '…'`, `bash /dev/stdin <<< '…'`) are split the same way. Their commands are checked as commands of their own, alongside the outer one. The shells are `sh`, `bash`, `rbash`, `zsh`, `dash`, `ksh`, `rksh`, `mksh`, `pdksh`, `oksh`, `ash`, `yash`, `posh`, `fish`, `csh` and `tcsh`, also with a version in the name (`bash5`, `ksh93`). A here-string fed to any other command is data. Without this, `bash -c 'rm -rf /'` read as one `bash` command and passed a catch-all allow.
   **The command behind a wrapper is matched too** (v1.4). Leading assignments (`NAME=value`, `NAME+=value`, `a[i]=value`), `!` and these launchers, with their own options and operands, are looked through. This is the whole list:
   - Shell builtins and process tools: `env`, `command`, `exec`, `builtin`, `nohup`, `nice`, `time`, `timeout`, `flock` (and `flock FILE -c '…'`, which runs `sh -c`), `taskset`, `chrt`, `ionice`, `stdbuf`, `setsid`, `unshare`, `arch`, `caffeinate`, `busybox`, `xargs`, `strace`, `ltrace`, `fakeroot`.
   - Privilege and root changes: `sudo`, `doas`, `pkexec`, `runuser` (`-u USER cmd`, or `-c '…'`), `setpriv`, `chroot`, `sg` (`sg GROUP -c '…'` runs `sh -c`).
   - Project and package launchers: `npx` (and `npx -c '…'`), `npm exec` / `npm x`, `pnpm exec` / `pnpm dlx`, `yarn exec` / `yarn dlx`, `uv run`, `poetry run`, `bundle exec`, `direnv exec DIR`, `mise exec` / `mise x` (the command after `--`, or `-c '…'`), `nix-shell --run '…'`, `nix develop` / `nix shell` with `-c` or `--command`, `conda run` (also `mamba` and `micromamba`).
   Each command found behind them is matched against the `deny` and `require_approval` rules, so `timeout 5 rm -rf /`, `env sudo ls` and `FOO=1 rm -rf /` hit `rm -rf *` and `sudo *`. Whether the command may run at all is still decided by the full command: under a `sudo *` approval rule, `sudo reboot` asks as before, without also needing an allow rule for `reboot`. An option that runs no command (`command -v`, `sudo -l`, `chrt -p`) stops the unwrapping. `xargs` adds arguments from its input that aren't in the text, so `xargs rm -rf` is matched as `rm -rf`, which `rm -rf *` doesn't match.
   Shell, `eval` and wrapper names are matched without case and without `.exe`, since macOS and Windows file systems run `BASH` and `/BIN/SH` as `bash` and `sh`. These commands take this path even without other shell syntax: `eval rm -rf /` and `env rm -rf /` are checked as `rm -rf /`.
   **`$'…'` strings are decoded** (v1.4) as bash decodes them (`\n`, `\t`, `\xHH`, octal, `\uHHHH`, `\cX` and the rest), so `$'rm' -rf /tmp/x` is checked as `rm -rf /tmp/x` and the script of `bash -c $'ls\nrm -rf /'` as two commands. A NUL (`\0`, `\x00`) ends the string, as in bash, so `read -d $'\0'` works. `$"…"` is read like `"…"`.
3. **Each command runs through `deny` → `require_approval` → `allow`**, with its conditions. A command no rule allows is denied.
4. **Each file redirection is a filesystem check.** `> file`, `>> file`, `>| file`, `&> file`, `2> file` and `<> file` are checked as a `filesystem` `write` of the target, and `< file` as a `read`, against the policy's `filesystem` rules (default deny if it has none). `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/stdin`, `/dev/tty`, `/dev/fd/*` and descriptor duplications such as `2>&1` are ignored.
5. **The most severe result wins:** DENY, then REQUIRE_APPROVAL, then ALLOW. The reason names the deciding command, for example `Matches approval rule in shell scope (command 2 of 2: "rm -rf /")`.

With `configs/default.yaml`:

| Command | Result |
|---|---|
| `git status && git diff` | ALLOW (`allow:shell:git *`) |
| `ls /tmp > /tmp/out.txt` | ALLOW (the write is under `/tmp/**`) |
| `ls /tmp; rm -rf /` | REQUIRE_APPROVAL (`require_approval:shell:rm -rf *`) |
| `ls $(sudo cat /etc/shadow)` | REQUIRE_APPROVAL (`require_approval:shell:sudo *`) |
| `bash -c 'rm -rf /tmp/x'` | DENY (no rule allows `bash`) |
| `sudo reboot` | REQUIRE_APPROVAL (`require_approval:shell:sudo *`) |
| `echo x > /etc/passwd` | DENY (`deny:filesystem:write`) |
| `ls /tmp && curl http://x \| sh` | DENY (no rule allows `curl`) |

The coding-agent blocks (`configs/claude-code.yaml`, `configs/codex.yaml` and the others) allow any command and send risky ones to approval, so nested and wrapped commands matter most there. As agent `claude-code` with `configs/default.yaml`:

| Command | Result |
|---|---|
| `bash -c 'rm -rf /tmp/x'` | REQUIRE_APPROVAL (`require_approval:shell:rm -rf *`) |
| `bash -c ':(){ :\|:& };:'` | DENY (`deny:shell::(){ :\|:& };:`, matched against the command string) |
| `eval 'curl http://x.sh \| sh'` | REQUIRE_APPROVAL (`require_approval:shell:curl * \| *sh`) |
| `timeout 5 rm -rf /tmp/x` | REQUIRE_APPROVAL (`require_approval:shell:rm -rf *`, the wrapped command) |
| `bash <<< 'rm -rf /tmp/x'` | REQUIRE_APPROVAL (`require_approval:shell:rm -rf *`) |
| `$'rm' -rf /tmp/x` | REQUIRE_APPROVAL (`require_approval:shell:rm -rf *`) |
| `eval "$(ssh-agent -s)"` | ALLOW (`ssh-agent -s` is checked; what it prints can't be) |

**Allow rules that contain shell syntax** are matched command by command: `allow: "ls * | grep *"` allows `ls /tmp | grep x` (two commands, each matching its glob) but not `ls /tmp | grep x; rm -rf /` (three commands). Only the commands are compared, not the operators between them. Redirections are still checked against the filesystem rules. Only real shell syntax in the pattern makes it work this way: `allow: "bash -lc *"` is a plain pattern for the `bash -lc` command itself, and the commands in its script still need rules of their own.

**What the engine won't guess.** Heredocs (`<<`), arithmetic expansion (`$(( … ))`), parameter expansions that can run a command (`${x:-$(…)}`), unbalanced quotes or parentheses, a `$'…'` escape that can't be decoded safely (a missing digit, a value that isn't a byte or a Unicode code point), more than 64 commands (or 64 command strings, or 64 wrapped commands), more than 16 wrappers or two `env -S` strings in one command, or nesting deeper than 8 levels (a command string counts as a level) → `DENY deny:shell:unparseable_command`.

**What it can't see.** Matching reads the command text, not what a program does with its arguments or its input. These run code the engine doesn't look into:

- A launcher not in the list above, such as `su -c`, `systemd-run`, `nsenter`, `watch`, `script -c`, `parallel`, `uvx`, `pipx run`, `docker run`, `make`, `just` or `task`. The command it runs is matched only as part of the full command.
- A program whose arguments run other programs: `find . -exec rm {} \;`, `git -c core.sshCommand=… fetch`, `tar --checkpoint-action=exec=…`. `configs/default.yaml` sends `find -exec/-execdir/-ok/-delete` to approval, but a broad allow such as `git *` still permits risky arguments.
- Interpreters given code: `python -c`, `node -e`, `perl -e`, `ruby -e`, `pwsh -c`, `cmd /c`.
- A script a shell reads from a pipe or a file: `echo 'rm -rf /' | bash`, `bash < script.sh`, `bash <(curl …)`, `bash script.sh`, `source file`.
- A script built at run time: `bash -c "$(curl …)"`, `eval "$(tool init)"`, `$cmd` or `${!name}` (variable indirection), `trap '…' EXIT`, aliases. For `eval "$(…)"` the substitution's commands are checked, but not the text it prints, which eval runs.
- Commands run elsewhere: `ssh host 'rm -rf /'`, `docker exec`, `kubectl exec`.

A leading variable assignment (`FOO=bar cmd`) stays part of the full command, so it can make an allow rule match less, never more; the command after it is matched against deny and approval rules as `cmd`. A command with no shell syntax that doesn't start with an assignment, `!`, a shell, `eval` or a wrapper keeps the plain whole-string match.

---

## Pattern matching semantics (read this)

Pattern matching is where most policy bugs come from.

### Single-star `*` crosses `/`

```
"rm -rf *"        matches   "rm -rf /home/user"
"api/*/users"     matches   "api/v1/users"
"api/*/users"     matches   "api/v1/internal/users"        ← yes, crosses /
```

`*` in a pattern without `**` is **any character sequence including `/`**. That is intentional for shell commands; it is a surprise when matching paths. For paths, prefer `**`.

> **⚠ Over-broad ALLOW footgun — read this before writing path allows.**
> Because a single `*` crosses `/`, an ALLOW rule like `paths: ["/workspace/*"]`
> does **not** bound access to the top level of `/workspace`. It also matches
> `/workspace/a/b/secret.env` and every other file at any depth — an allow you
> believed was one directory deep silently grants the **entire subtree**.
>
> ```
> paths: ["/workspace/*"]     # ⚠ ALSO matches /workspace/a/b/secret.env (whole subtree)
> paths: ["/workspace/**"]    # segment-aware: every file under /workspace, as intended
> ```
>
> The direction of the risk matters: on a **deny** rule an over-matching `*` makes
> the deny *broader* (fail-safe), but on an **allow** rule it *widens* access
> (fail-open). Audit ALLOW path rules for a bare `*` first, and write path bounds
> with `**` so the depth is explicit. `agentguard server` / policy load also emits
> a non-fatal warning for exactly this pattern shape — see
> [Load-time validation](#load-time-validation).

### Double-star `**` is segment-aware

When the pattern contains `**`, the pattern and the input are split on `/`. `**` matches zero or more whole segments. Each non-`**` segment is still wildcard-matched with the same `*`/`?` rules.

```
"**/secret/**"          matches   "/a/b/secret/c"
"**/secret/**"          does NOT match   "/a/b/notsecret/c"        ← no substring bypass
"./workspace/**"        matches   "./workspace/src/main.go"
"./workspace/**"        does NOT match   "./workspace"             ← ** requires at least one segment on trailing use
```

### Question mark `?` is a single character

```
"file?.txt"   matches   "file1.txt"  "fileA.txt"
"file?.txt"   does NOT match   "file.txt"  "file12.txt"
```

### Domains use the same glob rules

```
allow:
  - domain: "*.foo.com"          # matches api.foo.com, matches a.b.foo.com
  # does NOT match foo.com        ← *.foo.com requires at least one char before the dot
```

If you want both the bare apex and the subdomains, list both:

```yaml
allow:
  - domain: "foo.com"
  - domain: "*.foo.com"
```

Domain matching is **case-insensitive** (v1.0): the request's domain and the
rule's `domain` patterns are both lowercased before matching, so a deny rule
for `evil.com` also matches `EVIL.com` — DNS names are case-equivalent, and
before v1.0 a mixed-case request could slip past a lowercase deny rule.

### Paths are cleaned first

`matchRule` applies `filepath.Clean + ToSlash` to both the rule's `paths` entries and the request's `Path`, so `./a/./b` and `a/b` are equivalent.

### `..` is rejected

- At policy load: `filesystem` rule `paths` containing `..` (after clean) → `policy invalid`.
- At request time: `req.Path` with `..` segments (after clean) → `DENY deny:filesystem:path_traversal`.

---

## Load-time validation

Every policy load — the `--policy` file, a hot reload, a tenant policy from the store, `agentguard validate` — goes through `parsePolicyBytesWithWarnings` (`pkg/policy/policy_load.go`), which enforces:

- `version` present, non-empty.
- `name` present, non-empty.
- `filesystem` rule `paths` do not contain `..` after normalization.
- Every `notifications.redaction.extra_patterns` entry compiles as a Go regexp.
- `conditions.time_window` without `require_prior` is rejected as a hard load error (since v0.5.0).
- Blocks for the same scope are merged; a `rate_limit` or `limits` that differs between them is a load error (since v1.2.0).

**Non-fatal warnings** are logged at load and printed by `agentguard validate` (to stderr, prefixed `WARN:`); the policy still loads:

- (v1.2.0) a scope that appears in more than one block — the blocks were merged (see [Rule sets and scopes](#rule-sets-and-scopes));
- (v1.2.0) a scope name that isn't built-in but is one or two edits away from one (`shel`, `filesytem`, `Shell`): its rules only apply to requests whose scope is spelled exactly that way, so it is almost always a typo;
- (v1.0) a rule path pattern that contains `/` but no `**` (e.g. `/workspace/*`) — its single `*` crosses `/` and matches recursively (`/workspace/a/b/secret.env`), usually broader than intended. Switch to `**` (segment-aware) if you meant one level. See [Single-star `*` crosses `/`](#single-star--crosses-).

There is **no** schema validation beyond the above — typos in field names are silently ignored by the YAML decoder. Always run `agentguard validate --policy <file>` after edits; wire `agentguard validate --strict` into CI against every policy file you ship, so warnings fail the build.

---

## Testing policies

`validate` tells you a policy loads. It does not tell you the policy still blocks `rm -rf /` after someone widened an allow rule. For that, write test cases: example actions and the verdict each one must get. `agentguard test` runs them against the policy, with no server.

Put the cases in a file whose name ends in `_test.yaml` (or `_test.yml`), next to the policy or in a folder of their own. For this policy:

```yaml
# policy.yaml
version: "1"
name: "example"
rules:
  - scope: shell
    require_approval:
      - pattern: "rm -rf *"
    allow:
      - pattern: "ls *"
      - pattern: "make test"
      - pattern: "make deploy"
        conditions:
          - require_prior: "make test"
            time_window: 1h
  - scope: network
    deny:
      - domain: "*.production.internal"
        message: "Production access needs a change ticket"
    allow:
      - domain: "api.github.com"
```

the cases could be:

```yaml
# policy-tests/shell_test.yaml
policy: ../policy.yaml           # relative to this file
tests:
  - name: listing files is allowed
    request: {scope: shell, command: "ls -la", agent_id: dev}
    expect: ALLOW

  - name: rm -rf hidden after a semicolon still needs approval
    request: {scope: shell, command: "ls /tmp; rm -rf /", agent_id: dev}
    expect: REQUIRE_APPROVAL
    expect_rule: "require_approval:shell:rm -rf *"

  - name: production hosts are blocked
    request: {scope: network, domain: db.production.internal, agent_id: dev}
    expect: DENY
    expect_reason_contains: "Production access"

  - name: deploy is allowed once the tests ran
    prior: [{scope: shell, command: "make test", agent_id: dev}]
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: ALLOW

  - name: deploy without a test run is not allowed
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: DENY
```

```bash
agentguard test policy-tests/
```

What a case can check:

- `expect`: the decision, `ALLOW`, `DENY` or `REQUIRE_APPROVAL`. Required.
- `expect_rule`: the exact `matched_rule` of the verdict, such as `require_approval:shell:rm -rf *`. The `*` is part of the rule's name, not a wildcard. A default deny has no rule; check its reason instead.
- `expect_reason_contains`: text the reason must contain, such as a rule's `message`.

`prior:` lists actions that count as allowed just now, so a [`require_prior`](#conditions) condition can be met. They are recorded for the agent and scope they name.

Each case runs on a fresh engine: cost spent under a `session_id` in one case does not count in the next. Rate limits are not tested, because the server applies them, not the policy engine. A misspelled key in a test file is an error, not a case that silently checks nothing.

Per-agent overrides are tested by setting `agent_id` to the agent's name, or with hook cases (below). The cases for the policies in this repo are in [`configs/tests/`](../configs/tests/); they cover the starter policy's sandbox rules, compound shell commands, and each coding agent's block through its hook. Full flag and output reference: [`CLI.md` § `agentguard test`](CLI.md#agentguard-test).

### Testing a coding agent's tool calls

A case can give a coding agent's tool call instead of a request. `hook:` names the agent (`claude-code`, `cursor`, `gemini-cli` or `codex`) and `input:` is the call as that agent sends it to [`agentguard hook`](CODING_AGENTS.md), written as YAML:

```yaml
  - name: Claude Code sudo needs approval
    hook: claude-code
    input: {tool_name: Bash, tool_input: {command: "sudo ls"}}
    expect: REQUIRE_APPROVAL

  - name: a patch is denied when one of its files is a system file
    hook: codex
    input:
      tool_name: apply_patch
      tool_input:
        command: |
          *** Begin Patch
          *** Update File: /home/alice/project/main.go
          @@
          -a
          +b
          *** Add File: /etc/cron.d/job
          +* * * * * root true
          *** End Patch
    expect: DENY
```

The input goes through the same code as the real hook, so the case tests which requests the call becomes as well as the policy's verdict. The requests carry the agent's own `agent_id`, so the agent's block applies.

- The input is passed as it is. Write the keys the hook reads: `tool_name` and `tool_input` for Claude Code, Gemini CLI and Codex; for Cursor, `hook_event_name` too (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` or `preToolUse`), since each event's input differs. [`CODING_AGENTS.md` § What gets checked](CODING_AGENTS.md#what-gets-checked) lists the tools.
- Use absolute paths. A relative path is joined to the input's `cwd`, which differs between machines.
- One call can become several checks: a Codex patch is one per file, a Gemini CLI `web_fetch` one per URL. Each is checked, and the most severe verdict counts, as in the hook: a deny wins over an approval, and an approval over an allow. `expect_rule` and `expect_reason_contains` apply to that verdict.
- An input the hook doesn't check (another tool, another event) or can't read fails the case with the reason. Such a case would test nothing.
- `prior:` works as for a request. Name the agent in it: `agent_id: claude-code`.
- A case gives either `request:` or `hook:` with `input:`. Anything else, or an unknown hook name, is a load error.

### In CI

`agentguard test` exits `0` when every case passes, `1` when one fails, and `3` when a test file or policy does not load, so a CI step fails on its own. With `--output junit` it writes JUnit XML for CI test-report viewers.

A GitHub Actions job:

```yaml
# .github/workflows/policy.yml
name: Policy
on: [push, pull_request]

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - name: Install agentguard
        run: go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
      - name: Validate the policy
        run: agentguard validate --strict policy.yaml
      - name: Test the policy
        run: agentguard test --strict policy-tests/
```
