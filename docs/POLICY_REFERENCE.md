# Policy Reference

Canonical reference for the AgentGuard policy YAML format as of **v0.5.0**.

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
- [Pattern matching semantics (read this)](#pattern-matching-semantics-read-this)
- [Load-time validation](#load-time-validation)

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
| `shell` | none | `pattern`, optional `conditions` |
| `filesystem` | `..` path-traversal guard at load + at request time | `action`, `paths` |
| `network` | none | `domain` or `pattern` |
| `browser` | none | `domain` |
| `cost` | dedicated `checkCost` evaluator; `limits` block | no rule fields — driven entirely by `limits` and `est_cost` on the request |
| `data` | none (generic) | `pattern`, `action` (`form_input`), `domain` — see [data scope](#data-scope) |
| `mcp_tool` | none (generic) | `pattern` matched against `<namespace>:<tool>` — see [mcp_tool scope](#mcp_tool-scope) |
| *any other string* | none | generic; `pattern`/`action`/`domain` all still work |

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

**Backed by the audit log.** Conditions are evaluated via `HistoryQuerier.RecentActions(agentID, scope, since=now-time_window)`. The querier is the in-process adapter over `Logger.Query`.

### Footgun: `time_window` without `require_prior`

If you set only `time_window`, the condition is a **no-op** — it is always satisfied. `LoadFromFile` emits:

```
WARNING: rule "…" has time_window without require_prior — condition will be ignored
```

This is a deliberate v0.4.0-compat quirk. It is **scheduled to become a hard error in v0.5.0** (`docs/DEPRECATIONS.md`). Either remove the orphan `time_window` or add a `require_prior`.

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

**In-memory and per-instance.** Multi-replica deployments do not share buckets — agents can burst past the nominal cap by hitting different pods. See [`docs/OPERATIONS.md`](OPERATIONS.md).

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
- `Engine.RecordCost` / `RefundCost` exist for out-of-band accounting but are **not** wired into the HTTP proxy in v0.4.1.

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
- Shorter values run through the regex redactor (Bearer tokens, AWS `AKIA…`, `ghp_…`, `xox?-…`, `secret=…`).

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
  - pattern: "github:*"
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
| `network` | `URL` ← `url` arg. `Domain` ← parsed from URL or from `domain`/`host`/`hostname` arg. |
| `browser` | `URL` + `Domain` as for network; `Action` ← un-prefixed tool name. |
| `shell` | `Command` ← first non-empty of `command`/`cmd`/`script`. Falls back to `<ns>:<tool>` + serialised `args`. |
| `data` | `Command` ← first non-empty of `value`/`content`/`text`/`data`. `Action` ← `"form_input"`. `URL`/`Domain` projected as for network. |

Rules in the mapped scope (`filesystem`, `network`, etc.) match on these fields exactly as they would for an SDK or proxy request — there is no MCP-specific matching path.

### Why the list form, not an inline map

A YAML map (`fs:read_file: filesystem`) would be more compact, but Go map iteration is non-deterministic and the dual-check is first-match-wins. Operators write a few extra lines per entry; the gateway guarantees the same scope for the same tool name on every host regardless of YAML library quirks.

### Without a `tool_scope_map`

`--policy-mode strict` requires the gateway to load a policy file via `--policy <path>`. If `tool_scope_map` is absent (or no entry matches the tool), the gateway runs only the `mcp_tool` check — equivalent to fast mode for that specific tool.

`--policy-mode fast` skips the second `Engine.Check` entirely and never consults `tool_scope_map`. The gateway still runs the `mcp_tool` check via the central server.

See [`docs/MCP_GATEWAY.md`](./MCP_GATEWAY.md) for the gateway's full wire format, approval round-trip, and reconnect strategy.

---

## LLM API Proxy tool scope mapping

The LLM API Proxy (`agentguard-llm-proxy`) inspects upstream model responses for `tool_calls` and gates each call against operator policy **using the same `tool_scope_map:` section** the MCP Gateway uses. There is no separate `llm_tool_scope_map:` key — the bare tool names emitted by chat-style models (`bash`, `read_file`, `web_search`) and the namespaced names emitted by MCP servers (`fs:read_file`, `github:create_issue`) occupy disjoint regions of the pattern space, so a single mapping table covers both transports without ambiguity.

### Bundled defaults

The proxy binary ships with a built-in mapping for common tool names so operators do not have to enumerate every LangChain / CrewAI / browser-use tool by hand. Source of truth: `pkg/llmproxy/scope_map.go` (`DefaultLLMToolScopeMap`). Categories:

| Scope | Default tool names |
|---|---|
| `shell` | `bash`, `sh`, `shell`, `run_command`, `execute_command`, `cmd`, `system`, `exec` |
| `filesystem` | `read_file`, `write_file`, `list_directory`, `list_files`, `file_read`, `file_write`, `edit_file`, `delete_file`, `create_directory`, `ls`, `cat`, `find`, `glob` |
| `network` | `web_search`, `fetch_url`, `http_request`, `http_get`, `http_post`, `search`, `fetch`, `url_request` |
| `browser` | `playwright_*`, `browser_*`, `chrome_*`, `firefox_*`, `selenium_*`, `navigate`, `click`, `screenshot` |
| `data` | (no defaults) — operators map `fill_form` / `submit_form` here for PII gating |
| `cost` | (no defaults) — model-cost gating uses SDK `est_cost`, not tool-name mapping |

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
- `redaction.extra_patterns` → Go `regexp` (RE2) patterns appended to the built-in redactor list (Bearer tokens, `AKIA…`, `ghp_…`, `xox?-…`, `secret=…`). Applied to `Command`, `URL`, `Reason`, and every `Meta` value before dispatch. Invalid regex → policy load fails.
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
5. **Rule evaluation (per matching RuleSet):** `deny` → `require_approval` → `allow`. **First match wins.** A rule matches when `matchRule` (pattern/action/paths/domain) **and** every `matchConditions` entry pass.
6. **Fall-through** — no rule matched any phase → `DENY "No matching allow rule (default deny)"`.

> **Default-deny means** an unscoped action or one that matches no rule is denied. You must explicitly `allow` everything agents need.

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

### Paths are cleaned first

`matchRule` applies `filepath.Clean + ToSlash` to both the rule's `paths` entries and the request's `Path`, so `./a/./b` and `a/b` are equivalent.

### `..` is rejected

- At policy load: `filesystem` rule `paths` containing `..` (after clean) → `policy invalid`.
- At request time: `req.Path` with `..` segments (after clean) → `DENY deny:filesystem:path_traversal`.

---

## Load-time validation

`LoadFromFile` (in `pkg/policy/engine.go:174`) enforces:

- `version` present, non-empty.
- `name` present, non-empty.
- `filesystem` rule `paths` do not contain `..` after normalization.
- Every `notifications.redaction.extra_patterns` entry compiles as a Go regexp.
- `conditions.time_window` without `require_prior` emits a WARNING (not yet an error).

There is **no** schema validation beyond the above — typos in field names are silently ignored by the YAML decoder. Always run `agentguard validate --policy <file>` after edits; wire it into CI against every policy file you ship.
