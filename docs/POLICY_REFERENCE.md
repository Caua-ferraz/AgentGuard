# Policy Reference

Canonical reference for the AgentGuard policy YAML format as of **v0.4.1**.

Source of truth: `pkg/policy/engine.go` (types) and `pkg/policy/engine.go:Engine.Check` (evaluation). Examples here are the shapes the Go YAML decoder accepts — unknown keys are silently ignored.

---

## Table of contents

- [Top-level document](#top-level-document)
- [Rule sets and scopes](#rule-sets-and-scopes)
- [Rule fields](#rule-fields)
- [Conditions](#conditions)
- [Rate limits](#rate-limits)
- [Cost guardrails](#cost-guardrails)
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
| `data` | none | `pattern`, `action` (generic string match) |
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
      url: "https://hooks.slack.com/services/..."
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
