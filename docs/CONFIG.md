# AgentGuard Policy Configuration Reference

This document enumerates every tunable key in an AgentGuard policy YAML file and documents its default, validation rules, and runtime effect. Rule-level fields (`scope`, `allow`, `deny`, `require_approval`, `pattern`, `paths`, `domain`, `action`, `conditions`, `rate_limit`, `limits`) are covered in the policy tutorial and examples under `configs/`; this file focuses on the **non-rule** keys introduced in v0.4.1.

Every key listed here is optional. An operator who upgrades from v0.4.0 without changing their policy file gets the same runtime behavior they had before — each unset key falls back to a compile-time default that matches v0.4.0.

## Quick reference

```yaml
version: "1"
name: my-policy

# Server-side tunables (v0.4.1+).
proxy:
  session:
    ttl: "1h"                  # duration; default 1h
  request:
    max_body_bytes: 1048576    # bytes; default 1048576 (1 MiB)
  audit:
    default_limit: 100         # rows returned when ?limit is omitted; default 100
    max_limit: 1000            # hard ceiling on ?limit; default 1000

# Notification dispatcher tunables (v0.4.1+).
notifications:
  dispatch_timeout: "10s"      # default timeout for webhook/slack; default 10s
  approval_required:
    - type: webhook
      url: "https://hooks.example/approval"
      timeout: "5s"            # optional per-target override
```

## `proxy`

Server-side tunables that apply to the HTTP surface itself — not to policy evaluation. All fields are optional.

### `proxy.session.ttl`

| | |
|---|---|
| **Type** | duration (Go `time.ParseDuration`) |
| **Default** | `1h` |
| **Affects** | Dashboard session cookie lifetime |
| **Validation** | Must parse cleanly and be `> 0`. Invalid values fail at policy load. |

Controls how long an `ag_session` cookie stays valid after `/auth/login` succeeds. Shorter values force dashboard operators to re-authenticate more often; longer values reduce login friction but extend the window where a stolen laptop can act on approvals. The `ag_csrf` companion cookie is issued with the same expiry.

### `proxy.request.max_body_bytes`

| | |
|---|---|
| **Type** | integer (bytes) |
| **Default** | `1048576` (1 MiB) |
| **Affects** | `POST /v1/check` body acceptance |
| **Validation** | Must be `> 0` when present. Invalid values fail at policy load. |

Caps the size of `/v1/check` request bodies. Requests larger than this receive HTTP `413 Request Entity Too Large`, a warning log line including the source, `Content-Length`, and the effective limit, and an increment on the Prometheus counter `agentguard_request_rejected_total{reason="body_too_large"}`. Tune down in hostile environments where a small request surface is part of the threat model; tune up only if a legitimate agent produces genuinely large `meta` payloads.

### `proxy.audit.default_limit`

| | |
|---|---|
| **Type** | integer (row count) |
| **Default** | `100` |
| **Affects** | `GET /v1/audit` when `?limit=` is omitted |
| **Validation** | Must be `> 0` when present. Must be `<= proxy.audit.max_limit`. |

The row count returned by `/v1/audit` when the caller does not pass `?limit=`. The dashboard, SDKs, and `agentguard audit` CLI call through this endpoint; tuning this sizes the default page everywhere.

### `proxy.audit.max_limit`

| | |
|---|---|
| **Type** | integer (row count) |
| **Default** | `1000` |
| **Affects** | `GET /v1/audit` ceiling on `?limit=` |
| **Validation** | Must be `> 0` when present. Must be `>= proxy.audit.default_limit`. |

Hard ceiling on `?limit=`. Clients requesting more than this receive this many rows (silently clamped, not rejected). The ceiling exists so a caller cannot pass `?limit=2147483647` and cause an unbounded scan of the audit file.

## `notifications`

The `notifications` section already carries `approval_required`, `on_deny`, and `redaction` in v0.4.0. v0.4.1 adds `dispatch_timeout` and per-target `timeout`.

### `notifications.dispatch_timeout`

| | |
|---|---|
| **Type** | duration |
| **Default** | `10s` |
| **Affects** | `http.Client.Timeout` used by webhook and Slack notifiers |
| **Validation** | Must parse cleanly and be `> 0`. |

Default per-notification HTTP timeout for webhook and Slack targets. Console and log notifiers ignore it — they are synchronous and local. A slow webhook that used to block dispatcher workers for the full hard-coded 10s can now be cut down (or up) without a binary change.

### `notifications.approval_required[].timeout`, `notifications.on_deny[].timeout`

| | |
|---|---|
| **Type** | duration |
| **Default** | inherits `notifications.dispatch_timeout` |
| **Affects** | That specific target's `http.Client.Timeout` |
| **Validation** | If present, must parse cleanly and be `> 0`. |

Per-target override. Use this when you run one webhook that is consistently slow but reliable and another that should fail fast.

## Interaction with hot reload

Policy hot reload (`--watch`) re-parses the file and swaps the `policy.Engine`'s policy pointer. **Runtime tunables resolved at startup do not change on reload** — `proxy.session.ttl` and `proxy.request.max_body_bytes` are latched into the `Server` struct, and the notify dispatcher's per-notifier `http.Client.Timeout` is set when each client is constructed. Change these in the policy file and the new values apply on the next process restart.

Rule-level keys (allow/deny/require_approval, rate limits, cost limits) continue to reload live as they did in v0.4.0.

## Validation errors

`agentguard validate <policy.yaml>` and `agentguard serve` both run the same validators. A failure prints the offending YAML path:

```
INVALID: proxy.session.ttl: time: unknown unit "hr" in duration "1hr"
INVALID: proxy.audit.max_limit (50) must be >= proxy.audit.default_limit (200)
INVALID: notifications.dispatch_timeout: must be > 0, got "0s"
```

Operators can run `agentguard validate` in CI to reject bad configs before they reach a server.

## Defaults, at a glance

| Key | Default | Default is defined in |
|---|---|---|
| `proxy.session.ttl` | `1h` | `policy.DefaultSessionTTL` |
| `proxy.request.max_body_bytes` | `1048576` | `policy.DefaultMaxRequestBodyBytes` |
| `proxy.audit.default_limit` | `100` | `policy.DefaultAuditDefaultLimit` |
| `proxy.audit.max_limit` | `1000` | `policy.DefaultAuditMaxLimit` |
| `notifications.dispatch_timeout` | `10s` | `policy.DefaultNotifyDispatchTimeout` |

These constants live in `pkg/policy/engine.go` and are exported so tests and external callers can reference the same values without re-hardcoding them.
