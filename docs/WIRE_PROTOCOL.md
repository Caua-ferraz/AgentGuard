# AgentGuard Wire Protocol — v1

This document is the operator-facing description of the JSON wire format
for the AgentGuard `/v1/check` endpoint. It is the public contract between
the proxy (Go) and any client SDK (Python, TypeScript, or third-party).

The machine-readable spec lives at
[`pkg/proxy/schema/v1/schema.json`](../pkg/proxy/schema/v1/schema.json)
(JSON Schema draft-07). The canonical Go types live in
[`pkg/policy`](../pkg/policy/engine.go) (`ActionRequest`, `CheckResult`)
and are re-exported as type aliases from
[`pkg/proxy/schema/v1`](../pkg/proxy/schema/v1/types.go).

## Schema versioning

Every request and response carries a `schema_version` field. v0.5+ servers
emit `"v1"` on every response and accept any of:

- `schema_version` omitted → defaulted to `"v1"`
- `schema_version: "v1"` → accepted
- any other value → rejected with `HTTP 400` and a structured error body
  ```json
  {"error":"unsupported schema_version; expected v1","received":"v2"}
  ```

The constant lives at `pkg/proxy.SchemaVersionV1` (Go) and
`pkg/proxy/schema/v1.Version`. Closes audit finding **R1 F4** (no
`schema_version` field on the wire).

### Evolution policy

`v1` is **frozen**:

1. No field is ever removed.
2. No field's JSON name or type ever changes.
3. New optional fields **may** be added under v1. SDKs MUST tolerate
   unknown response fields (ignore-and-pass-through). Servers MUST
   tolerate unknown request fields (the Go decoder does this by default).
4. Breaking changes ship as a separate `pkg/proxy/schema/v2` package
   with its own `Version = "v2"` constant. The proxy will negotiate
   between v1 and v2 by inspecting `schema_version` on the request.

Strict clients that reject unknown response fields (a security-hardened
mode you opt in to) are responsible for coordinating their upgrade window
with their server.

## Cross-language contract test

A single set of fixtures under
[`pkg/proxy/schema/v1/testdata/`](../pkg/proxy/schema/v1/testdata/)
is loaded by tests in all three languages. Drift between any pair (Go ↔
Python ↔ TypeScript) fails CI:

| Language | Test file |
|----------|-----------|
| Go | `pkg/proxy/schema/v1/types_test.go` |
| Python | `plugins/python/tests/test_wire_format.py` |
| TypeScript | `plugins/typescript/src/__tests__/wire_format.test.ts` |

This closes audit finding **R1 F7** (no contract test, silent drift
between SDKs and the Go proxy).

## `POST /v1/check` request — `ActionRequest`

Fields are JSON-encoded; only `scope` is required.

| Field            | Type              | Required | Description |
|------------------|-------------------|----------|-------------|
| `schema_version` | string (`"v1"`)   | optional | Wire-format version. Empty → defaulted to `"v1"`; any other value → 400. |
| `scope`          | string            | **required** | Policy rule scope. Built-ins: `filesystem`, `shell`, `network`, `browser`, `cost`, `data`, `mcp_tool` (v0.5+, used by the MCP gateway's dual-check). Custom scopes are valid if defined in policy. |
| `action`         | string            | optional | Action verb for action-style scopes (e.g. `read`, `write`, `delete` on `filesystem`). |
| `command`        | string            | optional | Shell command string for the `shell` scope. Matched against rule `pattern`. |
| `path`           | string            | optional | Filesystem path. The server URL-decodes `%HH` once, then rejects any `..` segment after `filepath.Clean`. |
| `domain`         | string            | optional | Hostname for the `network` / `browser` scope. |
| `url`            | string            | optional | Full URL for the `network` scope. |
| `agent_id`       | string            | optional | Stable agent identifier. Used as a per-agent override key and as a rate-limit key. |
| `session_id`     | string            | optional | Required to use `cost.max_per_session` accumulation; also keyed by audit `Query`. |
| `est_cost`       | number ≥ 0        | optional | Estimated cost of this action in USD. Required for the `cost` scope. SDKs drop this field when its value is `0` to avoid spurious cost-scope evaluations. |
| `meta`           | object<string,string> | optional | Free-form string-keyed metadata. Forwarded to notifiers and the audit log; may be redacted by `notify.DefaultRedactor`. |

### Example

```json
{
  "schema_version": "v1",
  "agent_id": "test-agent-001",
  "session_id": "sess-abc",
  "scope": "shell",
  "command": "ls -la",
  "meta": {"source": "ci-fixture"}
}
```

This is the canonical fixture at
[`pkg/proxy/schema/v1/testdata/sample_request.json`](../pkg/proxy/schema/v1/testdata/sample_request.json).

## `POST /v1/check` response — `CheckResult`

| Field            | Type              | Always set | Description |
|------------------|-------------------|------------|-------------|
| `schema_version` | string (`"v1"`)   | yes (v0.5+) | Wire-format version emitted by the server. |
| `decision`       | enum              | yes | One of `"ALLOW"`, `"DENY"`, `"REQUIRE_APPROVAL"`. |
| `reason`         | string            | yes | Human-readable explanation. Stable enough for log aggregation but not part of the policy contract — wording may evolve. |
| `matched_rule`   | string            | usually | Identifier of the rule that produced the decision (e.g. `"allow:shell:ls"`, `"deny:filesystem:path_traversal"`, `"deny:ratelimit:shell"`). Empty only on synthetic results that do not correspond to a single rule. |
| `approval_id`    | string            | only on `REQUIRE_APPROVAL` | Format: `ap_` followed by 32 hex chars. Pass to `/v1/approve/{id}`, `/v1/deny/{id}`, `/v1/status/{id}`. |
| `approval_url`   | string (URL)      | only on `REQUIRE_APPROVAL` | Absolute URL clients can present to a human reviewer. |

### Example

```json
{
  "schema_version": "v1",
  "decision": "ALLOW",
  "reason": "matched allow rule",
  "matched_rule": "allow:shell:ls"
}
```

This is the canonical fixture at
[`pkg/proxy/schema/v1/testdata/sample_result.json`](../pkg/proxy/schema/v1/testdata/sample_result.json).

## Backward-compatibility rules

These rules apply to every change to v1, regardless of who proposes it:

- **Never remove a field.** Even unused fields stay on the wire — a
  client that reads them today must keep reading them after upgrade.
- **Never change a field's type.** A `string` field stays `string`; a
  `number` stays `number`. Nullability does not change.
- **Never change a field's JSON name.** Renames ship as v2.
- **New optional fields are allowed.** They MUST default to absent
  (`omitempty` on the Go side; the equivalent on Python and TS).
  Existing SDK versions MUST continue to function with the new field
  absent or unknown.
- **Required fields stay required.** Adding a new required field is a
  breaking change and must wait for v2.
- **Decision enum stays closed.** Adding `REVIEW` or `RATE_LIMITED` to
  the response decision is a breaking change for every client that
  switches on the value. Use existing values plus `matched_rule`
  granularity (e.g. `deny:ratelimit:shell`) instead.

## SDK behavior

Both first-party SDKs (Python and TypeScript) emit a body whose key set
is a subset of the v1 schema. Specifically:

- They emit `snake_case` JSON keys (the Go server is strict about names).
- They drop `est_cost` when its value is `0`.
- They do **not** currently emit `schema_version`; the server defaults
  it. This is a documented optimization — adding `schema_version: "v1"`
  to every request is a no-op for v0.5 servers and forward-compatible.
- Both fail closed by default when the proxy is unreachable (DENY
  decision with `reason: "AgentGuard unreachable: …"`). The TypeScript
  SDK additionally honors `failMode: 'allow'` for callers whose threat
  model treats AgentGuard as best-effort.

## Related documentation

- [`API.md`](API.md) — endpoint reference (HTTP methods, status codes, auth).
- [`SDK_PYTHON.md`](SDK_PYTHON.md) — Python SDK guide.
- [`POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — YAML policy schema (separate from the wire schema).
- [`MIGRATION.md`](MIGRATION.md) — operator-facing upgrade notes.
