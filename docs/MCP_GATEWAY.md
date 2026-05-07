# MCP Gateway (v0.5)

> **Phase 4A design doc — locks the wire format, capability-merging
> rules, scope mapping, and approval flow for the `agentguard-mcp-gateway`
> binary that Phase 4B will implement.**

For cross-cutting concerns (binary structure, audit transport tag,
deployment topologies, fail-mode flag) see
[`docs/PROXY_ARCHITECTURE.md`](./PROXY_ARCHITECTURE.md).

The Phase 3 A15 preview (`python -m agentguard.adapters.mcp --upstream
"<cmd>"`, single upstream, no namespace prefixing) demonstrated the
shape. v0.5's gateway productionises and extends it: multi-upstream,
capability merging, namespaced tools, reconnect with backoff, and
typed JSON-RPC error responses.

---

## 1. Architecture

```
                       ┌──────────────────────────────────────┐
                       │  MCP host (Claude Desktop, Cursor,…) │
                       │   spawns the gateway as a subprocess │
                       └───────────────────┬──────────────────┘
                                           │ stdio (JSON-RPC, newline-delimited UTF-8)
                                           │
                       ┌───────────────────▼──────────────────┐
                       │       agentguard-mcp-gateway        │
                       │                                      │
                       │  • dispatcher: route by ns prefix   │
                       │  • policy: Engine.Check via         │
                       │    --guard-url /v1/check (HTTP)     │
                       │  • audit: BufferedAsyncLogger or    │
                       │    pass-through to central server   │
                       │  • upstream pool (one per ns):      │
                       │    • subprocess.Popen + reader/     │
                       │      writer goroutines              │
                       │    • reconnect-with-backoff         │
                       └───┬─────────────────┬────────────────┘
                           │                 │           …
            stdio          │                 │ stdio
                           │                 │
                ┌──────────▼─────┐  ┌────────▼────────┐
                │ fs MCP server  │  │ github MCP server│
                │ (filesystem)   │  │                 │
                └────────────────┘  └─────────────────┘
```

The gateway is **a single Go process** with one stdio in (the MCP host)
and N stdio out subprocesses (downstream MCP servers). It does **not**
embed an HTTP server for client-facing traffic — the MCP host always
talks stdio. It does open an HTTP client to call the central
AgentGuard server's `/v1/check`.

### 1.1 Why Go (not Python)

The Phase 3 A15 preview is in Python. Phase 4B reimplements in Go to
match the rest of the daemon binaries and to share `pkg/policy`,
`pkg/audit`, `pkg/proxy.ApprovalQueue`, and `pkg/notify` directly
(no HTTP hop required when running in-process). The Python
`GuardedMCPGateway` stays in `plugins/python/agentguard/adapters/mcp.py`
as a fallback for environments that can't run a Go binary, but the docs
default to the Go binary.

---

## 2. CLI surface

```
agentguard-mcp-gateway \
  --upstream "fs:npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --upstream "github:npx -y @modelcontextprotocol/server-github" \
  --upstream "everything:npx -y @modelcontextprotocol/server-everything" \
  --guard-url http://127.0.0.1:8080 \
  --api-key $AGENTGUARD_API_KEY \
  --tenant-id local \
  --fail-mode deny \
  --log-level info
```

| flag                | repeatable | meaning                                         |
|---------------------|------------|-------------------------------------------------|
| `--upstream "<ns>:<cmd>"` | yes  | Downstream MCP server. `ns` is the namespace prefix; `cmd` is the command (passed through `shlex.Split`). If `ns:` is omitted, the namespace defaults to the first whitespace-delimited token of `cmd`. |
| `--guard-url`       | no         | central server URL. Default `http://127.0.0.1:8080`. |
| `--api-key`         | no         | bearer for `/v1/check`. Falls back to `AGENTGUARD_API_KEY` env. |
| `--tenant-id`       | no         | default `local`.                                |
| `--fail-mode`       | no         | `deny` / `allow` / `fail-closed-with-audit`. Default `deny`. |
| `--log-level`       | no         | stderr verbosity. Default `info`.               |
| `--upstream-timeout`| no         | per-frame upstream-response timeout. Default `30s`. |
| `--reconnect-cap`   | no         | upper bound on reconnect backoff. Default `60s`. |

Stdout is reserved for JSON-RPC. All logging goes to stderr — the MCP
spec explicitly permits this (the host MAY capture or ignore it).

---

## 3. Protocol negotiation

### 3.1 Supported MCP protocol versions

```go
var SupportedProtocolVersions = []string{
    "2025-11-25", // current spec, default
    "2025-03-26", // streamable HTTP era
    "2024-11-05", // legacy stdio (still common in the field)
}
```

The Python SDK adapter is pinned to `2024-11-05` (`MCP_PROTOCOL_VERSION`
in `plugins/python/agentguard/adapters/mcp.py`). The Go gateway
deliberately accepts a wider set so it can sit between a recent client
and an older downstream (or vice versa).

### 3.2 Initialize handshake

Sequence:

1. Host sends `initialize` to the gateway over stdio:
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "initialize",
     "params": {
       "protocolVersion": "2025-11-25",
       "capabilities": { "roots": { "listChanged": true } },
       "clientInfo": { "name": "Claude Desktop", "version": "1.x" }
     }
   }
   ```
2. The gateway picks the **highest version in `SupportedProtocolVersions`
   that is ≤ the requested version**. If the requested version is older
   than the gateway's lowest supported version, it returns the JSON-RPC
   error spec'd by the MCP lifecycle doc:
   ```json
   {
     "jsonrpc": "2.0", "id": 1,
     "error": {
       "code": -32602,
       "message": "Unsupported protocol version",
       "data": { "supported": ["2024-11-05","2025-03-26","2025-11-25"], "requested": "1999-01-01" }
     }
   }
   ```
3. The gateway forwards `initialize` to **every configured upstream**
   with the negotiated version. If any upstream returns a different
   version (downstream pinned older), the gateway downgrades the
   session to the lowest common denominator and logs WARN.
4. The gateway returns its own `initialize` response to the host:
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "result": {
       "protocolVersion": "2025-11-25",
       "serverInfo": { "name": "agentguard-mcp-gateway", "version": "0.5.0" },
       "capabilities": {
         "tools": { "listChanged": false }
       }
     }
   }
   ```
   The gateway does **not** pretend to be the downstream — its
   `serverInfo` always identifies it as `agentguard-mcp-gateway`.
5. Host sends the `notifications/initialized` notification (no id, no
   response). The gateway forwards this to every upstream.

### 3.3 Capability merging

The gateway's `capabilities` returned to the host is the **union** of
each downstream's capabilities, intersected with what the gateway
itself can faithfully proxy.

| capability       | gateway behaviour                                          |
|------------------|------------------------------------------------------------|
| `tools`          | always advertised. `listChanged: false` because the gateway does not subscribe to upstream `tools/list_changed` notifications in v0.5 — see TODO below. |
| `resources`      | advertised iff at least one upstream advertises. v0.5 forwards `resources/list` and `resources/read` verbatim with namespace-prefixed URIs. (Out of scope for the MVP — listed here so the design doesn't preclude it.) |
| `prompts`        | same as resources. Out of scope for v0.5 MVP. |
| `logging`        | always advertised; gateway forwards `logging/setLevel` to every upstream. |
| `completions`    | not advertised. v0.6 follow-up. |

`TODO(v0.6, #N): forward upstream notifications/tools/list_changed and
flip our advertised capability to listChanged: true`. The notification
needs reverse-direction (server→host) plumbing that v0.5 keeps simple
by polling on `tools/list` calls.

---

## 4. Multi-upstream routing

### 4.1 Namespace prefixing

Each `--upstream "<ns>:<cmd>"` registers a namespace. Tool names from
that upstream are prefixed `<ns>:<toolname>` when surfaced to the host.

The colon delimiter is chosen because the MCP tool-name spec
(`2025-11-25/server/tools`) explicitly allows `_`, `-`, `.`, plus ASCII
alphanumerics. Colon is **not** in the SHOULD-allowed set, so it
unambiguously identifies the prefix as gateway-injected.

> **Design note — colon vs dot.** MCP's tool name SHOULD-set is
> `[A-Za-z0-9._-]`. Dots are allowed and are sometimes used by upstream
> servers (e.g., `admin.tools.list` from the spec example). Using `.`
> as the prefix delimiter would create ambiguity with such upstreams.
> Colon stands out and the spec only says SHOULD on the allowed-char
> set, so this is a controlled deviation. Document it loudly in
> `--help`.

### 4.2 `tools/list` aggregation

```json
// host → gateway
{ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }
```

The gateway fans out `tools/list` to every healthy upstream (skipping
degraded namespaces — see § 7). It receives N responses, each with its
own `result.tools` array, and merges them by name-prefixing every tool
and concatenating the arrays.

```json
// gateway → host
{
  "jsonrpc": "2.0", "id": 2,
  "result": {
    "tools": [
      { "name": "fs:read_file",     "description": "...", "inputSchema": {...} },
      { "name": "fs:write_file",    "description": "...", "inputSchema": {...} },
      { "name": "github:create_issue", "description": "...", "inputSchema": {...} }
    ]
  }
}
```

`description` and `inputSchema` are passed through unchanged.

If pagination is in play (`params.cursor`), the gateway implements
paging by streaming through upstreams in `--upstream` declaration
order: first exhaust namespace 1's pages, then 2's, etc. The
`nextCursor` value is opaque-base64 of `{"ns": "fs", "upstream_cursor":
"..."}` so the next call can resume on the right upstream.

### 4.3 `tools/call` routing

```json
// host → gateway
{
  "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "fs:read_file", "arguments": { "path": "/tmp/x" } }
}
```

The gateway:

1. Splits the name on the **first** `:`. Left = namespace; right =
   upstream tool name.
2. If no `:` is present or the namespace doesn't match a configured
   upstream: return `-32602 Invalid params: unknown namespace`.
3. Runs policy check (see § 4.4).
4. On `ALLOW`, rewrites the request to drop the prefix and forwards to
   the upstream:
   ```json
   { "jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": { "name": "read_file", "arguments": { "path": "/tmp/x" } } }
   ```
5. Relays the upstream's response to the host **verbatim**.

### 4.4 Policy mapping — the dual-check decision

**Recommendation: dual-check by default.** Each `tools/call` results in
**two** `Engine.Check` calls:

- One with `scope: "mcp_tool"`, `command: "<ns>:<toolname>"`,
  arguments redacted into `meta["arguments"]`.
- One with the **mapped scope** if the tool name (or its arguments) maps
  to an existing scope. E.g.:
  - `fs:read_file` with `path: "/etc/passwd"` → also check
    `scope: "filesystem"`, `path: "/etc/passwd"`, `action: "read"`.
  - `github:fetch_url` with `url: "https://api.github.com/..."` → also
    check `scope: "network"`, `url: ...`, `domain: "api.github.com"`.

The forwarded action proceeds **only if both checks return ALLOW**. If
either denies, the call denies. If either requires approval, the call
requires approval (and we surface the union of approval URLs — in
practice, the first one to fire).

#### 4.4.1 Why dual-check

Operators write existing scope rules:

```yaml
- scope: filesystem
  deny:
    - paths: ["/etc/**", "/root/**"]
```

…and they want those rules to apply whether the agent reaches
`/etc/passwd` via the SDK, the LLM proxy's tool-call extraction, **or**
an MCP `fs:read_file`. Single-check (mcp_tool only) breaks that
expectation: the operator would have to duplicate every filesystem rule
into an `mcp_tool` rule. Dual-check honours the existing rules without
duplication.

#### 4.4.2 Cost: two Engine.Check calls per tool call

Empirically (v0.4.x microbench), one `Engine.Check` runs ~5–15 µs on a
small policy. Two is still ≤ 30 µs — well below the network round-trip
to a downstream MCP server. The cost is acceptable.

#### 4.4.3 Configurable, but on by default

```
agentguard-mcp-gateway --policy-mode strict   # dual-check (default)
agentguard-mcp-gateway --policy-mode fast     # single-check (mcp_tool only)
```

`fast` mode dispatches one check with `scope: "mcp_tool"` and stamps
the inferred mapped scope as `meta["mapped_scope"]` — operators who
want filesystem semantics in `fast` mode have to write `mcp_tool` rules
that key on `meta.mapped_scope`. Most won't; that's why `strict` is the
default.

#### 4.4.4 Tool-scope mapping table

Two layers — built-in defaults + policy-YAML override.

Built-in (compiled into the gateway):

```go
var defaultToolScopeMap = []toolScopePattern{
    // pattern        scope        path-arg         url-arg      action-from-name
    {"*:read_*",      "filesystem", "path,file_path", "",          "read"},
    {"*:write_*",     "filesystem", "path,file_path", "",          "write"},
    {"*:edit_*",      "filesystem", "path,file_path", "",          "write"},
    {"*:delete_*",    "filesystem", "path,file_path", "",          "delete"},
    {"*:list_*",      "filesystem", "path,file_path", "",          "read"},
    {"*:fetch_*",     "network",    "",               "url",       ""},
    {"*:get_*",       "network",    "",               "url",       ""},
    {"*:post_*",      "network",    "",               "url",       ""},
    {"*:browse_*",    "browser",    "",               "url",       ""},
    {"*:execute_*",   "shell",      "",               "",          ""},
    {"*:run_*",       "shell",      "",               "",          ""},
    {"*:exec_*",      "shell",      "",               "",          ""},
}
```

Policy-YAML override under `mcp:`:

```yaml
mcp:
  tool_scope_map:
    "fs:read_file":   filesystem
    "fs:write_file":  filesystem
    "github:*":       network
    "*:execute_*":    shell
```

Merge semantics: policy entries are evaluated **before** built-ins.
First match wins. Operators can shadow a built-in by pinning a more
specific pattern earlier.

A tool that matches **no** mapping is checked only under `mcp_tool` —
operators who want default-deny on unknown tools write:

```yaml
rules:
  - scope: mcp_tool
    deny:
      - pattern: "*:*"            # belt-and-braces deny-all
    allow:
      - pattern: "fs:read_*"      # explicit allowlist
```

### 4.5 Example policy (full)

```yaml
version: "1"
name: "mcp-gated"

rules:
  # MCP-aware deny-list at the tool-name level
  - scope: mcp_tool
    deny:
      - pattern: "github:delete_*"
      - pattern: "fs:write_file"
        conditions:
          # require_prior so an explicit allow of read_file qualifies write
          require_prior: "fs:read_*"
          time_window: 5m
    require_approval:
      - pattern: "*:execute_*"
    allow:
      - pattern: "fs:read_*"
      - pattern: "everything:*"

  # Existing filesystem rules apply via the dual-check
  - scope: filesystem
    deny:
      - paths: ["/etc/**", "/root/**", "/.ssh/**"]
    allow:
      - paths: ["/tmp/**"]

  - scope: network
    deny:
      - domain: "169.254.169.254"     # cloud metadata
    allow:
      - domain: "api.github.com"

mcp:
  tool_scope_map:
    "fs:read_file":  filesystem
    "fs:write_file": filesystem
    "github:*":      network
```

---

## 5. Audit shape

One audit entry per `tools/call`, regardless of dual-check (the two
checks merge into a single audit entry with the **denying** rule's
result if either denies, otherwise the more specific scope's result).

```json
{
  "schema_version": "v1",
  "transport": "mcp_gateway",
  "timestamp": "2026-05-06T12:34:56.789Z",
  "session_id": "claude-desktop-pid-12345",
  "agent_id": "mcp-gateway",
  "request": {
    "scope": "mcp_tool",
    "command": "fs:read_file",
    "path": "/tmp/x",
    "meta": {
      "arguments_json": "{\"path\":\"/tmp/x\"}",
      "namespace": "fs",
      "upstream_cmd": "npx -y @modelcontextprotocol/server-filesystem /tmp",
      "policy_mode": "strict",
      "secondary_check_scope": "filesystem",
      "secondary_check_decision": "ALLOW"
    }
  },
  "result": {
    "decision": "ALLOW",
    "matched_rule": "allow:filesystem:tmp",
    "reason": "matched allow rule for /tmp/**"
  },
  "duration_ms": 4
}
```

`Meta["arguments_json"]` is **redacted** through
`pkg/notify.DefaultRedactor` before being written. Bearer tokens, AWS
keys, GitHub PATs, Slack tokens, and `key=value` secret patterns are
scrubbed.

The dashboard renders the `transport: "mcp_gateway"` chip in the audit
feed (color: blue, distinct from `sdk` green and `llm_api_proxy`
purple — A18/A22 implementers pick the exact palette).

---

## 6. Approval flow

### 6.1 First call (no approval id)

Host sends `tools/call`. Gateway runs policy check. Result =
`REQUIRE_APPROVAL` with `approval_id="ap_<32hex>"` and
`approval_url="http://127.0.0.1:8080/dashboard?approval=ap_..."`.

The gateway returns:

```json
{
  "jsonrpc": "2.0", "id": 3,
  "result": {
    "content": [{
      "type": "text",
      "text": "[AgentGuard] Action requires approval.\nReason: <reason>\nApproval ID: ap_<hex>\nApprove at: http://127.0.0.1:8080/dashboard?approval=ap_<hex>"
    }],
    "isError": true
  }
}
```

`isError: true` matches the spec for tool execution errors. The
language model sees this as a tool error and either retries (see § 6.2)
or surfaces the URL to the user.

### 6.2 Retry with approval id

The MCP spec's `_meta` reservation makes this clean. After the operator
approves on the dashboard, the model retries the same `tools/call` with
`_meta.dev.agentguard/approval_id` populated:

```json
{
  "jsonrpc": "2.0", "id": 4, "method": "tools/call",
  "params": {
    "name": "fs:write_file",
    "arguments": { "path": "/tmp/output.txt", "content": "..." },
    "_meta": { "dev.agentguard/approval_id": "ap_<hex>" }
  }
}
```

The round-trip is single-hop and stateless on the gateway — the
central server owns the truth:

1. The bridge reads `_meta["dev.agentguard/approval_id"]` and stamps
   it on the internal `ToolsCallRequest.ApprovalID`.
2. `HTTPPolicyClient.Check` propagates the value as a top-level
   `approval_id` field on the `/v1/check` body (alongside the existing
   `meta.approval_id` echo, which is retained for audit-trail
   discoverability).
3. The central server's `handleCheck`, when it sees a non-empty
   `approval_id` on the wire, consults its `ApprovalQueue` *before*
   running policy:
   - **resolved=true && decision=ALLOW** → returns
     `decision: ALLOW, matched_rule: "allow:approved"`. The audit
     log records this as a separate entry tagged
     `transport: "mcp_gateway"` so investigators can distinguish
     human-approved from policy-allowed traffic.
   - **resolved=true && decision=DENY** → returns
     `decision: DENY, matched_rule: "deny:approved"`. The bridge
     surfaces it as a tool error with the operator's reason.
   - **resolved=false** (still pending) → returns the *same*
     `approval_id` and `approval_url` back, so the polling client
     keeps waiting rather than spawning a duplicate queue entry.
   - **unknown id** (typo / expired / wrong tenant) → falls through
     to normal policy evaluation. An attacker who guesses an id
     gains nothing; an honest caller with a stale id gets correct
     enforcement.

The gateway never queries `/v1/status/{id}` directly on the retry —
that endpoint is reserved for the polling SDK clients. The dual-check
pattern (mcp_tool + mapped scope) preserves the approval id on both
calls so a resolved approval short-circuits whichever scope the
policy used to require it.

The reserved `_meta` prefix `dev.agentguard/` follows the MCP
`2025-11-25` `_meta` rules: reverse-DNS-style label, recommended
form. We **do not** use `io.modelcontextprotocol/` or `dev.mcp/` —
those are explicitly reserved for MCP itself.

### 6.3 Why client-supplied id (not in-process state)

The gateway is single-process per MCP host, but the central
`ApprovalQueue` lives on the central server. If we keyed approvals by
in-process call-signature on the gateway, we'd drop the mapping every
time the gateway restarted. Echoing the id through `_meta` is
restart-safe and doesn't require synchronisation across multiple
gateway instances behind a load balancer.

---

## 7. Reconnect strategy

Each upstream subprocess is owned by an "upstream manager" goroutine.
Detection: stdin/stdout EOF or process exit signal.

```go
backoff := []time.Duration{
    1 * time.Second,
    2 * time.Second,
    5 * time.Second,
    30 * time.Second,
    60 * time.Second,
}
// Capped at backoff[len-1] for subsequent retries.
```

While in degraded state:

- The namespace flag is set.
- `tools/list` aggregation **excludes** the namespace's tools (the
  client just doesn't see them — the model can't try to call them).
- `tools/call` to a degraded namespace returns:
  ```json
  {
    "jsonrpc": "2.0", "id": ...,
    "error": { "code": -32603,
               "message": "Internal error: <ns> upstream unavailable" }
  }
  ```
- Health endpoint reflects the degradation in `warnings`.

Recovery: when the subprocess restarts and re-completes `initialize`,
the namespace flag clears and the next `tools/list` aggregation
re-includes its tools.

The reconnect loop has a hard ceiling of 60s between attempts — a
permanently-broken upstream stays degraded indefinitely without
hammering the system.

---

## 8. Wire format details

### 8.1 Stdio framing

Per spec: newline-delimited UTF-8 JSON. **No embedded newlines** in any
JSON-RPC message. The gateway:

- Reads from stdin via `bufio.Scanner` with a 4 MiB max line buffer
  (raise from 64 KiB default; tool argument JSON can legitimately be
  large).
- Writes to stdout via a `*os.File` direct write, one frame at a time,
  with a `\n` terminator.
- Holds a write mutex for stdout so concurrent goroutines (say, two
  upstreams responding to two in-flight requests) don't interleave.

### 8.2 JSON parse errors

A malformed frame on the host's stdin **does not crash the gateway**.
Per the Phase 3 A15 pattern:

```go
for scanner.Scan() {
    line := scanner.Bytes()
    if len(bytes.TrimSpace(line)) == 0 { continue }
    var msg JSONRPCFrame
    if err := json.Unmarshal(line, &msg); err != nil {
        log.Printf("WARN dropping malformed frame: %v", err)
        continue
    }
    g.dispatch(msg)
}
if err := scanner.Err(); err != nil {
    // I/O failure — treat as host disconnect, run shutdown
}
```

Per the JSON-RPC 2.0 spec, we *could* emit a `-32700 Parse error`
response — but the malformed frame may not even have a parseable id, so
v0.5 silently drops as the SDK adapter does today.

### 8.3 Concurrency model

- **Stdin reader**: one goroutine. Pushes frames into a per-call
  dispatcher.
- **Per-call dispatcher**: spawns a goroutine for each tools/call so
  they run concurrently. Other JSON-RPC methods (initialize,
  tools/list, ping) are dispatched synchronously to maintain ordering.
- **Per-upstream**: one writer goroutine and one reader goroutine.
  Frames out of the dispatcher land on the writer's channel; frames in
  from the reader land in a per-id response map keyed by JSON-RPC id.
- **Stdout writer**: one goroutine drains a fan-in channel with a write
  mutex. Frames are flushed with `os.Stdout.Sync()` after every write.

### 8.4 Cancellation

When the host sends `notifications/cancelled` for an in-flight tool
call, the gateway forwards the notification to the relevant upstream
**and** cancels the goroutine waiting on the response. The audit entry
is still written (decision=`CANCELLED`, with the original policy
result if it had landed before cancellation).

---

## 9. Test strategy (informs Phase 4B implementation)

| layer                    | tests                                                                       |
|--------------------------|-----------------------------------------------------------------------------|
| Frame parser             | malformed JSON, embedded newline, oversize line, UTF-8 boundary             |
| Initialize               | version negotiation matrix (client newer/older/equal vs gateway support set)|
| Tools/list aggregation   | 0/1/N upstreams, paging, name collision across namespaces                   |
| Tools/call routing       | unknown namespace, ALLOW, DENY, REQUIRE_APPROVAL, retry-with-approval-id    |
| Dual-check               | `mcp_tool` allow + `filesystem` deny → DENY; both allow → ALLOW             |
| Reconnect                | upstream crashes mid-stream, backoff schedule respected, recovery clears flag|
| Approval round-trip      | _meta prefix variants, expired id (404), unresolved id (still pending)      |
| Cancellation             | cancel propagates to upstream and the policy check goroutine                |
| Stdout serialisation     | concurrent upstream responses don't interleave bytes                        |
| Real upstream            | spawn `npx -y @modelcontextprotocol/server-everything`, drive a full session|

The "real upstream" test is the equivalent of the Python integration
suite — it goes in a separate `integration-tests` job that's
non-blocking on PR until we have one week of green data (mirrors the
A14 decision).

---

## 10. Out of scope for v0.5 (TODOs)

- `TODO(v0.6, #N): forward upstream notifications/tools/list_changed
  and flip the gateway's advertised capability to listChanged: true`.
- `TODO(v0.6, #N): full resources/* and prompts/* support, currently
  forwarded verbatim with namespace-prefixed URIs but not test-covered`.
- `TODO(v0.6, #N): Streamable HTTP transport on the host-facing side`
  for non-stdio MCP hosts. v0.5 is stdio-only on both sides.
- `TODO(v0.6, #N): per-upstream rate limiting`. The central server's
  rate limiter applies, but a misbehaving downstream that floods on
  tools/list will be felt.

---

## 11. Client integration

Phase 4B ships working configs for the five MCP clients with the largest
user bases as of 2026-05. Each `examples/<client>-config.json` is the
authoritative copy-paste, and each has a sibling `<client>-config.md`
with the OS-specific config-file path, the source-doc URL, and a
verification checklist. The fastest end-to-end is
[`docs/QUICKSTART_MCP.md`](./QUICKSTART_MCP.md).

| Client | Example | Config-file path |
|---|---|---|
| Claude Desktop | [`examples/claude-desktop-config.json`](../examples/claude-desktop-config.json) | macOS `~/Library/Application Support/Claude/claude_desktop_config.json` • Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | [`examples/cursor-config.json`](../examples/cursor-config.json) | global `~/.cursor/mcp.json` or per-project `<workspace>/.cursor/mcp.json` |
| Cline (VS Code) | [`examples/cline-config.json`](../examples/cline-config.json) | inside VS Code's `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` (use the in-app **Configure MCP Servers** button) |
| Continue.dev | [`examples/continue-config.json`](../examples/continue-config.json) | `~/.continue/config.json` (legacy) or `<workspace>/.continue/mcpServers/*.yaml` |
| Zed | [`examples/zed-config.json`](../examples/zed-config.json) | `~/.config/zed/settings.json` — top-level key is `context_servers`, NOT `mcpServers` |

### 11.1 Minimal Claude Desktop config

```jsonc
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard-mcp-gateway",
      "args": [
        "--upstream", "fs:npx -y @modelcontextprotocol/server-filesystem /tmp",
        "--guard-url", "http://127.0.0.1:8080",
        "--api-key", "$AGENTGUARD_API_KEY",
        "--policy", "/etc/agentguard/policy.yaml",
        "--policy-mode", "strict",
        "--fail-mode", "deny"
      ],
      "env": { "AGENTGUARD_API_KEY": "<paste-or-source-from-secret-store>" }
    }
  }
}
```

The gateway namespaces tools per upstream (`fs:read_text_file`,
`github:create_issue`, …), so policies written against namespaced names
work without changes. Strict policy mode (the default) requires
`--policy <path>` because the gateway resolves the
`tool_scope_map` locally to drive the dual-check (mcp_tool + mapped
scope) — see § 4.4.3 above.

### 11.2 Verifying the integration

Once the config is saved and the client restarted (or, for Cline /
Continue, reloaded — they pick up changes live):

1. **The MCP indicator appears.** Claude Desktop shows a small slider in
   the chat input; Cursor's MCP panel lists `agentguard`; Cline's
   MCP-Servers tab shows green; Continue's tools list populates in agent
   mode; Zed's Assistant shows the merged tools.
2. **Tools/list aggregation works.** Ask the model "what tools do you
   have?" — every tool from every upstream should be present, prefixed
   with the namespace.
3. **An ALLOW shows on the dashboard.** Ask the model to perform a
   benign action (read a file from `/tmp`, fetch `https://example.com`).
   The dashboard at <http://127.0.0.1:8080/dashboard> shows an `ALLOW`
   event with `transport=mcp_gateway` and the namespaced tool name.
4. **A DENY shows on the dashboard.** Ask the model to read
   `/etc/passwd`. The dashboard shows a `DENY` event; the model reports
   the tool errored with the policy reason embedded.

If actions never reach AgentGuard, the gateway is probably failing to
launch — see § 11.3 below. If actions reach the gateway but never reach
AgentGuard's `/v1/check`, check that `--guard-url` is reachable from the
gateway's process (loopback issues on Docker bridge networks bite here).

### 11.3 Common gotchas

**Binary not on PATH.** Claude Desktop / Cursor / Zed / Cline launched
from the Finder (macOS) or the Start menu (Windows) inherit a sparse
PATH that does not include `$(go env GOPATH)/bin`. If `which
agentguard-mcp-gateway` works in your terminal but the MCP indicator
never appears, replace `"command": "agentguard-mcp-gateway"` with the
absolute path to the binary.

**Shell-var expansion in flag strings.** None of the supported clients
expand `$AGENTGUARD_API_KEY` or `$VAR` inside flag-string arguments.
The recommended pattern is:

- Set the variable in the `env` block of the server entry (which **is**
  forwarded to the subprocess).
- Reference it from your launcher script or secret manager — never paste
  raw keys into the JSON.
- Cursor additionally supports `${env:NAME}` interpolation in `args`
  (verified against Cursor docs 2026-05-05); the other clients do not.

**Stale tool list after policy edit.** Adding or removing tools from a
policy does not require a gateway restart — the gateway re-checks every
call against the central server, which hot-reloads via `--watch`. But
adding a *new upstream* (a new `--upstream` flag) does require a
gateway restart, which means restarting the MCP client.

**Missing `npx`.** All bundled examples use `npx -y …` for upstreams.
If `npx` isn't on PATH inside the MCP client's environment (a
notoriously common Windows issue), the upstream subprocess fails to
launch and the gateway logs a degraded-upstream WARN to stderr — visible
in Claude Desktop's `mcp.log` and equivalents. Install Node 18+ and
verify `npx --version` before debugging deeper.

**Cookie-based auth on macOS.** AgentGuard's session cookies depend on
the connection's TLS state. When the central server runs on plain HTTP
on `127.0.0.1` (the dev default) and Claude Desktop talks to it from
the gateway, the API key is sent as `Authorization: Bearer …` — no
cookies are involved, so this is fine. The cookie path only matters if
you log in to the dashboard from a browser, in which case use
`--allowed-origin` and (behind a TLS-terminating proxy)
`--tls-terminated-upstream`.

**`--api-key` is auth for `/v1/check`, not for the gateway itself.**
The gateway is launched as a subprocess by the MCP client and trusts
its parent — there is no inbound HTTP for the gateway. The
`--api-key` flag is only used for the gateway's outbound
`/v1/check` calls to the central AgentGuard server.

---

## 12. References

- MCP spec, current revision (verified 2026-05-06):
  - <https://modelcontextprotocol.io/specification/2025-11-25/basic>
  - <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
  - <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
  - <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP error codes: JSON-RPC 2.0 reserved range (-32768 to -32000); MCP
  uses `-32602` for invalid params, `-32603` for internal errors,
  `-32700` for parse errors. AgentGuard does not introduce custom
  error codes — denial and approval-required are returned as **tool
  execution errors** (`isError: true`), not JSON-RPC protocol errors.
- Phase 3 A15 preview: `plugins/python/agentguard/adapters/mcp.py`
  (`GuardedMCPGateway`).
- Cross-cutting design: [`docs/PROXY_ARCHITECTURE.md`](./PROXY_ARCHITECTURE.md).
