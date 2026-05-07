# LLM API Proxy

The `agentguard-llm-proxy` binary speaks `/v1/chat/completions`
(OpenAI) and `/v1/messages` (Anthropic) wire formats and forwards
to the real upstream after gating any tool calls the model emits —
including tool calls that arrive inside an SSE stream.

For cross-cutting concerns (binary structure, audit transport tag,
deployment topologies, fail-mode flag) see
[`docs/PROXY_ARCHITECTURE.md`](./PROXY_ARCHITECTURE.md).

The core technical idea — pause/resume of an LLM SSE stream when a
tool call needs gating — has direct parallels to mid-stream rewrites
in HTTP-mitm tools (go-mitmproxy's stream addons) but is novel in the
LLM-proxy space.

---

## 1. Architecture

```
                ┌─────────────────────────────────────┐
                │  agent process (LangChain, raw      │
                │  OpenAI SDK, etc.)                  │
                │  OPENAI_BASE_URL=http://...:8081    │
                └──────────────────┬──────────────────┘
                                   │ HTTP (chat/completions, messages)
                                   │ Authorization: Bearer <user-token>
                                   ▼
                ┌─────────────────────────────────────┐
                │      agentguard-llm-proxy           │
                │  (HTTP server, default 127.0.0.1:8081)│
                │                                      │
                │  ┌─ /v1/chat/completions  (OpenAI)   │
                │  ├─ /v1/completions       (legacy)   │
                │  ├─ /v1/messages          (Anthropic)│
                │  ├─ /v1/embeddings        (passthru) │
                │  ├─ /v1/models            (passthru) │
                │  └─ /metrics, /health                │
                │                                      │
                │  per-request:                        │
                │  • parse body for tools[]            │
                │  • upstream HTTP client (passthrough │
                │    Authorization)                    │
                │  • streaming parser (OAI deltas /    │
                │    Anthropic events)                 │
                │  • tool-call accumulator → policy    │
                │    check → forward / refuse-rewrite  │
                └──────────────────┬──────────────────┘
                                   │ HTTP/HTTPS (passthrough)
                                   ▼
                ┌─────────────────────────────────────┐
                │   api.openai.com  /  api.anthropic.com │
                │   (or self-hosted OpenAI-compatible)│
                └─────────────────────────────────────┘

       ─── policy-check side channel ───
       proxy → http://127.0.0.1:8080/v1/check  (central guard)
```

---

## 2. CLI surface

```
agentguard-llm-proxy \
  --listen 127.0.0.1:8081 \
  --upstream-openai https://api.openai.com \
  --upstream-anthropic https://api.anthropic.com \
  --guard-url http://127.0.0.1:8080 \
  --api-key $AGENTGUARD_API_KEY \
  --proxy-api-key $PROXY_AUTH_TOKEN \
  --tenant-id local \
  --fail-mode deny \
  --max-buffer-bytes 1048576 \
  --log-level info
```

| flag                     | meaning                                                   | default                      |
|--------------------------|-----------------------------------------------------------|------------------------------|
| `--listen`               | address to bind (host:port)                               | `127.0.0.1:8081`             |
| `--upstream-openai`      | base URL for OpenAI-shape requests                        | `https://api.openai.com`     |
| `--upstream-anthropic`   | base URL for Anthropic-shape requests                     | `https://api.anthropic.com`  |
| `--guard-url`            | central server `/v1/check` URL                            | `http://127.0.0.1:8080`      |
| `--api-key`              | bearer for `/v1/check` (from `AGENTGUARD_API_KEY`)        | unset (warn)                 |
| `--proxy-api-key`        | optional bearer the proxy itself enforces on inbound. Empty = no proxy auth (localhost-only safe). | unset |
| `--tenant-id`            | tenant header value                                       | `local`                      |
| `--fail-mode`            | `deny` / `allow` / `fail-closed-with-audit`               | `deny`                       |
| `--max-buffer-bytes`     | per-stream tool-call buffer cap (see § 6)                 | `1048576` (1 MiB)            |
| `--policy`               | path to AgentGuard policy YAML; loaded only for `tool_scope_map` operator overrides. Without it, the proxy falls back to `DefaultLLMToolScopeMap` and logs a WARN at startup. | unset |
| `--log-level`            | stderr verbosity                                          | `info`                       |

If `--api-key` is unset and `--listen` is non-loopback (`0.0.0.0:` or
external IP), the proxy logs WARN and refuses to start in production
(matches the central server's localhost-only fallback policy).

---

## 3. Forwarding model

### 3.1 Headers

The proxy is **dumb on auth**: it forwards `Authorization`,
`x-api-key` (Anthropic), `OpenAI-Organization`, `OpenAI-Project`, and
all other request headers to the upstream **verbatim**. The proxy
never reads the user's bearer token; the upstream is responsible for
auth. The `Authorization` header for the **central guard server** is a
separate concern (see § 3.2) — the proxy adds it on the
`/v1/check` side channel only, never on the upstream-forwarded request.

`User-Agent` is rewritten to include an `AgentGuard-Proxy/<version>`
suffix so server-side logs at OpenAI/Anthropic can identify
proxied traffic. Spec-compliant: `User-Agent` is mutable per RFC 7231.

The `Host` header is rewritten to the upstream's authority. Cookie
headers (rare for LLM APIs) are forwarded unchanged.

### 3.2 Body handling

Two paths:

#### Non-streaming (`stream: false` or absent)

1. Read full body into memory. Cap: `--max-buffer-bytes` (1 MiB
   default). Larger requests get HTTP 413.
2. Parse JSON to inspect `tools` (OpenAI) / `tools` (Anthropic) for
   policy-relevant context. **The request itself is not gated** — only
   the model's tool-call response is gated.
3. Forward the **original bytes** (not re-encoded JSON — preserves
   field order, whitespace, and any caller-specific quirks the
   upstream might key on).
4. Stream the upstream response back to the client. If the response
   contains `tool_calls` (OpenAI) or `tool_use` content blocks
   (Anthropic), gate them before forwarding the response body. See
   § 5.

#### Streaming (`stream: true` or `Accept: text/event-stream`)

1. Forward request body (capped, but typically small).
2. Open the upstream connection with `Accept: text/event-stream`.
3. Read the upstream SSE response chunk-by-chunk via the streaming
   parser (§ 5).
4. **Pause and gate** any tool calls before flushing the
   corresponding deltas to the client.

### 3.3 Pass-through endpoints

`/v1/embeddings` and `/v1/models` are forwarded with one audit entry
(`scope: "network"`, `transport: "llm_api_proxy"`) but **no policy
check** — there are no tool calls in the response. This is honest
about coverage: the proxy is for tool-call gating, not for blocking
the agent from talking to the model.

---

## 4. Tool-call → scope mapping

The mapping table is shipped with the binary and overridable via
policy YAML, mirroring the MCP gateway approach (§ 4.4 of
`MCP_GATEWAY.md`).

### 4.1 Built-in defaults

```go
var defaultLLMToolScopeMap = []toolScopePattern{
    // exact / glob name              scope         path-arg          url-arg     action
    {"bash",                          "shell",      "",               "",         ""},
    {"run_command",                   "shell",      "",               "",         ""},
    {"execute_command",               "shell",      "",               "",         ""},
    {"shell",                         "shell",      "",               "",         ""},
    {"read_file",                     "filesystem", "path,file_path", "",         "read"},
    {"write_file",                    "filesystem", "path,file_path", "",         "write"},
    {"edit_file",                     "filesystem", "path,file_path", "",         "write"},
    {"delete_file",                   "filesystem", "path,file_path", "",         "delete"},
    {"list_directory",                "filesystem", "path,file_path", "",         "read"},
    {"glob",                          "filesystem", "path",           "",         "read"},
    {"grep",                          "filesystem", "path",           "",         "read"},
    {"web_search",                    "network",    "",               "url,query","search"},
    {"fetch_url",                     "network",    "",               "url",      "fetch"},
    {"http_request",                  "network",    "",               "url",      ""},
    {"playwright_*",                  "browser",    "",               "url",      ""},
    {"browser_*",                     "browser",    "",               "url",      ""},
    {"navigate",                      "browser",    "",               "url",      "navigate"},
    {"click",                         "browser",    "",               "",         "click"},
}
```

### 4.2 Policy-YAML override

```yaml
llm:
  tool_scope_map:
    custom_db_query:    network
    deploy_lambda:      shell
    "*_secret":         data
```

Merge: policy entries **before** built-ins, first match wins. Same
semantics as the MCP gateway.

### 4.3 Unmapped tools

A tool name that matches **no** built-in or policy entry is dispatched
as `scope: "unmapped"` with the tool name in `command` and the
arguments in `meta["arguments_json"]` (redacted).

Operators MUST configure an `unmapped` scope rule to control behaviour:

```yaml
- scope: unmapped
  deny:
    - pattern: "*"     # default-deny on anything we don't recognise
```

If no `unmapped` rule exists, the engine's standard fall-through
default-deny applies — fail-closed by design. A tool the policy
author has not seen is, by AgentGuard's policy contract, denied.

### 4.4 Multiple-arg scope upgrades

Some tools take both `path` and `url` (e.g., a `download_to_file`
tool). The mapping resolves to the **most-specific scope inferred from
arguments** at check time:

- `path` present → `filesystem`,
- `url` present → `network`,
- both present → **two checks** dispatched (filesystem AND network); both
  must allow.

This mirrors the MCP gateway's dual-check pattern but applied to a
single tool definition rather than a wrapping `mcp_tool` scope.

---

## 5. Streaming pause / resume / rewrite — the hard one

This is the core technical innovation. When the response is streaming
and the model is calling tools, the proxy must:

1. Read the SSE stream from upstream chunk by chunk.
2. Parse tool-call deltas (different shape per provider — see § 5.1
   and § 5.2).
3. **Accumulate** until a tool call is complete.
4. **Pause** the stream to the client (do not flush partial deltas
   yet — buffer them).
5. Run `Engine.Check` on the assembled tool call.
6. **ALLOW** → flush buffered deltas to the client and resume the
   stream.
7. **DENY** → rewrite the buffered deltas as a synthetic tool-result
   message containing AgentGuard's denial; resume the stream with the
   rewrite.
8. **REQUIRE_APPROVAL** → similar to DENY but the synthetic message
   includes the approval URL.

### 5.1 OpenAI streaming wire format

> **Verified shape** (cross-checked against the OpenAI Python SDK
> source tree and live captures; reference docs at
> <https://platform.openai.com/docs/api-reference/chat/streaming> and
> <https://platform.openai.com/docs/guides/streaming-responses>.)

SSE-formatted lines: `data: <json>\n\n`. Final delimiter: `data: [DONE]\n\n`.

A streaming chat-completion delta with tool calls:

```
data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1730000000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"read_file","arguments":""}}]},"finish_reason":null}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path"}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\":\"/tmp/x"}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"}"}}]}}]}

data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]
```

Critical observations:

- Multiple tool calls in one assistant turn arrive **interleaved by
  `tool_calls[i].index`**. The accumulator MUST key by index, not by
  delta arrival order.
- `tool_calls[i].id` may appear only on the **first** delta for that
  index. Subsequent deltas for the same index have only `function`
  fields.
- `function.name` may be split across deltas in principle; in practice
  it always arrives whole on the first delta. The accumulator handles
  fragmentation for both `name` and `arguments` defensively.
- `arguments` is a **JSON-encoded string** in the wire format (yes — the
  field is a string, not an object). Concatenating fragments and
  parsing the result yields the actual argument object.
- `finish_reason: "tool_calls"` on a delta with empty `delta` signals
  the assistant turn is complete. **This is the gate trigger** — every
  accumulated tool call must be policy-checked before we forward the
  next delta.

### 5.2 Anthropic streaming wire format

> **Verified shape** (against `https://platform.claude.com/docs/en/api/messages`,
> fetched 2026-05-06.)

SSE event types arrive in this order for a single message that calls a
tool:

```
event: message_start
data: { "type": "message_start", "message": { ... } }

event: content_block_start
data: { "type": "content_block_start", "index": 0,
        "content_block": { "type": "tool_use",
                           "id": "toolu_01D7FLrfh4GYq7yT1ULFeyMV",
                           "name": "read_file",
                           "input": {} } }

event: content_block_delta
data: { "type": "content_block_delta", "index": 0,
        "delta": { "type": "input_json_delta",
                   "partial_json": "{\"path\": \"/tmp" } }

event: content_block_delta
data: { "type": "content_block_delta", "index": 0,
        "delta": { "type": "input_json_delta",
                   "partial_json": "/x\"}" } }

event: content_block_stop
data: { "type": "content_block_stop", "index": 0 }

event: message_delta
data: { "type": "message_delta", "delta": { "stop_reason": "tool_use" } }

event: message_stop
data: { "type": "message_stop" }
```

Critical observations:

- Each content block has its own `index` (0-based). Multiple tool_use
  blocks in one message stream get distinct indices.
- `content_block_start` carries `id`, `name`, and an empty `input: {}`.
- `content_block_delta` with `delta.type == "input_json_delta"` carries
  a `partial_json` string. Concatenate ALL `partial_json` for a given
  block index, parse the result as JSON.
- `content_block_stop` (with the matching index) signals the tool
  block is fully assembled. **This is the gate trigger** for that
  block. Anthropic gates **per block**, not per assistant message —
  this is the key shape difference vs OpenAI.
- `message_delta { stop_reason: "tool_use" }` is informational; gating
  has already happened.

### 5.3 Pause/resume mechanism (both providers)

Per-request state held in a `streamGater` struct:

```go
type streamGater struct {
    provider       string                       // "openai" | "anthropic"
    accumulator    map[int]*toolCallAccumulator // keyed by index
    bufferedBytes  []byte                       // raw upstream SSE bytes pending flush
    bufferedSize   int64                        // running size, capped by --max-buffer-bytes
    flushedHeader  bool                         // have we sent the SSE response headers downstream
    clientWriter   http.ResponseWriter
    flusher        http.Flusher
    upstreamReader io.ReadCloser
    guard          *guardClient                 // /v1/check side channel
    auditTransport string                       // "llm_api_proxy"
}
```

Algorithm (OpenAI):

```
for each SSE line from upstream:
  parse(line) -> delta
  append raw line bytes to bufferedBytes
  bufferedSize += len(line)
  if bufferedSize > maxBufferBytes:
    abort: write a synthetic refusal block to client and return
  for each delta.tool_calls[i]:
    accumulator[i].appendName(delta.tool_calls[i].function.name)
    accumulator[i].appendArgs(delta.tool_calls[i].function.arguments)
    accumulator[i].id = first non-empty delta id observed for this index
  if delta.finish_reason == "tool_calls":
    // GATE TRIGGER — assistant turn complete.
    decisions := for each accumulated tool_call: guard.Check(...)
    if all ALLOW:
      flush bufferedBytes to client                          // resume
      bufferedBytes = nil; bufferedSize = 0
      accumulator = {}
    else:
      // Don't flush the buffered deltas. Synthesize refusal:
      write synthetic chunk to client (see § 5.4)
      bufferedBytes = nil; bufferedSize = 0
      accumulator = {}
      // Continue reading upstream to drain it; discard remaining bytes
      // unless there are no more tool calls coming (assistant turn done).
  elif delta has no tool_calls AND no buffered tool calls:
    // Plain content delta; flush immediately to keep TTFT low.
    flush this delta to client
    bufferedBytes = ...  // reset to empty for non-tool deltas
```

Algorithm (Anthropic): identical structure, but:

- Gate per `content_block_stop` (with matching index whose
  `content_block_start` was a `tool_use`), not per `finish_reason`.
- Plain `text` blocks pass through immediately. Only `tool_use` blocks
  buffer.
- The buffer scope is **the bytes for that one block**, from
  `content_block_start` through `content_block_stop`. Other content
  blocks (text, image) flow around the buffered tool block in arrival
  order — but if a text block arrives **after** an unflushed
  `tool_use` block on the same message, we flush the tool block first
  (preserving order).

### 5.4 Synthetic refusal shape

#### OpenAI

When DENY (or REQUIRE_APPROVAL with a URL):

```
data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"[AgentGuard] Tool call denied: <reason>"},"finish_reason":"stop"}]}

data: [DONE]
```

The agent SDK's normal text-completion handling engages — the model
appears to have given up and returned plain text. No SDK changes
required.

For REQUIRE_APPROVAL the content is:

```
[AgentGuard] Tool call requires approval.
Reason: <reason>
Approval ID: ap_<hex>
Approve at: <approval_url>
```

> **Design note on `tool` role injection.** An earlier draft proposed
> injecting a synthetic `role: "tool"` message with a fake
> `tool_call_id`. That has two problems: (a) `role: "tool"` messages
> are valid in **request** turns, not response deltas — the OpenAI
> response schema only emits `role: "assistant"`; (b) the agent's SDK
> would expect a paired `tool_calls[*].id` it had already buffered,
> which the proxy did NOT flush. Synthesising assistant text is
> simpler and correct.

#### Anthropic

For a denied `tool_use` block, the proxy emits a synthetic `text`
block in place:

```
event: content_block_start
data: { "type": "content_block_start", "index": <same>,
        "content_block": { "type": "text", "text": "" } }

event: content_block_delta
data: { "type": "content_block_delta", "index": <same>,
        "delta": { "type": "text_delta",
                   "text": "[AgentGuard] Tool call denied: <reason>" } }

event: content_block_stop
data: { "type": "content_block_stop", "index": <same> }
```

Anthropic's content_block index is reusable — emitting a `text` block
at the same index that the `tool_use` block was buffered for is wire-
legal. The downstream `message_delta { stop_reason }` field is
rewritten from `tool_use` to `end_turn` to prevent the agent from
expecting a tool result it's not getting.

### 5.5 Byte-identity invariant on ALLOW

**Critical correctness property:** in the ALLOW path, the bytes
delivered to the client must be **byte-identical** to what the upstream
sent. The proxy buffers raw bytes (not re-marshalled JSON) for exactly
this reason. Re-marshalling could re-order fields, normalise
whitespace, or change Unicode escape forms — any of which can break
client SDKs that rely on byte-level invariants (some agents hash the
delta stream for reproducibility).

This invariant is testable: capture an upstream stream once, replay it
through the proxy with an ALLOW policy, byte-diff the output. The CI
suite asserts the diff is empty.

### 5.6 Pause/resume mechanism — buffer bound

`--max-buffer-bytes` (default 1 MiB) caps the bytes buffered while
gating a single tool call. Rationale:

- Typical tool argument JSON is 50–500 bytes.
- Pathological cases (large file contents passed as a tool argument,
  e.g., a `write_file` with a multi-megabyte payload) hit this cap.
- Above the cap, the proxy emits a synthetic refusal: "tool call too
  large to gate (> N bytes); rejected by AgentGuard". Operators see a
  metric (`agentguard_llm_stream_overflow_total`) and can raise the
  limit if their use case needs it.

Why 1 MiB:

- Matches the central server's `MaxRequestBodySize` for /v1/check.
- Captures 99% of real-world tool calls.
- Keeps the proxy memory bounded under load (N concurrent streams ×
  1 MiB worst case).

---

## 6. Concurrency model

- Standard Go `http.Handler` per-request goroutine isolation.
- Each request gets its own `streamGater` struct → its own buffer,
  parser state, and accumulator. **No shared mutable state** between
  requests.
- The upstream HTTP client is shared (with a per-host connection pool
  via `http.Transport`), but per-request response readers are independent.
- The `/v1/check` HTTP client is shared. It uses a small connection
  pool; the central guard server's `MaxRequestBodySize` of 1 MiB is
  far above the per-tool-call check payload size so we never hit body
  limits for the side channel.
- Cancellation: when the client closes the connection
  (`r.Context().Done()` fires), the proxy cancels both the upstream
  read and any in-flight `/v1/check` call, then drops buffers.

`bufio.Scanner` is **not** used for SSE parsing because SSE events
don't have a hard line bound (and Go's scanner has a 64 KiB default
that's awkward to raise for streams). Instead, the proxy uses a
hand-rolled `bufio.Reader` loop that reads up to `\n\n` (SSE event
delimiter), bounded by `--max-buffer-bytes`.

---

## 7. Audit shape

One audit entry per **tool call** (not per stream, not per delta).

```json
{
  "schema_version": "v1",
  "transport": "llm_api_proxy",
  "timestamp": "2026-05-06T12:34:56.789Z",
  "session_id": "<derived from x-session-id header or chatcmpl id>",
  "agent_id": "<from x-agent-id header, or 'llm-proxy'>",
  "request": {
    "scope": "filesystem",
    "command": "read_file",
    "path": "/tmp/x",
    "action": "read",
    "meta": {
      "arguments_json": "{\"path\":\"/tmp/x\"}",
      "tool_call_id": "call_abc",
      "model": "gpt-4",
      "provider": "openai",
      "stream": "true",
      "upstream_status": "200"
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

`Meta["arguments_json"]` is redacted via `pkg/notify.DefaultRedactor`.

For an unmapped scope: `request.scope = "unmapped"`,
`request.command = "<tool_name>"`, `meta["arguments_json"]` carries
the raw (redacted) arguments.

Dashboard chip: `transport: "llm_api_proxy"` (color: purple — distinct
from `mcp_gateway` blue and `sdk` green).

---

## 8. Auth posture

### 8.1 Inbound (agent → proxy)

By default, the proxy enforces **no auth** of its own and binds to
loopback (`127.0.0.1`). Treat this like the central guard server's
no-API-key fallback: localhost is the implicit trust boundary.

If `--proxy-api-key` is set, the proxy enforces `Authorization: Bearer
<key>` on every inbound request. The shape mirrors the central
server's auth (constant-time compare, 401 on mismatch). The
**user-supplied** `Authorization` header (the OpenAI / Anthropic API
key) is forwarded as a **second bearer** in the upstream request — the
inbound and upstream credentials are independent.

This is consistent with how LiteLLM and similar proxies handle it: the
proxy can be an internal trust boundary that re-keys the call to the
real upstream.

If `--listen` is non-loopback **and** `--proxy-api-key` is unset, the
proxy refuses to start (logs ERROR and exits 1). Avoids accidental
internet-exposed proxies.

### 8.2 Outbound to central guard

The proxy uses `--api-key` as `Authorization: Bearer <key>` on every
`/v1/check` call. Same shape as the SDKs.

### 8.3 Rate limiting

The proxy itself does **not** rate-limit. The central guard server's
existing per-scope per-agent rate limiter applies — synthetic DENY
with `Rule="deny:ratelimit:<scope>"` flows back to the proxy via the
`/v1/check` response and is rewritten as a synthetic refusal in the
stream. Operators can tune the limits in policy YAML
(`rate_limit.max_requests` / `rate_limit.window`).

---

## 9. Test strategy

| layer                              | tests                                                                                                |
|------------------------------------|------------------------------------------------------------------------------------------------------|
| Header passthrough                 | Authorization, x-api-key, OpenAI-Organization survive round trip                                     |
| Body passthrough (non-streaming)   | byte-diff request body upstream-side                                                                 |
| OpenAI tool-call accumulator       | single tool, multiple tools (interleaved indices), `name` whole vs split, `arguments` 1 byte at a time |
| OpenAI gate trigger                | `finish_reason="tool_calls"` triggers; absent triggers don't                                          |
| Anthropic tool-block accumulator   | single block, multiple text+tool_use blocks, partial_json across N events                             |
| Anthropic gate trigger             | `content_block_stop` for a `tool_use` block triggers; for `text` doesn't                              |
| ALLOW byte-identity                | replay-and-diff captured upstream stream                                                              |
| DENY synthetic refusal (OpenAI)    | client receives valid SSE with `[DONE]` terminator; SDK parses without error                          |
| DENY synthetic refusal (Anthropic) | client receives `text` block + `message_stop`; SDK parses                                             |
| REQUIRE_APPROVAL                   | approval URL embedded in synthetic content; retry not auto-handled (operator approves, agent re-prompts) |
| Buffer-overflow                    | synthetic refusal at `--max-buffer-bytes`; metric increments                                          |
| Concurrency                        | 100 concurrent streams, no cross-request state leakage                                                |
| Cancellation                       | client disconnect cancels upstream + /v1/check                                                        |
| Pass-through endpoints             | /v1/embeddings, /v1/models forwarded with one audit entry                                             |
| Unmapped tool                      | `scope: "unmapped"`; default-deny when no rule configured                                             |
| Real upstream                      | OpenAI dev key + tiny model, run a multi-tool agent loop end-to-end                                   |

---

## 10. Currently out of scope

- Google Gemini wire format (different shape again, uses
  `functionCall` content parts in a streaming JSON-line format).
- Per-model cost gating beyond the existing cost-scope rules — the
  proxy uses `scope: cost` against the agent-supplied `est_cost`, not
  actual model token usage.
- Tool-result inspection — gating the agent's **response** to a tool's
  output (e.g., refuse to act on data containing PII patterns). The
  proxy gates request-side only.
- Caching of policy decisions for repeat tool calls inside one stream.
  The proxy makes one `/v1/check` call per tool call.
- The OpenAI Assistants API (different wire format, different streaming
  envelope). Supported endpoints are `/v1/chat/completions` and
  `/v1/messages` only.

---

## 11. Client integration

AgentGuard ships working examples for the four most common ways agents
talk to OpenAI / Anthropic: the raw OpenAI and Anthropic Python SDKs,
LangChain (`langchain-openai`), and CrewAI (LiteLLM under the hood).
Each example is a runnable Python script with a paired `.md`
walkthrough. The fastest end-to-end is
[`docs/QUICKSTART_LLM_PROXY.md`](./QUICKSTART_LLM_PROXY.md).

| SDK | Example | Path convention |
|---|---|---|
| OpenAI Python | [`examples/openai-sdk-config.py`](../examples/openai-sdk-config.py) + [`openai-sdk-config.md`](../examples/openai-sdk-config.md) | `OPENAI_BASE_URL=http://127.0.0.1:8081/v1` (with `/v1` suffix) |
| Anthropic Python | [`examples/anthropic-sdk-config.py`](../examples/anthropic-sdk-config.py) + [`anthropic-sdk-config.md`](../examples/anthropic-sdk-config.md) | `ANTHROPIC_BASE_URL=http://127.0.0.1:8081` (no `/v1` — the SDK appends it) |
| LangChain | [`examples/langchain-agent-config.py`](../examples/langchain-agent-config.py) + [`langchain-agent-config.md`](../examples/langchain-agent-config.md) | `ChatOpenAI(base_url="http://127.0.0.1:8081/v1")` (1.x signature) |
| CrewAI | [`examples/crewai-agent-config.py`](../examples/crewai-agent-config.py) + [`crewai-agent-config.md`](../examples/crewai-agent-config.md) | `LLM(base_url="http://127.0.0.1:8081/v1", model=..., api_key=...)` |

### 11.1 Per-SDK base-URL summary

| SDK | Constructor parameter | Env var | Path convention | Verified version |
|---|---|---|---|---|
| OpenAI Python | `base_url=` | `OPENAI_BASE_URL` | `/v1` suffix | openai==2.35.1 (2026-05-05) |
| Anthropic Python | `base_url=` | `ANTHROPIC_BASE_URL` | no `/v1` | anthropic==0.100.0 (2026-05-05) |
| LangChain `ChatOpenAI` | `base_url=` | (inherits OpenAI SDK) | `/v1` suffix | langchain-openai 1.x (2026-05-05) |
| LangChain `ChatAnthropic` | `base_url=` | (inherits Anthropic SDK) | no `/v1` | langchain-anthropic 1.x (2026-05-05) |
| CrewAI `LLM` | `base_url=` | `OPENAI_API_BASE` / `OPENAI_BASE_URL` | `/v1` suffix (OpenAI-shape) | crewai 1.14.x (2026-05-05) |

### 11.2 Verifying the integration

Once the proxy is running and your code points at it:

1. **The proxy logs a startup line.** Stderr: `agentguard-llm-proxy
   <version> listening on 127.0.0.1:8081 (...)`. If you don't see
   this, the proxy didn't start — check `--listen` and policy paths.
2. **The first SDK call appears on the dashboard.** Send any
   tool-using prompt — within a second the dashboard at
   <http://127.0.0.1:8080/dashboard> shows an event with
   `transport=llm_api_proxy` (purple chip), the resolved scope, and
   the tool name as `command`. If nothing appears, the proxy isn't
   reaching the central server's `/v1/check` — check `--guard-url`
   and `--api-key`.
3. **An ALLOW rule round-trips.** With the bundled
   `configs/default.yaml`, ask the model to `ls /tmp` via a
   `bash`-named tool. The dashboard logs `ALLOW`; the SDK receives
   the original streamed tool-call deltas byte-identically.
4. **A DENY rule rewrites the stream.** Add a `deny` rule for
   `rm -rf *` under `scope: shell` (or use the bundled one). Prompt
   the model to `rm -rf /etc`. The dashboard logs `DENY`; your code
   receives a synthetic assistant text starting with
   `[AgentGuard] Tool call denied:` instead of any tool-call deltas.

If actions never reach AgentGuard, the SDK is probably still talking
to the real upstream — verify the env var is set for the process
that runs your script (not just the parent shell), and that the SDK
constructor isn't overriding `base_url` from elsewhere.

### 11.3 Common gotchas

**Both binaries must be running.** The proxy alone does not gate
anything — every tool call triggers a callback to the central
server's `/v1/check`. If the central server is down, the proxy's
`--fail-mode` controls behaviour: `deny` (default), `allow`, or
`fail-closed-with-audit`. `fail-closed-with-audit` is currently
identical to `deny` except for the synthetic Rule string
(`deny:llm_api_proxy:fail_closed_audit`) so operators can monitor
central-server outage events specifically; the proxy does not yet
emit a local audit log entry on this path. See
[`docs/PROXY_ARCHITECTURE.md`](./PROXY_ARCHITECTURE.md) § 6.1 for the
full table.

**Two API keys, two purposes.** `OPENAI_API_KEY` /
`ANTHROPIC_API_KEY` flows through the proxy verbatim to the upstream;
the proxy never reads it. `AGENTGUARD_API_KEY` is the central
server's bearer for `/v1/check` — the proxy uses it only on the
side-channel call. The optional `--proxy-api-key` is a third,
independent thing: a bearer the proxy itself enforces on inbound
requests via the `X-AgentGuard-Proxy-Auth` header (separate from
`Authorization` so the upstream's bearer can pass through
unmodified). Don't confuse the three.

**Anthropic's path convention.** `ANTHROPIC_BASE_URL` should be
`http://127.0.0.1:8081` — no `/v1` suffix. The Anthropic SDK appends
`/v1/messages` itself. Setting `http://127.0.0.1:8081/v1` produces
double-prefixed paths and 404s. This is the most common
configuration mistake; double-check the env var when debugging.

**Approval-id round-trip is opt-in.** When AgentGuard returns
`REQUIRE_APPROVAL`, the proxy emits a synthetic refusal with the
approval ID embedded. The SDK or end user needs to:

1. Click approve on the dashboard (or via `agentguard approve <id>`).
2. Re-prompt the model with the same intent.
3. Pass `meta.approval_id` to the proxy's `/v1/check` (handled
   automatically when retrying through the proxy and your harness
   sets `_meta.dev.agentguard/approval_id` — see the MCP Gateway's
   approval-id round-trip in [`docs/APPROVAL_WORKFLOW.md`](./APPROVAL_WORKFLOW.md)).

The OpenAI / Anthropic SDKs do **not** carry `_meta` round-trip
state automatically; for one-shot CLI agents the typical flow is:
operator clicks approve, user re-prompts, model emits the tool call
again, AgentGuard sees the approved id and short-circuits to
`ALLOW`.

**Streaming vs non-streaming.** The proxy's pause/resume/rewrite
mechanism (§ 5) runs on the streaming path (`stream=True` for
OpenAI; `messages.stream(...)` for Anthropic). Non-streaming
requests are buffered in full (capped by `--max-buffer-bytes`), and
tool calls are gated before the response body is forwarded. Both
work; streaming is the recommended path for interactive UIs (lower
TTFT) and the default for most modern agent frameworks.

**Concurrency safety.** Each request gets its own `streamGater`
struct with isolated parser state. Concurrent SDK calls from a
single process are safe — there is no shared mutable state across
streams (§ 6). The upstream HTTP client is shared (per-host
connection pool), but per-request response readers are independent.

**Custom tool names need a `tool_scope_map:` entry.** AgentGuard
ships a default mapping for ~17 common tool names (see
[`pkg/llmproxy/scope_map.go`](../pkg/llmproxy/scope_map.go)).
Anything else dispatches as `scope: unmapped`, which the engine
treats as default-deny unless an `unmapped` rule exists. For custom
tools, add an entry under your policy's `tool_scope_map:` section
(see [`docs/POLICY_REFERENCE.md` § "LLM API Proxy tool scope mapping"](./POLICY_REFERENCE.md)) — the proxy hot-reloads via the same mechanism the central server uses.

**Self-hosted OpenAI-compatible upstreams.** The proxy's
`--upstream-openai` flag accepts any OpenAI-compatible base URL
(LM Studio, vLLM, llama.cpp's `--api-key` server, Together AI,
Anyscale, etc.). The streaming wire format is the same; the
`/v1/chat/completions` parser handles them all. For Azure OpenAI,
note the path convention is different (`/openai/v1/...` not
`/v1/...`) — point `--upstream-openai` at the Azure base URL
including the resource path.

---

## 12. References

- OpenAI Python SDK (verified 2026-05-05):
  - <https://github.com/openai/openai-python> — README documents
    `base_url=` and `OPENAI_BASE_URL`. Latest release v2.35.1.
  - <https://platform.openai.com/docs/api-reference/chat/create>
  - <https://platform.openai.com/docs/api-reference/chat/streaming>.
    The streaming wire shape in § 5.1 is cross-checked against the
    OpenAI Python SDK source tree.
- Anthropic Python SDK (verified 2026-05-05):
  - <https://github.com/anthropics/anthropic-sdk-python> — README +
    `src/anthropic/_client.py` document `base_url=` and
    `ANTHROPIC_BASE_URL`. Default base URL is
    `https://api.anthropic.com` with no `/v1` suffix; SDK appends
    `/v1/messages` etc. itself.
  - <https://platform.claude.com/docs/en/api/client-sdks>
  - <https://platform.claude.com/docs/en/api/messages>
- LangChain (verified 2026-05-05):
  - <https://docs.langchain.com/oss/python/integrations/chat/openai> —
    `langchain_openai.ChatOpenAI` `base_url=` parameter.
  - <https://reference.langchain.com/python/langchain-anthropic/chat_models/ChatAnthropic> —
    `langchain_anthropic.ChatAnthropic` `base_url=` parameter.
- CrewAI (verified 2026-05-05):
  - <https://docs.crewai.com/en/learn/llm-connections> — `LLM(...)`
    `base_url=` parameter; `OPENAI_API_BASE` env var honored.
- Architectural reference (no feature copying):
  - go-mitmproxy stream addons: <https://github.com/lqqyt2423/go-mitmproxy>
  - LiteLLM proxy structure: <https://github.com/BerriAI/litellm>
- Cross-cutting design: [`docs/PROXY_ARCHITECTURE.md`](./PROXY_ARCHITECTURE.md).
