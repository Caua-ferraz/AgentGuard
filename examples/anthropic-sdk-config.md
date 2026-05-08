# Anthropic Python SDK — AgentGuard LLM API Proxy

Same shape as [`openai-sdk-config.md`](./openai-sdk-config.md) but for
the Anthropic Python SDK. The proxy speaks both `/v1/chat/completions`
(OpenAI) and `/v1/messages` (Anthropic) on the same listen address —
one proxy, two providers.

> Sources:
> - <https://github.com/anthropics/anthropic-sdk-python> (verified
>   2026-05-05). anthropic==0.100.0 is the latest published release.
>   `src/anthropic/_client.py` defines `base_url` (constructor) and
>   `ANTHROPIC_BASE_URL` (env var) with default `https://api.anthropic.com`
>   (no `/v1` suffix — the SDK appends it itself).
> - <https://platform.claude.com/docs/en/api/client-sdks> (verified
>   2026-05-05) — official SDK landing page.

## Prerequisites

- Python 3.10+
- `pip install "anthropic>=0.40"`
- A valid `ANTHROPIC_API_KEY` (forwarded verbatim by the proxy as
  `x-api-key` to api.anthropic.com)
- Two `agentguard` binaries on `PATH`:

  ```bash
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest
  ```

## What this config does

```
your script ──► Anthropic SDK ──► http://127.0.0.1:8081/v1/messages
                                              │
                                    (agentguard-llm-proxy)
                                              │
                            ┌─────────────────┼─────────────────────┐
                            │                                       │
                            ▼                                       ▼
       http://127.0.0.1:8080/v1/check          https://api.anthropic.com/v1/messages
       (central AgentGuard server)             (the real upstream)
```

The proxy buffers `tool_use` content blocks (between
`content_block_start` and `content_block_stop` for that index) until
each one is complete, runs `Engine.Check`, and either flushes the
upstream bytes byte-identically (ALLOW) or replaces the block in place
with a synthetic `text` block (DENY / REQUIRE_APPROVAL). The
`message_delta`'s `stop_reason` is rewritten from `tool_use` to
`end_turn` on a refusal so the SDK doesn't wait for a tool result.

## Setup (4 steps)

1. **Generate AgentGuard's API key:**

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

2. **Start the central AgentGuard server** in one terminal:

   ```bash
   agentguard serve \
       --policy configs/default.yaml \
       --dashboard \
       --watch \
       --api-key "$AGENTGUARD_API_KEY"
   ```

3. **Start the LLM API Proxy** in a second terminal:

   ```bash
   agentguard-llm-proxy \
       --listen 127.0.0.1:8081 \
       --policy configs/default.yaml \
       --guard-url http://127.0.0.1:8080 \
       --api-key "$AGENTGUARD_API_KEY"
   ```

4. **Point the Anthropic SDK at the proxy** and run the example:

   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   export ANTHROPIC_BASE_URL=http://127.0.0.1:8081   # NO /v1 suffix
   python examples/anthropic-sdk-config.py
   ```

## Path convention — Anthropic differs from OpenAI

| SDK | Set env / `base_url=` to | Path appended by SDK |
|---|---|---|
| OpenAI Python | `http://127.0.0.1:8081/v1` | `/chat/completions`, `/embeddings`, … |
| Anthropic Python | `http://127.0.0.1:8081` | `/v1/messages`, `/v1/complete`, … |

If you mistakenly add `/v1` to `ANTHROPIC_BASE_URL`, requests land at
`/v1/v1/messages` and the proxy returns 404. This is the most common
configuration mistake — double-check the env var when debugging.

## Verification

- **ALLOW (default policy):** the model calls `bash` with
  `command: "ls /tmp"` — the proxy gates it as `scope: shell`,
  ALLOWs, and your script prints the tool-input deltas as they arrive.
- **DENY:** modify the prompt to ask for `rm -rf /etc`. The proxy
  emits a synthetic `text` block at the same `content_block` index
  starting with `[AgentGuard] Tool call denied:`. The
  `message_delta`'s `stop_reason` is rewritten to `end_turn` so the
  SDK terminates the iteration cleanly.
- **REQUIRE_APPROVAL:** prompt for `sudo *` — the synthetic text
  includes the approval URL and approval ID. Click approve on the
  dashboard, then re-run the prompt with the approval-id round-trip
  (see [`docs/APPROVAL_WORKFLOW.md`](../docs/APPROVAL_WORKFLOW.md)).

## Inspecting the audit log

```bash
agentguard audit --transport llm_api_proxy --limit 20
```

Audit entries from the Anthropic side have `meta.provider="anthropic"`
and `meta.tool_call_id` carrying the upstream-assigned `toolu_...` id
(useful for correlating with Anthropic's own server-side logs).

## Common gotchas

- **No `/v1` in `ANTHROPIC_BASE_URL`.** The SDK appends `/v1/messages`
  itself. Setting `http://127.0.0.1:8081/v1` produces double-prefixed
  paths.
- **`x-api-key` not `Authorization`.** The Anthropic SDK uses the
  `x-api-key` header (not `Authorization: Bearer`). The proxy
  forwards both header families verbatim, so this works without
  configuration — but if you have request-tracing logic looking for
  one or the other, expect Anthropic traffic to use `x-api-key`.
- **Streaming uses SSE event types.** Unlike OpenAI's "single delta
  field with `tool_calls[i]`", Anthropic streams emit explicit event
  types (`content_block_start`, `content_block_delta`,
  `content_block_stop`, `message_delta`, `message_stop`). The proxy's
  parser handles both shapes — see
  [`docs/LLM_API_PROXY.md` § 5.2](../docs/LLM_API_PROXY.md) for the
  wire-format design.
- **`message.stream(...)` context manager.** This example uses the
  raw event stream so we can see tool-input deltas as they assemble.
  If you only care about text output, `stream.text_stream` is the
  convenience iterator that yields plain text deltas only.
- **Stop reason rewrite on refusal.** When AgentGuard DENIES a
  `tool_use` block, the proxy rewrites the message's `stop_reason`
  from `tool_use` to `end_turn`. This prevents your code from waiting
  for a `tool_result` user message it would otherwise expect.

## Trimming the example

Replace the `bash` tool definition with whatever your real agent
needs. The default LLM tool-scope map covers `read_file`,
`write_file`, `web_search`, `fetch_url`, `playwright_*`, `browser_*`,
etc. — see [`pkg/llmproxy/scope_map.go`](../pkg/llmproxy/scope_map.go).
For custom names, add a `tool_scope_map:` entry to your policy YAML
(see [`docs/POLICY_REFERENCE.md`](../docs/POLICY_REFERENCE.md)).
