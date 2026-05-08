# OpenAI Python SDK — AgentGuard LLM API Proxy

Drop-in script that drives the official `openai` Python client through
`agentguard-llm-proxy`, which gates every tool call inside the response
stream against your AgentGuard policy before it reaches your code.

> Source: <https://github.com/openai/openai-python> (verified 2026-05-05).
> openai==2.35.1 is the latest published release as of writing; the
> `base_url=` constructor arg and `OPENAI_BASE_URL` env var have been
> stable since the 1.0 redesign.

## Prerequisites

- Python 3.10+
- `pip install "openai>=1.0"`
- A valid `OPENAI_API_KEY` (the proxy forwards it verbatim — it does
  not read the bearer token)
- Two `agentguard` binaries on `PATH`:

  ```bash
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest
  ```

## What this config does

```
your script ──► OpenAI SDK ──► http://127.0.0.1:8081/v1/...
                                           │
                                  (agentguard-llm-proxy)
                                           │
                          ┌────────────────┼─────────────────┐
                          │                                  │
                          ▼                                  ▼
       http://127.0.0.1:8080/v1/check         https://api.openai.com/v1/...
       (central AgentGuard server, runs       (the real upstream)
        Engine.Check on every tool call)
```

Every `chat.completions.create(...)` call still talks to OpenAI. Tool
calls inside the streamed response are buffered, evaluated against your
YAML policy, and either flushed to your code byte-identically (ALLOW)
or rewritten as a synthetic assistant text refusal (DENY /
REQUIRE_APPROVAL). The OpenAI SDK does not need to know the proxy
exists.

## Setup (4 steps)

1. **Generate an API key for the central server** and export it:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

   This is unrelated to your `OPENAI_API_KEY` — it gates AgentGuard's
   own approve/deny/audit endpoints.

2. **Start the central AgentGuard server** in one terminal:

   ```bash
   git clone https://github.com/Caua-ferraz/AgentGuard.git
   cd AgentGuard
   agentguard serve \
       --policy configs/default.yaml \
       --dashboard \
       --watch \
       --api-key "$AGENTGUARD_API_KEY"
   ```

   Open <http://127.0.0.1:8080/dashboard>. Log in with the API key.

3. **Start the LLM API Proxy** in a second terminal:

   ```bash
   agentguard-llm-proxy \
       --listen 127.0.0.1:8081 \
       --policy configs/default.yaml \
       --guard-url http://127.0.0.1:8080 \
       --api-key "$AGENTGUARD_API_KEY"
   ```

   The proxy binds to loopback by default — non-loopback binds without
   `--proxy-api-key` are refused at startup (see
   [`docs/LLM_API_PROXY.md` § 8](../docs/LLM_API_PROXY.md)).

4. **Point the OpenAI SDK at the proxy** and run the example:

   ```bash
   export OPENAI_API_KEY=sk-...                       # your real key
   export OPENAI_BASE_URL=http://127.0.0.1:8081/v1    # the proxy
   python examples/openai-sdk-config.py
   ```

## Verification

- **ALLOW (default policy):** prompt the model to `ls /tmp` via the
  bash tool — `configs/default.yaml`'s `shell` rules ALLOW it. The
  dashboard logs an `ALLOW` event with `transport=llm_api_proxy` and
  the bash tool name. Your script prints the tool-call deltas the
  model emitted.
- **DENY:** modify the prompt in the script to ask the model to
  `rm -rf /etc`. The default policy includes a `deny` rule for
  `rm -rf *`; the proxy rewrites the stream as an assistant text
  refusal (`[AgentGuard] Tool call denied: ...`). The dashboard logs
  a `DENY` event.
- **REQUIRE_APPROVAL:** ask for `sudo apt update` (the default policy
  routes `sudo *` to `require_approval`). Your script receives a
  synthetic assistant text including the approval ID and approval URL.
  Click approve in the dashboard, then re-run the prompt — see
  [`docs/APPROVAL_WORKFLOW.md`](../docs/APPROVAL_WORKFLOW.md) for the
  approval-id round-trip details.

## Inspecting the audit log

Each gated tool call lands in the JSON-Lines audit log. Filter by the
LLM proxy transport:

```bash
agentguard audit --transport llm_api_proxy --limit 20
```

Add `--decision DENY` or `--scope shell` to narrow further.

## Common gotchas

- **Both binaries must be running.** The proxy alone does not gate
  anything — it calls back to the central server's `/v1/check` for
  every tool call. If the central server is down, the proxy's
  `--fail-mode` controls behaviour (`deny` is the default).
- **Two API keys, two purposes.** `OPENAI_API_KEY` flows through the
  proxy to OpenAI. `AGENTGUARD_API_KEY` is the central server's
  bearer for `/v1/check` (the proxy uses it on the side-channel call).
  These are independent — losing one does not affect the other.
- **The proxy's optional `--proxy-api-key`** is a third, separate
  thing: a bearer the proxy itself enforces on inbound requests via
  the `X-AgentGuard-Proxy-Auth` header. Unset by default; only set
  when the proxy binds to a non-loopback address.
- **Stream vs non-stream.** This example sets `stream=True`. The
  proxy's pause/resume/rewrite mechanism is the streaming path; the
  non-streaming path buffers the full response body and gates tool
  calls before forwarding. Both work — the non-streaming path is
  marginally simpler to debug if you're new to the proxy.
- **`tools` is OpenAI-shape.** The example uses
  `[{"type": "function", "function": {...}}]`. Anthropic uses a flatter
  shape — see `examples/anthropic-sdk-config.py`.
- **The model still needs to choose to call the tool.** AgentGuard
  gates calls the model emits — it does not force the model to call
  tools. If the model returns plain text, no policy check happens
  for that turn (text generation itself is not gated; that's by
  design — see [`docs/LLM_API_PROXY.md` § 3.3](../docs/LLM_API_PROXY.md)).

## Trimming the example

The script defines a single `bash` tool. Add or remove tools in the
`tools=[...]` list; AgentGuard's default LLM tool-scope map covers the
common names (`bash`, `read_file`, `write_file`, `web_search`, etc. —
see [`pkg/llmproxy/scope_map.go`](../pkg/llmproxy/scope_map.go) for the
full list). Custom tool names need an operator entry in your policy's
`tool_scope_map:` section — see
[`docs/POLICY_REFERENCE.md` § "LLM API Proxy tool scope mapping"](../docs/POLICY_REFERENCE.md).
