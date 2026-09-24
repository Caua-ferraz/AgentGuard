# CrewAI — AgentGuard LLM API Proxy

A minimal CrewAI Crew (one agent, one tool, one task) wired through
the AgentGuard LLM API Proxy by passing a CrewAI `LLM(...)` instance
with `base_url=` set to the proxy. CrewAI delegates LLM calls to
LiteLLM, which forwards the OpenAI-compatible base URL to its OpenAI
client.

> Source: <https://docs.crewai.com/en/learn/llm-connections> (verified
> 2026-05-05). The `LLM(model=..., base_url=..., api_key=...)`
> constructor is canonical for crewai 1.14.x. Both `OPENAI_API_BASE`
> and `OPENAI_BASE_URL` env vars are honored as fallbacks via
> LiteLLM's resolution chain.

## Prerequisites

- Python 3.10+
- `pip install "crewai>=1.0,<2.0"` (matches the pin in
  [`plugins/python/pyproject.toml`](../plugins/python/pyproject.toml))
- A valid `OPENAI_API_KEY` (forwarded to OpenAI by LiteLLM via the
  proxy)
- Two `agentguard` binaries on `PATH`:

  ```bash
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest
  ```

## What this config does

```
Crew.kickoff() ──► CrewAI Agent loop ──► CrewAI LLM(base_url=...)
                                                   │
                                                   ▼
                                              LiteLLM client
                                                   │
                                                   ▼
                              http://127.0.0.1:8081/v1/chat/completions
                                                   │
                                          (agentguard-llm-proxy)
                                                   │
                          ┌────────────────────────┼─────────────────────────┐
                          ▼                                                  ▼
        http://127.0.0.1:8080/v1/check               https://api.openai.com/...
        (central AgentGuard)                          (real upstream)
```

The CrewAI agent loop is unmodified. Each tool call the model emits
inside a turn is gated by AgentGuard before LiteLLM streams the
response back to CrewAI.

## Setup (5 steps)

1. **Install CrewAI:**

   ```bash
   pip install "crewai>=1.0,<2.0"
   ```

2. **Generate AgentGuard's API key:**

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   ```

3. **Start the central AgentGuard server** in one terminal:

   ```bash
   agentguard serve \
       --policy configs/default.yaml \
       --dashboard \
       --watch \
       --api-key "$AGENTGUARD_API_KEY"
   ```

4. **Start the LLM API Proxy** in a second terminal:

   ```bash
   agentguard-llm-proxy \
       --listen 127.0.0.1:8081 \
       --policy configs/default.yaml \
       --guard-url http://127.0.0.1:8080 \
       --api-key "$AGENTGUARD_API_KEY"
   ```

5. **Point CrewAI at the proxy** and run the example:

   ```bash
   export OPENAI_API_KEY=sk-...
   export OPENAI_API_BASE=http://127.0.0.1:8081/v1
   export OPENAI_BASE_URL=http://127.0.0.1:8081/v1
   python examples/crewai-agent-config.py
   ```

   The example also passes `base_url=` explicitly to `LLM(...)`, so the
   env vars are belt-and-braces.

## Configure custom tool names

The script defines a CrewAI tool called `list_tmp_files`. As with the
LangChain example, this is not in AgentGuard's bundled tool-scope map,
so map it to a scope in your policy and allow it there:

```yaml
# In your policy file (configs/default.yaml or your own)
tool_scope_map:
  - pattern: "list_tmp_files"
    scope: shell

rules:
  - scope: shell
    allow:
      - pattern: "list_tmp_files"
```

`tool_scope_map` is a list of `pattern` / `scope` entries. For a tool mapped to `shell`, the proxy checks the tool's `command` argument; `list_tmp_files` takes no arguments, so the check runs with the tool name as the command — that's why the `allow` rule names it. In `configs/default.yaml`, add the mapping at the top of the existing `tool_scope_map:` list and the `pattern:` line to the existing `shell` block's `allow:` list, rather than a second `shell` block (a second block is merged into the first, and `agentguard validate` warns about it).

The proxy reloads its policy file on its own when you save it; so does `agentguard serve`.

## Verification

- **ALLOW:** with the mapping and the allow rule above, the agent's
  `list_tmp_files` call is ALLOWed (`allow:shell:list_tmp_files`) and
  the local `_run` executes. CrewAI's verbose logging shows the
  tool result; the dashboard logs `ALLOW` with
  `transport=llm_api_proxy`.
- **DENY:** add `- pattern: "list_tmp_files"` to the `shell` block's
  `deny:` list. Re-run — the proxy rewrites the LLM's response
  as a synthetic refusal text. CrewAI's agent loop reads the
  assistant text and adapts its plan; the final crew result is the
  refusal text propagated through the agent's reasoning.
- **REQUIRE_APPROVAL:** put the same pattern under `require_approval:`
  instead. The refusal text includes the approval ID; approve it on
  the dashboard, then re-run.

## Inspecting the audit log

```bash
agentguard audit --transport llm_api_proxy --limit 20
```

CrewAI agents often emit several tool calls per `kickoff()`. Filter
by agent ID by passing `meta.agent_id` from the `X-Agent-Id` header
(set in CrewAI's LiteLLM client headers if you want to attribute
calls cleanly).

## Common gotchas

- **LiteLLM in the middle.** CrewAI's `LLM(...)` wraps LiteLLM, not
  the OpenAI SDK directly. LiteLLM resolves `base_url=` into its
  underlying OpenAI client's `api_base`. Both `OPENAI_API_BASE` (the
  LiteLLM env name) and `OPENAI_BASE_URL` (the OpenAI SDK env name)
  are honored — set both for safety, as the example does.
- **CrewAI 1.x's tool-call shape.** CrewAI's BaseTool subclass system
  emits tool calls in the same OpenAI shape underneath, so the proxy's
  parser handles them transparently.
- **Streaming default.** CrewAI passes `stream=True` to LiteLLM by
  default for most models, which exercises the proxy's pause/resume
  path. Setting `stream=False` on the `LLM(...)` constructor falls
  back to the non-streaming gating path (which buffers the full
  response and gates tool_calls before forwarding the body).
- **Multiple tool calls per turn.** Some CrewAI agents emit batched
  tool calls in a single assistant turn. The proxy's accumulator keys
  by `tool_calls[i].index` (OpenAI) or content-block index
  (Anthropic), so each call is gated independently. A single DENY
  refuses the whole turn — the model's other tool calls are not
  delivered either, by design (agents that mix benign and risky
  calls in one turn should be refactored).
- **Two API keys, two purposes.** `OPENAI_API_KEY` flows through the
  proxy to OpenAI. `AGENTGUARD_API_KEY` is the central server's
  bearer for `/v1/check`. They are independent.
- **CrewAI's `verbose=True`.** The example sets `verbose=True` on
  both the agent and the crew so you can watch the tool calls fire
  in CrewAI's own logs alongside the AgentGuard dashboard. Drop
  verbose flags for production.

## Anthropic models in CrewAI

CrewAI/LiteLLM also supports Anthropic models. Set
`model="anthropic/claude-3-5-sonnet-latest"` and
`api_key=os.environ["ANTHROPIC_API_KEY"]`; LiteLLM will route to
Anthropic. Point `base_url=` at the proxy without `/v1`
(`http://127.0.0.1:8081`) — same as the
[`anthropic-sdk-config.md`](./anthropic-sdk-config.md) example. The
proxy speaks both providers on the same listen address.

## Pairing with the AgentGuard CrewAI adapter

The Python SDK ships `GuardedCrewTool` (in
[`plugins/python/agentguard/adapters/crewai.py`](../plugins/python/agentguard/adapters/crewai.py))
which adds a `Guard.check` call inside the tool's `_run`. Stack it
on top of the proxy for defense-in-depth: the proxy gates the wire,
the adapter gates the local Python execution. See
[`docs/ADAPTERS.md`](../docs/ADAPTERS.md).
