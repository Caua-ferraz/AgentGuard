# LangChain — AgentGuard LLM API Proxy

A minimal LangChain agent (`langchain_openai.ChatOpenAI` + a Python
tool bound via `bind_tools`) wired through the AgentGuard LLM API
Proxy. Existing LangChain code that uses the OpenAI provider works
unchanged after passing one `base_url=` argument (or exporting one env
var).

> Sources:
> - <https://docs.langchain.com/oss/python/integrations/chat/openai>
>   (verified 2026-05-05). The langchain-openai 1.x signature uses
>   `base_url=` directly. The legacy `openai_api_base=` parameter is
>   still accepted but `base_url=` is the documented form.
> - langchain==1.2.x and langchain-core==1.3.x match the floors
>   pinned in [`plugins/python/pyproject.toml`](../plugins/python/pyproject.toml)
>   for the `langchain` extra.

## Prerequisites

- Python 3.10+
- `pip install "langchain>=0.3,<2.0" "langchain-openai>=0.2"`
- A valid `OPENAI_API_KEY` (the proxy forwards it verbatim)
- Two `agentguard` binaries on `PATH`:

  ```bash
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest
  ```

## What this config does

```
your script ──► LangChain ChatOpenAI ──► OpenAI SDK ──► http://127.0.0.1:8081/v1
                                                                   │
                                                          (agentguard-llm-proxy)
                                                                   │
                                                ┌──────────────────┴──────────────┐
                                                ▼                                  ▼
                                  central server /v1/check        api.openai.com
```

LangChain's `ChatOpenAI(base_url=...)` constructor sets the underlying
OpenAI client's `base_url`. Every `bind_tools(...).invoke(...)` /
`stream(...)` call lands on the proxy first; tool calls inside the
response are buffered, gated, and either flushed or rewritten as a
synthetic refusal.

## Setup (5 steps)

1. **Install the LangChain extras** (matches the pin in
   `plugins/python/pyproject.toml`):

   ```bash
   pip install "langchain>=0.3,<2.0" "langchain-openai>=0.2"
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

5. **Point LangChain at the proxy** and run the example:

   ```bash
   export OPENAI_API_KEY=sk-...
   export OPENAI_BASE_URL=http://127.0.0.1:8081/v1   # optional;
                                                     # script also
                                                     # passes base_url=
   python examples/langchain-agent-config.py
   ```

## Configure custom tool names

The script defines a tool called `list_tmp_files`. AgentGuard's
default LLM tool-scope map (in
[`pkg/llmproxy/scope_map.go`](../pkg/llmproxy/scope_map.go)) does not
have an entry for that name — it's not one of the bundled built-ins
(`bash`, `read_file`, `write_file`, `web_search`, …). The proxy will
dispatch the call as `scope: unmapped`, which the engine treats as
default-deny unless an explicit `unmapped` rule exists.

The recommended fix: add an operator entry to your policy YAML so
your tool name maps to the right scope.

```yaml
# In configs/default.yaml or your custom policy
tool_scope_map:
  list_tmp_files: shell
  my_db_query:    network
  read_secret:    data
```

After editing, the proxy hot-reloads via `--watch`. See
[`docs/POLICY_REFERENCE.md` § "LLM API Proxy tool scope mapping"](../docs/POLICY_REFERENCE.md)
for the full schema.

## Verification

With `tool_scope_map.list_tmp_files: shell` in place:

- **ALLOW:** the agent calls `list_tmp_files()`. Scope `shell`
  evaluates the rule chain and ALLOWs — the script's `tool_calls`
  branch runs, the local Python function executes, and the result
  prints. Dashboard logs `ALLOW` with `transport=llm_api_proxy`.
- **DENY:** add `deny: [{pattern: "list_tmp_files*"}]` under
  `scope: shell`. Re-run — the proxy rewrites the response as an
  assistant text refusal; `response.tool_calls` is empty and
  `response.content` carries `[AgentGuard] Tool call denied: ...`.
- **REQUIRE_APPROVAL:** swap `deny` for `require_approval`. The
  refusal text contains the approval ID and approval URL; click
  approve on the dashboard.

Without any `tool_scope_map` entry, the proxy reports
`scope: unmapped` and the engine's fall-through default-deny applies —
fail-closed by design (a tool the policy author has not seen is, by
contract, denied).

## Inspecting the audit log

```bash
agentguard audit --transport llm_api_proxy --limit 20
```

Each entry has `meta.provider="openai"`, `meta.tool_call_id` (the
OpenAI `call_xxx` id), and the resolved scope from the tool-scope map.

## Common gotchas

- **`base_url=` vs `openai_api_base=`.** langchain-openai 1.x accepts
  both; new code should use `base_url=` (the documented form going
  forward, matching the underlying OpenAI SDK).
- **`bind_tools` is the modern API.** Older LangChain code used
  `convert_to_openai_function` + manual function-call extraction.
  langchain-core 1.x's `bind_tools` returns a Runnable that handles
  tool-call parsing for you; the script uses this path.
- **Async / streaming.** The script uses synchronous `invoke(...)`
  for clarity. `stream(...)` and `ainvoke(...)` work the same way —
  the proxy's pause/resume mechanism is provider-side, not
  framework-side.
- **`tool_calls` vs `additional_kwargs.tool_calls`.** Different
  langchain-openai versions surface tool calls under different
  attribute names. The script reads `response.tool_calls`, which is
  the modern (1.x) location. On older versions you may need
  `response.additional_kwargs["tool_calls"]`.
- **Tool execution is your responsibility.** AgentGuard gates the
  *call* — the *execution* of the local Python function is
  unguarded. If you want both ends gated, also wire the AgentGuard
  Python SDK's `Guard.check(...)` inside the tool's `_run`. See
  [`docs/SDK_PYTHON.md`](../docs/SDK_PYTHON.md).

## Pairing with the AgentGuard LangChain adapter

The Python SDK ships a `GuardedTool` wrapper that adds a `Guard.check`
call inside the tool's `invoke`. You can stack it on top of the proxy
for defense-in-depth: the proxy gates what the model emits *over the
wire*, and `GuardedTool` gates what the local Python actually runs.
See [`docs/ADAPTERS.md`](../docs/ADAPTERS.md) for the wrapping
pattern.

## CrewAI

CrewAI's `LLM(...)` wraps LiteLLM, which honors the same
OpenAI-compatible base URL. Use the same setup with CrewAI: see
[`crewai-agent-config.md`](./crewai-agent-config.md).
