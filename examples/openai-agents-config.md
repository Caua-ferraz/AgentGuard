# OpenAI Agents SDK — AgentGuard adapter

A minimal OpenAI Agents SDK agent (one agent, one shell tool) whose
function tool is gated by the AgentGuard Python adapter. `guard_tools`
returns copies of the agent's `FunctionTool`s that call `Guard.check`
before the tool body runs, so a denied call never executes.

> Source: <https://openai.github.io/openai-agents-python/tools/>
> (verified 2026-10-14). The adapter supports `openai-agents>=0.3.3,<1.0`
> (the pin in [`plugins/python/pyproject.toml`](../plugins/python/pyproject.toml));
> 0.23.x is the verified release.

## Prerequisites

- Python 3.10+
- `pip install 'agentguardproxy[openai-agents]'`
- A valid `OPENAI_API_KEY` for the agent's model
- The `agentguard` binary on `PATH`:

  ```bash
  go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
  ```

## What this config does

```
Runner.run(agent) ──► model (OpenAI) ──► tool call run_shell({"command": ...})
                                                   │
                                     gated FunctionTool.on_invoke_tool
                                                   │
                         http://127.0.0.1:8080/v1/check (central AgentGuard)
                                                   │
                          ALLOW ──► run_shell runs, result goes to the model
                          DENY / REQUIRE_APPROVAL ──► Runner.run raises
```

Only the tools pass through AgentGuard; the model traffic goes straight
to OpenAI. To gate the model's tool calls on the wire as well, see
[Stacking with the LLM API Proxy](#stacking-with-the-llm-api-proxy).

## Setup (3 steps)

1. **Install the SDK with the extra:**

   ```bash
   pip install 'agentguardproxy[openai-agents]'
   ```

2. **Start the central AgentGuard server** in one terminal:

   ```bash
   export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"
   agentguard server \
       --policy configs/default.yaml \
       --dashboard \
       --watch \
       --api-key "$AGENTGUARD_API_KEY"
   ```

3. **Run the example** in a second terminal:

   ```bash
   export OPENAI_API_KEY=sk-...
   python examples/openai-agents-config.py "list the files in /tmp"
   ```

   `AGENTGUARD_URL` overrides the server address (default
   `http://localhost:8080`).

## Verification

With `configs/default.yaml`:

- **ALLOW:** `"list the files in /tmp"`. The model calls
  `run_shell({"command": "ls /tmp"})`, which matches `allow: ls *` in
  the `shell` scope. The tool runs and the agent answers with the
  listing.
- **REQUIRE_APPROVAL:** `"delete /tmp/agentguard-demo recursively"`.
  `rm -rf /tmp/agentguard-demo` matches `require_approval: rm -rf *`.
  The tool does not run; `Runner.run` raises
  `AgentGuardApprovalRequired`, and the script prints the approval URL
  and exits 3. Approve on the dashboard, then re-run.
- **DENY:** any command the policy denies (for example
  `dd if=/dev/zero of=/tmp/x`, blocked by the `dd if=/dev/*` rule)
  raises `AgentGuardDenied`; the script prints the reason and exits 1.

The dashboard shows each decision live, with agent ID
`openai-agents-example`.

## Common gotchas

- **A deny ends the run.** The gate sits outside the tool's own
  `failure_error_function`, so the model does not see the deny as a tool
  result: `Runner.run` raises. If the model should see the reason and
  pick another action, attach `agentguard_tool_guardrail(guard)` as a
  tool input guardrail instead (or as well). See the OpenAI Agents SDK
  section of [`docs/ADAPTERS.md`](../docs/ADAPTERS.md).
- **Agents used as tools.** If the gated tools belong to an inner agent
  the outer agent calls through `inner.as_tool()`, the outer tool's
  default `failure_error_function` turns the deny into a generic tool
  error and the outer run continues. Pass
  `inner.as_tool(..., failure_error_function=None)` to propagate it.
  The denied tool never runs either way.
- **Only function tools can be gated.** Hosted tools such as
  `WebSearchTool` run on OpenAI's servers, so `guard_tools` raises
  `TypeError` for them. Tools from an agent's `mcp_servers` do not pass
  through `tools`; gate those with
  [`agentguard-mcp-gateway`](../docs/MCP_GATEWAY.md).
- **Arguments the tool does not declare are ignored.** The check sees
  the arguments projected onto the tool's JSON schema, which is what
  the SDK passes to the tool. A call that sets two names for one
  parameter to different values (`command` and `cmd`, or `path` and
  `file_path`) is denied without a server round-trip.
- **Two API keys, two purposes.** `OPENAI_API_KEY` is for the model.
  `AGENTGUARD_API_KEY` is the central server's bearer token for the
  approval endpoints; `/v1/check` does not need it.

## Stacking with the LLM API Proxy

`agentguard-llm-proxy` speaks the OpenAI Chat Completions wire format,
not the Responses API the Agents SDK uses by default. To route the
model through the proxy as well, switch the SDK to Chat Completions and
point the OpenAI client at the proxy:

```python
from agents import set_default_openai_api

set_default_openai_api("chat_completions")
# and export OPENAI_BASE_URL=http://127.0.0.1:8081/v1
```

The proxy then gates tool calls in the model's response, and the
adapter gates what the local Python runs. See
[`openai-sdk-config.md`](openai-sdk-config.md) for the proxy setup.
