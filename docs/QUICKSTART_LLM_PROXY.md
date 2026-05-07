# LLM API Proxy Quickstart (90 seconds)

You'll go from "OpenAI SDK calls api.openai.com directly" to "OpenAI
SDK calls flow through AgentGuard, with every tool call policy-gated"
in under 90 seconds.

By the end, every `chat.completions.create(...)` call your agent makes
passes through AgentGuard, is evaluated against a YAML policy, and
shows up live on a dashboard you can approve / deny from.

## Prerequisites

- **Python 3.9+** with the OpenAI SDK: `pip install "openai>=1.0"`
- A valid `OPENAI_API_KEY` (the proxy forwards it verbatim to
  `api.openai.com`)
- **Go 1.22+** for `go install`: <https://go.dev/dl/>

This walkthrough uses the OpenAI SDK. The same pattern works for
Anthropic, LangChain, and CrewAI — see [`examples/`](../examples/)
for ready-to-run scripts.

## 30 seconds — install AgentGuard

```bash
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest
go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard-llm-proxy@latest
```

Confirm both binaries are on `PATH`:

```bash
which agentguard agentguard-llm-proxy
# /Users/you/go/bin/agentguard
# /Users/you/go/bin/agentguard-llm-proxy
```

If `which` finds nothing, add `$(go env GOPATH)/bin` to your shell's
`PATH` and re-source the rc file.

## 30 seconds — start the policy server + proxy

You need two AgentGuard processes running side by side: the central
policy server (port 8080) and the LLM API Proxy (port 8081). Generate
a shared API key, then start both.

In the first terminal:

```bash
export AGENTGUARD_API_KEY="$(openssl rand -hex 32)"

git clone https://github.com/Caua-ferraz/AgentGuard.git
cd AgentGuard

agentguard serve \
    --policy configs/default.yaml \
    --dashboard \
    --watch \
    --api-key "$AGENTGUARD_API_KEY"
```

Open the dashboard at <http://127.0.0.1:8080/dashboard> and log in
with the API key. Leave this terminal running.

In a second terminal (same env, same key):

```bash
export AGENTGUARD_API_KEY="<paste the key from the first terminal>"

agentguard-llm-proxy \
    --listen 127.0.0.1:8081 \
    --policy configs/default.yaml \
    --guard-url http://127.0.0.1:8080 \
    --api-key "$AGENTGUARD_API_KEY"
```

The proxy refuses to bind to non-loopback hosts without
`--proxy-api-key` set, so the localhost defaults are safe by
construction.

## 30 seconds — point your code at the proxy

In a third terminal:

```bash
export OPENAI_API_KEY=sk-...                       # your real OpenAI key
export OPENAI_BASE_URL=http://127.0.0.1:8081/v1    # the proxy

python examples/openai-sdk-config.py
```

The example asks the model to list `/tmp` via a `bash` tool. The
default policy's `shell` rules ALLOW it; the dashboard logs an
`ALLOW` event with `transport=llm_api_proxy` within a second of the
script firing.

## Verify (the satisfying part)

Watch the dashboard at <http://127.0.0.1:8080/dashboard>. You should
see one `ALLOW` entry with:

- transport chip: `llm_api_proxy` (purple)
- scope: `shell`
- command: `bash` (the LLM tool name, mapped via the bundled scope map)

Now edit `configs/default.yaml` — add a deny rule:

```yaml
rules:
  - scope: shell
    deny:
      - pattern: "rm -rf *"
    # ... existing rules ...
```

The proxy hot-reloads via `--watch`. Modify the prompt in
`examples/openai-sdk-config.py` to ask the model to `rm -rf /etc`
and re-run. The model emits a tool call; AgentGuard intercepts it
mid-stream and rewrites the response as a synthetic assistant text:

```
[AgentGuard] Tool call denied: deny:shell:rm-rf
```

The dashboard logs a `DENY`. No SDK changes, no agent code changes —
the model's tool call literally never reaches your script.

That's the loop. Every tool call → policy check → audit log → live
dashboard. Tool deltas in ALLOW are byte-identical to the upstream
bytes; deltas in DENY/REQUIRE_APPROVAL are rewritten in place as
provider-shaped synthetic refusals.

## Next steps

- **Customize the policy:** [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md)
  for the full schema, including `require_approval` rules that pause
  the call until you click the dashboard's approve button. The
  `tool_scope_map:` section is the LLM-proxy-specific knob — see
  [`docs/POLICY_REFERENCE.md` § "LLM API Proxy tool scope mapping"](POLICY_REFERENCE.md).
- **Anthropic Messages API.** Same flow, set `ANTHROPIC_BASE_URL`
  instead — note the **no `/v1`** path convention. See
  [`examples/anthropic-sdk-config.py`](../examples/anthropic-sdk-config.py)
  + [`anthropic-sdk-config.md`](../examples/anthropic-sdk-config.md).
- **LangChain / CrewAI.** Same `base_url=` argument, just on a
  different LLM constructor. See
  [`examples/langchain-agent-config.py`](../examples/langchain-agent-config.py)
  and [`examples/crewai-agent-config.py`](../examples/crewai-agent-config.py).
- **MCP Gateway** — the other proxy. If your agent talks MCP (Claude
  Desktop, Cursor, Cline, Continue, Zed), the LLM API Proxy isn't
  the right tool: use the MCP Gateway. See
  [`docs/QUICKSTART_MCP.md`](QUICKSTART_MCP.md).
- **Approval flow walkthrough:**
  [`docs/APPROVAL_WORKFLOW.md`](APPROVAL_WORKFLOW.md) shows how
  `REQUIRE_APPROVAL` decisions surface on the dashboard / Slack /
  webhooks and how the approval ID round-trips back through
  `/v1/check` so the model can retry without losing context.
- **Streaming wire-format design.** The pause/resume/rewrite mechanism
  for SSE streams is documented in
  [`docs/LLM_API_PROXY.md` § 5](LLM_API_PROXY.md). Read this if you
  need to debug a parser edge case or extend coverage to a new
  provider.
- **Threat model.** The proxy is wire-level for the configured base
  URL — but an agent that controls its own runtime can still bypass
  it by ignoring `OPENAI_BASE_URL` and pointing at api.openai.com
  directly. Read [README § Limitations & Threat Model](../README.md#limitations--threat-model)
  before you trust this as a last line of defense.
