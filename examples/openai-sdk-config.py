"""
AgentGuard LLM API Proxy — OpenAI Python SDK example.

This is the "no framework" path: a raw `openai` client whose `base_url`
is pointed at the AgentGuard LLM API Proxy. Existing code that already
talks to the OpenAI Chat Completions API works unchanged after exporting
one environment variable.

Verified against:
  - openai==2.35.1 (https://github.com/openai/openai-python, 2026-05-05).
    Constructor parameter `base_url=` and env var `OPENAI_BASE_URL` are
    the canonical knobs; both honor a `/v1` suffix.
  - AgentGuard LLM API Proxy v0.4.1+ (`agentguard-llm-proxy --listen
    127.0.0.1:8081`).

Setup:
  pip install "openai>=1.0"
  export OPENAI_API_KEY=sk-...                    # your real OpenAI key
  export OPENAI_BASE_URL=http://127.0.0.1:8081/v1 # the proxy

Run AgentGuard side (two terminals):

  # Terminal 1 — central policy server + dashboard
  agentguard serve \\
      --policy configs/default.yaml \\
      --dashboard \\
      --watch \\
      --api-key "$AGENTGUARD_API_KEY"

  # Terminal 2 — LLM API Proxy (OpenAI-shape on /v1/*)
  agentguard-llm-proxy \\
      --listen 127.0.0.1:8081 \\
      --policy configs/default.yaml \\
      --guard-url http://127.0.0.1:8080 \\
      --api-key "$AGENTGUARD_API_KEY"

Then run this script:
  python examples/openai-sdk-config.py

Expected behaviour with the bundled `configs/default.yaml`:
  - Plain text completion: passes through, byte-identical to a direct
    OpenAI call.
  - `bash` tool call for `ls /tmp`: routed via the default
    LLM tool-scope map to scope `shell`; the policy ALLOWs it and the
    SDK receives the original streamed tool-call deltas.
  - `bash` tool call for `rm -rf /etc`: scope `shell` denies; the proxy
    rewrites the SSE stream as a synthetic assistant text message
    starting with `[AgentGuard] Tool call denied:`.

Open the dashboard at http://127.0.0.1:8080/dashboard to watch each
decision land live (transport chip: `llm_api_proxy`).
"""

from __future__ import annotations

import os
import sys

# The OpenAI SDK constructor reads OPENAI_BASE_URL from the environment
# automatically. Setting it here belt-and-braces in case the operator
# forgot to export it before running this file.
os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:8081/v1")

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - guidance for first-time users
    sys.stderr.write(
        "openai-sdk-config.py: the 'openai' package is not installed.\n"
        "Install it with:  pip install 'openai>=1.0'\n"
    )
    sys.exit(2)


def main() -> None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.stderr.write(
            "openai-sdk-config.py: OPENAI_API_KEY is not set.\n"
            "Export your real OpenAI key — the proxy forwards it verbatim "
            "to api.openai.com.\n"
        )
        sys.exit(2)

    base_url = os.environ["OPENAI_BASE_URL"]
    print(f"[client] base_url={base_url}")

    # The SDK forwards OPENAI_API_KEY in the Authorization header; the
    # proxy pipes it through to the upstream untouched (it never reads
    # the bearer token). The proxy's own optional --proxy-api-key is a
    # separate header (X-AgentGuard-Proxy-Auth) and is unset by default
    # when the proxy binds to 127.0.0.1.
    client = OpenAI(base_url=base_url, api_key=api_key)

    # Define a shell tool for the model to call. The default LLM
    # tool-scope map (pkg/llmproxy/scope_map.go) routes "bash" to scope
    # "shell"; the policy rules in configs/default.yaml gate it.
    tools = [
        {
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Execute a shell command on the local host.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The exact shell command to run.",
                        },
                    },
                    "required": ["command"],
                },
            },
        },
    ]

    # Drive a turn that the model is overwhelmingly likely to satisfy
    # by emitting a `bash` tool call. Try the second prompt to see a
    # DENY; try `sudo apt update` to see a REQUIRE_APPROVAL with the
    # bundled default policy.
    user_prompt = "List the files in /tmp by calling the bash tool."
    print(f"[user]   {user_prompt}\n")

    stream = client.chat.completions.create(
        model="gpt-4o-mini",  # the proxy is model-agnostic — any OpenAI model
        messages=[{"role": "user", "content": user_prompt}],
        tools=tools,
        stream=True,
    )

    print("[assistant stream]")
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta

        # Plain text: ALLOWed pass-through OR a synthetic refusal that
        # AgentGuard injected after a DENY. Same wire shape; the
        # operator distinguishes via the dashboard / audit log.
        if getattr(delta, "content", None):
            print(delta.content, end="", flush=True)

        # Tool-call deltas: byte-identical bytes from upstream when
        # AgentGuard ALLOWs. On DENY/REQUIRE_APPROVAL the proxy
        # suppresses them and emits an assistant text refusal instead,
        # so the `tool_calls` branch is naturally skipped.
        for tc in getattr(delta, "tool_calls", None) or []:
            fn = tc.function
            if fn and fn.name:
                print(f"\n[tool_call.name={fn.name}]", flush=True)
            if fn and fn.arguments:
                print(fn.arguments, end="", flush=True)
    print()


if __name__ == "__main__":
    main()
