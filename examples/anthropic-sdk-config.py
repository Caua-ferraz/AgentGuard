"""
AgentGuard LLM API Proxy — Anthropic Python SDK example.

Same shape as openai-sdk-config.py but for the official `anthropic`
package. Note Anthropic's URL convention differs from OpenAI's: there
is **no `/v1` suffix** — the SDK appends `/v1/messages` itself.

Verified against:
  - anthropic==0.100.0 (https://github.com/anthropics/anthropic-sdk-python,
    src/anthropic/_client.py, 2026-05-05). Constructor parameter
    `base_url=` and env var `ANTHROPIC_BASE_URL`. The default value is
    `https://api.anthropic.com` (no path).
  - AgentGuard LLM API Proxy v0.4.1+ (`agentguard-llm-proxy --listen
    127.0.0.1:8081`).

Setup:
  pip install "anthropic>=0.40"
  export ANTHROPIC_API_KEY=sk-ant-...           # your real Anthropic key
  export ANTHROPIC_BASE_URL=http://127.0.0.1:8081  # the proxy — NO /v1

Run AgentGuard side (two terminals):

  # Terminal 1
  agentguard serve \\
      --policy configs/default.yaml \\
      --dashboard \\
      --watch \\
      --api-key "$AGENTGUARD_API_KEY"

  # Terminal 2 — same proxy as the OpenAI example: it speaks both
  # /v1/chat/completions (OpenAI) AND /v1/messages (Anthropic).
  agentguard-llm-proxy \\
      --listen 127.0.0.1:8081 \\
      --policy configs/default.yaml \\
      --guard-url http://127.0.0.1:8080 \\
      --api-key "$AGENTGUARD_API_KEY"

Then run this script:
  python examples/anthropic-sdk-config.py

Expected behaviour:
  - Tool-using turn: the proxy buffers the `tool_use` content_block
    until `content_block_stop`, runs `Engine.Check`, and either flushes
    byte-identical bytes (ALLOW) or emits a synthetic `text` block in
    place at the same content-block index, plus `message_delta` with
    `stop_reason: end_turn` (DENY / REQUIRE_APPROVAL).
  - The dashboard shows the decision live with `transport=llm_api_proxy`.
"""

from __future__ import annotations

import os
import sys

# Anthropic SDK reads ANTHROPIC_BASE_URL automatically. Set a default
# in case the operator forgot to export it before running.
os.environ.setdefault("ANTHROPIC_BASE_URL", "http://127.0.0.1:8081")

try:
    from anthropic import Anthropic
except ImportError:  # pragma: no cover - guidance only
    sys.stderr.write(
        "anthropic-sdk-config.py: the 'anthropic' package is not installed.\n"
        "Install it with:  pip install 'anthropic>=0.40'\n"
    )
    sys.exit(2)


def main() -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        sys.stderr.write(
            "anthropic-sdk-config.py: ANTHROPIC_API_KEY is not set.\n"
            "Export your real Anthropic key — the proxy forwards x-api-key "
            "verbatim to api.anthropic.com.\n"
        )
        sys.exit(2)

    base_url = os.environ["ANTHROPIC_BASE_URL"]
    print(f"[client] base_url={base_url}  (note: no /v1 suffix)")

    client = Anthropic(base_url=base_url, api_key=api_key)

    # Same shell tool as the OpenAI example, but in the Anthropic
    # `tools` shape (no `function` wrapper). The default LLM tool-scope
    # map (pkg/llmproxy/scope_map.go) maps `bash` → `shell`.
    tools = [
        {
            "name": "bash",
            "description": "Execute a shell command on the local host.",
            "input_schema": {
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
    ]

    user_prompt = "List the files in /tmp by calling the bash tool."
    print(f"[user]   {user_prompt}\n")

    # `messages.stream(...)` is the canonical streaming call. Iterating
    # the context manager yields raw events; `.text_stream` is the
    # convenience iterator over text deltas only. We use the raw event
    # stream so we can also surface tool-input deltas as they arrive.
    print("[assistant stream]")
    with client.messages.stream(
        model="claude-3-5-haiku-latest",  # any Claude model — proxy is model-agnostic
        max_tokens=512,
        tools=tools,
        messages=[{"role": "user", "content": user_prompt}],
    ) as stream:
        for event in stream:
            etype = getattr(event, "type", "")
            # Streaming text deltas (the `text` content block path —
            # also where AgentGuard's synthetic refusal lands when a
            # tool_use block was DENIED).
            if etype == "content_block_delta":
                delta = getattr(event, "delta", None)
                if getattr(delta, "type", "") == "text_delta":
                    print(delta.text, end="", flush=True)
                # Tool-input fragments (the `input_json_delta` path).
                elif getattr(delta, "type", "") == "input_json_delta":
                    print(delta.partial_json, end="", flush=True)
            elif etype == "content_block_start":
                block = getattr(event, "content_block", None)
                if getattr(block, "type", "") == "tool_use":
                    print(f"\n[tool_use.name={block.name}]", flush=True)
            elif etype == "message_stop":
                # `message_delta` carries the stop_reason that the proxy
                # rewrites to `end_turn` on a DENY (so the SDK doesn't
                # wait for a tool result that won't come).
                pass
    print()


if __name__ == "__main__":
    main()
