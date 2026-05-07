"""
AgentGuard LLM API Proxy — CrewAI example.

Drives a real CrewAI Crew through the AgentGuard LLM API Proxy by
passing a CrewAI `LLM(...)` instance with `base_url=` set to the proxy.
CrewAI delegates LLM calls to LiteLLM under the hood; LiteLLM honors
the OpenAI-compatible base URL the same way the raw `openai` SDK does.

Verified against:
  - crewai 1.14.x — `from crewai import Agent, Crew, Task, LLM` and
    `LLM(model=..., base_url=..., api_key=...)`. Source:
    https://docs.crewai.com/en/learn/llm-connections (verified
    2026-05-05). The `base_url=` parameter is canonical; the
    `OPENAI_API_BASE` env var is honored as a fallback.

Setup:
  pip install "crewai>=0.80,<2.0"
  export OPENAI_API_KEY=sk-...
  export OPENAI_API_BASE=http://127.0.0.1:8081/v1   # CrewAI/LiteLLM
                                                    # also reads
                                                    # OPENAI_BASE_URL

Run AgentGuard side (two terminals):

  # Terminal 1
  agentguard serve \\
      --policy configs/default.yaml \\
      --dashboard \\
      --watch \\
      --api-key "$AGENTGUARD_API_KEY"

  # Terminal 2
  agentguard-llm-proxy \\
      --listen 127.0.0.1:8081 \\
      --policy configs/default.yaml \\
      --guard-url http://127.0.0.1:8080 \\
      --api-key "$AGENTGUARD_API_KEY"

Then run this script:
  python examples/crewai-agent-config.py

Expected behaviour:
  - The Crew kicks off; the agent's first turn calls a tool. The
    proxy gates the tool_call before LiteLLM streams it to CrewAI.
    On DENY, the model "decides" not to call the tool and returns a
    synthetic assistant message instead — CrewAI logs the agent's
    final answer as the refusal text.
  - The dashboard shows the decision live, transport chip
    `llm_api_proxy`. Filter the audit log:
        agentguard audit --transport llm_api_proxy --limit 20
"""

from __future__ import annotations

import os
import subprocess
import sys

os.environ.setdefault("OPENAI_API_BASE", "http://127.0.0.1:8081/v1")
os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:8081/v1")

try:
    from crewai import Agent, Crew, LLM, Task
    from crewai.tools import BaseTool
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "crewai-agent-config.py: the 'crewai' package is not installed.\n"
        "Install with:  pip install 'crewai>=0.80,<2.0'\n"
    )
    sys.exit(2)


class ListTmpFilesTool(BaseTool):
    name: str = "list_tmp_files"
    description: str = "List the files in the /tmp directory of the host."

    def _run(self) -> str:  # type: ignore[override]
        try:
            result = subprocess.run(
                ["ls", "-la", "/tmp"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout or result.stderr or "(no output)"
        except Exception as exc:  # pragma: no cover - host-dependent
            return f"error: {exc}"


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        sys.stderr.write(
            "crewai-agent-config.py: OPENAI_API_KEY is not set.\n"
            "Export your real OpenAI key — the proxy forwards it verbatim.\n"
        )
        sys.exit(2)

    base_url = os.environ["OPENAI_API_BASE"]
    print(f"[crewai] LLM(base_url={base_url!r})")

    # Bind the LLM to the proxy. CrewAI's LLM(...) wraps LiteLLM; the
    # `base_url=` argument flows into LiteLLM's openai client as
    # `api_base`, so the model call lands on the proxy's
    # `/v1/chat/completions` instead of `api.openai.com`.
    llm = LLM(
        model="gpt-4o-mini",
        base_url=base_url,
        api_key=os.environ["OPENAI_API_KEY"],
        # Streaming exercises the proxy's pause/resume mechanism. Set
        # to False to drive the non-streaming path.
        stream=True,
        temperature=0,
    )

    file_lister = Agent(
        role="File Inspector",
        goal="Report what is currently in the /tmp directory.",
        backstory=(
            "You inspect the local filesystem on demand. You always use "
            "the list_tmp_files tool — never answer from memory."
        ),
        tools=[ListTmpFilesTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    inspect_task = Task(
        description="List the files in /tmp and summarize what you find.",
        expected_output="A short summary of the visible /tmp contents.",
        agent=file_lister,
    )

    crew = Crew(agents=[file_lister], tasks=[inspect_task], verbose=True)

    # `kickoff()` runs the agent loop. Each tool call the agent emits
    # passes through the AgentGuard proxy and is policy-gated; the
    # final answer is whatever the agent reaches after the gated turns
    # complete.
    result = crew.kickoff()
    print("\n[crew result]")
    print(result)


if __name__ == "__main__":
    main()
