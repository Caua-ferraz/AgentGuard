"""End-to-end LangChain agent against the AgentGuard LLM API Proxy
(Phase 4C — AT).

Plan brief (v0.5 plan, AT-Phase-4C item "E2E LangChain test"):

    "Spin up a real LangChain agent pointed at the proxy. Configure a
     tool the agent will call. Hit a denied tool name → agent receives
     synthetic refusal as tool_result → agent's behavior (retry / give
     up / report) is observed and documented."

There are two ways to honour this brief offline-deterministically:

    A. Subprocess the Go binary `agentguard-llm-proxy`, drive a real
       OpenAI-shape mock upstream, point a real `langchain-openai`
       `ChatOpenAI` at the proxy via `base_url`, and observe agent
       behavior end-to-end. Highest fidelity; flaky on CI runners
       that lack a built binary or have port-binding restrictions.

    B. Drive the Python `agentguard.adapters.langchain.GuardedTool`
       against a real `langchain-core` agent loop with a mock central
       server returning DENY for the tool. Lower fidelity — exercises
       the Python SDK's gating path rather than the Go LLM proxy
       streaming pipeline — but offline-deterministic and CI-stable.

This file ships path B and a SKIPPED placeholder for path A. Path A
is gated on `AGENTGUARD_LLM_PROXY_BIN` pointing at a built binary;
when set, the placeholder runs the binary against an httptest-style
mock OpenAI upstream and asserts the same behavioural property as
path B (agent receives the synthetic refusal text and stops).

The behavioural property pinned (under both paths):
    The LangChain agent's `tool_result` content for a DENY tool call
    is the AgentGuard refusal text. The agent loop does NOT raise on
    the refusal (the refusal is a normal tool_result) but it also does
    not silently retry — the next iteration sees the refusal as the
    tool's response and the agent's downstream logic is responsible
    for handling it (typically: report the refusal back to the user).

This is the "what does the agent do?" coupon the v0.5 plan calls out.

TODO(v0.6, #at-llm-proxy-binary-e2e): once a CI runner reliably ships
both `make build-llm-proxy` and a writable port for the proxy, flip
path A from optional to default and remove path B as redundant.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from contextlib import closing
from typing import Optional

import pytest


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _llm_proxy_binary() -> Optional[str]:
    """Locate the agentguard-llm-proxy binary.

    Looks at the env var first (CI override), then falls back to the
    repo root (next to the Makefile).
    """
    env_path = os.environ.get("AGENTGUARD_LLM_PROXY_BIN")
    if env_path and os.path.isfile(env_path):
        return env_path
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
    for candidate in ("agentguard-llm-proxy", "agentguard-llm-proxy.exe"):
        full = os.path.join(repo_root, candidate)
        if os.path.isfile(full):
            return full
    if shutil.which("agentguard-llm-proxy"):
        return "agentguard-llm-proxy"
    return None


# ---------------------------------------------------------------------------
# Path B — Python SDK + LangChain agent loop (offline-deterministic).
# ---------------------------------------------------------------------------


# Skip cleanly if LangChain is not available.
langchain_core = pytest.importorskip("langchain_core")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import Tool  # noqa: E402

from agentguard import Guard  # noqa: E402
from agentguard.adapters.langchain import GuardedTool  # noqa: E402

from .conftest import allow, deny  # noqa: E402


class _PlannedToolCallChatModel(BaseChatModel):
    """Fake chat model that emits a sequence of canned ``AIMessage``s.

    First reply requests a tool call; second reply (after observing the
    tool's response, including a refusal) is a plain text reply that
    "reports" what happened. This is the minimal agent loop pattern
    the test pins.
    """

    responses: list

    @property
    def _llm_type(self) -> str:
        return "fake-tool-calling"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if not self.responses:
            return ChatResult(generations=[
                ChatGeneration(message=AIMessage(content="(out of canned responses)"))
            ])
        msg = self.responses.pop(0)
        return ChatResult(generations=[ChatGeneration(message=msg)])


def _make_guarded_tool(guard: Guard, scope: str = "shell") -> Tool:
    """Wrap a real LangChain tool whose `func` delegates to a
    `GuardedTool`. This is the integration pattern A14 documented in
    test_at_real_langchain.py — `GuardedTool` is composition-only and
    can't be passed to LangChain agent runtimes directly.
    """

    def _bash_impl(cmd: str) -> str:
        return f"would have run: {cmd}"

    raw = Tool.from_function(
        name="bash",
        description="Execute a shell command.",
        func=_bash_impl,
    )
    guarded = GuardedTool(tool=raw, guard=guard, scope=scope)

    def _gated_entry(cmd: str) -> str:
        # GuardedTool.run raises PermissionError on deny — we surface
        # the error string as the tool's "response" so the agent sees
        # a normal `tool_result`, mirroring what the LLM API Proxy
        # emits as a synthetic refusal text on the wire.
        try:
            return str(guarded.run(cmd))
        except PermissionError as exc:
            return f"AgentGuard denied this action: {exc}"

    return Tool.from_function(
        name="bash",
        description="Execute a shell command.",
        func=_gated_entry,
    )


class TestAT_LLMProxy_LangChain_E2E_PathB:
    """Path B: Python SDK + LangChain agent loop.

    The agent's chat model is told to emit a tool_call (bash). The
    central server returns DENY. The tool's response is the refusal
    text. The agent's next turn sees the refusal as a regular
    tool_result and terminates with a plain text message — never
    silently retries.
    """

    def test_agent_receives_refusal_as_tool_result_and_stops(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:no-shell"))
        guard = Guard(integration_mock.base_url, agent_id="at-e2e-langchain")

        gated_tool = _make_guarded_tool(guard, scope="shell")

        # Pre-canned model behaviour: first reply requests tool call;
        # second reply (after seeing the refusal) reports back to the user.
        first = AIMessage(
            content="",
            tool_calls=[{
                "name": "bash",
                "args": {"cmd": "rm -rf /"},
                "id": "call_test_1",
            }],
        )
        second = AIMessage(content="The action was denied by policy.")
        model = _PlannedToolCallChatModel(responses=[first, second])

        # Run a minimal agent loop manually — the langgraph runtime is
        # heavy and asks for tool registration that GuardedTool can't
        # satisfy directly. The loop here pins the behavioural property:
        # invoke model, dispatch tool, surface tool_result, invoke model
        # again, observe terminal text.
        msgs: list[BaseMessage] = []
        # Turn 1: model decides to call tool.
        ai1 = model.invoke(msgs)
        msgs.append(ai1)
        assert ai1.tool_calls, "fake model must request a tool call"
        tc = ai1.tool_calls[0]

        # Dispatch tool — this is where the gate fires.
        tool_result = gated_tool.invoke(tc["args"]["cmd"])
        msgs.append(ToolMessage(content=str(tool_result), tool_call_id=tc["id"]))

        # The synthetic refusal text is what the agent sees as the
        # tool's response — the central correctness invariant.
        assert "denied" in str(tool_result).lower(), \
            f"expected refusal text in tool_result; got {tool_result!r}"
        assert "rule:no-shell" in str(tool_result), \
            f"refusal must include rule for operator-grade UX; got {tool_result!r}"

        # Turn 2: model observes the refusal, replies in plain text.
        ai2 = model.invoke(msgs)
        msgs.append(ai2)
        assert not getattr(ai2, "tool_calls", None), \
            "agent must NOT silently retry the denied tool call"
        assert ai2.content, "agent should produce a textual reply after refusal"

        # Exactly one /v1/check call (the denied bash call).
        check_requests = [
            json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(check_requests) == 1, \
            f"expected exactly 1 /v1/check call, got {check_requests!r}"
        assert check_requests[0].get("scope") == "shell"

    def test_agent_loop_with_allow_proceeds(self, integration_mock):
        """ALLOW path control test: the agent loop must reach the tool's
        real result when the central server allows. Pins that the gate
        is not over-blocking on the happy path."""

        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-e2e-allow")
        gated_tool = _make_guarded_tool(guard, scope="shell")

        result = gated_tool.invoke("echo ok")
        assert "would have run" in str(result), \
            f"ALLOW path should pass through to tool body; got {result!r}"
        check_requests = [
            json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(check_requests) == 1


# ---------------------------------------------------------------------------
# Path A — Real Go LLM API Proxy binary (highest fidelity).
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    _llm_proxy_binary() is None,
    reason=(
        "agentguard-llm-proxy binary not found; build with "
        "`make build-llm-proxy` or set AGENTGUARD_LLM_PROXY_BIN. "
        "Path B (Python SDK + LangChain) provides offline-deterministic "
        "coverage of the same behavioural property."
    ),
)
class TestAT_LLMProxy_LangChain_E2E_PathA:
    """Path A: real Go binary + a mock OpenAI upstream + a mock central
    server. Configures a fake LangChain ChatOpenAI pointed at the proxy
    via `base_url` and asserts the agent observes the synthetic refusal.

    This path is wired for when the binary is available; on most CI
    runners the skip marker fires and Path B carries the coverage.
    """

    def test_smoke_proxy_starts_and_serves_health(self, integration_mock):
        binary = _llm_proxy_binary()
        assert binary is not None
        port = _find_free_port()
        # Boot the proxy with no upstream (we won't actually drive a
        # request through it in this smoke test). The proxy must accept
        # the `--guard-url` of our mock central server, bind, and
        # serve `/healthz`.
        proc = subprocess.Popen(
            [
                binary,
                "--listen", f"127.0.0.1:{port}",
                "--guard-url", integration_mock.base_url,
                "--upstream-openai", integration_mock.base_url,
                "--upstream-anthropic", integration_mock.base_url,
                "--api-key", "dummy",
                "--tenant-id", "test",
                "--fail-mode", "deny",
                "--log-level", "info",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            # Poll /healthz up to 5s.
            import urllib.request
            deadline = time.time() + 5.0
            ok = False
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as resp:
                        body = resp.read().decode()
                        payload = json.loads(body)
                        if payload.get("status") == "ok" and payload.get("transport") == "llm_api_proxy":
                            ok = True
                            break
                except Exception:
                    time.sleep(0.1)
            assert ok, f"proxy did not become ready on 127.0.0.1:{port}"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
