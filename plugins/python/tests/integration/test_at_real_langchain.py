"""Deeper LangChain agent-loop E2E tests (Phase 3 — AT).

A14's existing ``test_real_langchain.py`` covers the surface — direct
``GuardedTool.invoke`` against a real ``langchain_core.tools.Tool`` plus
toolkit / batch / async / introspection. The contribution of *this* file
is the **agent loop**: a model that decides to call a tool, the agent
runtime that dispatches, and the gate firing during that dispatch.

Why a fake LLM? AgentGuard's repo policy is "no API keys in tests" —
so we use ``FakeMessagesListChatModel`` from langchain_core. The fake
model emits a pre-canned sequence of ``AIMessage`` objects (including
ones carrying ``tool_calls``), the agent runtime invokes the tool, and
the gate must fire on that invocation path.

Important architectural note (verified by these tests):
-------------------------------------------------------
``GuardedTool`` is a composition wrapper, not a ``BaseTool`` subclass
(see A11 decision-log). LangChain's ``create_react_agent`` /
``create_agent`` runtime registers tools through pydantic's
``coerce_to_runnable``, which calls ``isinstance(thing, Runnable)`` and
will REJECT a ``GuardedTool`` with a ``ValueError``. The realistic
integration pattern is therefore one of:

  1. Pass the underlying ``Tool`` to the agent runtime, but build that
     tool's ``func`` to delegate to a ``GuardedTool``. Every agent-driven
     tool dispatch then routes through the gate. (This is the test we
     write below — it mirrors a real user wrapping their own tool entry.)

  2. Use ``GuardedTool.invoke(...)`` directly from imperative code
     (covered by A14).

This file's E2E tests pin pattern (1). If a future LangChain release
allows registering ``GuardedTool`` directly, that's a strict
improvement; the test still passes either way.

Closes the v0.5 plan AT brief item: "Run a turn that the model decides
to call the tool. Assert the gate fires on the modern invoke() path."
"""

from __future__ import annotations

import json

import pytest


# Real LangChain stack — skip cleanly if unavailable. minversion is dropped
# because pyproject's [project.optional-dependencies] enforces the floor at
# install time; pytest.importorskip's minversion check parses module
# `__version__` via packaging and stumbled on langchain 1.x's version layout
# in CI even with pip-installed 1.2.x.
langchain_core = pytest.importorskip("langchain_core")
langgraph = pytest.importorskip("langgraph")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import Tool  # noqa: E402

from agentguard import Guard  # noqa: E402
from agentguard.adapters.langchain import GuardedTool  # noqa: E402

from .conftest import allow, deny  # noqa: E402


# ---------------------------------------------------------------------------
# A fake chat model that supports bind_tools — required by the langgraph
# / langchain agent runtimes. The stock FakeMessagesListChatModel does not
# override bind_tools and inherits the BaseChatModel raise-NotImplementedError
# stub, so we provide a minimal subclass tailored for tool-calling agent loops.
# ---------------------------------------------------------------------------


class _ToolCallingFakeChatModel(BaseChatModel):
    """Emit a pre-canned sequence of ``AIMessage`` objects."""

    responses: list

    @property
    def _llm_type(self) -> str:
        return "tool_calling_fake_chat"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # noqa: ANN001
        # Pop the next canned response from the queue.
        if not self.responses:
            msg = AIMessage(content="(no more canned responses)")
        else:
            msg = self.responses.pop(0)
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kwargs):  # noqa: ARG002
        # The real model would inject the tool schemas into the prompt
        # and produce structured tool_calls. Our canned model already
        # emits the right tool_calls, so binding is a pass-through.
        return self


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_gated_tool(guard, name: str = "echo", scope: str = "shell"):
    """Build the realistic agent-runtime registration pattern.

    The agent-runtime accepts a ``langchain_core.tools.Tool``. We build a
    ``Tool`` whose ``func`` dispatches into a ``GuardedTool``. Every
    agent-driven invocation therefore routes through the gate.

    Returns ``(agent_tool, calls)`` where ``calls`` is a list the
    underlying function appends to on each invocation.
    """
    calls: list = []

    def _underlying(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    underlying = Tool.from_function(
        name=f"_underlying_{name}", description="actual work", func=_underlying
    )
    gt = GuardedTool(underlying, guard, scope=scope)

    # Public-facing Tool the agent registers. Each invocation dispatches
    # to gt.invoke, which gates and forwards. This mirrors the realistic
    # operator pattern and surfaces gate failures as Tool errors the
    # agent runtime can route.
    def _gated(text: str) -> str:
        return gt.invoke(text)

    public = Tool.from_function(
        name=name,
        description="echoes input through the AgentGuard gate",
        func=_gated,
    )
    return public, calls


# ---------------------------------------------------------------------------
# Agent-loop E2E
# ---------------------------------------------------------------------------


class TestAgentLoopGate:
    def test_agent_runtime_calls_guarded_tool_gate_fires(self, integration_mock):
        """A langgraph ``create_react_agent`` configured with a fake LLM
        emits a tool_call. The agent runtime dispatches to the wrapped
        tool. The gate MUST fire exactly once during that dispatch.

        We capture the calls into the AgentGuard mock to assert the
        ``/v1/check`` body shape and count.
        """
        # We build the agent loop with langgraph's prebuilt helper because
        # it is the modern public API for "run an agent with these tools".
        # The classic ``langchain.agents.AgentExecutor`` was removed in
        # langchain 1.x, so the prebuilt route is what real users hit.
        try:
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            pytest.skip("langgraph.prebuilt.create_react_agent unavailable")

        integration_mock.set_default_check(allow())

        guard = Guard(integration_mock.base_url, agent_id="lc-agent-loop")
        agent_tool, calls = _make_gated_tool(guard, name="echo")

        # The fake model emits one tool_call message, then a final answer.
        # tool_call ids must be unique strings; the agent runtime matches
        # them up with ToolMessage results internally.
        tool_call_msg = AIMessage(
            content="",
            tool_calls=[
                {"name": "echo", "args": {"text": "hello"}, "id": "tc_1"},
            ],
        )
        final_answer = AIMessage(content="echo:hello")
        fake_llm = _ToolCallingFakeChatModel(responses=[tool_call_msg, final_answer])

        agent = create_react_agent(fake_llm, tools=[agent_tool])
        result = agent.invoke({"messages": [("user", "say hi")]})

        # The wrapped function ran exactly once with the model's argument.
        assert calls == ["hello"], f"calls={calls!r} result={result!r}"

        # The gate fired exactly once.
        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 1, f"expected 1 gate call, got {len(bodies)}: {bodies!r}"
        assert bodies[0]["scope"] == "shell"
        assert bodies[0]["agent_id"] == "lc-agent-loop"
        # The model's intended argument shows up as the gated command.
        assert bodies[0]["command"] == "hello"

    def test_agent_runtime_deny_propagates_through_loop(self, integration_mock):
        """A DENY decision raises through the agent runtime — the agent
        does NOT swallow ``PermissionError`` and continue."""
        try:
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            pytest.skip("langgraph.prebuilt.create_react_agent unavailable")

        integration_mock.set_default_check(deny(reason="rule:no-shell"))

        guard = Guard(integration_mock.base_url, agent_id="lc-agent-deny")
        agent_tool, calls = _make_gated_tool(guard, name="echo")

        # The fake model emits a tool_call. The gate denies. The runtime
        # surfaces the error rather than silently consuming it.
        tool_call_msg = AIMessage(
            content="",
            tool_calls=[{"name": "echo", "args": {"text": "rm -rf /"}, "id": "tc_2"}],
        )
        # Provide a follow-up final-answer message in case the runtime
        # tries to recover on tool error. If the runtime DOES recover, we
        # at least assert the underlying function never ran.
        final_answer = AIMessage(content="failed")
        fake_llm = _ToolCallingFakeChatModel(responses=[tool_call_msg, final_answer])

        agent = create_react_agent(fake_llm, tools=[agent_tool])

        # Two acceptable shapes:
        #   1) The agent raises (PermissionError surfaces).
        #   2) The agent catches the tool error and surfaces it as a
        #      ToolMessage with `status="error"`.
        # Either way: the wrapped function never ran AND the gate fired.
        try:
            result = agent.invoke({"messages": [("user", "be evil")]})
            # No raise — runtime caught the tool error. Make sure the
            # tool itself never executed.
            assert calls == [], f"tool ran despite DENY: {calls!r}"
            # Look for an error ToolMessage in the trajectory.
            messages = result.get("messages", [])
            error_text_seen = any(
                ("denied" in str(getattr(m, "content", "")).lower())
                or (getattr(m, "status", None) == "error")
                for m in messages
            )
            assert error_text_seen, (
                f"no error ToolMessage in trajectory: {messages!r}"
            )
        except PermissionError:
            # Agent raised through. That's also fine.
            assert calls == []

        # Either way the gate fired exactly once.
        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 1, f"expected 1 gate call, got {len(bodies)}"
        assert bodies[0]["command"] == "rm -rf /"

    def test_two_tool_calls_two_gate_checks(self, integration_mock):
        """The model emits TWO tool_calls in one AIMessage. Agent runtime
        runs both. The gate fires for EACH dispatch.

        Real-world relevance: modern agents emit parallel tool_calls; if
        the gate is only being fired once per AIMessage instead of once
        per tool_call, this catches it.
        """
        try:
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            pytest.skip("langgraph.prebuilt.create_react_agent unavailable")

        integration_mock.set_default_check(allow())

        guard = Guard(integration_mock.base_url, agent_id="lc-agent-parallel")
        agent_tool, calls = _make_gated_tool(guard, name="echo")

        msg = AIMessage(
            content="",
            tool_calls=[
                {"name": "echo", "args": {"text": "first"}, "id": "tc_1"},
                {"name": "echo", "args": {"text": "second"}, "id": "tc_2"},
            ],
        )
        final = AIMessage(content="done")
        fake_llm = _ToolCallingFakeChatModel(responses=[msg, final])

        agent = create_react_agent(fake_llm, tools=[agent_tool])
        agent.invoke({"messages": [("user", "two calls")]})

        assert calls == ["first", "second"]
        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        # Two tool_calls → two /v1/check calls.
        assert len(bodies) == 2, f"expected 2 gate calls, got {len(bodies)}: {bodies!r}"
        commands = sorted(b["command"] for b in bodies)
        assert commands == ["first", "second"]
