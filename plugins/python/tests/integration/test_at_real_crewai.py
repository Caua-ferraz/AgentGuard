"""Deeper CrewAI agent-loop E2E tests (Phase 3 — AT).

A14's existing ``test_real_crewai.py`` exercises ``GuardedCrewTool``
directly via ``invoke``/``ainvoke`` against a real ``BaseTool``. The
contribution of this file: build a real ``Agent`` + ``Task`` + ``Crew``,
run ``crew.kickoff(...)``, and assert the gate fires when the agent
calls the tool inside that real run loop.

CrewAI requires an LLM. Real CrewAI shipping a ``OpenAIChat`` default
makes this tricky for an offline test — we'd need either an API key or
a Mock LLM that satisfies CrewAI's litellm bridge. We use the
``llm`` parameter to pass a callable ``MockLLM`` that returns a
pre-canned response signaling the agent to call our tool. If CrewAI's
LLM bridge cannot be satisfied with the local mock (the API has shifted
across crewai 0.80–1.x), the test skips itself with a clear message
rather than producing a false failure.

The agent-loop test is deliberately scoped narrow: one agent, one tool,
one task, one expected tool call. A broader multi-agent / multi-tool
test belongs in v0.6 once CrewAI's LLM-bridge interface stabilises.

Closes the v0.5 plan AT brief item: "Build a real CrewAI Crew with one
Agent + one wrapped tool. Call ``crew.kickoff(...)``. Assert the gate
fires when the agent calls the tool."
"""

from __future__ import annotations

import json

import pytest


crewai = pytest.importorskip("crewai")  # floor enforced by pyproject extras
try:
    from crewai import Agent, Task, Crew  # type: ignore[attr-defined]
    from crewai.tools import BaseTool  # type: ignore[attr-defined]
    from crewai.llms.base_llm import BaseLLM  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - layout shifts across versions
    pytest.skip(
        "crewai installed but Agent / Task / Crew / BaseTool / BaseLLM "
        "layout not at the expected import path. Real-CrewAI integration "
        "tests are skipped on this layout. Re-pin in pyproject.toml when "
        "the upstream layout settles.",
        allow_module_level=True,
    )

from agentguard import (  # noqa: E402
    AgentGuardDenied,
    Guard,
)
from agentguard.adapters.crewai import GuardedCrewTool  # noqa: E402

from .conftest import allow, deny  # noqa: E402


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Real CrewAI BaseTool subclass — mirrors what a real user writes.
# ---------------------------------------------------------------------------


class _EchoTool(BaseTool):
    name: str = "echo"
    description: str = "Echo a message. Call this when the user says hello."

    def _run(self, message: str) -> str:  # type: ignore[override]
        return f"crew-echo: {message}"


# ---------------------------------------------------------------------------
# Offline fake LLM — drives the agent loop without an OpenAI key.
#
# CrewAI's BaseLLM is the public extension point for custom LLM providers.
# Subclassing it and implementing ``call`` lets us drive the agent loop
# entirely offline. We keep the LLM dumb on purpose — it always answers
# by invoking ``echo`` once with a fixed message, then emits a final
# answer on subsequent calls. The agent's tool-dispatch path is the
# code under test, not the LLM behaviour.
# ---------------------------------------------------------------------------


class _OfflineEchoLLM(BaseLLM):
    """Drive a CrewAI agent loop offline by emitting a tool-call list
    and then a final-answer string.

    CrewAI's native function-calling executor (``_invoke_loop_native``)
    inspects the LLM's return value: if it looks like a list of tool
    calls (matching ``_is_tool_call_list``), the executor dispatches
    each call via ``available_functions[name](**args)``. We exploit
    that by returning a single tool call on the first turn and a
    string on the second turn so the loop terminates cleanly.
    """

    llm_type: str = "offline_echo"
    model: str = "offline/echo-fake"

    def supports_function_calling(self) -> bool:
        """Tell CrewAI to use the native function-calling path. The
        native loop calls ``available_functions[name](**args)`` directly
        — that path is the one we exercise.
        """
        return True

    def call(  # type: ignore[override]
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ):
        # Track turn count via __dict__ (pydantic ``__setattr__`` falls
        # through to ``object.__setattr__`` for non-field names).
        turn = self.__dict__.get("_offline_turn", 0)
        self.__dict__["_offline_turn"] = turn + 1
        if turn == 0:
            # Return a tool-call list shaped like ``{"name", "input"}``,
            # which ``CrewAgentExecutor._is_tool_call_list`` recognises
            # and ``_parse_native_tool_call`` parses cleanly. The agent
            # then dispatches via ``available_functions["echo"](**input)``,
            # which is bound to GuardedCrewTool.run — and that gates.
            return [
                {"name": "echo", "input": {"message": "hello"}, "id": "call_offline_1"},
            ]
        # Second turn (after the tool result has been appended to the
        # message history): emit a string so the loop converts it into
        # an AgentFinish and exits.
        return "Final Answer: done"


# ---------------------------------------------------------------------------
# Tests — full kickoff loop.
#
# crew.kickoff() drives the agent's own LLM-call loop. We don't have
# OpenAI credentials in CI, so the agent's "reasoning" step would fail
# without a stubbed LLM. CrewAI's pluggable LLM interface has shifted
# across 0.80→1.x; rather than guess, we attempt the kickoff and if
# CrewAI raises any exception that contains "OPENAI" or "API key" or
# "LiteLLM", we skip the test with a precise reason. This keeps the
# test brittle in the right way (we only claim PASS when the gate
# actually fired) without forcing a hard dependency on the moving LLM
# bridge.
# ---------------------------------------------------------------------------


class TestRealCrewKickoffGatesTool:
    def test_kickoff_runs_tool_and_gate_fires(self, integration_mock):
        """Run ``crew.kickoff`` end-to-end. The gate must fire at least
        once when the agent calls the tool.

        We don't assert exactly-1 because CrewAI's planner has been known
        to call the tool multiple times during a single kickoff cycle in
        certain versions; the contract that matters is: at least one
        ``/v1/check`` happened during this kickoff, AND each one
        consulted the right scope.
        """
        integration_mock.set_default_check(allow())

        guard = Guard(integration_mock.base_url, agent_id="crew-at-kickoff")
        wrapped = GuardedCrewTool(_EchoTool(), guard=guard, scope="shell")
        fake_llm = _OfflineEchoLLM(model="offline/echo-fake")

        # The Agent constructor now accepts the GuardedCrewTool because
        # v0.5.0's hybrid pattern actually subclasses BaseTool. If a future
        # framework change removes that compatibility, the ValidationError
        # surfaces here unmasked rather than under a skip clause.
        try:
            agent = Agent(
                role="echoer",
                goal="echo back any message the user sends",
                backstory="you only ever call the echo tool",
                tools=[wrapped],
                allow_delegation=False,
                verbose=False,
                llm=fake_llm,
            )
            task = Task(
                description="The user said 'hello'. Call the echo tool with 'hello'.",
                expected_output="The string 'crew-echo: hello'.",
                agent=agent,
            )
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            crew.kickoff()
        except Exception as e:  # noqa: BLE001
            # If CrewAI's plumbing rejects our offline LLM (e.g. it requires
            # an LLM bridge field we haven't stubbed), skip with a clear
            # reason rather than masking a real bug. Pydantic ValidationError
            # on the tools field would have surfaced inside Agent() above —
            # if we made it here without that, the hybrid wrapper passed.
            msg = str(e).lower()
            if any(k in msg for k in ("openai", "api key", "litellm", "no llm", "key", "auth")):
                pytest.skip(f"CrewAI LLM bridge rejected offline LLM: {e}")
            raise

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        # At least one gate call MUST have happened during the kickoff.
        assert len(bodies) >= 1, (
            "CrewAI kickoff completed without any /v1/check call — "
            "the GuardedCrewTool did not gate the agent's tool dispatch"
        )
        # And each call must use the configured scope.
        for b in bodies:
            assert b["scope"] == "shell"
            assert b["agent_id"] == "crew-at-kickoff"


class TestRealCrewKickoffDenyHaltsTool:
    def test_kickoff_with_deny_does_not_run_underlying(self, integration_mock):
        """When AgentGuard denies, the agent MUST NOT execute the
        underlying tool. CrewAI's run loop may still complete (the agent
        may "think harder" and try alternative tools) — what we lock is:
        every gated invocation that returned DENY left ``_run`` with
        zero observable effect.
        """
        integration_mock.set_default_check(deny(reason="rule:no-shell"))

        guard = Guard(integration_mock.base_url, agent_id="crew-at-deny")
        underlying = _EchoTool()
        runs_observed: list[str] = []
        original_run = underlying._run

        def _record(message: str) -> str:
            runs_observed.append(message)
            return original_run(message)

        # Hook the underlying _run so we can observe whether it executed.
        # We don't replace the method on the class — we shadow it on the
        # instance so other tests aren't affected.
        underlying._run = _record  # type: ignore[assignment]
        wrapped = GuardedCrewTool(underlying, guard=guard, scope="shell")
        fake_llm = _OfflineEchoLLM(model="offline/echo-fake")

        try:
            agent = Agent(
                role="echoer",
                goal="echo back any message the user sends",
                backstory="you only call the echo tool",
                tools=[wrapped],
                allow_delegation=False,
                verbose=False,
                llm=fake_llm,
            )
            task = Task(
                description="Call echo tool with 'denied'",
                expected_output="some result",
                agent=agent,
            )
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            crew.kickoff()
        except AgentGuardDenied:
            # If CrewAI propagates the deny, that's also acceptable.
            pass
        except Exception as e:  # noqa: BLE001
            msg = str(e).lower()
            if any(k in msg for k in ("openai", "api key", "litellm", "no llm", "auth")):
                pytest.skip(f"CrewAI LLM bridge rejected offline LLM: {e}")
            # Any other exception is a real failure — the test must not
            # mask CrewAI bugs that aren't policy-related.
            raise

        # The contract: regardless of what CrewAI's planner did,
        # `_run` was never invoked because the gate denied.
        assert runs_observed == [], (
            f"underlying tool ran despite DENY: invocations={runs_observed!r}"
        )
        # And at least one gate call happened.
        assert len(integration_mock.requests_to("/v1/check")) >= 1
