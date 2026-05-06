"""Real-CrewAI integration tests (Phase 3 — A14).

These tests build and exercise actual ``crewai`` ``BaseTool`` subclasses,
not mocks. The AgentGuard HTTP server is mocked via ``integration_mock``.

Closes audit findings R5 P1 (real-framework canary), R5 P2/P3/P4 (modern
CrewAI / LangChain Runnable bypass closure), R1 F1 (version floor bound).

CrewAI pulls in heavy transitive deps (LiteLLM, OpenAI client, etc.). The
``importorskip`` keeps the suite green when only ``langchain`` is
installed.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# Pin floor matches the upper bound documented in pyproject.toml's crewai
# extra. CrewAI 0.80 was the first release on the modern Runnable API —
# all of A12's hardening targets that surface.
crewai = pytest.importorskip("crewai", minversion="0.80")
try:
    from crewai.tools import BaseTool  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - layout differs across versions
    pytest.skip(
        "crewai installed but BaseTool not at crewai.tools.BaseTool",
        allow_module_level=True,
    )

from agentguard import (  # noqa: E402
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    Guard,
)
from agentguard.adapters.crewai import (  # noqa: E402
    GuardedCrewTool,
    guard_crew_tools,
)

from .conftest import allow, deny, require_approval  # noqa: E402


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers — define a real CrewAI BaseTool subclass.
#
# We avoid pydantic Field declarations beyond the BaseTool defaults so the
# subclass works across the 0.80–0.89 CrewAI range without triggering
# version-specific schema validation.
# ---------------------------------------------------------------------------


class _RealCrewTool(BaseTool):
    name: str = "real_crew_echo"
    description: str = "echo a real input through CrewAI's BaseTool"

    def _run(self, query: str) -> str:  # type: ignore[override]
        return f"crew-echo:{query}"


# ---------------------------------------------------------------------------
# Modern Runnable API
# ---------------------------------------------------------------------------


class TestRealCrewAIInvoke:
    def test_real_crewai_invoke_allow(self, integration_mock):
        """A real BaseTool wrapped by GuardedCrewTool runs through invoke()."""
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="crew-int")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        # CrewAI's Runnable invoke accepts dict or str depending on the tool.
        # Use a dict shape because that is what CrewAI agents emit when
        # calling a BaseTool with structured input.
        out = wrapped.invoke({"query": "hello-crew"})

        # Result shape varies between CrewAI versions: some return the raw
        # string, some wrap it. Accept either.
        assert "crew-echo" in str(out)
        assert len(integration_mock.requests_to("/v1/check")) == 1

    def test_real_crewai_invoke_deny_raises(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:rm-rf"))
        guard = Guard(integration_mock.base_url, agent_id="crew-int")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        with pytest.raises(AgentGuardDenied) as ei:
            wrapped.invoke({"query": "bad"})
        assert "denied" in str(ei.value).lower()

    def test_real_crewai_invoke_approval_raises(self, integration_mock):
        integration_mock.set_default_check(require_approval(approval_id="ap_crew1"))
        guard = Guard(integration_mock.base_url, agent_id="crew-int")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        with pytest.raises(AgentGuardApprovalRequired):
            wrapped.invoke({"query": "needs-review"})


class TestRealCrewAIAsync:
    def test_real_crewai_ainvoke_allow(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="crew-int-async")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        async def _drive():
            return await wrapped.ainvoke({"query": "async"})

        out = asyncio.run(_drive())
        assert "crew-echo" in str(out)


# ---------------------------------------------------------------------------
# Run-loop / multi-call scenarios
# ---------------------------------------------------------------------------


class TestRealCrewAIRunLoop:
    """An agent loop that calls the same tool N times sees N gate checks."""

    def test_repeated_invocation_one_check_per_call(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="crew-int-loop")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        for q in ("a", "b", "c"):
            wrapped.invoke({"query": q})

        # Three invocations → three independent /v1/check calls.
        bodies = [json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")]
        assert len(bodies) == 3
        assert all(b["scope"] == "shell" for b in bodies)

    def test_mid_loop_deny_stops_caller(self, integration_mock):
        """Two ALLOWs then a DENY: the loop must surface the DENY."""
        integration_mock.enqueue_check(allow(), allow(), deny(reason="rule:max"))
        guard = Guard(integration_mock.base_url, agent_id="crew-int-loop")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        wrapped.invoke({"query": "1"})
        wrapped.invoke({"query": "2"})
        with pytest.raises(AgentGuardDenied):
            wrapped.invoke({"query": "3"})


# ---------------------------------------------------------------------------
# Attribute introspection
# ---------------------------------------------------------------------------


class TestRealCrewAIAttributeIntrospection:
    def test_metadata_passthrough(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="crew-int-meta")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        assert wrapped.name == "real_crew_echo"
        assert "echo" in wrapped.description.lower()

    def test_bypass_attribute_blocked(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="crew-int-meta")
        wrapped = GuardedCrewTool(_RealCrewTool(), guard=guard, scope="shell")

        # 'func' / 'coroutine' / 'stream' / 'batch' are all denied.
        for blocked in ("func", "coroutine", "stream", "batch"):
            with pytest.raises(AttributeError):
                getattr(wrapped, blocked)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class TestGuardCrewToolsFactory:
    def test_factory_wraps_each_tool(self, integration_mock):
        integration_mock.set_default_check(allow())
        wrapped = guard_crew_tools(
            tools=[_RealCrewTool(), _RealCrewTool()],
            guard_url=integration_mock.base_url,
            agent_id="crew-int-factory",
        )
        assert all(isinstance(t, GuardedCrewTool) for t in wrapped)
        wrapped[0].invoke({"query": "x"})
        wrapped[1].invoke({"query": "y"})
        assert len(integration_mock.requests_to("/v1/check")) == 2
