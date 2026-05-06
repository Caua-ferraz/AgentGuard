"""Real-LangChain integration tests (Phase 3 — A14).

These tests exercise full Runnable pipelines against the actual
``langchain_core`` and ``langchain`` packages — never a mock of the
framework. Only the AgentGuard HTTP server is mocked (``integration_mock``
fixture).

Closes audit findings R5 P1 (real-framework canary), R5 P2/P3/P4
(end-to-end gate enforcement under modern LangChain), R1 F1 (version-
floor bound).

These tests are gated by ``@pytest.mark.integration`` so the regular
``pytest -m "not integration"`` run skips them. The CI integration-tests
job and weekly cron run them with the framework extras installed.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# pyproject.toml's [project.optional-dependencies] langchain group enforces
# the version floor at install time (langchain-core>=0.3,<2.0). At test
# time we only need to verify the packages are importable — minversion=...
# was previously checking again, but pytest.importorskip parses
# `module.__version__` via packaging, and langchain 1.x's version-attribute
# layout caused spurious skips on CI even with pip-installed 1.2.x. The
# install-time floor is the source of truth; importorskip without
# minversion just gates on the import succeeding.
langchain_core = pytest.importorskip("langchain_core")
langchain = pytest.importorskip("langchain")

from langchain_core.tools import Tool  # noqa: E402

from agentguard import Guard  # noqa: E402
from agentguard.adapters.langchain import GuardedTool, GuardedToolkit  # noqa: E402

from .conftest import allow, deny, require_approval  # noqa: E402


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_real_tool(name: str = "echo", description: str = "echoes input"):
    """Build a real ``langchain_core`` Tool around a tracked function."""
    calls: list = []

    def _fn(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    tool = Tool.from_function(name=name, description=description, func=_fn)
    return tool, calls


# ---------------------------------------------------------------------------
# Full agent / chain loops
# ---------------------------------------------------------------------------


class TestRealLangChainInvoke:
    """End-to-end Runnable.invoke against the actual langchain_core runtime.

    Note: GuardedTool is a composition wrapper, not a Runnable subclass
    (see A11's decision-log entry). LangChain's ``coerce_to_runnable`` runs
    an ``isinstance(thing, Runnable)`` check and will refuse to compose a
    GuardedTool via the ``|`` operator. That is by design: the wrapper is
    used as a list entry to ``create_react_agent`` / ``AgentExecutor``,
    which call ``tool.invoke(input)`` directly. These tests exercise that
    direct-invoke path.
    """

    def test_real_langchain_invoke_allow(self, integration_mock):
        """A real langchain_core ``Tool`` wrapped by GuardedTool runs through invoke().

        What this catches: a regression where LangChain changes how
        ``BaseTool.invoke`` dispatches and bypasses our explicit override.
        """
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.invoke("hello")

        assert out == "echo:hello"
        assert calls == ["hello"]
        # Exactly one /v1/check should fire.
        assert len(integration_mock.requests_to("/v1/check")) == 1

    def test_real_langchain_invoke_deny_raises(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:rm-rf"))
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("rm -rf /")

        assert "denied" in str(ei.value).lower()
        # The wrapped tool must NOT have been called.
        assert calls == []

    def test_real_langchain_invoke_approval_raises(self, integration_mock):
        """REQUIRE_APPROVAL also surfaces as PermissionError for invoke()."""
        integration_mock.set_default_check(require_approval(approval_id="ap_lc1"))
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, _ = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("anything")
        assert "approval" in str(ei.value).lower()

    def test_real_langchain_underlying_tool_invoke(self, integration_mock):
        """Verify that the wrapped Tool's ``.invoke`` runs the function.

        This validates that GuardedTool.invoke forwards correctly to a
        real ``langchain_core.tools.Tool``'s invoke() — not just calling
        ``.func`` directly.
        """
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int")
        tool, calls = _make_real_tool(name="counter", description="counts")
        gt = GuardedTool(tool, guard, scope="shell")

        # Invoke via dict input (Tool.from_function accepts string or dict
        # depending on the args_schema).
        gt.invoke("first")
        gt.invoke("second")

        assert calls == ["first", "second"]
        assert len(integration_mock.requests_to("/v1/check")) == 2


class TestRealLangChainAsync:
    def test_chain_ainvoke_allow(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-async")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        async def _drive():
            return await gt.ainvoke("async-hi")

        out = asyncio.run(_drive())
        assert out == "echo:async-hi"
        assert calls == ["async-hi"]


class TestRealLangChainBatch:
    """Runnable.batch over multiple inputs with mixed decisions."""

    def test_batch_all_allow(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-batch")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.batch(["a", "b", "c"])

        assert out == ["echo:a", "echo:b", "echo:c"]
        assert calls == ["a", "b", "c"]
        # Three checks (one per batch entry) before the underlying batch fires.
        assert len(integration_mock.requests_to("/v1/check")) == 3

    def test_batch_partial_deny_raises_with_index(self, integration_mock):
        """Mock denies the second entry; the whole batch must fail with index 1."""
        integration_mock.enqueue_check(allow(), deny(reason="bad-2"), allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-batch")
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.batch(["a", "b", "c"])

        msg = str(ei.value)
        assert "batch entry 1" in msg
        assert "denied" in msg.lower()
        # No call ran — batch is whole-batch-fails-on-first-deny.
        assert calls == []


class TestRealLangChainAttributeIntrospection:
    """LangChain runtime introspects ``args_schema``, ``name``, ``description``.

    The strict allowlist on GuardedTool must keep that introspection path
    open, while still blocking ``func``, ``_tool``, etc.
    """

    def test_metadata_passthrough_works(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-meta")
        tool, _ = _make_real_tool(name="echo_v2", description="real LC tool")
        gt = GuardedTool(tool, guard, scope="shell")

        # These three reads happen during real LangChain agent construction
        # (see langchain.agents.create_react_agent's tool registration).
        assert gt.name == "echo_v2"
        assert gt.description == "real LC tool"
        assert gt.args_schema is None or hasattr(gt.args_schema, "__name__")

    def test_bypass_attribute_blocked(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="lc-int-meta")
        tool, _ = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(AttributeError) as ei:
            _ = gt.func
        assert "bypass" in str(ei.value).lower()


class TestRealLangChainToolkit:
    """Toolkit factory wraps a list of real Tools and infers scopes."""

    def test_toolkit_wraps_real_tools_and_routes_scopes(self, integration_mock):
        integration_mock.set_default_check(allow())

        net_tool = Tool.from_function(
            name="http_get",
            description="Fetch a URL via HTTP",
            func=lambda url: f"GET {url}",
        )
        fs_tool = Tool.from_function(
            name="file_read",
            description="Read a file from disk",
            func=lambda path: f"READ {path}",
        )

        toolkit = GuardedToolkit(
            tools=[net_tool, fs_tool],
            guard_url=integration_mock.base_url,
            agent_id="lc-int-toolkit",
        )

        # toolkit.tools is the drop-in replacement; verify both are gated
        # GuardedTools (not the raw langchain Tool objects).
        assert all(isinstance(t, GuardedTool) for t in toolkit.tools)

        # Drive each tool. The /v1/check call's body should reflect the
        # inferred scope.
        toolkit.tools[0].invoke("https://example.com")
        toolkit.tools[1].invoke("/tmp/x.txt")

        bodies = [
            json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 2
        assert bodies[0]["scope"] == "network"
        # File-tool gets static-inferred scope=filesystem from name keywords.
        assert bodies[1]["scope"] == "filesystem"
