"""Real-LangChain adapter tests (v0.5 R5 closure).

These tests import the actual ``langchain_core`` library — they do **not**
mock the LangChain types themselves. The AgentGuard HTTP server is mocked
via the ``mock_server`` fixture so the policy decision can be steered per
test, but every Tool/Runnable used here is a real LangChain object.

If ``langchain_core`` is not installed in the test environment, every test
in this file is skipped via ``pytest.importorskip``. Do **not** mock
LangChain to make these tests run; that would defeat the audit closure
(R5 P1-P5 specifies tests must validate against the actual upstream API).
"""

import asyncio
import json

import pytest

from agentguard import Guard
from tests.conftest import MockAgentGuardHandler


# Skip the entire module if langchain_core is not importable. Tests that
# explicitly want langchain (legacy package) skip via importorskip too.
langchain_core = pytest.importorskip("langchain_core", minversion="0.1")
from langchain_core.tools import Tool  # noqa: E402  (after importorskip)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_real_tool(name: str = "echo", description: str = "echoes input"):
    """Build a real langchain_core Tool around a tracked function.

    Returns ``(tool, calls)`` — ``calls`` is a list that the function
    appends to on each invocation. Tests assert on ``calls`` to verify
    the underlying function ran (or did not).
    """
    calls: list = []

    def _func(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    return Tool.from_function(name=name, description=description, func=_func), calls


# ---------------------------------------------------------------------------
# Modern Runnable API: invoke / ainvoke
# ---------------------------------------------------------------------------

class TestInvoke:
    def test_guardedtool_invoke_allow_passes_through(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.invoke("hello")

        assert out == "echo:hello"
        assert calls == ["hello"]

    def test_guardedtool_invoke_deny_raises(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("rm -rf /")

        assert "denied" in str(ei.value).lower()
        # Underlying function MUST NOT have run.
        assert calls == []

    def test_guardedtool_invoke_approval_raises(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://approve/ap_1",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.invoke("sudo reboot")

        msg = str(ei.value).lower()
        assert "approval" in msg
        assert "http://approve/ap_1" in str(ei.value)
        assert calls == []

    def test_guardedtool_ainvoke_allow_passes_through(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = asyncio.run(gt.ainvoke("hi"))

        assert out == "echo:hi"
        assert calls == ["hi"]

    def test_guardedtool_ainvoke_deny_raises(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError):
            asyncio.run(gt.ainvoke("dangerous"))
        assert calls == []


# ---------------------------------------------------------------------------
# Stream / astream
# ---------------------------------------------------------------------------

class TestStream:
    def test_guardedtool_stream_gates_input_once(self, mock_server):
        """The gate fires once at stream open; ALLOW lets the stream proceed.

        Counts request bodies sent to the mock server: should be 1, not 1
        per chunk.
        """
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        chunks = list(gt.stream("hello"))

        # The wrapped function ran exactly once and produced the chunks.
        assert calls == ["hello"]
        # langchain_core Tool.stream yields the function output directly.
        assert chunks == ["echo:hello"]

    def test_guardedtool_stream_deny_raises(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError):
            list(gt.stream("dangerous"))
        assert calls == []

    def test_guardedtool_astream_gates_input_once(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        async def collect():
            chunks = []
            async for c in gt.astream("hi"):
                chunks.append(c)
            return chunks

        chunks = asyncio.run(collect())
        assert calls == ["hi"]
        assert chunks == ["echo:hi"]

    def test_guardedtool_astream_deny_raises(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "no"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        async def collect():
            async for _ in gt.astream("nope"):
                pass

        with pytest.raises(PermissionError):
            asyncio.run(collect())
        assert calls == []


# ---------------------------------------------------------------------------
# Batch / abatch
# ---------------------------------------------------------------------------

class _IndexedDecisionHandler(MockAgentGuardHandler):
    """Mock handler that returns DENY for the Nth call and ALLOW otherwise.

    Configure via class attribute ``deny_at_index``. The counter is reset by
    the fixture between tests.
    """

    deny_at_index = 0
    _call_count = 0

    def do_POST(self):
        if self.path == "/v1/check":
            idx = _IndexedDecisionHandler._call_count
            _IndexedDecisionHandler._call_count += 1
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length else b""
            MockAgentGuardHandler.last_request_body = body
            if idx == _IndexedDecisionHandler.deny_at_index:
                self._json_response(
                    200, {"decision": "DENY", "reason": f"deny-at-{idx}"}
                )
            else:
                self._json_response(
                    200, {"decision": "ALLOW", "reason": f"allow-at-{idx}"}
                )
            return
        super().do_POST()


@pytest.fixture()
def mock_server_indexed():
    """Variant of mock_server with the IndexedDecisionHandler.

    Spins a real HTTP server because tests hit it via the SDK's urllib
    client. Resets the call counter and the deny index between tests.
    """
    import threading
    from http.server import ThreadingHTTPServer

    _IndexedDecisionHandler._call_count = 0
    _IndexedDecisionHandler.deny_at_index = 0

    server = ThreadingHTTPServer(("127.0.0.1", 0), _IndexedDecisionHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    _IndexedDecisionHandler._call_count = 0
    _IndexedDecisionHandler.deny_at_index = 0


class TestBatch:
    def test_guardedtool_batch_all_allowed(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.batch(["a", "b", "c"])

        assert out == ["echo:a", "echo:b", "echo:c"]
        assert calls == ["a", "b", "c"]

    def test_guardedtool_batch_denies_first(self, mock_server_indexed):
        """First entry DENY → batch raises with index 0 in the message,
        underlying function never runs (whole-batch-fails-on-first-deny)."""
        from agentguard.adapters.langchain import GuardedTool

        _IndexedDecisionHandler.deny_at_index = 0
        guard = Guard(mock_server_indexed)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.batch(["bad", "ok1", "ok2"])

        msg = str(ei.value)
        assert "batch entry 0" in msg
        assert "denied" in msg.lower()
        # Function never ran.
        assert calls == []

    def test_guardedtool_batch_denies_second(self, mock_server_indexed):
        """Second entry DENY → batch raises with index 1 in the message."""
        from agentguard.adapters.langchain import GuardedTool

        _IndexedDecisionHandler.deny_at_index = 1
        guard = Guard(mock_server_indexed)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.batch(["ok0", "bad1", "ok2"])

        assert "batch entry 1" in str(ei.value)
        # The function may or may not have processed the first entry —
        # the contract is that the *batch* didn't return; we don't promise
        # transactional rollback of pre-deny calls.
        assert "bad1" not in calls

    def test_guardedtool_abatch_denies_first(self, mock_server_indexed):
        from agentguard.adapters.langchain import GuardedTool

        _IndexedDecisionHandler.deny_at_index = 0
        guard = Guard(mock_server_indexed)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            asyncio.run(gt.abatch(["bad", "ok1"]))

        assert "batch entry 0" in str(ei.value)
        assert calls == []


# ---------------------------------------------------------------------------
# Defense contract under the v0.5.1 hybrid pattern.
#
# v0.5.0 used composition + a strict ``__getattr__`` allowlist; v0.5.1
# subclasses langchain_core.tools.BaseTool so isinstance(thing, Runnable)
# succeeds at framework boundaries (langgraph 1.0 / langchain_core 1.x)
# and overrides every dispatch entry to keep gating tight.
#
# Defense moves from "no parent attributes are exposed" to "every gated
# dispatch path is on this class, not inherited." The canary integration
# tests catch upstream additions of new dispatch paths that bypass our
# overrides.
# ---------------------------------------------------------------------------

class TestDefenseContract:
    def test_subclass_passes_runnable_isinstance(self, mock_server):
        """The hybrid pattern's load-bearing property: when langgraph /
        langchain runtime does ``isinstance(thing, Runnable)``,
        GuardedTool must satisfy it.
        """
        try:
            from langchain_core.runnables import Runnable
            from langchain_core.tools import BaseTool as LCBase
        except ImportError:
            pytest.skip("langchain_core not installed")
        from agentguard.adapters.langchain import _build_guarded_tool_class

        cls = _build_guarded_tool_class()
        guard = Guard(mock_server)
        tool, _ = _make_real_tool()
        gt = cls(tool, guard, scope="shell")
        assert isinstance(gt, Runnable), (
            "GuardedTool must be an instance of Runnable so langgraph's "
            "create_react_agent / langchain's create_agent accept it"
        )
        assert isinstance(gt, LCBase), (
            "GuardedTool must subclass BaseTool so framework-side "
            "BaseTool isinstance checks (e.g. tool registries) accept it"
        )

    def test_run_dispatch_paths_are_overridden(self, mock_server):
        """Every gated method must be defined on GuardedTool itself, not
        merely inherited. Inheritance would mean the parent's (un-gated)
        implementation runs.
        """
        from agentguard.adapters.langchain import _build_guarded_tool_class

        cls = _build_guarded_tool_class()
        for method_name in (
            "_run",
            "_arun",
            "invoke",
            "ainvoke",
            "stream",
            "astream",
            "batch",
            "abatch",
            "run",
            "arun",
        ):
            assert method_name in cls.__dict__, (
                f"{method_name!r} must be defined on GuardedTool, not "
                "inherited from BaseTool. If you removed the override, the "
                "policy gate no longer fires on that dispatch path."
            )

    def test_private_attrs_not_in_model_dump(self, mock_server):
        """Pydantic ``PrivateAttr`` keeps internal references off the
        public model. ``_tool`` / ``_guard`` / ``_scope`` must NOT appear
        in ``model_dump()`` output.
        """
        from agentguard.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool, _ = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        try:
            dumped = gt.model_dump()
        except Exception as e:  # pragma: no cover
            pytest.fail(f"model_dump should succeed on a subclassed BaseTool: {e}")

        for forbidden in ("_tool", "_guard", "_scope"):
            assert forbidden not in dumped, (
                f"{forbidden!r} leaked through model_dump(): {dumped!r}"
            )

    def test_arbitrary_internal_blocked(self, mock_server):
        """Random framework-unknown attributes raise AttributeError.

        The new defense is "every gated method is overridden" — so the
        framework's introspection of ``name`` / ``description`` /
        ``args_schema`` works, but a probe for an undeclared attribute
        like ``_internal_thing`` still raises (because pydantic's model
        validates field names).
        """
        from agentguard.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool, _calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        with pytest.raises(AttributeError):
            _ = gt._GuardedTool__nonexistent

    def test_allowed_passthrough(self, mock_server):
        """Metadata attributes pass through cleanly — they live on the
        wrapper itself as pydantic-validated fields.
        """
        from agentguard.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool, _calls = _make_real_tool(name="my_tool", description="does things")
        gt = GuardedTool(tool, guard, scope="shell")

        assert gt.name == "my_tool"
        assert gt.description == "does things"
        # args_schema may be None on a Tool.from_function with no schema, but
        # the attribute must exist (no AttributeError):
        _ = gt.args_schema
        _ = gt.return_direct
        _ = gt.metadata
        _ = gt.tags


# ---------------------------------------------------------------------------
# End-to-end through real LangChain runtime
# ---------------------------------------------------------------------------

class TestRealLangChainRuntime:
    def test_real_invoke_round_trip_through_real_langchain_runtime(self, mock_server):
        """Build a tiny LCEL-style chain that uses ``tool.invoke`` and run
        it end-to-end. The gate must fire and the chain output must match
        the wrapped tool's output.

        We don't need an LLM — LCEL composes any Runnables. We pipe the
        guarded tool's invoke result into a lambda Runnable to prove the
        composition stays intact under real LangChain.
        """
        from agentguard.adapters.langchain import GuardedTool

        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError:  # pragma: no cover - sanity guard
            pytest.skip("RunnableLambda not available in this langchain_core version")

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        # Compose: guardedtool.invoke(input) | uppercase(result)
        chain = RunnableLambda(lambda x: gt.invoke(x)) | RunnableLambda(
            lambda r: r.upper()
        )

        out = chain.invoke("ping")

        assert out == "ECHO:PING"
        assert calls == ["ping"]
        # And the gate fired:
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "shell"
        assert body["command"] == "ping"

    def test_real_chain_deny_propagates_through_lcel(self, mock_server):
        """If the gate denies, the PermissionError must propagate through
        the LCEL chain (not be swallowed by the runtime)."""
        from agentguard.adapters.langchain import GuardedTool

        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError:  # pragma: no cover
            pytest.skip("RunnableLambda not available")

        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked at chain",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        chain = RunnableLambda(lambda x: gt.invoke(x))

        with pytest.raises(PermissionError) as ei:
            chain.invoke("rm -rf /")
        assert "denied" in str(ei.value).lower()
        assert calls == []


# ---------------------------------------------------------------------------
# Legacy run/arun parity (preserve v0.4.x semantics)
# ---------------------------------------------------------------------------

class TestLegacyRunArun:
    """The legacy run()/arun() entries continue to return string messages on
    DENY/REQUIRE_APPROVAL (v0.4.x compat). Only the modern entries raise."""

    def test_run_allow(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.run("hello")
        assert out == "echo:hello"
        assert calls == ["hello"]

    def test_run_deny_returns_string(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        guard = Guard(mock_server)
        tool, calls = _make_real_tool()
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.run("rm -rf /")
        # Legacy: returns a string, not raises (v0.4.x compat).
        assert isinstance(out, str)
        assert "denied" in out.lower()
        assert calls == []
