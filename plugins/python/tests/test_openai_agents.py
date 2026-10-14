"""Unit tests for the OpenAI Agents SDK adapter.

Most tests use a FunctionTool-shaped fake (name, description,
params_json_schema, async on_invoke_tool) and the mock AgentGuard server,
so they need no SDK. The few that touch SDK types (exception classes,
the tool input guardrail) importorskip ``agents``. The real Runner loop
lives in tests/integration/test_at_real_openai_agents.py.
"""

import asyncio
import importlib.metadata
import json
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, List

import pytest

from agentguard import (
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    CheckResult,
    Guard,
)
from agentguard.adapters import openai_agents as oa
from agentguard.adapters.openai_agents import (
    agentguard_tool_guardrail,
    guard_tool,
    guard_tools,
)
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _FakeFunctionTool:
    """Stand-in for agents.FunctionTool: the fields the adapter reads."""

    name: str = "run_shell"
    description: str = "Run a shell command"
    params_json_schema: dict = field(default_factory=lambda: {"type": "object"})
    calls: List[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        calls = self.calls

        async def _invoke(ctx: Any, input_json: str) -> str:
            calls.append(input_json)
            return f"ran:{input_json}"

        self.on_invoke_tool = _invoke


class _RecordingGuard:
    """Guard double that returns a fixed decision and records each check."""

    def __init__(self, decision: str = "ALLOW", delay: float = 0.0) -> None:
        self.decision = decision
        self.delay = delay
        self.calls: List[tuple] = []
        self.threads: List[int] = []

    def check(self, scope: str, **params: Any) -> CheckResult:
        self.threads.append(threading.get_ident())
        if self.delay:
            time.sleep(self.delay)  # blocking, like the real urllib call
        self.calls.append((scope, params))
        return CheckResult(
            decision=self.decision,
            reason="test",
            approval_id="ap_1" if self.decision == "REQUIRE_APPROVAL" else "",
            approval_url="http://x/approve" if self.decision == "REQUIRE_APPROVAL" else "",
        )


def _invoke(tool: Any, input_json: str) -> Any:
    return asyncio.run(tool.on_invoke_tool(None, input_json))


def _last_check_body() -> dict:
    return json.loads(MockAgentGuardHandler.last_request_body)


# ---------------------------------------------------------------------------
# Decisions against the mock server
# ---------------------------------------------------------------------------


class TestDecisions:
    def test_allow_runs_the_tool_with_the_original_input(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, Guard(mock_server, agent_id="oa"))

        out = _invoke(guarded, '{"command": "ls -la"}')

        assert out == 'ran:{"command": "ls -la"}'
        assert tool.calls == ['{"command": "ls -la"}']
        body = _last_check_body()
        assert body["scope"] == "shell"
        assert body["command"] == "ls -la"
        assert body["agent_id"] == "oa"

    def test_deny_raises_and_never_runs_the_tool(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "rule:no-rm"}
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, Guard(mock_server))

        with pytest.raises(AgentGuardDenied) as ei:
            _invoke(guarded, '{"command": "rm -rf /"}')

        assert tool.calls == []
        assert isinstance(ei.value, PermissionError)
        assert "Action denied" in str(ei.value)
        assert "rule:no-rm" in str(ei.value)
        assert ei.value.result.denied

    def test_approval_raises_with_id_and_url_and_never_runs_the_tool(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_42",
            "approval_url": "http://localhost:8080/approve/ap_42",
        }
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, Guard(mock_server))

        with pytest.raises(AgentGuardApprovalRequired) as ei:
            _invoke(guarded, '{"command": "terraform apply"}')

        assert tool.calls == []
        assert ei.value.approval_id == "ap_42"
        assert ei.value.approval_url == "http://localhost:8080/approve/ap_42"
        assert "http://localhost:8080/approve/ap_42" in str(ei.value)

    def test_unknown_decision_fails_closed(self):
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, _RecordingGuard(decision="MAYBE"))

        with pytest.raises(AgentGuardDenied):
            _invoke(guarded, '{"command": "ls"}')
        assert tool.calls == []

    def test_unreachable_server_fails_closed_by_default(self):
        tool = _FakeFunctionTool()
        # Port 9 (discard) on localhost: nothing listens, connection refused.
        guarded = guard_tool(tool, Guard("http://127.0.0.1:9", timeout=1))

        with pytest.raises(AgentGuardDenied):
            _invoke(guarded, '{"command": "ls"}')
        assert tool.calls == []

    def test_each_call_is_checked(self):
        guard = _RecordingGuard()
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, guard)

        for cmd in ("a", "b", "c"):
            _invoke(guarded, json.dumps({"command": cmd}))

        assert [p["command"] for _, p in guard.calls] == ["a", "b", "c"]
        assert len(tool.calls) == 3


# ---------------------------------------------------------------------------
# Async behaviour
# ---------------------------------------------------------------------------


class TestAsync:
    def test_check_runs_off_the_event_loop_thread(self):
        guard = _RecordingGuard()
        guarded = guard_tool(_FakeFunctionTool(), guard)

        async def _drive() -> int:
            await guarded.on_invoke_tool(None, '{"command": "ls"}')
            return threading.get_ident()

        loop_thread = asyncio.run(_drive())
        assert guard.threads and guard.threads[0] != loop_thread

    def test_slow_check_does_not_block_other_tasks(self):
        guard = _RecordingGuard(delay=0.3)
        guarded = guard_tool(_FakeFunctionTool(), guard)
        ticks: List[float] = []

        async def _ticker() -> None:
            for _ in range(5):
                ticks.append(time.monotonic())
                await asyncio.sleep(0.03)

        async def _drive() -> None:
            await asyncio.gather(
                guarded.on_invoke_tool(None, '{"command": "ls"}'),
                _ticker(),
            )

        start = time.monotonic()
        asyncio.run(_drive())
        # All five ticks land while the 0.3 s blocking check is in flight.
        # A check on the loop thread would push every tick past 0.3 s.
        assert len(ticks) == 5
        assert ticks[-1] - start < 0.28

    def test_parallel_calls_check_concurrently(self):
        guard = _RecordingGuard(delay=0.2)
        guarded = guard_tool(_FakeFunctionTool(), guard)

        async def _drive() -> None:
            await asyncio.gather(
                *(guarded.on_invoke_tool(None, '{"command": "ls"}') for _ in range(4))
            )

        start = time.monotonic()
        asyncio.run(_drive())
        assert len(guard.calls) == 4
        assert time.monotonic() - start < 0.6  # serial would be >= 0.8 s


# ---------------------------------------------------------------------------
# Scope inference and parameter extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name,description,args,scope,want_scope,want_params",
    [
        (
            "run_shell", "Run a shell command", {"command": "ls"}, None,
            "shell", {"command": "ls"},
        ),
        (
            "run_shell", "Run a shell command", {"cmd": "ls"}, None,
            "shell", {"command": "ls"},
        ),
        (
            "do_thing", "", {"url": "https://api.example.com/v1"}, None,
            "network", {"url": "https://api.example.com/v1", "domain": "api.example.com"},
        ),
        (
            "read_file", "", {"path": "/etc/passwd"}, None,
            "filesystem", {"path": "/etc/passwd", "action": "read"},
        ),
        (
            "delete_file", "", {"file_path": "/tmp/x"}, None,
            "filesystem", {"path": "/tmp/x", "action": "delete"},
        ),
        (
            "set_target", "", {"path": "/tmp/x"}, None,
            "filesystem", {"path": "/tmp/x"},
        ),
        ("lookup", "Fetch a web page", {"q": "cats"}, None, "network", {}),
        ("lookup", "List a directory", {"q": "cats"}, None, "filesystem", {}),
        ("lookup", "Click a button in the browser", {}, None, "browser", {}),
        ("lookup", "Do something", {"q": "cats"}, None, "shell", {}),
        (
            "lookup", "Do something", {"session_id": "s1", "est_cost": 0.5}, None,
            "shell", {"session_id": "s1", "est_cost": 0.5},
        ),
        (
            "do_thing", "", {"url": "https://example.com"}, "data",
            "data", {"url": "https://example.com", "domain": "example.com"},
        ),
    ],
)
def test_scope_and_params(tool_name, description, args, scope, want_scope, want_params):
    guard = _RecordingGuard()
    tool = _FakeFunctionTool(name=tool_name, description=description)
    guarded = guard_tool(tool, guard, scope=scope)

    _invoke(guarded, json.dumps(args))

    assert guard.calls == [(want_scope, want_params)]


class TestInputParsing:
    def test_invalid_json_is_gated_as_a_command_and_passed_through(self):
        guard = _RecordingGuard()
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, guard)

        _invoke(guarded, "rm -rf / {not json")

        assert guard.calls == [("shell", {"command": "rm -rf / {not json"})]
        # The tool still receives the raw string; its own validation rejects it.
        assert tool.calls == ["rm -rf / {not json"]

    def test_invalid_json_is_denied_without_running_the_tool(self):
        guard = _RecordingGuard(decision="DENY")
        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, guard)

        with pytest.raises(AgentGuardDenied):
            _invoke(guarded, "rm -rf /")
        assert tool.calls == []

    def test_empty_input_checks_with_no_params(self):
        guard = _RecordingGuard()
        guarded = guard_tool(_FakeFunctionTool(), guard)

        _invoke(guarded, "")

        assert guard.calls == [("shell", {})]

    def test_json_string_is_gated_as_a_command(self):
        guard = _RecordingGuard()
        guarded = guard_tool(_FakeFunctionTool(), guard)

        _invoke(guarded, '"ls -la"')

        assert guard.calls == [("shell", {"command": "ls -la"})]

    def test_json_array_carries_no_params(self):
        guard = _RecordingGuard()
        guarded = guard_tool(_FakeFunctionTool(), guard)

        _invoke(guarded, '["ls", "-la"]')

        assert guard.calls == [("shell", {})]


# ---------------------------------------------------------------------------
# Wrapping contract
# ---------------------------------------------------------------------------


class TestWrapping:
    def test_caller_tool_is_not_mutated(self):
        tool = _FakeFunctionTool()
        original_invoker = tool.on_invoke_tool
        guarded = guard_tool(tool, _RecordingGuard())

        assert guarded is not tool
        assert tool.on_invoke_tool is original_invoker
        assert guarded.on_invoke_tool is not original_invoker
        assert guarded.name == tool.name
        assert guarded.description == tool.description
        assert guarded.params_json_schema == tool.params_json_schema

    def test_gated_invoker_mirrors_the_original_signature(self):
        # The SDK chooses ToolContext vs a plain RunContextWrapper from the
        # invoker's first-parameter annotation; the gate must expose the
        # original's, not its own ``ctx: Any``.
        import inspect

        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, _RecordingGuard())

        assert inspect.signature(guarded.on_invoke_tool) == inspect.signature(
            tool.on_invoke_tool
        )

    def test_calling_the_original_tool_is_not_gated(self):
        guard = _RecordingGuard(decision="DENY")
        tool = _FakeFunctionTool()
        guard_tool(tool, guard)

        _invoke(tool, '{"command": "ls"}')

        assert guard.calls == []
        assert tool.calls == ['{"command": "ls"}']

    def test_guard_tools_wraps_every_tool_with_one_guard(self):
        guard = _RecordingGuard()
        tools = [_FakeFunctionTool(name="a"), _FakeFunctionTool(name="b")]

        guarded = guard_tools(tools, guard, scope="shell")

        assert [t.name for t in guarded] == ["a", "b"]
        for t in guarded:
            _invoke(t, '{"command": "x"}')
        assert len(guard.calls) == 2
        assert all(t.calls for t in tools)

    def test_guard_tools_refuses_a_tool_it_cannot_gate(self):
        def plain_function(command: str) -> str:
            return command

        with pytest.raises(TypeError, match="@function_tool"):
            guard_tools([_FakeFunctionTool(), plain_function], _RecordingGuard())

    def test_hosted_tool_shape_is_refused(self):
        hosted = SimpleNamespace(name="web_search")  # no on_invoke_tool

        with pytest.raises(TypeError, match="cannot be gated"):
            guard_tool(hosted, _RecordingGuard())


# ---------------------------------------------------------------------------
# Version floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "found,refused",
    [
        ("0.2.11", True),
        ("0.3.2", True),
        ("0.3.3", False),
        ("0.23.1", False),
        ("0.24.0rc1", False),
    ],
)
def test_version_floor(monkeypatch, found, refused):
    real_version = importlib.metadata.version

    def fake_version(name):
        return found if name == "openai-agents" else real_version(name)

    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    if refused:
        with pytest.raises(ImportError, match=r"requires openai-agents>=0\.3\.3"):
            guard_tool(_FakeFunctionTool(), _RecordingGuard())
    else:
        guard_tool(_FakeFunctionTool(), _RecordingGuard())


def test_sdk_not_installed_is_not_an_error_for_guard_tool(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    oa._require_supported_sdk()


# ---------------------------------------------------------------------------
# SDK integration points (need the real package)
# ---------------------------------------------------------------------------


class TestSDKTypes:
    def test_raised_deny_is_an_agents_exception(self):
        agents_exceptions = pytest.importorskip("agents.exceptions")
        guarded = guard_tool(_FakeFunctionTool(), _RecordingGuard(decision="DENY"))

        with pytest.raises(AgentGuardDenied) as ei:
            _invoke(guarded, '{"command": "ls"}')

        # The SDK runner re-raises AgentsException unchanged instead of
        # wrapping it in UserError, so callers can catch AgentGuardDenied.
        assert isinstance(ei.value, agents_exceptions.AgentsException)
        assert ei.value.run_data is None

    def test_raised_approval_is_an_agents_exception(self):
        agents_exceptions = pytest.importorskip("agents.exceptions")
        guarded = guard_tool(
            _FakeFunctionTool(), _RecordingGuard(decision="REQUIRE_APPROVAL")
        )

        with pytest.raises(AgentGuardApprovalRequired) as ei:
            _invoke(guarded, '{"command": "ls"}')

        assert isinstance(ei.value, agents_exceptions.AgentsException)
        assert ei.value.approval_id == "ap_1"


def _guardrail_data(tool_name: str, arguments: str) -> Any:
    return SimpleNamespace(
        context=SimpleNamespace(tool_name=tool_name, tool_arguments=arguments),
        agent=None,
    )


class TestToolGuardrail:
    @pytest.fixture(autouse=True)
    def _needs_sdk(self):
        pytest.importorskip("agents")

    def test_allow_lets_the_call_through(self):
        guard = _RecordingGuard()
        guardrail = agentguard_tool_guardrail(guard)

        out = asyncio.run(guardrail.run(_guardrail_data("run_shell", '{"command": "ls"}')))

        assert out.behavior["type"] == "allow"
        assert out.output_info.allowed
        assert guard.calls == [("shell", {"command": "ls"})]

    def test_deny_rejects_with_a_message_for_the_model(self):
        guardrail = agentguard_tool_guardrail(_RecordingGuard(decision="DENY"))

        out = asyncio.run(guardrail.run(_guardrail_data("run_shell", '{"command": "rm"}')))

        assert out.behavior["type"] == "reject_content"
        assert "Action denied" in out.behavior["message"]

    def test_approval_rejects_with_the_approval_url(self):
        guardrail = agentguard_tool_guardrail(_RecordingGuard(decision="REQUIRE_APPROVAL"))

        out = asyncio.run(guardrail.run(_guardrail_data("run_shell", '{"command": "rm"}')))

        assert out.behavior["type"] == "reject_content"
        assert "http://x/approve" in out.behavior["message"]

    def test_raise_on_block_trips_the_guardrail(self):
        guardrail = agentguard_tool_guardrail(
            _RecordingGuard(decision="DENY"), raise_on_block=True
        )

        out = asyncio.run(guardrail.run(_guardrail_data("run_shell", '{"command": "rm"}')))

        assert out.behavior["type"] == "raise_exception"
        assert out.output_info.denied

    def test_scope_is_inferred_from_arguments_and_name(self):
        guard = _RecordingGuard()
        guardrail = agentguard_tool_guardrail(guard)

        asyncio.run(guardrail.run(_guardrail_data("read_file", '{"path": "/etc/hosts"}')))

        assert guard.calls == [("filesystem", {"path": "/etc/hosts", "action": "read"})]

    def test_explicit_scope_wins(self):
        guard = _RecordingGuard()
        guardrail = agentguard_tool_guardrail(guard, scope="data", name="ag")

        asyncio.run(guardrail.run(_guardrail_data("read_file", '{"path": "/etc/hosts"}')))

        assert guard.calls[0][0] == "data"
        assert guardrail.get_name() == "ag"
