"""Real OpenAI Agents SDK integration tests: the gate on real FunctionTools.

These build tools with the SDK's own ``@function_tool`` decorator and call
the guarded ``on_invoke_tool`` with a real ``ToolContext``, the way the
runner does. The AgentGuard server is mocked via ``integration_mock``.
The full Agent + Runner loop lives in ``test_at_real_openai_agents.py``.
"""

from __future__ import annotations

import asyncio
import copy
import json
from typing import List

import pytest

agents = pytest.importorskip("agents")  # floor enforced by the pyproject extra
try:
    from agents import FunctionTool, function_tool  # type: ignore[attr-defined]
    from agents.tool_context import ToolContext  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - layout differs across versions
    pytest.skip(
        "openai-agents installed but FunctionTool / function_tool / "
        "ToolContext are not at the expected import paths.",
        allow_module_level=True,
    )

from agentguard import (  # noqa: E402
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    Guard,
)
from agentguard.adapters.openai_agents import guard_tool, guard_tools  # noqa: E402

from .conftest import allow, deny, require_approval  # noqa: E402


pytestmark = pytest.mark.integration


def _make_tools(ran: List[str]):
    @function_tool
    def run_shell(command: str) -> str:
        """Run a shell command."""
        ran.append(command)
        return f"ran: {command}"

    @function_tool
    def read_file(path: str) -> str:
        """Read a file."""
        ran.append(path)
        return f"contents of {path}"

    return run_shell, read_file


def _call(tool, arguments: str):
    ctx = ToolContext(
        context=None,
        tool_name=tool.name,
        tool_call_id="call_1",
        tool_arguments=arguments,
    )
    return asyncio.run(tool.on_invoke_tool(ctx, arguments))


def _check_bodies(integration_mock) -> List[dict]:
    return [json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")]


class TestRealFunctionTool:
    def test_allow_runs_the_tool(self, integration_mock):
        integration_mock.set_default_check(allow())
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guarded = guard_tool(run_shell, Guard(integration_mock.base_url, agent_id="oa-int"))

        out = _call(guarded, json.dumps({"command": "ls"}))

        assert "ran: ls" in str(out)
        assert ran == ["ls"]
        assert _check_bodies(integration_mock) == [
            {"scope": "shell", "agent_id": "oa-int", "command": "ls"}
        ]

    def test_deny_raises_before_the_tool_runs(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:no-rm"))
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guarded = guard_tool(run_shell, Guard(integration_mock.base_url))

        with pytest.raises(AgentGuardDenied, match="rule:no-rm"):
            _call(guarded, json.dumps({"command": "rm -rf /"}))
        assert ran == []

    def test_approval_raises_before_the_tool_runs(self, integration_mock):
        integration_mock.set_default_check(require_approval(approval_id="ap_oa1"))
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guarded = guard_tool(run_shell, Guard(integration_mock.base_url))

        with pytest.raises(AgentGuardApprovalRequired) as ei:
            _call(guarded, json.dumps({"command": "terraform apply"}))
        assert ei.value.approval_id == "ap_oa1"
        assert ran == []

    def test_filesystem_scope_and_action_are_inferred(self, integration_mock):
        integration_mock.set_default_check(allow())
        ran: List[str] = []
        _, read_file = _make_tools(ran)
        guarded = guard_tool(read_file, Guard(integration_mock.base_url))

        _call(guarded, json.dumps({"path": "/etc/hosts"}))

        body = _check_bodies(integration_mock)[0]
        assert body["scope"] == "filesystem"
        assert body["path"] == "/etc/hosts"
        assert body["action"] == "read"

    def test_guarded_tool_keeps_the_sdk_shape(self, integration_mock):
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guarded = guard_tool(run_shell, Guard(integration_mock.base_url))

        assert isinstance(guarded, FunctionTool)
        assert guarded.name == run_shell.name
        assert guarded.description == run_shell.description
        assert guarded.params_json_schema == run_shell.params_json_schema
        assert guarded.strict_json_schema == run_shell.strict_json_schema

    def test_original_tool_is_left_ungated(self, integration_mock):
        integration_mock.set_default_check(deny())
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guard_tool(run_shell, Guard(integration_mock.base_url))

        _call(run_shell, json.dumps({"command": "ls"}))

        assert ran == ["ls"]
        assert integration_mock.requests_to("/v1/check") == []

    def test_a_copy_of_the_guarded_tool_is_still_gated(self, integration_mock):
        # The SDK copies FunctionTools in places (FunctionTool.__copy__);
        # the gate must survive that.
        integration_mock.set_default_check(deny())
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guarded = copy.copy(guard_tool(run_shell, Guard(integration_mock.base_url)))

        with pytest.raises(AgentGuardDenied):
            _call(guarded, json.dumps({"command": "ls"}))
        assert ran == []

    def test_invalid_json_is_checked_then_rejected_by_the_sdk(self, integration_mock):
        integration_mock.set_default_check(allow())
        ran: List[str] = []
        run_shell, _ = _make_tools(ran)
        guarded = guard_tool(run_shell, Guard(integration_mock.base_url))

        out = _call(guarded, "rm -rf / {not json")

        # The gate saw the raw string as a command ...
        assert _check_bodies(integration_mock)[0]["command"] == "rm -rf / {not json"
        # ... and the SDK's own validation, behind the gate, refused to run it
        # and returned its failure_error_function text for the model.
        assert ran == []
        assert "error occurred" in str(out).lower()

    def test_tool_errors_still_use_the_sdk_failure_handler(self, integration_mock):
        integration_mock.set_default_check(allow())

        @function_tool
        def flaky(command: str) -> str:
            """Always fails."""
            raise RuntimeError("boom")

        guarded = guard_tool(flaky, Guard(integration_mock.base_url))

        out = _call(guarded, json.dumps({"command": "x"}))

        assert "error occurred" in str(out).lower()

    def test_guard_tools_gates_each_tool(self, integration_mock):
        integration_mock.enqueue_check(allow(), deny())
        ran: List[str] = []
        guarded = guard_tools(_make_tools(ran), Guard(integration_mock.base_url))

        _call(guarded[0], json.dumps({"command": "ls"}))
        with pytest.raises(AgentGuardDenied):
            _call(guarded[1], json.dumps({"path": "/etc/shadow"}))

        assert ran == ["ls"]
        assert len(integration_mock.requests_to("/v1/check")) == 2
