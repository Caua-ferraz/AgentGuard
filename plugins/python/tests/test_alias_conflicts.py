"""Alias-key smuggling: two names for one check parameter must not split.

``extract_check_params`` reads ``command`` or ``cmd`` (and ``path`` or
``file_path``). A model that sends both, with different values, could
otherwise have one checked and the other executed:
``{"command": "ls", "cmd": "rm -rf /"}`` to a tool whose parameter is
``cmd``. The shared extractor raises ConflictingToolInput, and every
adapter that uses it turns that into a DENY without running the tool
and without asking the server.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, List

import pytest

from agentguard import AgentGuardDenied, Guard
from agentguard.adapters._common import (
    ConflictingToolInput,
    conflict_denial,
    extract_check_params,
)
from tests.conftest import MockAgentGuardHandler


SMUGGLE = {"command": "ls", "cmd": "rm -rf /"}


def _check_requests() -> List[dict]:
    return [r for r in MockAgentGuardHandler.request_log if r["path"] == "/v1/check"]


# ---------------------------------------------------------------------------
# The shared extractor
# ---------------------------------------------------------------------------


class TestExtractCheckParams:
    def test_conflicting_command_aliases_raise(self):
        with pytest.raises(ConflictingToolInput) as ei:
            extract_check_params(SMUGGLE, "run_shell")
        assert ei.value.param == "command"
        assert ei.value.keys == ("command", "cmd")

    def test_conflicting_path_aliases_raise(self):
        with pytest.raises(ConflictingToolInput) as ei:
            extract_check_params(
                {"path": "/tmp/ok", "file_path": "/etc/shadow"}, "read_file"
            )
        assert ei.value.param == "path"

    def test_equal_aliases_are_not_a_conflict(self):
        params = extract_check_params({"command": "ls", "cmd": "ls"}, "run_shell")
        assert params == {"command": "ls"}

    def test_equal_but_differently_typed_aliases_conflict(self):
        # 1 == True in Python; the tool would still see different values.
        with pytest.raises(ConflictingToolInput):
            extract_check_params({"path": 1, "file_path": True})

    def test_single_alias_is_used(self):
        assert extract_check_params({"cmd": "rm -rf /"}) == {"command": "rm -rf /"}
        assert extract_check_params({"file_path": "/x"}, "read_file") == {
            "path": "/x",
            "action": "read",
        }

    def test_string_input_is_not_checked_for_aliases(self):
        assert extract_check_params("command cmd") == {"command": "command cmd"}

    def test_conflict_denial_is_a_deny(self):
        result = conflict_denial(ConflictingToolInput("command", ("command", "cmd")))
        assert result.denied
        assert "conflicting values for 'command'" in result.reason


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------


class _FakeCrewAITool:
    def __init__(self) -> None:
        self.name = "run_shell"
        self.description = ""
        self.calls: list = []

    def _run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return "ran"

    def run(self, *args, **kwargs):
        return self._run(*args, **kwargs)

    def invoke(self, input, config=None, **kwargs):  # noqa: A002
        self.calls.append(input)
        return "ran"


class TestCrewAI:
    def test_smuggled_alias_is_denied_without_a_server_call(self, mock_server):
        pytest.importorskip("crewai")
        from agentguard.adapters.crewai import GuardedCrewTool

        tool = _FakeCrewAITool()
        gct = GuardedCrewTool(tool, guard=Guard(mock_server), scope="shell")

        with pytest.raises(AgentGuardDenied, match="conflicting values for 'command'"):
            gct.invoke(dict(SMUGGLE))
        with pytest.raises(AgentGuardDenied):
            gct._run(**SMUGGLE)

        assert tool.calls == []
        assert _check_requests() == []


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------


class TestLangChain:
    def test_smuggled_alias_is_denied_without_a_server_call(self, mock_server):
        pytest.importorskip("langchain_core", minversion="0.1")
        from langchain_core.tools import StructuredTool

        from agentguard.adapters.langchain import GuardedTool

        calls: list = []

        def run_shell(cmd: str) -> str:
            calls.append(cmd)
            return f"ran {cmd}"

        tool = StructuredTool.from_function(
            func=run_shell, name="run_shell", description="Run a command."
        )
        gt = GuardedTool(tool, Guard(mock_server), scope="shell")

        with pytest.raises(PermissionError, match="conflicting values for 'command'"):
            gt.invoke(dict(SMUGGLE))
        with pytest.raises(PermissionError):
            asyncio.run(gt.ainvoke(dict(SMUGGLE)))

        assert calls == []
        assert _check_requests() == []


# ---------------------------------------------------------------------------
# MCP server and Python gateway
# ---------------------------------------------------------------------------


class TestMCP:
    def test_server_denies_a_smuggled_alias(self, mock_server):
        from agentguard.adapters.mcp import GuardedMCPServer

        s = GuardedMCPServer(guard_url=mock_server)
        calls: list = []
        s.add_tool(
            "run_shell", "run", handler=lambda **kw: calls.append(kw), scope="shell"
        )

        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "run_shell", "arguments": dict(SMUGGLE)},
        })

        assert resp["result"]["isError"] is True
        text = resp["result"]["content"][0]["text"]
        assert "denied" in text.lower()
        assert "conflicting values for 'command'" in text
        assert calls == []
        assert _check_requests() == []

    def test_gateway_denies_a_smuggled_alias(self, mock_server):
        from agentguard.adapters.mcp import GuardedMCPGateway

        forwarded: list = []

        class _Upstream:
            def request(self, frame, timeout=30.0):
                forwarded.append(frame)
                if frame.get("method") == "tools/list":
                    return {"jsonrpc": "2.0", "id": frame.get("id"),
                            "result": {"tools": [{"name": "read_file"}]}}
                return {"jsonrpc": "2.0", "id": frame.get("id"), "result": {}}

            def close(self):
                pass

        gw = GuardedMCPGateway(upstream=["echo", "ignored"], guard=Guard(mock_server))
        gw._upstream.close()
        gw._upstream = _Upstream()

        resp = gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/ok", "file_path": "/etc/shadow"},
            },
        })

        assert resp["result"]["isError"] is True
        assert "conflicting values for 'path'" in resp["result"]["content"][0]["text"]
        assert all(f.get("method") != "tools/call" for f in forwarded)
        assert _check_requests() == []


# ---------------------------------------------------------------------------
# OpenAI Agents SDK (FunctionTool-shaped fake)
# ---------------------------------------------------------------------------


@dataclass
class _FakeFunctionTool:
    """FunctionTool stand-in whose invoker, like the SDK's, validates the
    JSON against the declared params and drops undeclared keys."""

    name: str = "run_shell"
    description: str = "Run a shell command"
    params_json_schema: dict = field(default_factory=lambda: {
        "type": "object",
        "properties": {"cmd": {"type": "string"}},
        "required": ["cmd"],
    })
    ran: List[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        ran = self.ran
        declared = set(self.params_json_schema.get("properties", {}))

        async def _invoke(ctx: Any, input_json: str) -> str:
            args = {k: v for k, v in json.loads(input_json).items() if k in declared}
            ran.append(args)
            return f"ran {args}"

        self.on_invoke_tool = _invoke


def _invoke(tool: Any, input_json: str) -> Any:
    return asyncio.run(tool.on_invoke_tool(None, input_json))


class TestOpenAIAgents:
    def test_smuggled_alias_is_denied_without_a_server_call(self, mock_server):
        from agentguard.adapters.openai_agents import guard_tool

        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, Guard(mock_server))

        with pytest.raises(AgentGuardDenied, match="conflicting values for 'command'"):
            _invoke(guarded, json.dumps(SMUGGLE))

        assert tool.ran == []
        assert _check_requests() == []

    def test_check_sees_only_the_declared_arguments(self, mock_server):
        # An undeclared key the SDK would drop must not steer the check:
        # here a stray "path" would otherwise move the call to the
        # filesystem scope and check /tmp instead of the command.
        from agentguard.adapters.openai_agents import guard_tool

        tool = _FakeFunctionTool()
        guarded = guard_tool(tool, Guard(mock_server, agent_id="oa"))

        _invoke(guarded, json.dumps({"cmd": "rm -rf /", "path": "/tmp/ok"}))

        body = json.loads(_check_requests()[0]["body"])
        assert body == {"scope": "shell", "agent_id": "oa", "command": "rm -rf /"}
        assert tool.ran == [{"cmd": "rm -rf /"}]

    def test_undeclared_alias_is_dropped_before_the_check(self, mock_server):
        # The tool reads "command"; a stray "cmd" never reaches it, but it
        # still conflicts and denies: the raw input is ambiguous.
        from agentguard.adapters.openai_agents import guard_tool

        tool = _FakeFunctionTool(params_json_schema={
            "type": "object", "properties": {"command": {"type": "string"}},
        })
        guarded = guard_tool(tool, Guard(mock_server))

        with pytest.raises(AgentGuardDenied):
            _invoke(guarded, json.dumps({"command": "ls", "cmd": "rm -rf /"}))
        assert tool.ran == []

    def test_schema_allowing_extra_keys_is_not_projected(self, mock_server):
        from agentguard.adapters.openai_agents import guard_tool

        tool = _FakeFunctionTool(params_json_schema={
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "additionalProperties": True,
        })
        guarded = guard_tool(tool, Guard(mock_server))

        _invoke(guarded, json.dumps({"cmd": "ls", "url": "https://example.com/"}))

        body = json.loads(_check_requests()[0]["body"])
        assert body["scope"] == "network"
        assert body["domain"] == "example.com"

    def test_guardrail_denies_a_smuggled_alias(self, mock_server):
        pytest.importorskip("agents")
        from types import SimpleNamespace

        from agentguard.adapters.openai_agents import agentguard_tool_guardrail

        guardrail = agentguard_tool_guardrail(Guard(mock_server))
        data = SimpleNamespace(
            context=SimpleNamespace(
                tool_name="run_shell", tool_arguments=json.dumps(SMUGGLE)
            ),
            agent=None,
        )
        out = asyncio.run(guardrail.guardrail_function(data))

        assert out.output_info.denied
        assert _check_requests() == []
