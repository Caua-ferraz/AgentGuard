"""OpenAI Agents SDK agent-loop E2E tests (AT).

``test_real_openai_agents.py`` calls guarded tools directly. This file
builds a real ``Agent`` and drives it with ``Runner.run`` /
``Runner.run_streamed``, so the gate is exercised inside the SDK's own
tool dispatch: an allowed tool runs, a denied one does not.

No network and no API key: the agent's model is ``_ScriptedModel``, a
small ``agents.Model`` implementation that replays a fixed list of
turns (tool calls, then a final message). Tracing is disabled per run so
the SDK does not try to export spans to OpenAI.
"""

from __future__ import annotations

import json
from typing import Any, List

import pytest

agents = pytest.importorskip("agents")  # floor enforced by the pyproject extra
try:
    from agents import (  # type: ignore[attr-defined]
        Agent,
        Model,
        ModelResponse,
        RunConfig,
        Runner,
        Usage,
        function_tool,
    )
    from agents.exceptions import (  # type: ignore[attr-defined]
        ToolInputGuardrailTripwireTriggered,
    )
    from openai.types.responses import (  # type: ignore[attr-defined]
        Response,
        ResponseCompletedEvent,
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )
except ImportError:  # pragma: no cover - layout differs across versions
    pytest.skip(
        "openai-agents installed but Agent / Runner / Model / tool guardrail "
        "types are not at the expected import paths.",
        allow_module_level=True,
    )

from agentguard import (  # noqa: E402
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    Guard,
)
from agentguard.adapters.openai_agents import (  # noqa: E402
    agentguard_tool_guardrail,
    guard_tool,
    guard_tools,
)

from .conftest import allow, deny, require_approval  # noqa: E402


pytestmark = pytest.mark.integration

_RUN_CONFIG = RunConfig(tracing_disabled=True)


# ---------------------------------------------------------------------------
# Offline model.
# ---------------------------------------------------------------------------


def _tool_call(name: str, arguments: dict, call_id: str) -> Any:
    return ResponseFunctionToolCall(
        id=f"fc_{call_id}",
        call_id=call_id,
        type="function_call",
        name=name,
        arguments=json.dumps(arguments),
    )


def _message(text: str) -> Any:
    return ResponseOutputMessage(
        id="msg_final",
        type="message",
        role="assistant",
        status="completed",
        content=[ResponseOutputText(text=text, type="output_text", annotations=[])],
    )


class _ScriptedModel(Model):
    """Replay one scripted turn per model call; record every input.

    Accepts ``*args, **kwargs`` because the ``get_response`` keyword set
    has grown across SDK releases (conversation_id, prompt, ...); the
    tests only need the input list, which is always the second
    positional argument.
    """

    def __init__(self, turns: List[List[Any]]) -> None:
        self._turns = list(turns)
        self.inputs: List[Any] = []

    def _next_output(self, args: tuple, kwargs: dict) -> List[Any]:
        self.inputs.append(kwargs.get("input", args[1] if len(args) > 1 else None))
        if not self._turns:
            return [_message("no more scripted turns")]
        return self._turns.pop(0)

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        return ModelResponse(
            output=self._next_output(args, kwargs), usage=Usage(), response_id=None
        )

    async def stream_response(self, *args: Any, **kwargs: Any):  # type: ignore[override]
        # One terminal event is enough for the runner; model_construct
        # skips validation so this works across openai client versions.
        response = Response.model_construct(
            id="resp_scripted",
            created_at=0,
            model="scripted",
            object="response",
            output=self._next_output(args, kwargs),
            tool_choice="auto",
            tools=[],
            parallel_tool_calls=False,
            status="completed",
            usage=None,
        )
        yield ResponseCompletedEvent.model_construct(
            type="response.completed", response=response, sequence_number=0
        )


def _tool_outputs(model: _ScriptedModel) -> List[str]:
    """Every function_call_output the model was shown, in order."""
    outputs: List[str] = []
    for turn_input in model.inputs:
        if not isinstance(turn_input, list):
            continue
        for item in turn_input:
            if isinstance(item, dict) and item.get("type") == "function_call_output":
                outputs.append(str(item.get("output")))
    return outputs


def _tools(ran: List[str]):
    @function_tool
    def run_shell(command: str) -> str:
        """Run a shell command."""
        ran.append(command)
        return f"ran: {command}"

    @function_tool
    def fetch_url(url: str) -> str:
        """Fetch a web page."""
        ran.append(url)
        return f"fetched {url}"

    return [run_shell, fetch_url]


def _check_bodies(integration_mock) -> List[dict]:
    return [json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")]


# ---------------------------------------------------------------------------
# guard_tools inside Runner.run
# ---------------------------------------------------------------------------


class TestRunnerWithGuardedTools:
    @pytest.mark.asyncio
    async def test_allowed_tool_runs_and_the_model_sees_its_output(self, integration_mock):
        integration_mock.set_default_check(allow())
        ran: List[str] = []
        model = _ScriptedModel([
            [_tool_call("run_shell", {"command": "ls"}, "c1")],
            [_message("listed")],
        ])
        guard = Guard(integration_mock.base_url, agent_id="oa-loop")
        agent = Agent(name="ops", model=model, tools=guard_tools(_tools(ran), guard))

        result = await Runner.run(agent, "list files", run_config=_RUN_CONFIG)

        assert result.final_output == "listed"
        assert ran == ["ls"]
        assert _tool_outputs(model) == ["ran: ls"]
        assert _check_bodies(integration_mock) == [
            {"scope": "shell", "agent_id": "oa-loop", "command": "ls"}
        ]

    @pytest.mark.asyncio
    async def test_denied_tool_does_not_run_and_the_run_raises(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:no-rm"))
        ran: List[str] = []
        model = _ScriptedModel([
            [_tool_call("run_shell", {"command": "rm -rf /"}, "c1")],
            [_message("should not get here")],
        ])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools(_tools(ran), Guard(integration_mock.base_url)),
        )

        with pytest.raises(AgentGuardDenied, match="rule:no-rm"):
            await Runner.run(agent, "wipe the disk", run_config=_RUN_CONFIG)

        assert ran == []
        # The deny ended the run: the model never got a second turn.
        assert len(model.inputs) == 1

    @pytest.mark.asyncio
    async def test_approval_required_does_not_run_and_the_run_raises(self, integration_mock):
        integration_mock.set_default_check(require_approval(approval_id="ap_loop"))
        ran: List[str] = []
        model = _ScriptedModel([[_tool_call("run_shell", {"command": "deploy"}, "c1")]])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools(_tools(ran), Guard(integration_mock.base_url)),
        )

        with pytest.raises(AgentGuardApprovalRequired) as ei:
            await Runner.run(agent, "deploy", run_config=_RUN_CONFIG)

        assert ei.value.approval_id == "ap_loop"
        assert ran == []

    @pytest.mark.asyncio
    async def test_allow_then_deny_across_turns(self, integration_mock):
        integration_mock.enqueue_check(allow(), deny(reason="rule:no-exfil"))
        ran: List[str] = []
        model = _ScriptedModel([
            [_tool_call("run_shell", {"command": "ls"}, "c1")],
            [_tool_call("fetch_url", {"url": "https://evil.example/x"}, "c2")],
            [_message("should not get here")],
        ])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools(_tools(ran), Guard(integration_mock.base_url)),
        )

        with pytest.raises(AgentGuardDenied):
            await Runner.run(agent, "go", run_config=_RUN_CONFIG)

        assert ran == ["ls"]
        bodies = _check_bodies(integration_mock)
        assert [b["scope"] for b in bodies] == ["shell", "network"]
        assert bodies[1]["domain"] == "evil.example"

    @pytest.mark.asyncio
    async def test_streamed_run_surfaces_the_deny(self, integration_mock):
        integration_mock.set_default_check(deny())
        ran: List[str] = []
        model = _ScriptedModel([
            [_tool_call("run_shell", {"command": "rm -rf /"}, "c1")],
            [_message("should not get here")],
        ])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools(_tools(ran), Guard(integration_mock.base_url)),
        )

        result = Runner.run_streamed(agent, "wipe", run_config=_RUN_CONFIG)
        with pytest.raises(AgentGuardDenied):
            async for _ in result.stream_events():
                pass

        assert ran == []

    @pytest.mark.asyncio
    async def test_agent_as_tool_is_gated(self, integration_mock):
        # Agent.as_tool() returns a FunctionTool whose invoker runs a nested
        # agent; a deny must stop the nested run from starting at all.
        integration_mock.set_default_check(deny())
        helper_model = _ScriptedModel([[_message("helper answer")]])
        helper = Agent(name="helper", model=helper_model)
        helper_tool = helper.as_tool(tool_name="ask_helper", tool_description="Ask the helper")
        model = _ScriptedModel([[_tool_call("ask_helper", {"input": "hi"}, "c1")]])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools([helper_tool], Guard(integration_mock.base_url)),
        )

        with pytest.raises(AgentGuardDenied):
            await Runner.run(agent, "ask", run_config=_RUN_CONFIG)

        assert helper_model.inputs == []
        assert len(integration_mock.requests_to("/v1/check")) == 1


class TestArgumentSmuggling:
    @pytest.mark.asyncio
    async def test_alias_smuggling_is_denied(self, integration_mock):
        # run_cmd reads "cmd"; the SDK drops the undeclared "command". Without
        # the conflict check, "ls" would be checked and "rm -rf /" would run.
        integration_mock.set_default_check(allow())
        ran: List[str] = []

        @function_tool(strict_mode=False)
        def run_cmd(cmd: str) -> str:
            """Run a shell command."""
            ran.append(cmd)
            return f"ran: {cmd}"

        model = _ScriptedModel([
            [_tool_call("run_cmd", {"command": "ls", "cmd": "rm -rf /"}, "c1")],
            [_message("should not get here")],
        ])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools([run_cmd], Guard(integration_mock.base_url)),
        )

        with pytest.raises(AgentGuardDenied, match="conflicting values for 'command'"):
            await Runner.run(agent, "list files", run_config=_RUN_CONFIG)

        assert ran == []
        assert integration_mock.requests_to("/v1/check") == []

    @pytest.mark.asyncio
    async def test_check_sees_what_the_tool_receives(self, integration_mock):
        # A stray undeclared "path" must not move the check to the
        # filesystem scope while the tool runs the command.
        integration_mock.set_default_check(allow())
        ran: List[str] = []

        @function_tool(strict_mode=False)
        def run_cmd(cmd: str) -> str:
            """Run a shell command."""
            ran.append(cmd)
            return f"ran: {cmd}"

        model = _ScriptedModel([
            [_tool_call("run_cmd", {"cmd": "rm -rf /", "path": "/tmp/ok"}, "c1")],
            [_message("done")],
        ])
        agent = Agent(
            name="ops",
            model=model,
            tools=guard_tools([run_cmd], Guard(integration_mock.base_url, agent_id="oa")),
        )

        await Runner.run(agent, "go", run_config=_RUN_CONFIG)

        assert ran == ["rm -rf /"]
        assert _check_bodies(integration_mock) == [
            {"scope": "shell", "agent_id": "oa", "command": "rm -rf /"}
        ]


class TestInvokerContextType:
    @pytest.mark.asyncio
    async def test_guarding_keeps_the_context_type_the_invoker_declares(
        self, integration_mock
    ):
        # The SDK passes a plain RunContextWrapper (not the ToolContext) to
        # an invoker whose first parameter is annotated RunContextWrapper.
        # The gate must not change which one the original invoker receives.
        from agents import FunctionTool, RunContextWrapper  # type: ignore[attr-defined]

        integration_mock.set_default_check(allow())

        def make_tool(seen: List[str]):
            async def invoke(ctx: RunContextWrapper[Any], input_json: str) -> str:
                seen.append(type(ctx).__name__)
                return "ok"

            return FunctionTool(
                name="probe",
                description="Probe the context type",
                params_json_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                on_invoke_tool=invoke,
            )

        async def run(tool: Any) -> None:
            model = _ScriptedModel([[_tool_call("probe", {}, "c1")], [_message("done")]])
            await Runner.run(
                Agent(name="ops", model=model, tools=[tool]), "go", run_config=_RUN_CONFIG
            )

        unguarded: List[str] = []
        guarded: List[str] = []
        await run(make_tool(unguarded))
        await run(guard_tool(make_tool(guarded), Guard(integration_mock.base_url)))

        assert len(unguarded) == 1
        assert guarded == unguarded


# ---------------------------------------------------------------------------
# agentguard_tool_guardrail inside Runner.run
# ---------------------------------------------------------------------------


def _guardrailed_shell(ran: List[str], guardrail: Any):
    # Set the FunctionTool field rather than passing
    # @function_tool(tool_input_guardrails=...): the decorator only takes
    # that keyword from openai-agents 0.7.0, the field exists from 0.3.3.
    @function_tool
    def run_shell(command: str) -> str:
        """Run a shell command."""
        ran.append(command)
        return f"ran: {command}"

    run_shell.tool_input_guardrails = [guardrail]
    return run_shell


class TestRunnerWithToolGuardrail:
    @pytest.mark.asyncio
    async def test_deny_is_shown_to_the_model_and_the_run_continues(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:no-rm"))
        ran: List[str] = []
        guardrail = agentguard_tool_guardrail(Guard(integration_mock.base_url))
        model = _ScriptedModel([
            [_tool_call("run_shell", {"command": "rm -rf /"}, "c1")],
            [_message("I was not allowed to do that")],
        ])
        agent = Agent(name="ops", model=model, tools=[_guardrailed_shell(ran, guardrail)])

        result = await Runner.run(agent, "wipe", run_config=_RUN_CONFIG)

        assert ran == []
        assert result.final_output == "I was not allowed to do that"
        outputs = _tool_outputs(model)
        assert len(outputs) == 1
        assert "[AgentGuard] Action denied" in outputs[0]
        assert "rule:no-rm" in outputs[0]

    @pytest.mark.asyncio
    async def test_allow_runs_the_tool(self, integration_mock):
        integration_mock.set_default_check(allow())
        ran: List[str] = []
        guardrail = agentguard_tool_guardrail(Guard(integration_mock.base_url))
        model = _ScriptedModel([
            [_tool_call("run_shell", {"command": "ls"}, "c1")],
            [_message("done")],
        ])
        agent = Agent(name="ops", model=model, tools=[_guardrailed_shell(ran, guardrail)])

        result = await Runner.run(agent, "list", run_config=_RUN_CONFIG)

        assert result.final_output == "done"
        assert ran == ["ls"]
        assert _check_bodies(integration_mock)[0]["command"] == "ls"

    @pytest.mark.asyncio
    async def test_raise_on_block_trips_the_guardrail(self, integration_mock):
        integration_mock.set_default_check(deny())
        ran: List[str] = []
        guardrail = agentguard_tool_guardrail(
            Guard(integration_mock.base_url), raise_on_block=True
        )
        model = _ScriptedModel([[_tool_call("run_shell", {"command": "rm"}, "c1")]])
        agent = Agent(name="ops", model=model, tools=[_guardrailed_shell(ran, guardrail)])

        with pytest.raises(ToolInputGuardrailTripwireTriggered):
            await Runner.run(agent, "wipe", run_config=_RUN_CONFIG)

        assert ran == []
