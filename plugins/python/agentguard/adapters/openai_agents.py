"""
AgentGuard OpenAI Agents SDK Adapter.

Gates the function tools of an OpenAI Agents SDK agent (PyPI
``openai-agents``, import name ``agents``) through AgentGuard policy
checks.

Usage
-----
    from agents import Agent, Runner, function_tool
    from agentguard import Guard
    from agentguard.adapters.openai_agents import guard_tools

    @function_tool
    def run_shell(command: str) -> str:
        ...

    guard = Guard("http://localhost:8080", agent_id="my-agent")
    agent = Agent(name="ops", tools=guard_tools([run_shell], guard))
    result = await Runner.run(agent, "clean up the build directory")

Two entry points
----------------
``guard_tool`` / ``guard_tools`` (the enforcement point)
    Return a copy of each ``FunctionTool`` whose ``on_invoke_tool`` runs
    ``Guard.check`` first and calls the original invoker only on ALLOW.
    DENY raises :class:`AgentGuardDenied` and REQUIRE_APPROVAL raises
    :class:`AgentGuardApprovalRequired` before the tool body runs.

    The gate sits OUTSIDE the SDK's own error handling (the tool's
    ``failure_error_function``), so the deny is never turned into a tool
    output: the exception ends the run, and ``Runner.run`` raises it to
    the caller. The raised object subclasses both the AgentGuard
    exception and ``agents.exceptions.AgentsException``; the runner
    re-raises ``AgentsException`` as-is instead of wrapping it in
    ``UserError``, so ``except AgentGuardDenied`` (or ``except
    PermissionError``) around ``Runner.run`` catches it. The model sees
    nothing: the run is over.

``agentguard_tool_guardrail`` (the model-visible option)
    Returns an SDK tool input guardrail. On DENY / REQUIRE_APPROVAL it
    rejects the call with ``ToolGuardrailFunctionOutput.reject_content``:
    the tool does not run, the model receives the AgentGuard message as
    the tool result, and the run continues. With
    ``raise_on_block=True`` it trips the guardrail instead, and
    ``Runner.run`` raises ``ToolInputGuardrailTripwireTriggered``.
    Guardrails only run inside the SDK runner (a direct
    ``on_invoke_tool`` call skips them), so ``guard_tool`` stays the
    hard gate; the guardrail is for agents that should see the reason
    and pick another action.

Why not rely on the SDK's error handling
----------------------------------------
Exceptions raised INSIDE a tool built with ``@function_tool`` go to the
tool's ``failure_error_function``. On openai-agents 0.23 its default
returns a fixed "An error occurred while running the tool. Please try
again." string (older releases appended the error text). Either way the
model is invited to retry, and a deny that reads as a transient failure
is the wrong signal. Gating outside that handler makes the outcome
independent of how the tool was configured: a denied call never reaches
the tool body.

Scope inference and parameter extraction
----------------------------------------
The SDK hands ``on_invoke_tool`` the model's arguments as a JSON string.
The adapter parses it and reduces it to ``Guard.check`` keywords with
the shared ``extract_check_params`` (command/cmd, url + domain,
path/file_path + an action inferred from the tool-name verb,
session_id, est_cost). Arguments that are not valid JSON are gated as a
raw command string; the original string still goes to the tool, whose
own validation rejects it.

``guard_tool`` first projects the arguments onto the properties the
tool's ``params_json_schema`` declares (unless the schema allows
additional properties): the SDK's params model drops undeclared keys,
so the check sees exactly what the tool receives. Two alias keys for
one parameter with different values (``{"command": "ls", "cmd": "rm -rf
/"}``) are denied outright, without a server call, in both entry
points: the adapter cannot know which one the tool reads.

Scope is fixed when ``scope=`` is passed. Otherwise it is inferred, in
order: a url/domain argument means ``network``, a path/file_path
argument means ``filesystem``, then keywords in the tool name and
description (as in the CrewAI adapter), then ``shell``.

Lazy framework import
---------------------
The module never imports ``agents`` at load time, so ``pip install
agentguardproxy`` keeps working without the extra. ``guard_tool`` works
on any FunctionTool-shaped object and only touches the SDK to build its
exception classes; ``agentguard_tool_guardrail`` imports the SDK when
called and raises an install hint if it is missing.
"""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any, FrozenSet, Iterable, List, Optional, Tuple

from agentguard import (
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    CheckResult,
    Guard,
)
from agentguard.adapters._common import (
    ConflictingToolInput,
    check_alias_conflicts,
    conflict_denial,
    extract_check_params,
)


# openai-agents 0.3.3 is the first release with tool input guardrails
# (agents.tool_guardrails) and ToolContext.tool_arguments, both of which
# agentguard_tool_guardrail needs. guard_tool itself only needs
# FunctionTool.on_invoke_tool, which is older, but one floor for the whole
# adapter keeps the support statement simple.
_MIN_OPENAI_AGENTS = (0, 3, 3)
_MIN_OPENAI_AGENTS_STR = ".".join(str(p) for p in _MIN_OPENAI_AGENTS)

_INSTALL_HINT = "Install it with `pip install 'agentguardproxy[openai-agents]'`."


def _parse_version(found: str) -> Tuple[int, ...]:
    parts = []
    for piece in found.split(".")[:3]:
        digits = ""
        for ch in piece:
            if not ch.isdigit():
                break
            digits += ch
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _require_supported_sdk() -> None:
    """Refuse openai-agents releases older than the verified floor.

    A no-op when the SDK is not installed: guard_tool then only sees
    FunctionTool-shaped objects the caller built, and the guardrail
    builder raises its own install hint.
    """
    try:
        from importlib.metadata import version

        found = version("openai-agents")
    except Exception:
        return
    if _parse_version(found) < _MIN_OPENAI_AGENTS:
        raise ImportError(
            f"agentguard OpenAI Agents adapter requires "
            f"openai-agents>={_MIN_OPENAI_AGENTS_STR} (found {found}). "
            "Older releases lack the tool guardrail API the adapter is "
            "tested against. Upgrade with "
            f"`pip install -U 'openai-agents>={_MIN_OPENAI_AGENTS_STR},<1.0'`."
        )


# ---------------------------------------------------------------------------
# Exception classes.
#
# The SDK runner wraps any tool exception that is not an AgentsException in
# UserError("Error running tool ..."), which hides the AgentGuard type behind
# __cause__. Raising a subclass of both the AgentGuard exception and
# AgentsException makes the runner re-raise it unchanged, so callers catch
# AgentGuardDenied / AgentGuardApprovalRequired (both PermissionError) around
# Runner.run directly. Built lazily and cached; without the SDK installed the
# plain AgentGuard classes are used.
# ---------------------------------------------------------------------------

_EXC_CLASSES: Optional[Tuple[type, type]] = None


def _exception_classes() -> Tuple[type, type]:
    global _EXC_CLASSES
    if _EXC_CLASSES is not None:
        return _EXC_CLASSES
    try:
        from agents.exceptions import AgentsException  # type: ignore[import-not-found]
    except ImportError:
        return AgentGuardDenied, AgentGuardApprovalRequired

    class OpenAIAgentsDenied(AgentGuardDenied, AgentsException):  # type: ignore[misc, valid-type]
        """AgentGuardDenied that the Agents SDK runner re-raises unchanged."""

        def __init__(self, message: str, result: Optional[CheckResult] = None):
            super().__init__(message, result)
            # PermissionError's C-level __init__ does not chain to
            # AgentsException.__init__, which is where run_data is set.
            self.run_data = None

    class OpenAIAgentsApprovalRequired(  # type: ignore[misc, valid-type]
        AgentGuardApprovalRequired, AgentsException
    ):
        """AgentGuardApprovalRequired that the Agents SDK runner re-raises unchanged."""

        def __init__(
            self,
            message: str,
            result: Optional[CheckResult] = None,
            approval_id: str = "",
            approval_url: str = "",
        ):
            super().__init__(message, result, approval_id, approval_url)
            self.run_data = None

    # Readable names in tracebacks instead of "_exception_classes.<locals>...".
    for cls in (OpenAIAgentsDenied, OpenAIAgentsApprovalRequired):
        cls.__qualname__ = cls.__name__
    _EXC_CLASSES = (OpenAIAgentsDenied, OpenAIAgentsApprovalRequired)
    return _EXC_CLASSES


# ---------------------------------------------------------------------------
# Input parsing, scope inference, and the shared gate.
# ---------------------------------------------------------------------------


def _parse_tool_input(input_json: Any) -> Any:
    """Decode the model's JSON argument string for the policy check.

    Returns the decoded value, ``{}`` for an empty input, or the raw
    string when it is not valid JSON (``extract_check_params`` then gates
    it as a command, the same as a bare-string input elsewhere).
    """
    if input_json is None:
        return {}
    if not isinstance(input_json, (str, bytes, bytearray)):
        return input_json
    if not input_json:
        return {}
    try:
        return json.loads(input_json)
    except ValueError:
        if isinstance(input_json, (bytes, bytearray)):
            return input_json.decode("utf-8", errors="replace")
        return input_json


_NETWORK_KEYWORDS = ("http", "api", "fetch", "request", "url", "web")
_FILESYSTEM_KEYWORDS = ("file", "read", "write", "directory", "path")
_BROWSER_KEYWORDS = ("browser", "navigate", "click", "page")


def _infer_scope(tool_input: Any, name: str, description: str) -> str:
    """Infer the policy scope from the arguments, then the tool metadata.

    Mirrors the CrewAI adapter's inference so the same tool lands in the
    same scope under either framework.
    """
    if isinstance(tool_input, dict):
        if tool_input.get("url") or tool_input.get("domain"):
            return "network"
        if tool_input.get("path") or tool_input.get("file_path"):
            return "filesystem"
    combined = f"{name} {description}".lower()
    if any(kw in combined for kw in _NETWORK_KEYWORDS):
        return "network"
    if any(kw in combined for kw in _FILESYSTEM_KEYWORDS):
        return "filesystem"
    if any(kw in combined for kw in _BROWSER_KEYWORDS):
        return "browser"
    return "shell"


def _denied_message(result: CheckResult) -> str:
    return f"[AgentGuard] Action denied.\nReason: {result.reason}"


def _approval_message(result: CheckResult) -> str:
    return (
        f"[AgentGuard] Action requires approval. "
        f"Approve at: {result.approval_url}\n"
        f"Reason: {result.reason}"
    )


def _schema_keys(schema: Any) -> Optional[FrozenSet[str]]:
    """The argument names a tool's JSON schema declares, or None.

    None means "do not project": the schema has no ``properties`` map,
    or it explicitly allows additional properties, so the tool may read
    keys the schema does not list.
    """
    if not isinstance(schema, dict):
        return None
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    extra = schema.get("additionalProperties")
    if extra is True or isinstance(extra, dict):
        return None
    return frozenset(k for k in properties if isinstance(k, str))


async def _check(
    guard: Guard,
    scope: Optional[str],
    name: str,
    description: str,
    input_json: Any,
    schema_keys: Optional[FrozenSet[str]] = None,
) -> CheckResult:
    """Run Guard.check for one tool call without blocking the event loop.

    Guard.check is a blocking urllib call; running it on the loop thread
    would stall every other task in the run (parallel tool calls,
    streaming) for the length of the round-trip.

    With ``schema_keys``, a dict input is first projected onto those
    keys: the SDK validates the arguments against the tool's params
    model, which drops undeclared keys, so the check must see exactly
    what the tool receives. Alias conflicts (command/cmd,
    path/file_path) are looked for BEFORE the projection and deny.
    """
    tool_input = _parse_tool_input(input_json)
    try:
        check_alias_conflicts(tool_input)
        if schema_keys is not None and isinstance(tool_input, dict):
            tool_input = {k: v for k, v in tool_input.items() if k in schema_keys}
        params = extract_check_params(tool_input, name)
    except ConflictingToolInput as e:
        return conflict_denial(e)
    resolved_scope = scope or _infer_scope(tool_input, name, description)
    return await asyncio.to_thread(guard.check, resolved_scope, **params)


def _raise_if_blocked(result: CheckResult) -> None:
    if result.allowed:
        return
    denied_cls, approval_cls = _exception_classes()
    if result.needs_approval:
        raise approval_cls(
            _approval_message(result),
            result=result,
            approval_id=result.approval_id,
            approval_url=result.approval_url,
        )
    # DENY, and any decision this SDK version does not know, fail closed.
    raise denied_cls(_denied_message(result), result=result)


class _GatedInvoker:
    """Replacement ``on_invoke_tool``: gate first, then the original invoker."""

    def __init__(
        self,
        inner: Any,
        guard: Guard,
        scope: Optional[str],
        name: str,
        description: str,
        schema_keys: Optional[FrozenSet[str]] = None,
    ) -> None:
        self._inner = inner
        self._guard = guard
        self._scope = scope
        self._name = name
        self._description = description
        self._schema_keys = schema_keys

    async def __call__(self, ctx: Any, input_json: str) -> Any:
        result = await _check(
            self._guard,
            self._scope,
            self._name,
            self._description,
            input_json,
            self._schema_keys,
        )
        _raise_if_blocked(result)
        return await self._inner(ctx, input_json)

    def __repr__(self) -> str:
        return f"<AgentGuard gated invoker for {self._name!r}>"


def _is_function_tool(tool: Any) -> bool:
    return (
        isinstance(getattr(tool, "name", None), str)
        and isinstance(getattr(tool, "params_json_schema", None), dict)
        and callable(getattr(tool, "on_invoke_tool", None))
    )


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def guard_tool(tool: Any, guard: Guard, scope: Optional[str] = None) -> Any:
    """Return a copy of ``tool`` whose every call is gated by AgentGuard.

    Args:
        tool: An ``agents.FunctionTool`` (what ``@function_tool`` and
            ``Agent.as_tool`` return). The caller's object is not changed.
        guard: The :class:`Guard` client to check with.
        scope: Policy scope for every call. ``None`` infers it per call
            from the arguments and the tool's name and description.

    Returns:
        A new ``FunctionTool`` with the same name, schema and settings.

    Raises:
        TypeError: ``tool`` is not a FunctionTool. Hosted tools
            (WebSearchTool, FileSearchTool, ...) run on OpenAI's servers
            and cannot be gated here.
        ImportError: the installed openai-agents is older than the
            supported floor.
    """
    _require_supported_sdk()
    if not _is_function_tool(tool):
        raise TypeError(
            "guard_tool expects an agents.FunctionTool "
            f"(got {type(tool).__name__}). Decorate plain functions with "
            "@function_tool first. Hosted tools such as WebSearchTool run on "
            "OpenAI's servers and cannot be gated by AgentGuard; MCP servers "
            "can be gated with agentguard-mcp-gateway."
        )
    # copy.copy, not dataclasses.replace: FunctionTool.__copy__ (0.15+)
    # rebinds the SDK's own invoker to the copy, so the tool's failure
    # handling keeps resolving against the copy's settings.
    guarded = copy.copy(tool)
    description = getattr(tool, "description", "")
    guarded.on_invoke_tool = _GatedInvoker(
        guarded.on_invoke_tool,
        guard,
        scope,
        tool.name,
        description if isinstance(description, str) else "",
        _schema_keys(tool.params_json_schema),
    )
    return guarded


def guard_tools(
    tools: Iterable[Any], guard: Guard, scope: Optional[str] = None
) -> List[Any]:
    """Gate every tool in ``tools`` with one shared :class:`Guard`.

    Raises TypeError on the first tool that is not a FunctionTool rather
    than passing it through ungated.
    """
    return [guard_tool(tool, guard, scope=scope) for tool in tools]


def agentguard_tool_guardrail(
    guard: Guard,
    scope: Optional[str] = None,
    raise_on_block: bool = False,
    name: str = "agentguard",
) -> Any:
    """Build an SDK tool input guardrail that checks each call with AgentGuard.

    Attach it with ``@function_tool(tool_input_guardrails=[...])``
    (openai-agents 0.7.0+) or by setting ``FunctionTool.tool_input_guardrails``
    (every supported release). On DENY /
    REQUIRE_APPROVAL the tool does not run and, by default, the model gets
    the AgentGuard message as the tool result and the run continues. With
    ``raise_on_block=True`` the guardrail trips and ``Runner.run`` raises
    ``ToolInputGuardrailTripwireTriggered``. Either way ``output_info`` on
    the guardrail result carries the :class:`CheckResult`.

    The guardrail sees the tool name and arguments but not its
    description, so scope inference uses arguments and name only; pass
    ``scope=`` to pin it.
    """
    _require_supported_sdk()
    try:
        from agents import (  # type: ignore[import-not-found]
            ToolGuardrailFunctionOutput,
            ToolInputGuardrail,
        )
    except ImportError as e:
        raise ImportError(
            "agentguard OpenAI Agents adapter requires the `openai-agents` "
            f"package. {_INSTALL_HINT} (underlying import error: {e!r})"
        ) from e

    async def _agentguard_guardrail(data: Any) -> Any:
        ctx = data.context
        tool_name = getattr(ctx, "tool_name", "") or ""
        result = await _check(
            guard, scope, tool_name, "", getattr(ctx, "tool_arguments", "")
        )
        if result.allowed:
            return ToolGuardrailFunctionOutput.allow(output_info=result)
        if raise_on_block:
            return ToolGuardrailFunctionOutput.raise_exception(output_info=result)
        message = (
            _approval_message(result)
            if result.needs_approval
            else _denied_message(result)
        )
        return ToolGuardrailFunctionOutput.reject_content(message, output_info=result)

    return ToolInputGuardrail(guardrail_function=_agentguard_guardrail, name=name)
