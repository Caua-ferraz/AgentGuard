"""
AgentGuard CrewAI Adapter (v0.5 hardened)

Wraps CrewAI tools so every invocation passes through AgentGuard policy checks.

Hardening summary (v0.5, R5 E3 / R5 E12 / T3 partial)
-----------------------------------------------------
CrewAI's modern tool surface (CrewAI >= 0.80, which inherits from
`langchain_core.runnables.Runnable`) exposes several call-equivalent entry
points. The v0.4.x adapter only intercepted `run` and `_run`, leaving
`invoke`, `ainvoke`, and `__call__` to fall through `__getattr__` to the
wrapped tool — silently bypassing policy enforcement.

This v0.5 adapter:

1. **Gates every invocation entry point.** The wrapper overrides
   `run`, `_run`, `arun`, `_arun`, `invoke`, `ainvoke`, and `__call__`,
   and each one consults the policy engine before forwarding.

2. **On DENY or REQUIRE_APPROVAL the wrapper raises `PermissionError`.**
   Returning a plain string (the v0.4.x behavior) was indistinguishable
   from a tool that legitimately produced an error message and let buggy
   agents continue. A typed exception is unmissable.

3. **Strict attribute allowlist.** `__getattr__` no longer proxies
   arbitrary attributes to the wrapped tool. Only the attributes in
   ``_ALLOWED_PASSTHROUGH`` (CrewAI / LangChain BaseTool metadata that
   the framework needs to read for tool registration / serialization)
   pass through. Everything else — including `func`, `coroutine`, the
   private `_tool` reference, and any future framework-added method —
   raises ``AttributeError`` with a security explanation.

4. **Composition, not subclass.** ``GuardedCrewTool`` HOLDS a CrewAI
   ``BaseTool`` instance via ``self._tool`` and never inherits from it.
   This is the safer default: subclassing would expose every parent
   method and silently let new upstream methods bypass enforcement.
   When CrewAI / LangChain runtime code introspects the wrapper via
   ``isinstance(x, BaseTool)``, the wrapper registers itself as a
   virtual subclass via ``BaseTool.register(GuardedCrewTool)`` (best
   effort — done lazily once the framework is importable).

5. **Lazy framework import.** No bare ``import crewai`` at module load,
   so ``pip install agentguardproxy`` (without the ``[crewai]`` extra)
   continues to work for users who only need the LangChain or browser
   adapters.

Modern API note (CrewAI >= 0.80)
--------------------------------
CrewAI tools derive from LangChain's `BaseTool` which inherits the
`Runnable` protocol: ``invoke(input, config=None, **kwargs)``,
``ainvoke(...)``, plus ``stream`` / ``batch`` for streaming chains.
CrewAI tools also support direct ``tool(input)`` invocation. Each path
must be gated. Streaming is rare on CrewAI tools (they typically return
synchronously); ``stream`` / ``batch`` are not gated by default — see the
``v0.6`` deferred issue in ``.audit/v05_decisions.md``.

Usage
-----
    from agentguard.adapters.crewai import GuardedCrewTool, guard_crew_tools

    # Wrap a single tool
    guarded = GuardedCrewTool(my_tool, guard_url="http://localhost:8080")

    # Wrap all tools for a crew
    tools = guard_crew_tools(
        tools=[tool_a, tool_b],
        guard_url="http://localhost:8080",
        agent_id="my-crew-agent",
    )
"""

import asyncio
from typing import Any, List, Optional

from agentguard import (
    DEFAULT_BASE_URL,
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    Guard,
)


# ---------------------------------------------------------------------------
# Allowlist for __getattr__ pass-through.
#
# Only the metadata attributes that CrewAI / LangChain BaseTool exposes for
# tool registration, serialization, and rendering are forwarded to the
# wrapped tool. Anything else — including private/internal attributes that
# could expose the unguarded callable — raises AttributeError.
#
# The allowlist intentionally excludes:
#   - func / coroutine     -> would expose the raw callable
#   - _tool                -> the wrapped instance itself (bypass)
#   - _run / _arun / run /
#     arun / invoke /
#     ainvoke / __call__   -> these are gated METHODS on the wrapper
#                             (defined on the class, not resolved via
#                             __getattr__), so they hit the gate. Adding
#                             them here would be a no-op but is omitted
#                             to keep the contract obvious.
#   - stream / batch       -> deferred (CrewAI tools rarely stream)
# ---------------------------------------------------------------------------

_ALLOWED_PASSTHROUGH = frozenset({
    "name",
    "description",
    "args_schema",
    "result_as_answer",
    "cache_function",
    "return_direct",
    "metadata",
    "tags",
})


class GuardedCrewTool:
    """Composition wrapper around a CrewAI ``BaseTool`` that enforces
    AgentGuard policy on every invocation entry point.

    Holds (does not subclass) the wrapped tool. All call-equivalent
    methods (``run``, ``_run``, ``arun``, ``_arun``, ``invoke``,
    ``ainvoke``, ``__call__``) gate via :meth:`Guard.check` before
    forwarding to the inner tool. On DENY or REQUIRE_APPROVAL, raises
    :class:`PermissionError` (specifically
    :class:`agentguard.AgentGuardDenied` /
    :class:`agentguard.AgentGuardApprovalRequired`). On ALLOW, forwards
    to the wrapped tool.
    """

    # Slots are intentionally absent — pydantic / dataclass introspection
    # in CrewAI may set additional attributes on its own tool instances,
    # and the test suite's fixtures rely on attribute discovery. The
    # security boundary is __getattr__, not __slots__.

    def __init__(
        self,
        tool: Any,
        guard: Optional[Guard] = None,
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "",
        scope: str = "shell",
    ):
        # Use object.__setattr__ in case a future change introduces a
        # custom __setattr__; today's class has no override but keeping
        # the construction explicit avoids surprise.
        object.__setattr__(self, "_tool", tool)
        object.__setattr__(
            self,
            "_guard",
            guard if guard is not None else Guard(guard_url, agent_id=agent_id),
        )
        object.__setattr__(self, "_scope", scope)

        # Preserve original tool metadata so CrewAI's tool registration /
        # rendering logic still sees the right name and description.
        object.__setattr__(self, "name", getattr(tool, "name", type(tool).__name__))
        object.__setattr__(self, "description", getattr(tool, "description", ""))
        if hasattr(tool, "args_schema"):
            object.__setattr__(self, "args_schema", tool.args_schema)

        # Best-effort virtual-subclass registration so framework-side
        # ``isinstance(x, BaseTool)`` checks succeed without us actually
        # inheriting the surface area. Lazy + try/except so the SDK
        # imports cleanly without crewai installed.
        _maybe_register_basetool_virtual_subclass()

    # ------------------------------------------------------------------
    # Scope inference and parameter extraction
    # ------------------------------------------------------------------

    def _infer_scope(self, tool_input: Any) -> str:
        """Infer scope from the tool input.

        Order of precedence:
          1. Runtime input inspection — if ``tool_input`` is a dict
             carrying a url/domain/path key, upgrade scope to
             network/filesystem.
          2. Keyword inference over ``name + description`` (preserved
             from v0.4.0 for backward compatibility).
          3. The explicitly configured scope (``self._scope``).
        """
        if isinstance(tool_input, dict):
            if tool_input.get("url") or tool_input.get("domain"):
                return "network"
            if tool_input.get("path") or tool_input.get("file_path"):
                return "filesystem"
        combined = f"{self.name} {self.description}".lower()
        if any(kw in combined for kw in ["http", "api", "fetch", "request", "url", "web"]):
            return "network"
        if any(kw in combined for kw in ["file", "read", "write", "directory", "path"]):
            return "filesystem"
        if any(kw in combined for kw in ["browser", "navigate", "click", "page"]):
            return "browser"
        return self._scope

    def _extract_check_params(self, tool_input: Any) -> dict:
        """Extract parameters for the policy check from tool input."""
        params: dict = {}
        if isinstance(tool_input, str):
            params["command"] = tool_input
        elif isinstance(tool_input, dict):
            if "command" in tool_input or "cmd" in tool_input:
                params["command"] = tool_input.get("command", tool_input.get("cmd", ""))
            if "url" in tool_input:
                params["url"] = tool_input["url"]
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(tool_input["url"])
                    if parsed.hostname:
                        params["domain"] = parsed.hostname
                except Exception:
                    pass
            if "path" in tool_input or "file_path" in tool_input:
                params["path"] = tool_input.get("path", tool_input.get("file_path", ""))
            if "session_id" in tool_input:
                params["session_id"] = tool_input["session_id"]
            if "est_cost" in tool_input:
                params["est_cost"] = tool_input["est_cost"]
        return params

    # ------------------------------------------------------------------
    # The single shared gate.
    # ------------------------------------------------------------------

    def _check_or_raise(self, tool_input: Any) -> None:
        """Run the policy check and raise on DENY / REQUIRE_APPROVAL.

        On ALLOW, returns silently (caller forwards). Any non-ALLOW
        decision raises a :class:`PermissionError` subclass so the
        caller cannot mistake the response for a regular tool output.
        """
        params = self._extract_check_params(tool_input)
        scope = self._infer_scope(tool_input)
        result = self._guard.check(scope, **params)

        if result.allowed:
            return
        if result.needs_approval:
            raise AgentGuardApprovalRequired(
                f"[AgentGuard] Action requires approval. "
                f"Approve at: {result.approval_url}\n"
                f"Reason: {result.reason}",
                result=result,
            )
        # DENY (or any non-ALLOW / non-APPROVAL — fail closed)
        raise AgentGuardDenied(
            f"[AgentGuard] Action denied.\nReason: {result.reason}",
            result=result,
        )

    # ------------------------------------------------------------------
    # Synchronous entry points — every CrewAI / LangChain modern path
    # ------------------------------------------------------------------

    def run(self, tool_input: Any = "", **kwargs) -> Any:
        """Legacy CrewAI entry point. Gated."""
        self._check_or_raise(tool_input)
        if hasattr(self._tool, "_run"):
            return self._tool._run(tool_input, **kwargs)
        if hasattr(self._tool, "run"):
            return self._tool.run(tool_input, **kwargs)
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} has neither _run nor run"
        )

    def _run(self, *args, **kwargs) -> Any:
        """Internal CrewAI entry point. Gated.

        CrewAI's BaseTool.invoke ultimately calls _run; intercepting
        here closes the modern-API bypass of v0.4.x.
        """
        # Normalize *args -> tool_input. CrewAI passes either positional
        # or keyword arguments matching args_schema; the gate works on
        # whatever the agent provided.
        tool_input: Any
        if args:
            tool_input = args[0] if len(args) == 1 else args
        elif kwargs:
            tool_input = dict(kwargs)
        else:
            tool_input = ""
        self._check_or_raise(tool_input)
        if hasattr(self._tool, "_run"):
            return self._tool._run(*args, **kwargs)
        if hasattr(self._tool, "run"):
            return self._tool.run(*args, **kwargs)
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} has neither _run nor run"
        )

    def invoke(self, input: Any = None, config: Any = None, **kwargs) -> Any:  # noqa: A002
        """Modern CrewAI / LangChain Runnable entry point. Gated.

        Closes R5 E3: prior to v0.5, calling ``tool.invoke({...})``
        skipped the policy check entirely.
        """
        self._check_or_raise(input)
        if hasattr(self._tool, "invoke"):
            return self._tool.invoke(input, config=config, **kwargs)
        # Fall back to _run for tools that pre-date the Runnable API.
        if hasattr(self._tool, "_run"):
            return self._tool._run(input, **kwargs)
        if hasattr(self._tool, "run"):
            return self._tool.run(input, **kwargs)
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} exposes none of "
            "invoke / _run / run"
        )

    def __call__(self, *args, **kwargs) -> Any:
        """Direct call (``tool(input)``). Gated.

        CrewAI's StructuredTool / Pydantic-validated tools support this
        idiom. Without it, an agent doing ``tool(query)`` skipped the
        policy check.
        """
        tool_input: Any
        if len(args) == 1 and not kwargs:
            tool_input = args[0]
        elif kwargs and not args:
            tool_input = dict(kwargs)
        elif args:
            tool_input = args[0] if len(args) == 1 else list(args)
        else:
            tool_input = ""
        self._check_or_raise(tool_input)
        # Forward through whatever the wrapped tool provides.
        if callable(self._tool):
            return self._tool(*args, **kwargs)
        if hasattr(self._tool, "invoke"):
            return self._tool.invoke(args[0] if args else kwargs)
        if hasattr(self._tool, "_run"):
            return self._tool._run(*args, **kwargs)
        if hasattr(self._tool, "run"):
            return self._tool.run(*args, **kwargs)
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} is not callable "
            "and exposes none of invoke / _run / run"
        )

    # ------------------------------------------------------------------
    # Async entry points
    # ------------------------------------------------------------------

    async def arun(self, tool_input: Any = "", **kwargs) -> Any:
        """Legacy async CrewAI entry point. Gated.

        Note on sync-only tools: CrewAI's BaseTool defines ``_arun`` as a
        stub that raises ``NotImplementedError`` for tools that haven't
        overridden it (the common case — most CrewAI tools are sync).
        Catching the NotImplementedError per branch lets us fall through
        cleanly to a thread-executor sync path.
        """
        self._check_or_raise(tool_input)
        try:
            if hasattr(self._tool, "_arun"):
                return await self._tool._arun(tool_input, **kwargs)
        except NotImplementedError:
            pass
        try:
            if hasattr(self._tool, "arun"):
                return await self._tool.arun(tool_input, **kwargs)
        except NotImplementedError:
            pass
        # Sync fallback — run in a thread executor so the event loop is not blocked.
        if hasattr(self._tool, "_run"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool._run(tool_input, **kwargs)
            )
        if hasattr(self._tool, "run"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool.run(tool_input, **kwargs)
            )
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} exposes no async path"
        )

    async def _arun(self, *args, **kwargs) -> Any:
        """Internal async entry point. Gated. See ``arun`` for the
        NotImplementedError fallthrough rationale."""
        tool_input: Any
        if args:
            tool_input = args[0] if len(args) == 1 else args
        elif kwargs:
            tool_input = dict(kwargs)
        else:
            tool_input = ""
        self._check_or_raise(tool_input)
        try:
            if hasattr(self._tool, "_arun"):
                return await self._tool._arun(*args, **kwargs)
        except NotImplementedError:
            pass
        try:
            if hasattr(self._tool, "arun"):
                return await self._tool.arun(*args, **kwargs)
        except NotImplementedError:
            pass
        if hasattr(self._tool, "_run"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool._run(*args, **kwargs)
            )
        if hasattr(self._tool, "run"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool.run(*args, **kwargs)
            )
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} exposes no async path"
        )

    async def ainvoke(self, input: Any = None, config: Any = None, **kwargs) -> Any:  # noqa: A002
        """Modern async Runnable entry point. Gated.

        Closes R5 E3 (async leg): prior to v0.5, calling
        ``await tool.ainvoke({...})`` skipped the policy check.

        Sync-only-tool fallthrough: CrewAI's BaseTool defines async stubs
        (``_arun`` / ``ainvoke``) that raise ``NotImplementedError``
        when the tool hasn't overridden them. Each branch catches that and
        falls through to the next, ultimately running ``_run`` in a thread
        executor so calling ``await tool.ainvoke(...)`` works against any
        sync CrewAI tool.
        """
        self._check_or_raise(input)
        try:
            if hasattr(self._tool, "ainvoke"):
                return await self._tool.ainvoke(input, config=config, **kwargs)
        except NotImplementedError:
            pass
        try:
            if hasattr(self._tool, "_arun"):
                return await self._tool._arun(input, **kwargs)
        except NotImplementedError:
            pass
        try:
            if hasattr(self._tool, "arun"):
                return await self._tool.arun(input, **kwargs)
        except NotImplementedError:
            pass
        # Sync fallback — execute in thread executor so the event loop is unblocked.
        if hasattr(self._tool, "invoke"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool.invoke(input, config=config, **kwargs)
            )
        if hasattr(self._tool, "_run"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool._run(input, **kwargs)
            )
        if hasattr(self._tool, "run"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._tool.run(input, **kwargs)
            )
        raise AttributeError(
            f"wrapped tool {type(self._tool).__name__!r} exposes no callable path"
        )

    # ------------------------------------------------------------------
    # Strict attribute allowlist.
    #
    # __getattr__ is only consulted when normal attribute lookup fails.
    # Because invoke / ainvoke / run / _run / arun / _arun / __call__
    # are all defined as methods on this class, they are resolved
    # BEFORE __getattr__ runs. Same for self.name / self.description
    # (set by __init__). So the only attributes that reach __getattr__
    # are the ones the framework or user is asking for that the wrapper
    # itself hasn't defined.
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        # Block direct access to private/internal attributes that would
        # bypass the gate. We can't reach _tool itself via __getattr__
        # because it IS set on the instance, but a typo or future
        # rename could miss it — be explicit.
        if name in ("_tool", "_guard", "_scope"):
            # These are set on the instance; if __getattr__ is called
            # for them the instance was constructed wrong. Raise rather
            # than return None silently.
            raise AttributeError(
                f"{type(self).__name__!r} has no attribute {name!r} "
                "(instance not fully initialized?)"
            )

        if name in _ALLOWED_PASSTHROUGH:
            return getattr(self._tool, name)

        # Anything not on the allowlist is blocked. Includes:
        #   - func, coroutine          (raw callables)
        #   - stream, batch            (deferred Runnable streaming)
        #   - any future framework attribute
        # This converts the silent-bypass surface from "everything"
        # into "explicit allowlist only". Adding a new safe attribute
        # is a one-line code change + review, not a silent regression.
        raise AttributeError(
            f"{type(self).__name__!r} blocks access to attribute {name!r} "
            "as a security guard. Only metadata attributes "
            f"({sorted(_ALLOWED_PASSTHROUGH)}) are proxied to the "
            "wrapped tool. To add a new attribute, edit "
            "_ALLOWED_PASSTHROUGH in agentguard.adapters.crewai."
        )


def guard_crew_tools(
    tools: List[Any],
    guard_url: str = DEFAULT_BASE_URL,
    agent_id: str = "",
    default_scope: str = "shell",
) -> List[GuardedCrewTool]:
    """Wrap a list of CrewAI tools with AgentGuard enforcement.

    Args:
        tools: List of CrewAI tools to guard.
        guard_url: URL of the AgentGuard proxy.
        agent_id: Identifier for this agent in audit logs.
        default_scope: Default policy scope.

    Returns:
        List of :class:`GuardedCrewTool` instances. Each instance shares
        a single :class:`Guard` so they batch under one agent_id.
    """
    guard = Guard(guard_url, agent_id=agent_id)
    return [
        GuardedCrewTool(tool, guard=guard, scope=default_scope)
        for tool in tools
    ]


# ---------------------------------------------------------------------------
# Virtual-subclass registration for CrewAI / LangChain BaseTool.
#
# Many CrewAI internals do ``isinstance(t, BaseTool)`` before treating an
# object as a tool. We don't actually subclass BaseTool (that would expose
# every parent method to the agent without going through the gate), but
# we DO want the runtime check to succeed.
#
# ``BaseTool.register(GuardedCrewTool)`` makes Python's isinstance
# machinery treat the wrapper as a virtual subclass without changing
# attribute resolution — exactly what we want.
#
# This runs lazily the first time a GuardedCrewTool is constructed so
# importing this module does not require crewai / langchain at all.
# ---------------------------------------------------------------------------

_basetool_registered = False


def _maybe_register_basetool_virtual_subclass() -> None:
    """Best-effort: register GuardedCrewTool as a virtual subclass of
    CrewAI's BaseTool (and LangChain's, if importable) so framework-side
    isinstance checks succeed.

    Called at most once; failures (including ImportError when the
    framework is not installed) are swallowed so the adapter remains
    usable in pure-mock test environments.
    """
    global _basetool_registered
    if _basetool_registered:
        return
    _basetool_registered = True  # set first to avoid re-attempt loops

    # Try CrewAI's BaseTool first, then LangChain's. CrewAI re-exports
    # the class but the canonical location moved between versions:
    #   crewai.tools.BaseTool       (>=0.30, <0.80 ish)
    #   crewai_tools.BaseTool       (split package)
    #   crewai.tools.base_tool.BaseTool (newer internal layout)
    candidate_paths = [
        ("crewai.tools", "BaseTool"),
        ("crewai_tools", "BaseTool"),
        ("crewai.tools.base_tool", "BaseTool"),
        ("langchain_core.tools", "BaseTool"),
        ("langchain.tools", "BaseTool"),
    ]
    for module_name, attr in candidate_paths:
        try:
            module = __import__(module_name, fromlist=[attr])
            base = getattr(module, attr, None)
            if base is None:
                continue
            register = getattr(base, "register", None)
            if register is None:
                continue
            try:
                register(GuardedCrewTool)
            except (TypeError, RuntimeError):
                # ABC.register raises TypeError if the target already
                # exists in the MRO (harmless); RuntimeError can come
                # from pydantic-style classes that block register.
                continue
        except ImportError:
            continue
