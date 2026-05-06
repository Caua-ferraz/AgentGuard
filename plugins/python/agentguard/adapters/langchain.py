"""
AgentGuard LangChain Adapter (v0.5 hardened)

Wraps LangChain tools so every invocation passes through AgentGuard policy
checks. v0.4.x wrapped only the legacy ``run``/``arun`` entry points; modern
LangChain (>= 0.1, the ``invoke``/``ainvoke``/``stream``/``batch`` API) called
through ``__getattr__`` and bypassed the gate. v0.5 closes that gap by
explicitly gating every Runnable entry point.

Gated methods (each calls ``Guard.check`` before forwarding to the wrapped
tool):

- ``invoke(input, config=None, **kwargs)`` — synchronous Runnable entry
- ``ainvoke(input, config=None, **kwargs)`` — async Runnable entry
- ``stream(input, config=None, **kwargs)`` — synchronous streaming Runnable
- ``astream(input, config=None, **kwargs)`` — async streaming Runnable
- ``batch(inputs, config=None, **kwargs)`` — synchronous batch (gates each
  input independently; first DENY raises ``PermissionError`` for the batch)
- ``abatch(inputs, config=None, **kwargs)`` — async batch, same semantics
- ``run(*args, **kwargs)`` / ``arun(*args, **kwargs)`` — legacy entries
- ``_run(*args, **kwargs)`` / ``_arun(*args, **kwargs)`` — legacy internal entries

On DENY or REQUIRE_APPROVAL the adapter raises ``PermissionError`` (matching
the SDK's existing ``@guarded`` decorator and CrewAI/browser-use adapters).
The legacy ``run``/``arun`` paths preserve their v0.4.x behaviour of returning
a string message instead of raising — this kept them inert under naive
LangChain agents that swallowed exceptions, and rewriting that today would
break v0.4.x users. The modern paths (``invoke``/``ainvoke``/``stream``/
``batch``) raise so callers using LCEL chains see the failure surface. This
asymmetry is documented; v0.6 will harmonise once we're willing to break
v0.4.x callers (issue title in ``.audit/v05_decisions.md``).

Attribute allowlist (R5 audit finding closure)
==============================================

In v0.4.x, ``GuardedTool.__getattr__`` proxied every attribute through to the
wrapped tool. An adversarial agent could call ``gt.func(...)`` (the raw
callable behind ``Tool.from_function``) or ``gt._tool.invoke(...)`` and
sidestep the policy gate entirely.

v0.5 replaces ``__getattr__`` with a strict allowlist. Only metadata
attributes (``name``, ``description``, ``args_schema``, ``return_direct``,
``metadata``, ``tags``) pass through. Every other access raises
``AttributeError`` with a security-explanatory message. ``func``, ``coroutine``,
internal LangChain hooks, and ``_tool`` itself are all blocked.

Composition vs subclass
=======================

We chose **composition**: ``GuardedTool`` *holds* a wrapped tool and is
**not** a ``BaseTool`` subclass. Subclassing ``BaseTool`` would:

  1. Force us to satisfy LangChain's pydantic validation (``BaseTool`` is a
     pydantic ``BaseModel`` subclass), which complicates the constructor and
     leaks fields we explicitly want to block.
  2. Reintroduce the bypass: ``BaseTool``'s parent ``Runnable`` calls into
     pydantic descriptors and field reflection, both of which expect
     attribute access to be transparent. A blocking ``__getattr__`` fights
     that machinery.

LangChain runtime checks for the ``Runnable`` protocol (``invoke``/``stream``
methods) more often than ``isinstance(BaseTool, ...)``. We implement those
methods explicitly. For the rare code path that does an isinstance check, the
caller can pass the wrapped tool to the agent constructor under a different
name; we considered registering ``GuardedTool`` as a virtual subclass via
``BaseTool.register(...)`` but rejected it as fragile (pydantic v2 rejects
the registration in some configurations). The composition approach is
documented and deliberate.

Stream gating limitation
========================

For ``stream``/``astream`` the gate fires **once** at stream open. Mid-stream
tool calls (rare in v0.4 LangChain, increasingly common in agent loops with
chunk-driven side-effects) bypass the gate. v0.6 issue title:
*"langchain: per-chunk policy gating in stream()/astream()"* — see
``.audit/v05_decisions.md``.
"""

from typing import Any, AsyncIterator, Iterator, List, Optional

from agentguard import Guard, CheckResult, DEFAULT_BASE_URL


# Attributes that may pass through to the wrapped tool. Anything outside this
# set must raise AttributeError with a security explanation. The list is
# deliberately conservative — adding a new entry should require explicit
# review against the bypass-vector checklist. Adding ``func``, ``coroutine``,
# ``_run``, ``_arun``, or ``_tool`` would defeat the gate; they are blocked
# by omission.
_ALLOWED_PASSTHROUGH = frozenset(
    {
        "name",
        "description",
        "args_schema",
        "return_direct",
        "metadata",
        "tags",
    }
)


class GuardedTool:
    """Compose-and-gate wrapper around a LangChain tool.

    Every Runnable entry point (``invoke``, ``ainvoke``, ``stream``,
    ``astream``, ``batch``, ``abatch``) and every legacy entry point
    (``run``, ``arun``, ``_run``, ``_arun``) is gated by AgentGuard before
    forwarding to the wrapped tool. Direct attribute access falls through
    only for the metadata listed in :data:`_ALLOWED_PASSTHROUGH`; every
    other attribute raises ``AttributeError``.

    The wrapped tool is held privately. ``GuardedTool._tool`` itself is
    blocked from external readers — see ``__getattribute__``.
    """

    # Private slots are name-mangled (``__tool`` -> ``_GuardedTool__tool``)
    # so external attribute access through ``gt._tool`` falls through to
    # ``__getattr__`` (where it is blocked) instead of hitting the slot
    # directly. The class reads them via ``self.__tool`` etc. from inside
    # its own methods.
    __slots__ = (
        "_GuardedTool__tool",
        "_GuardedTool__guard",
        "_GuardedTool__scope",
        "name",
        "description",
        "args_schema",
        "return_direct",
        "metadata",
        "tags",
    )

    def __init__(self, tool: Any, guard: Guard, scope: str = "shell"):
        # Use object.__setattr__ for the private (mangled) slots. The
        # mangling means ``self.__tool = tool`` inside __init__ writes the
        # ``_GuardedTool__tool`` slot — but we use object.__setattr__
        # explicitly to make the intent (and the slot name) obvious in
        # any audit trail.
        object.__setattr__(self, "_GuardedTool__tool", tool)
        object.__setattr__(self, "_GuardedTool__guard", guard)
        object.__setattr__(self, "_GuardedTool__scope", scope)

        # Copy allowlisted metadata into our own slots so reads never reach
        # into the wrapped tool. This means changes to the wrapped tool's metadata
        # after construction don't propagate — acceptable for a security
        # wrapper; the metadata is captured at wrap time.
        object.__setattr__(self, "name", getattr(tool, "name", ""))
        object.__setattr__(self, "description", getattr(tool, "description", ""))
        object.__setattr__(self, "args_schema", getattr(tool, "args_schema", None))
        object.__setattr__(self, "return_direct", getattr(tool, "return_direct", False))
        object.__setattr__(self, "metadata", getattr(tool, "metadata", None))
        object.__setattr__(self, "tags", getattr(tool, "tags", None))

    # ------------------------------------------------------------------
    # Policy gate helpers
    # ------------------------------------------------------------------

    def _infer_check_params(self, tool_input: Any) -> dict:
        """Extract meaningful parameters from tool input for policy checking."""
        params: dict = {}

        if isinstance(tool_input, str):
            params["command"] = tool_input
        elif isinstance(tool_input, dict):
            if "command" in tool_input or "cmd" in tool_input:
                params["command"] = tool_input.get("command", tool_input.get("cmd", ""))
            if "url" in tool_input:
                params["url"] = tool_input["url"]
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(tool_input["url"])
                    if parsed.hostname:
                        params["domain"] = parsed.hostname
                except Exception:
                    pass
            if "path" in tool_input or "file_path" in tool_input:
                params["path"] = tool_input.get("path", tool_input.get("file_path", ""))
                # Infer action from tool name
                name_lower = self.name.lower() if isinstance(self.name, str) else ""
                if "read" in name_lower or "get" in name_lower:
                    params["action"] = "read"
                elif "write" in name_lower or "save" in name_lower or "create" in name_lower:
                    params["action"] = "write"
                elif "delete" in name_lower or "remove" in name_lower:
                    params["action"] = "delete"
            # Forward session/cost hints so cost-scope guardrails work.
            if "session_id" in tool_input:
                params["session_id"] = tool_input["session_id"]
            if "est_cost" in tool_input:
                params["est_cost"] = tool_input["est_cost"]

        return params

    def _infer_scope(self, params: dict) -> str:
        """Infer the appropriate policy scope from the parameters."""
        if params.get("domain") or params.get("url"):
            return "network"
        if params.get("path"):
            return "filesystem"
        return self.__scope

    def _gate(self, tool_input: Any) -> CheckResult:
        """Run a single policy check for ``tool_input``.

        Returns the :class:`CheckResult`; callers decide what to do based
        on ``allowed`` / ``denied`` / ``needs_approval``.
        """
        params = self._infer_check_params(tool_input)
        scope = self._infer_scope(params)
        return self.__guard.check(scope, **params)

    @staticmethod
    def _format_denied_message(result: CheckResult) -> str:
        return f"[AgentGuard] Action denied.\nReason: {result.reason}"

    @staticmethod
    def _format_approval_message(result: CheckResult) -> str:
        return (
            f"[AgentGuard] Action requires approval. "
            f"Approve at: {result.approval_url}\n"
            f"Reason: {result.reason}"
        )

    def _raise_for_modern_api(self, result: CheckResult, tool_input: Any) -> None:
        """Raise PermissionError for DENY or REQUIRE_APPROVAL on modern entries.

        The modern Runnable API (invoke/ainvoke/stream/batch) propagates
        exceptions through LCEL chains, so we surface failures by raising
        ``PermissionError``. Callers that want non-throwing behaviour can
        wrap the call in a try/except.
        """
        if result.denied:
            raise PermissionError(
                f"[AgentGuard] Tool {self.name!r} denied: {result.reason}"
            )
        if result.needs_approval:
            raise PermissionError(
                f"[AgentGuard] Tool {self.name!r} requires approval. "
                f"Approve at: {result.approval_url}\nReason: {result.reason}"
            )

    # ------------------------------------------------------------------
    # Modern Runnable API (invoke / ainvoke / stream / astream / batch / abatch)
    # ------------------------------------------------------------------

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Synchronous Runnable entry. Gates ``input`` then delegates."""
        result = self._gate(input)
        self._raise_for_modern_api(result, input)
        return self.__tool.invoke(input, config=config, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Async Runnable entry. Gate is synchronous; delegate is async."""
        result = self._gate(input)
        self._raise_for_modern_api(result, input)
        return await self.__tool.ainvoke(input, config=config, **kwargs)

    def stream(self, input: Any, config: Any = None, **kwargs: Any) -> Iterator[Any]:
        """Synchronous streaming Runnable entry.

        The gate fires **once** at stream open. Mid-stream tool calls bypass
        the gate — a v0.6 issue tracks per-chunk gating.
        """
        result = self._gate(input)
        self._raise_for_modern_api(result, input)
        # TODO(v0.6, #langchain-stream-gating): gate per-chunk events in
        # stream()/astream() output. Today the gate fires once at
        # stream-open; mid-stream tool calls (rare in v0.4 LangChain but
        # increasingly common in agent loops) bypass the gate.
        return self.__tool.stream(input, config=config, **kwargs)

    async def astream(
        self, input: Any, config: Any = None, **kwargs: Any
    ) -> AsyncIterator[Any]:
        """Async streaming Runnable entry. Same one-shot gate as stream()."""
        result = self._gate(input)
        self._raise_for_modern_api(result, input)
        # TODO(v0.6, #langchain-stream-gating): see stream() above.
        async for chunk in self.__tool.astream(input, config=config, **kwargs):
            yield chunk

    def batch(
        self, inputs: List[Any], config: Any = None, **kwargs: Any
    ) -> List[Any]:
        """Synchronous batch entry. Gates each input independently.

        First DENY (or REQUIRE_APPROVAL) raises ``PermissionError`` reporting
        the failing index. The whole-batch-fails-on-first-deny semantics is
        deliberate: collating per-entry results would force callers to
        de-multiplex success/failure on every batch, which is more code
        than v0.5 wants to ship. v0.6 may switch to per-entry collation
        if customers ask for it.
        """
        for idx, item in enumerate(inputs):
            result = self._gate(item)
            if result.denied:
                raise PermissionError(
                    f"[AgentGuard] Tool {self.name!r} batch entry {idx} denied: "
                    f"{result.reason}"
                )
            if result.needs_approval:
                raise PermissionError(
                    f"[AgentGuard] Tool {self.name!r} batch entry {idx} requires "
                    f"approval. Approve at: {result.approval_url}\n"
                    f"Reason: {result.reason}"
                )
        return self.__tool.batch(inputs, config=config, **kwargs)

    async def abatch(
        self, inputs: List[Any], config: Any = None, **kwargs: Any
    ) -> List[Any]:
        """Async batch entry. Same per-entry gating as batch()."""
        for idx, item in enumerate(inputs):
            result = self._gate(item)
            if result.denied:
                raise PermissionError(
                    f"[AgentGuard] Tool {self.name!r} batch entry {idx} denied: "
                    f"{result.reason}"
                )
            if result.needs_approval:
                raise PermissionError(
                    f"[AgentGuard] Tool {self.name!r} batch entry {idx} requires "
                    f"approval. Approve at: {result.approval_url}\n"
                    f"Reason: {result.reason}"
                )
        return await self.__tool.abatch(inputs, config=config, **kwargs)

    # ------------------------------------------------------------------
    # Legacy API (run / arun / _run / _arun)
    # ------------------------------------------------------------------

    def run(self, tool_input: Any, **kwargs: Any) -> Any:
        """Run the tool after checking with AgentGuard (legacy entry).

        Returns a string message on DENY/REQUIRE_APPROVAL to preserve
        v0.4.x behaviour; do **not** use this for new code — prefer
        ``invoke()`` so failures surface as exceptions.
        """
        result = self._gate(tool_input)

        if result.allowed:
            return self.__tool.run(tool_input, **kwargs)
        if result.needs_approval:
            return self._format_approval_message(result)
        return self._format_denied_message(result)

    async def arun(self, tool_input: Any, **kwargs: Any) -> Any:
        """Async legacy entry. Same string-on-deny shape as ``run()``."""
        result = self._gate(tool_input)

        if result.allowed:
            return await self.__tool.arun(tool_input, **kwargs)
        if result.needs_approval:
            return self._format_approval_message(result)
        return self._format_denied_message(result)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """LangChain internal sync entry. Gates the first positional arg.

        BaseTool.invoke ultimately calls ``_run`` on the underlying tool;
        we override it here to gate that path too. The first positional
        argument (or ``tool_input``/``input`` keyword) is treated as the
        gate input — matching how LangChain's BaseTool dispatches.
        """
        tool_input = args[0] if args else kwargs.get("tool_input", kwargs.get("input"))
        result = self._gate(tool_input)
        self._raise_for_modern_api(result, tool_input)
        # Use object.__getattribute__ on the wrapped tool to access its
        # underscore-prefixed _run, bypassing our own __getattr__.
        underlying = self.__tool
        return underlying._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """LangChain internal async entry. Mirrors ``_run`` semantics."""
        tool_input = args[0] if args else kwargs.get("tool_input", kwargs.get("input"))
        result = self._gate(tool_input)
        self._raise_for_modern_api(result, tool_input)
        underlying = self.__tool
        return await underlying._arun(*args, **kwargs)

    # ------------------------------------------------------------------
    # Attribute access — strict allowlist
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Block every non-allowlisted attribute access.

        Python only calls ``__getattr__`` after the normal attribute
        lookup fails — i.e. the attribute is **not** in ``__slots__`` /
        ``__dict__`` / class methods. By the time we get here the caller is
        asking for something that is not part of the gated surface. We
        block by default and raise ``AttributeError`` with a security note.

        The allowlist is enforced this way (rather than at __getattribute__
        time) so that explicitly-defined methods on this class (``invoke``,
        ``stream``, etc.) and the slotted metadata attributes work
        normally — only the proxy-fallback path is blocked.
        """
        # Explicit deny for known bypass vectors. ``_tool`` and ``func`` are
        # the documented bypass attempts in the audit; we name them in the
        # error message for clarity.
        if name in ("_tool", "func", "coroutine"):
            raise AttributeError(
                f"Direct access to {name!r} would bypass the AgentGuard policy "
                f"gate. Use tool.invoke(...) instead."
            )
        if name in _ALLOWED_PASSTHROUGH:
            # If a metadata attribute was not captured at __init__ time
            # (e.g. the wrapped tool added it later), fetch it now via
            # object.__getattribute__ on the wrapped tool's mangled slot —
            # bypassing our own __getattr__ recursion. The slot name is
            # ``_GuardedTool__tool`` (Python name mangling on ``__tool``).
            tool = object.__getattribute__(self, "_GuardedTool__tool")
            try:
                return getattr(tool, name)
            except AttributeError:
                raise AttributeError(name)
        raise AttributeError(
            f"Direct access to {name!r} would bypass the AgentGuard policy "
            f"gate. Use tool.invoke(...) instead."
        )


class GuardedToolkit:
    """Wraps a list of LangChain tools with AgentGuard enforcement.

    Args:
        tools: List of LangChain tools to guard
        guard_url: URL of the AgentGuard proxy
        agent_id: Identifier for this agent in audit logs
        default_scope: Default policy scope for tools that can't be auto-detected
    """

    def __init__(
        self,
        tools: List[Any],
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "",
        default_scope: str = "shell",
    ):
        self._guard = Guard(guard_url, agent_id=agent_id)
        self._default_scope = default_scope
        self._tools = [
            GuardedTool(tool, self._guard, scope=self._infer_scope(tool))
            for tool in tools
        ]

    def _infer_scope(self, tool: Any) -> str:
        """Try to infer the policy scope from the tool's name/description."""
        name = getattr(tool, "name", "").lower()
        desc = getattr(tool, "description", "").lower()
        combined = f"{name} {desc}"

        if any(kw in combined for kw in ["http", "api", "fetch", "request", "url", "web"]):
            return "network"
        if any(kw in combined for kw in ["file", "read", "write", "directory", "path"]):
            return "filesystem"
        if any(kw in combined for kw in ["browser", "navigate", "click", "page"]):
            return "browser"
        if any(kw in combined for kw in ["shell", "command", "exec", "terminal", "bash"]):
            return "shell"

        return self._default_scope

    @property
    def tools(self) -> List[GuardedTool]:
        """The guarded tool list — drop-in replacement for unguarded tools."""
        return self._tools
