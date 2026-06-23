"""
AgentGuard LangChain Adapter — subclass + override.

Wraps LangChain tools so every invocation passes through AgentGuard policy
checks.

Architecture
------------
``GuardedTool`` subclasses ``langchain_core.tools.BaseTool`` directly
so ``isinstance(thing, Runnable)`` and ``isinstance(thing, BaseTool)``
checks succeed natively. langgraph 1.0 + langchain_core 1.x's
``coerce_to_runnable`` and langchain 1.x's
``langchain.agents.create_agent`` both reject composition wrappers,
so the subclass approach is the only one that registers cleanly.

To keep the gate tight without an ``__getattr__`` allowlist, **every**
entry point the framework calls is explicitly overridden:

  - ``_run`` (abstract on the parent — required by the subclass) — the
    canonical sync dispatch path; ``BaseTool.run`` calls into ``_run``
    via ``self._run`` reflection, and ``BaseTool.invoke`` calls
    ``self.run``. Gating ``_run`` covers every sync path.
  - ``_arun`` — the async counterpart.
  - ``invoke`` / ``ainvoke`` — overridden anyway so the gate fires
    even if a future framework version short-circuits the parent's
    invoke -> run -> _run chain.
  - ``stream`` / ``astream`` — gated at stream open + periodic
    re-validation (see "Stream gating" below).
  - ``batch`` / ``abatch`` — gate each input independently; first DENY
    raises for the whole batch (whole-batch-fails-on-first-deny).
  - ``run`` / ``arun`` — legacy entries; preserve string-on-deny
    semantics for callers that depend on it.

The defense contract: every gated method is explicitly overridden on
this class. Pydantic ``PrivateAttr`` keeps internal references off
``model_fields`` and out of ``model_dump`` payloads. The canary
integration test (``test_at_real_langchain.py``) trips if upstream
adds a new dispatch path that bypasses our overrides.

Lazy framework import
---------------------
We never import ``langchain_core`` at module top level — the SDK must
remain ``pip install agentguardproxy``-friendly without the framework
extra. The class definition is wrapped in a builder that resolves
``langchain_core.tools.BaseTool`` on first instantiation; before that
the ``GuardedTool`` symbol is a callable factory that raises a clear
``ImportError`` when constructed.

Stream gating
=============

``stream`` / ``astream`` gate at stream open and re-validate the
decision every ``STREAM_REGATE_SECONDS`` (default 10s) while chunks
flow, so a mid-stream policy revocation cuts the stream off instead of
riding to completion.
"""

from __future__ import annotations

import time
from typing import Any, AsyncIterator, Iterator, List, Optional

from agentguard import Guard, CheckResult, DEFAULT_BASE_URL
from agentguard.adapters._common import extract_check_params

# How often a live stream re-validates its policy decision. Streams gate
# at open; without re-validation a long-lived stream would ride to
# completion even after a policy hot-reload revoked the permission.
# Re-checking costs one local /v1/check HTTP round-trip, so it runs on a
# wall-clock interval rather than per chunk. Tests shrink this to force
# a re-check on every chunk.
STREAM_REGATE_SECONDS = 10.0


# ---------------------------------------------------------------------------
# Lazy langchain_core BaseTool resolution.
# ---------------------------------------------------------------------------

_LC_BASETOOL: Optional[type] = None
_GUARDED_TOOL_CLASS: Optional[type] = None


def _is_valid_args_schema(value: Any) -> bool:
    """Return True if ``value`` is a pydantic BaseModel subclass or a
    JSON-schema-shaped dict.

    LangChain's ``BaseTool.__init__`` validates ``args_schema`` against
    these two shapes; passing anything else (e.g. a ``MagicMock``)
    raises ``TypeError``. We need to filter defensively because the
    SDK's adapter is sometimes wrapped around mock tools in user tests.
    """
    if isinstance(value, dict):
        return True
    try:
        from pydantic import BaseModel  # type: ignore[import-not-found]
        return isinstance(value, type) and issubclass(value, BaseModel)
    except Exception:
        return False


def _resolve_lc_basetool() -> type:
    """Return ``langchain_core.tools.BaseTool`` or raise ImportError."""
    global _LC_BASETOOL
    if _LC_BASETOOL is not None:
        return _LC_BASETOOL
    last_err: Optional[Exception] = None
    for module_name, attr in (
        ("langchain_core.tools", "BaseTool"),
        ("langchain_core.tools.base", "BaseTool"),
    ):
        try:
            module = __import__(module_name, fromlist=[attr])
            base = getattr(module, attr, None)
            if base is not None:
                _LC_BASETOOL = base
                return base
        except ImportError as e:
            last_err = e
            continue
    raise ImportError(
        "agentguard LangChain adapter requires the `langchain_core` package. "
        "Install it with `pip install 'agentguardproxy[langchain]'`. "
        f"(underlying import error: {last_err!r})"
    )


def _build_guarded_tool_class() -> type:
    """Build the GuardedTool class that subclasses langchain_core BaseTool."""
    global _GUARDED_TOOL_CLASS
    if _GUARDED_TOOL_CLASS is not None:
        return _GUARDED_TOOL_CLASS

    BaseTool = _resolve_lc_basetool()
    from pydantic import PrivateAttr  # type: ignore[import-not-found]

    class GuardedTool(BaseTool):  # type: ignore[misc, valid-type]
        """Hybrid subclass-and-override wrapper around a LangChain ``BaseTool``.

        Subclasses ``BaseTool`` so framework-side ``isinstance(thing,
        Runnable)`` checks succeed natively (langgraph 1.0 /
        langchain_core 1.x reject composition wrappers). Every entry
        point the framework calls is explicitly overridden to gate via
        Guard.check before forwarding.
        """

        # Pydantic private attrs — held on the instance but not part of
        # the public model. Set per-instance from __init__.
        _tool: Any = PrivateAttr(default=None)
        _guard: Any = PrivateAttr(default=None)
        _scope: str = PrivateAttr(default="shell")

        def __init__(self, tool: Any, guard: Guard, scope: str = "shell") -> None:
            # Names / descriptions: pydantic's BaseTool requires strings.
            # Defensive str() coercion handles mocks / objects in tests.
            name_attr = getattr(tool, "name", type(tool).__name__)
            desc_attr = getattr(tool, "description", "")
            init_kwargs: dict = {
                "name": str(name_attr) if not isinstance(name_attr, str) else name_attr,
                "description": (
                    str(desc_attr) if not isinstance(desc_attr, str) else desc_attr
                ),
            }
            # args_schema must be a pydantic BaseModel subclass or a JSON
            # schema dict (per langchain_core.tools.BaseTool validation).
            # Only forward if we can verify the type — otherwise drop the
            # attribute to avoid a hard pydantic ValidationError on mocks.
            args_schema = getattr(tool, "args_schema", None)
            if args_schema is not None and _is_valid_args_schema(args_schema):
                init_kwargs["args_schema"] = args_schema
            # Other metadata fields: forward only if they have a sane type.
            return_direct = getattr(tool, "return_direct", None)
            if isinstance(return_direct, bool):
                init_kwargs["return_direct"] = return_direct
            tags = getattr(tool, "tags", None)
            if isinstance(tags, list) and all(isinstance(t, str) for t in tags):
                init_kwargs["tags"] = tags
            metadata = getattr(tool, "metadata", None)
            if isinstance(metadata, dict):
                init_kwargs["metadata"] = metadata
            super().__init__(**init_kwargs)
            object.__setattr__(self, "_tool", tool)
            object.__setattr__(self, "_guard", guard)
            object.__setattr__(self, "_scope", scope)

        # --------------------------------------------------------------
        # Policy gate helpers
        # --------------------------------------------------------------

        def _infer_check_params(self, tool_input: Any) -> dict:
            """Extract meaningful parameters from tool input."""
            return extract_check_params(tool_input, self.name)

        def _infer_scope(self, params: dict) -> str:
            if params.get("domain") or params.get("url"):
                return "network"
            if params.get("path"):
                return "filesystem"
            return self._scope

        def _gate(self, tool_input: Any) -> CheckResult:
            params = self._infer_check_params(tool_input)
            scope = self._infer_scope(params)
            return self._guard.check(scope, **params)

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
            """Raise PermissionError on DENY / REQUIRE_APPROVAL."""
            if result.denied:
                raise PermissionError(
                    f"[AgentGuard] Tool {self.name!r} denied: {result.reason}"
                )
            if result.needs_approval:
                raise PermissionError(
                    f"[AgentGuard] Tool {self.name!r} requires approval. "
                    f"Approve at: {result.approval_url}\nReason: {result.reason}"
                )

        # --------------------------------------------------------------
        # Internal abstract entry: _run / _arun.
        # ``BaseTool.run`` calls ``self._run(*tool_args, **tool_kwargs)``
        # via ``context.run``. Gating here covers the canonical sync
        # dispatch path.
        # --------------------------------------------------------------

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            tool_input = self._reduce_to_tool_input(args, kwargs)
            result = self._gate(tool_input)
            self._raise_for_modern_api(result, tool_input)
            inner = self._tool
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has no _run / run"
            )

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            tool_input = self._reduce_to_tool_input(args, kwargs)
            result = self._gate(tool_input)
            self._raise_for_modern_api(result, tool_input)
            inner = self._tool
            if hasattr(inner, "_arun"):
                try:
                    return await inner._arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "arun"):
                try:
                    return await inner.arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            # Sync fallback in a thread executor.
            import asyncio
            loop = asyncio.get_running_loop()
            if hasattr(inner, "_run"):
                return await loop.run_in_executor(
                    None, lambda: inner._run(*args, **kwargs)
                )
            if hasattr(inner, "run"):
                return await loop.run_in_executor(
                    None, lambda: inner.run(*args, **kwargs)
                )
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has no async path"
            )

        @staticmethod
        def _reduce_to_tool_input(args: tuple, kwargs: dict) -> Any:
            """Map ``_run``'s *args/**kwargs onto a single tool_input.

            Special cases for the policy gate:
              * ``("hello",)`` → ``"hello"`` (string command form)
              * ``{"command": "hi"}`` → dict (rule-keyed extraction)
              * ``{"text": "hi"}`` (single-arg tool from
                ``Tool.from_function``) → ``"hi"`` so the command field
                is populated naturally — the agent runtime passes the
                LLM's tool-call args in dict form, but for single-arg
                tools the value is what operators write rules against.
            """
            # Strip LangChain runtime kwargs first so they never reach the
            # gate input.
            clean_kwargs = {
                k: v for k, v in kwargs.items()
                if k not in ("run_manager", "config", "callbacks")
            }
            if args and not clean_kwargs:
                return args[0] if len(args) == 1 else list(args)
            if not args and clean_kwargs:
                # Promote single-key dicts whose key is unrecognised by
                # _infer_check_params to a bare command string. The
                # canonical keys (command/cmd/url/path/...) keep their
                # dict form.
                recognised = {"command", "cmd", "url", "path", "file_path",
                              "domain", "session_id", "est_cost"}
                if (
                    len(clean_kwargs) == 1
                    and next(iter(clean_kwargs)) not in recognised
                ):
                    return next(iter(clean_kwargs.values()))
                return clean_kwargs
            if args and clean_kwargs:
                return {"args": list(args), **clean_kwargs}
            return ""

        # --------------------------------------------------------------
        # Modern Runnable API (invoke / ainvoke / stream / astream / batch / abatch)
        # --------------------------------------------------------------

        def _gate_input_for_invoke(self, raw_input: Any) -> Any:
            """Normalize an ``invoke``-style input for the policy gate.

            Handled shapes:
              * langchain_core ``ToolCall`` dict
                ``{"name", "args", "id", "type": "tool_call"}`` — agent
                runtime passes this to ``tool.invoke``. Unwrap to the
                ``args`` payload before extraction.
              * ``invoke({"text": "hello"})`` from a tool whose function
                takes a single non-canonical kwarg — promote to bare
                string "hello" so the command field populates.
              * ``invoke({"command": "hi"})`` keeps its dict shape so
                ``_infer_check_params``'s recognised-key extraction fires.
            """
            if isinstance(raw_input, dict):
                # Unwrap a langchain_core ToolCall dict.
                if (
                    raw_input.get("type") == "tool_call"
                    and "args" in raw_input
                ):
                    raw_input = raw_input["args"]
            if isinstance(raw_input, dict):
                recognised = {"command", "cmd", "url", "path", "file_path",
                              "domain", "session_id", "est_cost"}
                if (
                    len(raw_input) == 1
                    and next(iter(raw_input)) not in recognised
                ):
                    return next(iter(raw_input.values()))
            return raw_input

        def invoke(  # type: ignore[override]
            self,
            input: Any,  # noqa: A002
            config: Any = None,
            **kwargs: Any,
        ) -> Any:
            """Synchronous Runnable entry. Gates ``input`` then delegates
            to the wrapped tool's invoke (so its callbacks / serialization
            machinery runs)."""
            gate_input = self._gate_input_for_invoke(input)
            result = self._gate(gate_input)
            self._raise_for_modern_api(result, gate_input)
            inner = self._tool
            if hasattr(inner, "invoke"):
                return inner.invoke(input, config=config, **kwargs)
            if hasattr(inner, "_run"):
                return inner._run(input)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has no invoke / _run"
            )

        async def ainvoke(  # type: ignore[override]
            self,
            input: Any,  # noqa: A002
            config: Any = None,
            **kwargs: Any,
        ) -> Any:
            """Async Runnable entry."""
            gate_input = self._gate_input_for_invoke(input)
            result = self._gate(gate_input)
            self._raise_for_modern_api(result, gate_input)
            inner = self._tool
            if hasattr(inner, "ainvoke"):
                return await inner.ainvoke(input, config=config, **kwargs)
            # Sync fallback
            import asyncio
            loop = asyncio.get_running_loop()
            if hasattr(inner, "invoke"):
                return await loop.run_in_executor(
                    None, lambda: inner.invoke(input, config=config, **kwargs)
                )
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has no async path"
            )

        def stream(  # type: ignore[override]
            self,
            input: Any,  # noqa: A002
            config: Any = None,
            **kwargs: Any,
        ) -> Iterator[Any]:
            """Synchronous streaming Runnable entry. Gates at stream
            open, then re-validates every ``STREAM_REGATE_SECONDS``
            while chunks flow — a policy change mid-stream (permission
            revoked via hot-reload) cuts the stream off with the same
            typed ``PermissionError`` instead of riding to completion.
            """
            result = self._gate(input)
            self._raise_for_modern_api(result, input)
            inner = self._tool

            def guarded_chunks() -> Iterator[Any]:
                last_check = time.monotonic()
                for chunk in inner.stream(input, config=config, **kwargs):
                    now = time.monotonic()
                    if now - last_check >= STREAM_REGATE_SECONDS:
                        recheck = self._gate(input)
                        self._raise_for_modern_api(recheck, input)
                        last_check = now
                    yield chunk

            return guarded_chunks()

        async def astream(  # type: ignore[override]
            self,
            input: Any,  # noqa: A002
            config: Any = None,
            **kwargs: Any,
        ) -> AsyncIterator[Any]:
            """Async streaming Runnable entry. Same open-gate +
            periodic re-validation contract as :meth:`stream`."""
            result = self._gate(input)
            self._raise_for_modern_api(result, input)
            inner = self._tool
            last_check = time.monotonic()
            async for chunk in inner.astream(input, config=config, **kwargs):
                now = time.monotonic()
                if now - last_check >= STREAM_REGATE_SECONDS:
                    recheck = self._gate(input)
                    self._raise_for_modern_api(recheck, input)
                    last_check = now
                yield chunk

        def batch(  # type: ignore[override]
            self,
            inputs: List[Any],
            config: Any = None,
            **kwargs: Any,
        ) -> List[Any]:
            """Synchronous batch entry. Gates each input independently;
            first DENY raises for the whole batch."""
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
            return self._tool.batch(inputs, config=config, **kwargs)

        async def abatch(  # type: ignore[override]
            self,
            inputs: List[Any],
            config: Any = None,
            **kwargs: Any,
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
            return await self._tool.abatch(inputs, config=config, **kwargs)

        # --------------------------------------------------------------
        # Legacy API (run / arun) — string-on-deny shape preserved for
        # callers that depend on it; new code should prefer invoke().
        # --------------------------------------------------------------

        def run(  # type: ignore[override]
            self,
            tool_input: Any,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            """Run the tool (legacy entry).

            Returns a string message on DENY / REQUIRE_APPROVAL (legacy
            shape). New code should prefer ``invoke`` so failures surface
            as exceptions.
            """
            result = self._gate(tool_input)
            inner = self._tool
            if result.allowed:
                return inner.run(tool_input, *args, **kwargs)
            if result.needs_approval:
                return self._format_approval_message(result)
            return self._format_denied_message(result)

        async def arun(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
            """Async legacy entry. Same string-on-deny shape as ``run()``."""
            result = self._gate(tool_input)
            inner = self._tool
            if result.allowed:
                return await inner.arun(tool_input, *args, **kwargs)
            if result.needs_approval:
                return self._format_approval_message(result)
            return self._format_denied_message(result)

        # --------------------------------------------------------------
        # Hide private gating fields from model_dump.
        # --------------------------------------------------------------

        def model_dump(self, *args: Any, **kwargs: Any) -> dict:  # type: ignore[override]
            data = super().model_dump(*args, **kwargs)
            for k in ("_tool", "_guard", "_scope"):
                data.pop(k, None)
            return data

    _GUARDED_TOOL_CLASS = GuardedTool
    return GuardedTool


# ---------------------------------------------------------------------------
# Public GuardedTool symbol — a factory that builds and instantiates the
# real class lazily.
# ---------------------------------------------------------------------------


class _GuardedToolFactory:
    """Factory whose ``__call__`` returns a GuardedTool instance.

    Behaves like a class for ``isinstance`` checks once the underlying
    class has been built.
    """

    def __call__(self, tool: Any, guard: Guard, scope: str = "shell") -> Any:
        cls = _build_guarded_tool_class()
        return cls(tool, guard, scope=scope)

    def __instancecheck__(self, obj: Any) -> bool:  # pragma: no cover - delegated
        cls = _GUARDED_TOOL_CLASS
        if cls is None:
            return False
        return isinstance(obj, cls)

    def __subclasscheck__(self, sub: Any) -> bool:  # pragma: no cover - delegated
        cls = _GUARDED_TOOL_CLASS
        if cls is None:
            return False
        return issubclass(sub, cls)

    def __repr__(self) -> str:  # pragma: no cover
        return "<GuardedTool factory (lazy langchain_core.BaseTool subclass)>"


GuardedTool = _GuardedToolFactory()


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
        cls = _build_guarded_tool_class()
        self._tools = [
            cls(tool, self._guard, scope=self._infer_scope(tool))
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
    def tools(self) -> List[Any]:
        """The guarded tool list — drop-in replacement for unguarded tools."""
        return self._tools
