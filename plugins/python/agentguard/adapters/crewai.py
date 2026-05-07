"""
AgentGuard CrewAI Adapter (v0.5.1 hybrid: subclass + override)

Wraps CrewAI tools so every invocation passes through AgentGuard policy checks.

Why this file changed in v0.5.1
-------------------------------
v0.5.0 implemented ``GuardedCrewTool`` as a *composition* wrapper that held
a CrewAI ``BaseTool`` instance and registered itself as a virtual subclass
via ``BaseTool.register(GuardedCrewTool)``. The composition approach kept
the gating tight (an explicit ``__getattr__`` allowlist blocked any
parent-method bypass) but it broke at framework boundaries:

  CrewAI 1.x + pydantic 2.12 emit::

      For performance reasons, virtual subclasses registered using
      'BaseTool.register()' are not supported in 'isinstance()' and
      'issubclass()' checks.

  Concretely::

      Agent(tools=[GuardedCrewTool(...)])

  raises::

      pydantic_core._pydantic_core.ValidationError: 1 validation error for
      Agent tools.0  Input should be a valid dictionary or instance of
      BaseTool [...] input_type=GuardedCrewTool

That same architectural class affects langgraph 1.0 + langchain_core 1.x
(``isinstance(thing, Runnable)`` in ``coerce_to_runnable``).

The v0.5.1 fix: actually subclass CrewAI's ``BaseTool`` so isinstance
passes natively, and preserve the policy-enforcement contract by
overriding **every** entry point the framework calls. The
"every-method-is-on-this-class" property substitutes for the
composition-era ``__getattr__`` allowlist:

  - ``_run`` (abstract on the parent — we MUST override) gates every
    sync dispatch path the framework drives. CrewAI's ``BaseTool.run``,
    ``invoke`` (when present on a subclass / wrapper), and
    ``to_structured_tool`` all read ``_run`` off the instance, so a
    gated ``_run`` covers the entire sync surface.
  - ``_arun`` is overridden because CrewAI's ``arun`` calls ``_arun``.
  - ``run`` / ``arun`` / ``invoke`` / ``ainvoke`` / ``__call__`` are
    overridden explicitly so the gate fires regardless of which entry
    the agent runtime picks. Each one also runs the tool through the
    underlying instance's matching method, preserving CrewAI's usage
    accounting (``_claim_usage`` etc.) when the underlying tool defines
    those.
  - ``to_structured_tool`` is overridden so CrewAI's
    ``to_structured_tool`` pipeline (which does ``func=self._run``) ends
    up calling our gated ``_run``, not the wrapped tool's bare ``_run``.

The new defense contract
------------------------
Composition v0.5: "no parent methods are exposed; ``__getattr__`` is the
single chokepoint."

Subclass v0.5.1: "every gated method is explicitly overridden on this
class; the canary integration test (``test_at_real_crewai.py``) trips if
upstream adds a new dispatch path that bypasses our overrides." Pydantic
``PrivateAttr`` keeps internal references (``_tool``, ``_guard``,
``_scope``) off ``model_fields`` and out of ``model_dump`` payloads.

Lazy framework import
---------------------
We never import ``crewai`` at module top level — the SDK must remain
``pip install agentguardproxy``-friendly without the framework extra.
The class definition is wrapped in a builder that resolves
``crewai.tools.BaseTool`` on first instantiation; before that the
``GuardedCrewTool`` symbol is a sentinel that raises a clear
``ImportError`` when constructed.

Usage
-----
    from agentguard.adapters.crewai import GuardedCrewTool, guard_crew_tools

    guarded = GuardedCrewTool(my_tool, guard_url="http://localhost:8080")

    tools = guard_crew_tools(
        tools=[tool_a, tool_b],
        guard_url="http://localhost:8080",
        agent_id="my-crew-agent",
    )
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional

from agentguard import (
    DEFAULT_BASE_URL,
    AgentGuardApprovalRequired,
    AgentGuardDenied,
    Guard,
)


# ---------------------------------------------------------------------------
# Lazy CrewAI BaseTool resolution.
#
# Importing crewai is heavy (LiteLLM, OpenAI client, etc.) and we want
# ``pip install agentguardproxy`` to keep working without the [crewai]
# extra. We resolve the BaseTool the first time a GuardedCrewTool is
# constructed and cache it. A mismatched / missing CrewAI raises a clear
# ImportError instead of a confusing AttributeError deep inside pydantic.
# ---------------------------------------------------------------------------

_CREWAI_BASETOOL: Optional[type] = None
_GUARDED_CLASS: Optional[type] = None


def _is_valid_args_schema(value: Any) -> bool:
    """Return True if ``value`` is a pydantic BaseModel subclass or a
    JSON-schema-shaped dict. Filters MagicMock and other unusable types
    so we never pass an invalid value into pydantic's BaseTool init."""
    if isinstance(value, dict):
        return True
    try:
        from pydantic import BaseModel  # type: ignore[import-not-found]
        return isinstance(value, type) and issubclass(value, BaseModel)
    except Exception:
        return False


def _resolve_crewai_basetool() -> type:
    """Return ``crewai.tools.BaseTool`` or raise a clear ImportError.

    Cached so subsequent constructions do not re-walk the import paths.
    """
    global _CREWAI_BASETOOL
    if _CREWAI_BASETOOL is not None:
        return _CREWAI_BASETOOL
    last_err: Optional[Exception] = None
    for module_name, attr in (
        ("crewai.tools", "BaseTool"),
        ("crewai.tools.base_tool", "BaseTool"),
    ):
        try:
            module = __import__(module_name, fromlist=[attr])
            base = getattr(module, attr, None)
            if base is not None:
                _CREWAI_BASETOOL = base
                return base
        except ImportError as e:
            last_err = e
            continue
    raise ImportError(
        "agentguard CrewAI adapter requires the `crewai` package. "
        "Install it with `pip install 'agentguardproxy[crewai]'`. "
        f"(underlying import error: {last_err!r})"
    )


def _build_guarded_class() -> type:
    """Build the GuardedCrewTool class that subclasses CrewAI's BaseTool.

    The class is constructed once and cached. Re-imports of this module
    return the same class object so isinstance checks remain stable.
    """
    global _GUARDED_CLASS
    if _GUARDED_CLASS is not None:
        return _GUARDED_CLASS

    BaseTool = _resolve_crewai_basetool()
    # pydantic v2 PrivateAttr — these fields are not part of model_fields,
    # not validated, and not emitted by model_dump(). Imported here so the
    # SDK does not require pydantic at module load time.
    from pydantic import PrivateAttr  # type: ignore[import-not-found]

    class GuardedCrewTool(BaseTool):  # type: ignore[misc, valid-type]
        """Hybrid subclass-and-override wrapper around a CrewAI ``BaseTool``.

        Subclasses ``BaseTool`` so framework-side ``isinstance`` checks
        succeed natively (closes the v0.5.0 pydantic-2.12 / CrewAI 1.x
        regression). Every entry point the framework calls is explicitly
        overridden to gate via :meth:`Guard.check` before forwarding.
        """

        # Pydantic private attributes — held on the instance but not part
        # of the validated model (no ``model_fields`` entry) and not
        # emitted by ``model_dump`` / ``model_dump_json``. The ``PrivateAttr``
        # default is set per-instance via ``model_post_init`` because the
        # underlying tool / guard reference is not knowable at class-build
        # time.
        _tool: Any = PrivateAttr(default=None)
        _guard: Any = PrivateAttr(default=None)
        _scope: str = PrivateAttr(default="shell")

        # ----------------------------------------------------------
        # Construction
        # ----------------------------------------------------------

        def __init__(  # type: ignore[no-untyped-def]
            self,
            tool: Any,
            guard: Optional[Guard] = None,
            guard_url: str = DEFAULT_BASE_URL,
            agent_id: str = "",
            scope: str = "shell",
            **_extra: Any,
        ) -> None:
            # Initialise the pydantic side from the wrapped tool's metadata.
            # CrewAI's BaseTool requires ``name`` and ``description`` —
            # pull them from the wrapped instance so the agent registers
            # the tool under the right surface. ``args_schema`` is forwarded
            # only when it is a real pydantic class / dict (filtering
            # MagicMock and other unusable values defensively).
            name_attr = getattr(tool, "name", type(tool).__name__)
            desc_attr = getattr(tool, "description", "")
            init_kwargs: dict = {
                "name": str(name_attr) if not isinstance(name_attr, str) else name_attr,
                "description": (
                    str(desc_attr) if not isinstance(desc_attr, str) else desc_attr
                ),
            }
            args_schema = getattr(tool, "args_schema", None)
            if args_schema is not None and _is_valid_args_schema(args_schema):
                init_kwargs["args_schema"] = args_schema
            super().__init__(**init_kwargs)
            # Pydantic v2 lets us set private attrs after super().__init__.
            # Use object.__setattr__ to be defensive against any pydantic
            # __setattr__ override that intercepts non-private fields.
            object.__setattr__(self, "_tool", tool)
            object.__setattr__(
                self,
                "_guard",
                guard if guard is not None else Guard(guard_url, agent_id=agent_id),
            )
            object.__setattr__(self, "_scope", scope)

        # ----------------------------------------------------------
        # Scope inference and parameter extraction
        # ----------------------------------------------------------

        def _infer_scope(self, tool_input: Any) -> str:
            """Infer scope from runtime input or static metadata."""
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
            """Extract check params from str/dict tool input."""
            params: dict = {}
            if isinstance(tool_input, str):
                params["command"] = tool_input
            elif isinstance(tool_input, dict):
                if "command" in tool_input or "cmd" in tool_input:
                    params["command"] = tool_input.get(
                        "command", tool_input.get("cmd", "")
                    )
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
                    params["path"] = tool_input.get(
                        "path", tool_input.get("file_path", "")
                    )
                if "session_id" in tool_input:
                    params["session_id"] = tool_input["session_id"]
                if "est_cost" in tool_input:
                    params["est_cost"] = tool_input["est_cost"]
            return params

        # ----------------------------------------------------------
        # The single shared gate.
        # ----------------------------------------------------------

        def _check_or_raise(self, tool_input: Any) -> None:
            """Run the policy check and raise on DENY / REQUIRE_APPROVAL."""
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
            raise AgentGuardDenied(
                f"[AgentGuard] Action denied.\nReason: {result.reason}",
                result=result,
            )

        @staticmethod
        def _normalize_tool_input(args: tuple, kwargs: dict) -> Any:
            """Map *args/**kwargs onto a single ``tool_input`` for the gate."""
            if args:
                return args[0] if len(args) == 1 else list(args)
            if kwargs:
                return dict(kwargs)
            return ""

        # ----------------------------------------------------------
        # Synchronous entry points — every CrewAI / LangChain modern path
        # ----------------------------------------------------------

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            """Internal CrewAI sync entry. Implements the parent's abstract
            ``_run``. Every CrewAI sync path eventually flows through here
            (``run`` -> ``_run``, ``invoke`` -> ``_run`` via the structured
            tool conversion, ``to_structured_tool`` copies ``self._run`` as
            its ``func``).
            """
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has neither _run nor run"
            )

        def run(self, *args: Any, **kwargs: Any) -> Any:
            """Public sync entry. Gated.

            CrewAI's BaseTool.run normally dispatches to ``_run`` after
            ``_claim_usage`` accounting; we override it so the gate fires
            BEFORE the parent's accounting (a denied call must not consume
            a usage slot). On ALLOW we call the wrapped tool's ``run`` so
            its own accounting runs.
            """
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has neither run nor _run"
            )

        def invoke(  # type: ignore[override]
            self,
            input: Any = None,  # noqa: A002 — match Runnable signature
            config: Any = None,
            **kwargs: Any,
        ) -> Any:
            """Modern Runnable entry. Gated.

            CrewAI tools that don't define ``invoke`` inherit a parent
            implementation (or none — CrewAI 1.x's BaseTool currently has
            no ``invoke``); either way we provide a gated one. The agent
            runtime calls ``tool.invoke(input=..., config=...)``.
            """
            self._check_or_raise(input)
            inner = self._tool
            if hasattr(inner, "invoke"):
                return inner.invoke(input, config=config, **kwargs)
            if hasattr(inner, "_run"):
                return inner._run(input, **kwargs) if not isinstance(input, dict) else inner._run(**input, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(input, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} exposes no sync entry"
            )

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            """Direct call (``tool(input)``). Gated."""
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if callable(inner):
                try:
                    return inner(*args, **kwargs)
                except TypeError:
                    # Pydantic BaseModel instances are technically callable
                    # in some versions but reject positional args — fall
                    # through to invoke / _run.
                    pass
            if hasattr(inner, "invoke"):
                return inner.invoke(args[0] if args else kwargs)
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} is not callable"
            )

        # ----------------------------------------------------------
        # Async entry points
        # ----------------------------------------------------------

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            """Internal async entry. Gated.

            CrewAI's ``BaseTool._arun`` raises NotImplementedError unless
            the subclass overrides it. We override here so the async path
            is gated without forcing every wrapped tool to define _arun.
            On ALLOW we try the wrapped tool's ``_arun`` first, then
            ``arun``, then fall through to a thread-executor sync path.
            """
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
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
                f"wrapped tool {type(inner).__name__!r} exposes no async path"
            )

        async def arun(self, *args: Any, **kwargs: Any) -> Any:
            """Public async entry. Gated. See ``_arun`` for fallthrough notes."""
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "arun"):
                try:
                    return await inner.arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "_arun"):
                try:
                    return await inner._arun(*args, **kwargs)
                except NotImplementedError:
                    pass
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
                f"wrapped tool {type(inner).__name__!r} exposes no async path"
            )

        async def ainvoke(  # type: ignore[override]
            self,
            input: Any = None,  # noqa: A002
            config: Any = None,
            **kwargs: Any,
        ) -> Any:
            """Modern async Runnable entry. Gated."""
            self._check_or_raise(input)
            inner = self._tool
            if hasattr(inner, "ainvoke"):
                try:
                    return await inner.ainvoke(input, config=config, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "_arun"):
                try:
                    return await inner._arun(input, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "arun"):
                try:
                    return await inner.arun(input, **kwargs)
                except NotImplementedError:
                    pass
            loop = asyncio.get_running_loop()
            if hasattr(inner, "invoke"):
                return await loop.run_in_executor(
                    None, lambda: inner.invoke(input, config=config, **kwargs)
                )
            if hasattr(inner, "_run"):
                return await loop.run_in_executor(
                    None, lambda: inner._run(input, **kwargs)
                )
            if hasattr(inner, "run"):
                return await loop.run_in_executor(
                    None, lambda: inner.run(input, **kwargs)
                )
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} exposes no async path"
            )

        # ----------------------------------------------------------
        # to_structured_tool override.
        #
        # CrewAI's BaseTool.to_structured_tool builds a CrewStructuredTool
        # with ``func=self._run``. Because our _run is gated, the resulting
        # CrewStructuredTool also calls into the gate when invoked. We
        # override so the structured tool gets our gated _run, not the
        # wrapped tool's bare _run.
        # ----------------------------------------------------------

        def to_structured_tool(self) -> Any:
            """Convert to a CrewStructuredTool whose ``func`` is our
            gated ``_run``. Override of the parent so structured-tool
            conversion does not bypass the gate.
            """
            from crewai.tools.structured_tool import CrewStructuredTool  # type: ignore

            self._set_args_schema()
            structured_tool = CrewStructuredTool(
                name=self.name,
                description=self.description,
                args_schema=self.args_schema,
                func=self._run,  # gated
                result_as_answer=self.result_as_answer,
                max_usage_count=self.max_usage_count,
                current_usage_count=self.current_usage_count,
                cache_function=self.cache_function,
            )
            structured_tool._original_tool = self
            return structured_tool

        # ----------------------------------------------------------
        # model_dump / model_dump_json: hide private gating fields.
        #
        # PrivateAttr fields are not in model_fields by default, so they
        # are already excluded from model_dump output. We override anyway
        # to be explicit and to filter any future audit-tooling that might
        # walk __dict__.
        # ----------------------------------------------------------

        def model_dump(self, *args: Any, **kwargs: Any) -> dict:  # type: ignore[override]
            data = super().model_dump(*args, **kwargs)
            # Defensive: strip our private attrs if pydantic ever starts
            # leaking them.
            for k in ("_tool", "_guard", "_scope"):
                data.pop(k, None)
            return data

    _GUARDED_CLASS = GuardedCrewTool
    return GuardedCrewTool


# ---------------------------------------------------------------------------
# Module-level GuardedCrewTool symbol.
#
# We expose a callable factory so `from agentguard.adapters.crewai import
# GuardedCrewTool; GuardedCrewTool(my_tool)` works without a top-level
# crewai import. The factory builds (and caches) the real class on first
# call and constructs an instance.
# ---------------------------------------------------------------------------


class _GuardedCrewToolFactory:
    """Factory whose ``__call__`` returns a GuardedCrewTool instance.

    Behaves like a class for ``isinstance`` and ``issubclass`` checks via
    delegation to the real class once it is built. This means user code
    that does::

        isinstance(t, GuardedCrewTool)

    works regardless of whether the underlying class has been built yet —
    the first construction triggers the build, and the assertion uses the
    real class going forward.

    Module-level constant naming convention: this factory IS the public
    ``GuardedCrewTool`` symbol. The real class object is reachable via
    :func:`_build_guarded_class`.
    """

    def __call__(self, tool: Any, *args: Any, **kwargs: Any) -> Any:
        cls = _build_guarded_class()
        return cls(tool, *args, **kwargs)

    def __instancecheck__(self, obj: Any) -> bool:  # pragma: no cover - delegated
        cls = _GUARDED_CLASS
        if cls is None:
            return False
        return isinstance(obj, cls)

    def __subclasscheck__(self, sub: Any) -> bool:  # pragma: no cover - delegated
        cls = _GUARDED_CLASS
        if cls is None:
            return False
        return issubclass(sub, cls)

    def __repr__(self) -> str:  # pragma: no cover
        return "<GuardedCrewTool factory (lazy crewai.BaseTool subclass)>"


GuardedCrewTool = _GuardedCrewToolFactory()


def guard_crew_tools(
    tools: List[Any],
    guard_url: str = DEFAULT_BASE_URL,
    agent_id: str = "",
    default_scope: str = "shell",
) -> List[Any]:
    """Wrap a list of CrewAI tools with AgentGuard enforcement.

    Args:
        tools: List of CrewAI tools to guard.
        guard_url: URL of the AgentGuard proxy.
        agent_id: Identifier for this agent in audit logs.
        default_scope: Default policy scope.

    Returns:
        List of guarded tool instances. Each instance shares a single
        :class:`Guard` so they batch under one agent_id.
    """
    cls = _build_guarded_class()
    guard = Guard(guard_url, agent_id=agent_id)
    return [cls(tool, guard=guard, scope=default_scope) for tool in tools]
