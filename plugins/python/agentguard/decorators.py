"""The ``@guarded`` decorator: policy-check-then-call for plain
functions. Framework-specific integration lives in
``agentguard.adapters``; this module only depends on the core client.
"""

import functools
from typing import Optional

from agentguard.core import (
    DEFAULT_APPROVAL_TIMEOUT,
    DEFAULT_POLL_INTERVAL,
    AgentGuardApprovalRequired,
    AgentGuardApprovalTimeout,
    AgentGuardDenied,
    Guard,
)

# Set of kwargs that ``guarded(**check_kwargs)`` is allowed to forward to
# ``Guard.check``. Anything outside this set is almost always a typo
# (e.g. ``agent="x"`` instead of ``meta={"agent":"x"}``) — and silently
# forwarding it to ``Guard.check`` would either be dropped on the floor
# (``check`` only inspects keyword args it knows about) or raise a
# confusing TypeError much later in the call chain. Reject at the
# decorator boundary so the typo surfaces at definition time.
_GUARDED_VALID_CHECK_KWARGS = frozenset({
    "action",
    "command",
    "path",
    "domain",
    "url",
    "session_id",
    "est_cost",
    "meta",
})


# Convenience decorator for guarding functions
def guarded(
    scope: str,
    guard: Optional[Guard] = None,
    *,
    wait_for_approval: bool = False,
    approval_timeout: int = DEFAULT_APPROVAL_TIMEOUT,
    approval_poll_interval: int = DEFAULT_POLL_INTERVAL,
    **check_kwargs,
):
    """Decorator that checks policy before executing a function.

    Default behavior (v0.4.0/v0.4.1 compatible):
        @guarded("shell", guard=guard)
        def run_command(cmd: str):
            os.system(cmd)

        run_command("ls")        # executes if ALLOW
        run_command("rm -rf /")  # raises AgentGuardDenied (a PermissionError)

    Opt-in block-until-resolved:
        @guarded(
            "cost",
            guard=guard,
            wait_for_approval=True,
            approval_timeout=300,
            approval_poll_interval=2,
        )
        def expensive_call(prompt: str):
            ...

    On REQUIRE_APPROVAL, with ``wait_for_approval=True`` the wrapper calls
    :meth:`Guard.wait_for_approval` and then dispatches on the resolved
    decision: ALLOW runs the function, DENY raises :class:`AgentGuardDenied`,
    a synthetic "Approval timed out" raises :class:`AgentGuardApprovalTimeout`.
    With ``wait_for_approval=False`` (default), the wrapper raises
    :class:`AgentGuardApprovalRequired` immediately. That class extends
    ``PermissionError``, so existing ``except PermissionError:`` handlers
    continue to work unchanged.

    Unknown ``**check_kwargs`` raise ``TypeError`` at decoration time.
    Only the keyword arguments :meth:`Guard.check` understands
    (``action``, ``command``, ``path``, ``domain``, ``url``,
    ``session_id``, ``est_cost``, ``meta``) are accepted; a typo like
    ``agent="x"`` is rejected at definition time rather than silently
    dropped.
    """
    unknown = set(check_kwargs) - _GUARDED_VALID_CHECK_KWARGS
    if unknown:
        raise TypeError(
            f"@guarded got unexpected keyword arguments: "
            f"{sorted(unknown)!r}. Valid options: "
            f"{sorted(_GUARDED_VALID_CHECK_KWARGS)!r}"
        )

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            g = guard or Guard()
            # Try to extract meaningful info from args
            cmd = args[0] if args else kwargs.get("command", kwargs.get("cmd", ""))
            result = g.check(scope, command=str(cmd), **check_kwargs)

            if result.allowed:
                return func(*args, **kwargs)

            if result.needs_approval:
                if wait_for_approval:
                    # Block until a human resolves or the deadline elapses.
                    resolved = g.wait_for_approval(
                        result.approval_id,
                        timeout=approval_timeout,
                        poll_interval=approval_poll_interval,
                    )
                    if resolved.allowed:
                        return func(*args, **kwargs)
                    if resolved.denied and resolved.reason == "Approval timed out":
                        raise AgentGuardApprovalTimeout(
                            f"Approval for {result.approval_id} timed out after "
                            f"{approval_timeout}s",
                            result=resolved,
                            approval_id=result.approval_id,
                        )
                    raise AgentGuardDenied(
                        f"Action denied by AgentGuard: {resolved.reason}",
                        result=resolved,
                    )
                raise AgentGuardApprovalRequired(
                    # Stable message text — text-matchers in caller code
                    # depend on it.
                    f"Action requires approval. Approve at: {result.approval_url}",
                    result=result,
                    approval_id=result.approval_id,
                    approval_url=result.approval_url,
                )

            raise AgentGuardDenied(
                f"Action denied by AgentGuard: {result.reason}",
                result=result,
            )
        return wrapper
    return decorator
