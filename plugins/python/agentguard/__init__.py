"""
AgentGuard Python SDK

Lightweight client for checking actions against AgentGuard policies.

Usage:
    from agentguard import Guard

    guard = Guard("http://localhost:8080")
    result = guard.check("shell", command="rm -rf ./data")

    if result.allowed:
        execute(command)
    elif result.needs_approval:
        print(f"Approve at: {result.approval_url}")
    else:
        print(f"Blocked: {result.reason}")
"""

import functools
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib import request, error
from urllib.parse import quote as urlquote

# Public API surface. Everything else in this module is internal.
__all__ = [
    "Guard",
    "CheckResult",
    "guarded",
    "AgentGuardError",
    "AgentGuardDenied",
    "AgentGuardApprovalRequired",
    "AgentGuardApprovalTimeout",
    "AgentGuardAuthError",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_APPROVAL_TIMEOUT",
    "DEFAULT_POLL_INTERVAL",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DECISION_REQUIRE_APPROVAL",
    "LOCAL_TENANT_ID",
    "FAIL_MODE_DENY",
    "FAIL_MODE_ALLOW",
]

# Module-level logger. Used for non-fatal warnings (HTTP shape mismatches,
# unexpected content types) where the SDK still returns a CheckResult per
# the configured fail-mode but operators want visibility into the underlying
# transport oddity. Callers who want quiet behavior add a NullHandler.
log = logging.getLogger("agentguard")

# --- Defaults and constants ---
DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 5           # seconds, for individual HTTP calls
DEFAULT_APPROVAL_TIMEOUT = 300  # seconds, for wait_for_approval
DEFAULT_POLL_INTERVAL = 2       # seconds

# Decision values (must match the Go backend)
DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

# API endpoint paths. The leading "/v1" is added by Guard._url so a single
# code path handles both the legacy /v1/<suffix> URLs and the tenant-aware
# /v1/t/<tenant>/<suffix> form.
ENDPOINT_CHECK = "/check"
ENDPOINT_APPROVE = "/approve/"
ENDPOINT_DENY = "/deny/"
ENDPOINT_STATUS = "/status/"

# Default tenant when the SDK caller did not pass tenant_id and
# AGENTGUARD_TENANT_ID is unset. "local" is also the literal alias the Go
# proxy maps onto its single-tenant code path; passing it explicitly is
# equivalent to omitting the field. Any other value triggers the
# /v1/t/{tenant_id}/... URL family.
LOCAL_TENANT_ID = "local"

# Fail-mode values for the Guard() constructor. "deny" fails closed when the
# AgentGuard proxy is unreachable (the default). "allow" fails open —
# permitted as an explicit opt-in for agents whose threat model treats
# AgentGuard as best-effort; the caller is responsible for any resulting
# safety implications.
FAIL_MODE_DENY = "deny"
FAIL_MODE_ALLOW = "allow"
_VALID_FAIL_MODES = (FAIL_MODE_DENY, FAIL_MODE_ALLOW)


@dataclass
class CheckResult:
    """Result of a policy check."""
    decision: str
    reason: str
    matched_rule: str = ""
    approval_id: str = ""
    approval_url: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == DECISION_ALLOW

    @property
    def denied(self) -> bool:
        return self.decision == DECISION_DENY

    @property
    def needs_approval(self) -> bool:
        return self.decision == DECISION_REQUIRE_APPROVAL


# --- Typed exceptions raised by the @guarded decorator ---
#
# All three extend PermissionError so callers that already catch
# PermissionError keep working. New callers can catch the specific
# subclass and read structured fields (result, approval_id,
# approval_url) instead of parsing error strings.

class AgentGuardError(PermissionError):
    """Base class for AgentGuard-raised permission failures.

    Carries the originating :class:`CheckResult` (if any) so callers can
    inspect the decision, matched rule, and approval metadata without
    re-running the check. Messages preserve a stable string format so
    existing regex/text matchers continue to work.
    """

    def __init__(self, message: str, result: Optional[CheckResult] = None):
        super().__init__(message)
        self.result = result


class AgentGuardDenied(AgentGuardError):
    """Raised when the policy decision was DENY."""


class AgentGuardApprovalRequired(AgentGuardError):
    """Raised when the policy decision was REQUIRE_APPROVAL and the
    decorator was not configured to wait.
    """

    def __init__(
        self,
        message: str,
        result: Optional[CheckResult] = None,
        approval_id: str = "",
        approval_url: str = "",
    ):
        super().__init__(message, result)
        self.approval_id = approval_id
        self.approval_url = approval_url


class AgentGuardApprovalTimeout(AgentGuardError):
    """Raised when wait_for_approval was requested but the approval did
    not resolve before the deadline. The underlying ``result`` is the
    synthetic DENY/"Approval timed out" produced by :meth:`Guard.wait_for_approval`.
    """

    def __init__(
        self,
        message: str,
        result: Optional[CheckResult] = None,
        approval_id: str = "",
    ):
        super().__init__(message, result)
        self.approval_id = approval_id


class AgentGuardAuthError(AgentGuardError):
    """Raised when the AgentGuard server returned 401 or 403 from an
    auth-gated endpoint (``/v1/approve``, ``/v1/deny``, ``/v1/status``,
    ``/v1/audit``).

    Distinguishes "API key wrong / expired" from "approval poll timed
    out" so callers can surface the right operator-facing error.
    Extends :class:`AgentGuardError` so existing
    ``except PermissionError:`` handlers still catch it.
    """

    def __init__(
        self,
        message: str,
        status: int = 0,
        result: Optional[CheckResult] = None,
    ):
        super().__init__(message, result)
        self.status = status


# AgentGuardTimeoutError is an alias for AgentGuardApprovalTimeout
# kept for backwards compatibility — `except AgentGuardApprovalTimeout:`
# handlers still match.
AgentGuardTimeoutError = AgentGuardApprovalTimeout


class Guard:
    """Client for the AgentGuard server — the SDK enforcement layer.

    Call ``guard.check(scope, ...)`` before every gated action, or use the
    ``@guarded`` decorator / framework adapters in ``agentguard.adapters``
    for higher-level integration. For wire-level enforcement that needs no
    agent code change, see the ``agentguard-mcp-gateway`` and
    ``agentguard-llm-proxy`` binaries.
    """

    def __init__(
        self,
        base_url: str = "",
        agent_id: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        api_key: str = "",
        fail_mode: str = FAIL_MODE_DENY,
        tenant_id: Optional[str] = None,
    ):
        """Construct a Guard client.

        Args:
            base_url: Proxy URL. Falls back to AGENTGUARD_URL or the
                package default.
            agent_id: Stable identifier sent with every check.
            timeout: HTTP timeout in seconds for individual calls.
            api_key: Bearer token for /v1/approve, /v1/deny, /v1/status.
                Falls back to AGENTGUARD_API_KEY.
            fail_mode: Behavior when the proxy is unreachable. "deny"
                (the default) returns a DENY result so the agent fails
                closed. "allow" returns an ALLOW result — use only when
                the threat model treats AgentGuard as best-effort and
                the caller accepts the safety trade-off. An invalid
                value raises ValueError at construction.
            tenant_id: Optional tenant identifier. When set to a
                non-empty value other than ``"local"``, every HTTP call is
                routed through the tenant-aware ``/v1/t/{tenant_id}/...``
                URL family instead of the legacy ``/v1/...`` path.
                ``None`` or ``"local"`` selects the legacy URLs. Falls
                back to ``AGENTGUARD_TENANT_ID``. The bundled
                FilePolicyProvider only recognises ``"local"``;
                multi-tenant providers can register others.
        """
        if fail_mode not in _VALID_FAIL_MODES:
            raise ValueError(
                f"fail_mode must be one of {_VALID_FAIL_MODES!r}, got {fail_mode!r}"
            )
        self.base_url = (base_url or os.environ.get("AGENTGUARD_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.agent_id = agent_id
        self.timeout = timeout
        self.api_key = api_key or os.environ.get("AGENTGUARD_API_KEY", "")
        self.fail_mode = fail_mode
        # tenant_id resolution priority: explicit kwarg → AGENTGUARD_TENANT_ID
        # env → empty string. An explicit empty string from the caller is
        # honored (env lookup is skipped) so callers can disable an
        # accidentally-set environment variable in scoped tests.
        if tenant_id is None:
            tenant_id = os.environ.get("AGENTGUARD_TENANT_ID", "")
        self.tenant_id = tenant_id

    def _url(self, suffix: str) -> str:
        """Build the absolute URL for the given /v1 suffix.

        ``suffix`` is the path *after* ``/v1``, e.g. ``"/check"``,
        ``"/approve/ap_abc"``, ``"/audit"``. Tenant resolution:

        - tenant_id is unset, empty, or the literal ``"local"``:
          legacy URL family ``{base_url}/v1{suffix}``.
        - tenant_id is anything else: ``{base_url}/v1/t/{tenant_id}{suffix}``,
          with ``tenant_id`` URL-quoted via ``urllib.parse.quote(safe="")``
          so values containing ``/`` (or other reserved characters) are
          escaped rather than allowed to break the path layout.
        """
        if self.tenant_id and self.tenant_id != LOCAL_TENANT_ID:
            return f"{self.base_url}/v1/t/{urlquote(self.tenant_id, safe='')}{suffix}"
        return f"{self.base_url}/v1{suffix}"

    def check(
        self,
        scope: str,
        *,
        action: str = "",
        command: str = "",
        path: str = "",
        domain: str = "",
        url: str = "",
        session_id: str = "",
        est_cost: float = 0.0,
        meta: Optional[dict] = None,
    ) -> CheckResult:
        """Check an action against the policy.

        Args:
            scope: The rule scope (filesystem, shell, network, browser, cost, data)
            action: Action type (read, write, delete) — used with filesystem scope
            command: Shell command string — used with shell scope
            path: File path — used with filesystem scope
            domain: Target domain — used with network/browser scope
            url: Full URL — used with network scope
            session_id: Session identifier for session-level cost tracking
            est_cost: Estimated cost of this action in USD (for cost scope)
            meta: Additional metadata

        Returns:
            CheckResult with the policy decision
        """
        payload = {
            "scope": scope,
            "agent_id": self.agent_id,
        }
        if action:
            payload["action"] = action
        if command:
            payload["command"] = command
        if path:
            payload["path"] = path
        if domain:
            payload["domain"] = domain
        if url:
            payload["url"] = url
        if session_id:
            payload["session_id"] = session_id
        if est_cost:
            payload["est_cost"] = est_cost
        if meta:
            payload["meta"] = meta

        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self._url(ENDPOINT_CHECK),
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                # --- Honest response validation ---
                # A misconfigured reverse proxy serving an HTML error
                # page or a chunked plaintext body would silently produce
                # a JSONDecodeError that we *do* catch — but 200-OK plus
                # a non-JSON body that happened to start with `{` would
                # slip through. We positively assert:
                #   1. status in 2xx
                #   2. Content-Type is application/json (charset suffix ok)
                #   3. body is a dict carrying a `decision` field
                # Any failure logs at WARNING and falls through to
                # _failmode_result so we surface a CheckResult consistent
                # with fail_mode rather than raising into the caller.
                #
                # Implementation note: ``urllib`` responses expose status
                # via either ``.status`` (3.9+) or ``.getcode()`` (older);
                # tests sometimes use minimal fakes that lack both. We
                # treat "no status attribute" as "trust the response"
                # for back-compat with legacy test fakes, and only enforce
                # status/header checks when the attributes are present.
                status_attr = getattr(resp, "status", None)
                if status_attr is None and hasattr(resp, "getcode"):
                    try:
                        status_attr = resp.getcode()
                    except Exception:  # noqa: BLE001
                        status_attr = None
                if status_attr is not None and (status_attr < 200 or status_attr >= 300):
                    log.warning(
                        "agentguard: /v1/check returned non-2xx status=%s; "
                        "applying fail_mode=%s", status_attr, self.fail_mode,
                    )
                    return self._failmode_result(
                        f"AgentGuard returned status {status_attr}"
                    )

                hdrs = getattr(resp, "headers", None)
                if hdrs is not None:
                    try:
                        ctype = (hdrs.get("Content-Type") or "").lower()
                    except Exception:  # noqa: BLE001
                        ctype = ""
                    # Accept "application/json" and "application/json; charset=...".
                    # A response object with headers must announce JSON; an
                    # object without headers is presumed to be a test fake
                    # and not subject to this check.
                    if ctype and not ctype.startswith("application/json"):
                        log.warning(
                            "agentguard: /v1/check returned unexpected Content-Type "
                            "%r; applying fail_mode=%s", ctype, self.fail_mode,
                        )
                        return self._failmode_result(
                            f"AgentGuard returned unexpected content-type {ctype!r}"
                        )

                body = json.loads(resp.read())
                if not isinstance(body, dict) or "decision" not in body:
                    log.warning(
                        "agentguard: /v1/check returned malformed body "
                        "(missing 'decision'); applying fail_mode=%s",
                        self.fail_mode,
                    )
                    return self._failmode_result(
                        "AgentGuard returned malformed response body"
                    )
                return CheckResult(
                    decision=body.get("decision", DECISION_DENY),
                    reason=body.get("reason", ""),
                    matched_rule=body.get("matched_rule", ""),
                    approval_id=body.get("approval_id", ""),
                    approval_url=body.get("approval_url", ""),
                )
        except (error.URLError, OSError, json.JSONDecodeError) as e:
            # Transport failure. fail_mode picks the default: "deny"
            # fails closed; "allow" is an opt-in for callers whose
            # threat model treats AgentGuard as advisory.
            #
            # We catch three classes here:
            #   - URLError: urlopen() connection-phase failures (connect
            #     refused, DNS, SSL).
            #   - OSError: post-connect transport failures raised from
            #     resp.read() — ConnectionResetError, BrokenPipeError,
            #     socket.timeout under heavy concurrency. These are NOT
            #     URLError subclasses, so before this catch they would
            #     propagate to the caller and (in threaded callers like
            #     the MCP adapter) silently kill the worker.
            #   - JSONDecodeError: a truncated/garbage response body is
            #     an unreachable-proxy symptom from the caller's point
            #     of view; fail_mode is the right knob.
            return self._failmode_result(
                f"AgentGuard unreachable ({self.fail_mode}): {e}"
            )

    def _failmode_result(self, reason: str) -> CheckResult:
        """Build a CheckResult honoring ``self.fail_mode``.

        Centralizes the fail-mode dispatch so transport failures and HTTP
        contract violations (bad status, wrong content type, malformed
        body) all flow through one decision point.
        """
        decision = DECISION_ALLOW if self.fail_mode == FAIL_MODE_ALLOW else DECISION_DENY
        return CheckResult(decision=decision, reason=reason)

    def _auth_headers(self) -> dict:
        """Return Authorization header if api_key is set."""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def approve(self, approval_id: str) -> bool:
        """Approve a pending action."""
        req = request.Request(
            self._url(f"{ENDPOINT_APPROVE}{approval_id}"),
            headers=self._auth_headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout):
                return True
        except error.URLError:
            return False

    def deny(self, approval_id: str) -> bool:
        """Deny a pending action."""
        req = request.Request(
            self._url(f"{ENDPOINT_DENY}{approval_id}"),
            headers=self._auth_headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout):
                return True
        except error.URLError:
            return False

    def wait_for_approval(
        self,
        approval_id: str,
        timeout: int = DEFAULT_APPROVAL_TIMEOUT,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> CheckResult:
        """Block until a pending action is approved or denied (or timeout).

        Sends the API key on every poll because /v1/status is now auth-gated
        on servers configured with --api-key.

        Behavior:
        - Polling is jittered to ``[0.8, 1.2] * poll_interval`` to avoid
          synchronized retries from many clients waiting on the same
          approval bursting the proxy at exact ``poll_interval`` boundaries.
        - HTTP 401 / 403 from the status endpoint raise
          :class:`AgentGuardAuthError` immediately. Continuing to poll
          would just spin until ``timeout`` elapsed and return a
          synthetic "Approval timed out" DENY, masking the real cause
          (wrong/expired API key). Other HTTPErrors and URLErrors are
          swallowed and retried so transient network blips do not abort
          a long-running approval wait.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            # Poll the status endpoint for resolution
            req = request.Request(
                self._url(f"{ENDPOINT_STATUS}{approval_id}"),
                headers=self._auth_headers(),
                method="GET",
            )
            try:
                with request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read())
                    if body.get("status") == "resolved" and body.get("decision") in (
                        DECISION_ALLOW,
                        DECISION_DENY,
                    ):
                        return CheckResult(
                            decision=body["decision"],
                            reason=body.get("reason", "resolved"),
                        )
            except error.HTTPError as e:
                # 401/403: auth is broken. Fail fast — looping until
                # `timeout` would just hide the real error from the operator.
                if e.code in (401, 403):
                    raise AgentGuardAuthError(
                        f"AgentGuard rejected status poll for "
                        f"{approval_id!r} with HTTP {e.code} "
                        f"(check api_key)",
                        status=e.code,
                    )
                # Other HTTPErrors (5xx, transient): keep polling.
            except error.URLError:
                # Connection-level error (DNS, connection refused, TLS).
                # Keep polling — the proxy may come back up before the deadline.
                pass
            # Jittered sleep: 80%..120% of poll_interval. random.random() is
            # OK for jitter — non-cryptographic, just spreading retries.
            actual_sleep = poll_interval * (0.8 + 0.4 * random.random())
            time.sleep(actual_sleep)

        return CheckResult(decision=DECISION_DENY, reason="Approval timed out")


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
