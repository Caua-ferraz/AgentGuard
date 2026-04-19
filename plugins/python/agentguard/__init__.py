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
import os
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib import request, error

# --- Defaults and constants ---
DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 5           # seconds, for individual HTTP calls
DEFAULT_APPROVAL_TIMEOUT = 300  # seconds, for wait_for_approval
DEFAULT_POLL_INTERVAL = 2       # seconds

# Decision values (must match the Go backend)
DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

# API endpoint paths
ENDPOINT_CHECK = "/v1/check"
ENDPOINT_APPROVE = "/v1/approve/"
ENDPOINT_DENY = "/v1/deny/"
ENDPOINT_STATUS = "/v1/status/"

# Fail-mode values for the Guard() constructor. "deny" fails closed when the
# AgentGuard proxy is unreachable (the v0.4.0 default and current v0.4.1
# default). "allow" fails open — permitted as an explicit opt-in for agents
# whose threat model treats AgentGuard as best-effort; the caller is
# responsible for any resulting safety implications.
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


class Guard:
    """Client for the AgentGuard proxy."""

    def __init__(
        self,
        base_url: str = "",
        agent_id: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        api_key: str = "",
        fail_mode: str = FAIL_MODE_DENY,
    ):
        """Construct a Guard client.

        Args:
            base_url: Proxy URL. Falls back to AGENTGUARD_URL or the
                package default.
            agent_id: Stable identifier sent with every check.
            timeout: HTTP timeout in seconds for individual calls.
            api_key: Bearer token for /v1/approve, /v1/deny, /v1/status.
                Falls back to AGENTGUARD_API_KEY.
            fail_mode: Behavior when the proxy is unreachable. "deny" (the
                v0.4.0 default, current v0.4.1 default) returns a DENY
                result so the agent fails closed. "allow" returns an ALLOW
                result — use only when the threat model treats AgentGuard
                as best-effort and the caller accepts the safety trade-off.
                An invalid value raises ValueError at construction so the
                bug surfaces at startup instead of mid-request.

        v0.5.0 parity note: the TypeScript SDK already honors `failMode`,
        default `"deny"`. v0.5.0 will align both SDKs on explicit fail-mode
        documentation. Adding `fail_mode` now is purely forward-compatible;
        omitting it preserves v0.4.0 semantics exactly.
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
            f"{self.base_url}{ENDPOINT_CHECK}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read())
                return CheckResult(
                    decision=body.get("decision", DECISION_DENY),
                    reason=body.get("reason", ""),
                    matched_rule=body.get("matched_rule", ""),
                    approval_id=body.get("approval_id", ""),
                    approval_url=body.get("approval_url", ""),
                )
        except (error.URLError, OSError, json.JSONDecodeError) as e:
            # Transport failure. fail_mode picks the safe default: "deny"
            # preserves v0.4.0 fail-closed semantics; "allow" is an opt-in
            # for callers whose threat model treats AgentGuard as advisory.
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
            decision = DECISION_ALLOW if self.fail_mode == FAIL_MODE_ALLOW else DECISION_DENY
            return CheckResult(
                decision=decision,
                reason=f"AgentGuard unreachable ({self.fail_mode}): {e}",
            )

    def _auth_headers(self) -> dict:
        """Return Authorization header if api_key is set."""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def approve(self, approval_id: str) -> bool:
        """Approve a pending action."""
        req = request.Request(
            f"{self.base_url}{ENDPOINT_APPROVE}{approval_id}",
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
            f"{self.base_url}{ENDPOINT_DENY}{approval_id}",
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
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            # Poll the status endpoint for resolution
            req = request.Request(
                f"{self.base_url}{ENDPOINT_STATUS}{approval_id}",
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
            except error.URLError:
                pass
            time.sleep(poll_interval)

        return CheckResult(decision=DECISION_DENY, reason="Approval timed out")


# Convenience decorator for guarding functions
def guarded(scope: str, guard: Optional[Guard] = None, **check_kwargs):
    """Decorator that checks policy before executing a function.

    Usage:
        guard = Guard("http://localhost:8080")

        @guarded("shell", guard=guard)
        def run_command(cmd: str):
            os.system(cmd)
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            g = guard or Guard()
            # Try to extract meaningful info from args
            cmd = args[0] if args else kwargs.get("command", kwargs.get("cmd", ""))
            result = g.check(scope, command=str(cmd), **check_kwargs)
            if result.allowed:
                return func(*args, **kwargs)
            elif result.needs_approval:
                raise PermissionError(
                    f"Action requires approval. Approve at: {result.approval_url}"
                )
            else:
                raise PermissionError(f"Action denied by AgentGuard: {result.reason}")
        return wrapper
    return decorator
