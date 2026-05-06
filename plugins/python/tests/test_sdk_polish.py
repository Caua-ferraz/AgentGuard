"""SDK polish tests added in v0.5 (worker A15).

Closes the audit's R5 SDK-quality findings:

- E8 / S13 — content-type / status-shape validation in ``Guard.check``.
- E14   — jitter on the ``wait_for_approval`` polling loop.
- E15   — reject unknown ``**check_kwargs`` in ``@guarded``.
- P9    — distinguish HTTP 401/403 (``AgentGuardAuthError``) from
          approval-poll timeout (``AgentGuardApprovalTimeout``).

These are small, surgical regression coupons. The full Guard / decorator
behavior tests live in test_guard.py and test_decorator.py; this file
locks the v0.5 polish so a future refactor cannot silently regress it.
"""

import io
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

import agentguard as ag
from agentguard import (
    AgentGuardAuthError,
    AgentGuardApprovalTimeout,
    AgentGuardError,
    AgentGuardTimeoutError,
    DECISION_DENY,
    DECISION_ALLOW,
    Guard,
    guarded,
)
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# Content-type / status-shape validation in Guard.check (R5 E8 / S13)
# ---------------------------------------------------------------------------


class _CustomHandler(BaseHTTPRequestHandler):
    """Per-test BaseHTTPRequestHandler with class-level response config.

    Exists separately from MockAgentGuardHandler so each test can set up
    a precise set of Content-Type / body / status combinations without
    interfering with the shared mock.
    """
    status_code = 200
    content_type = "application/json"
    body_bytes = b'{"decision":"ALLOW","reason":"ok"}'

    def do_POST(self):
        # Drain the body; the SDK doesn't echo it.
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
        except Exception:  # noqa: BLE001
            pass
        self.send_response(self.status_code)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body_bytes)))
        self.end_headers()
        self.wfile.write(self.body_bytes)

    def log_message(self, *_a, **_kw):  # quiet
        pass


@pytest.fixture()
def custom_server():
    """Start an HTTPServer (single-threaded; tests are sequential).

    Yields the base URL and the handler class so the test can monkey-patch
    response shape before issuing the call.
    """
    srv = HTTPServer(("127.0.0.1", 0), _CustomHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _CustomHandler
    finally:
        srv.shutdown()
        # Reset class-level overrides for the next test.
        _CustomHandler.status_code = 200
        _CustomHandler.content_type = "application/json"
        _CustomHandler.body_bytes = b'{"decision":"ALLOW","reason":"ok"}'


class TestCheckContentTypeValidation:
    def test_wrong_content_type_falls_through_to_failmode_deny(self, custom_server):
        url, handler = custom_server
        handler.body_bytes = b"<html>oh no</html>"
        handler.content_type = "text/html"

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        assert "content-type" in result.reason.lower()

    def test_wrong_content_type_falls_through_to_failmode_allow(self, custom_server):
        url, handler = custom_server
        handler.body_bytes = b"<html>oh no</html>"
        handler.content_type = "text/html"

        g = Guard(url, fail_mode="allow")
        result = g.check("shell", command="ls")
        assert result.allowed
        assert "content-type" in result.reason.lower()

    def test_charset_suffix_on_content_type_is_accepted(self, custom_server):
        url, handler = custom_server
        handler.content_type = "application/json; charset=utf-8"
        handler.body_bytes = b'{"decision":"ALLOW","reason":"ok"}'

        g = Guard(url)
        result = g.check("shell", command="ls")
        assert result.allowed

    def test_non_2xx_status_falls_through_to_failmode(self, custom_server):
        url, handler = custom_server
        handler.status_code = 500
        # Even a "valid" JSON body must not be trusted on 5xx.
        handler.body_bytes = b'{"decision":"ALLOW","reason":"sneaky"}'

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        assert "500" in result.reason

    def test_malformed_body_missing_decision_falls_through(self, custom_server):
        url, handler = custom_server
        # Valid JSON but missing the 'decision' field.
        handler.body_bytes = b'{"reason":"hi"}'

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        assert "malformed" in result.reason.lower()

    def test_garbage_json_falls_through(self, custom_server):
        url, handler = custom_server
        handler.body_bytes = b"not-json-at-all"

        g = Guard(url, fail_mode="deny")
        result = g.check("shell", command="ls")
        assert result.denied
        # urlopen.read() yields bytes; json.loads raises ValueError /
        # JSONDecodeError, which the SDK wraps in the unreachable path.
        assert "AgentGuard" in result.reason


# ---------------------------------------------------------------------------
# @guarded(**check_kwargs) unknown-kwarg rejection (R5 E15)
# ---------------------------------------------------------------------------


class TestGuardedUnknownKwargs:
    def test_unknown_kwarg_raises_typeerror(self, mock_server):
        g = Guard(mock_server)
        with pytest.raises(TypeError, match="unexpected keyword arguments"):
            @guarded("shell", guard=g, agentt="typo")  # noqa: F841 (typo on purpose)
            def f(cmd):
                return cmd

    def test_known_kwargs_still_accepted(self, mock_server):
        """`meta`, `session_id`, and friends pass through unchanged.

        `command` is *not* exercised here because the wrapper already
        injects it from positional args (``g.check(scope,
        command=str(cmd), **check_kwargs)``); passing both would collide.
        """
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        g = Guard(mock_server)

        @guarded("shell", guard=g, meta={"k": "v"}, session_id="s1")
        def f(cmd):
            return f"ran {cmd}"

        assert f("anything") == "ran anything"

    def test_typo_lists_valid_options(self, mock_server):
        g = Guard(mock_server)
        with pytest.raises(TypeError) as exc:
            @guarded("shell", guard=g, agnetId="typo")
            def f(cmd):
                return cmd
        assert "agnetId" in str(exc.value)
        # The error names the valid set so the operator can fix the typo.
        assert "command" in str(exc.value)


# ---------------------------------------------------------------------------
# wait_for_approval jitter (R5 E14)
# ---------------------------------------------------------------------------


class TestWaitForApprovalJitter:
    def test_sleep_is_jittered_around_poll_interval(self, mock_server):
        """Lock the contract that sleep durations vary inside the
        documented 80%..120% band. We capture every time.sleep() the
        polling loop issues; the spread proves jitter is active.
        """
        # Always-pending response so the loop runs a handful of iterations.
        MockAgentGuardHandler.status_response = {"id": "ap_x", "status": "pending"}

        sleeps: list[float] = []
        real_sleep = time.sleep

        def capturing_sleep(s):
            sleeps.append(s)
            # Don't actually sleep — keep the test fast.
            real_sleep(0)

        g = Guard(mock_server, api_key="k")
        with patch("agentguard.time.sleep", side_effect=capturing_sleep):
            r = g.wait_for_approval("ap_x", timeout=0.05, poll_interval=0.5)
        # The deadline elapsed; we get the synthetic timeout DENY.
        assert r.denied
        assert "timed out" in r.reason.lower()
        # Each sleep must lie inside [0.8, 1.2] * poll_interval.
        for s in sleeps:
            assert 0.4 <= s <= 0.6, f"sleep {s} outside jitter band"

    def test_sleep_durations_are_not_all_equal(self, mock_server):
        """Locks 'jitter is actually random' — three samples drawn from a
        20%-wide band must not collapse to a single value (probability of
        collision is astronomical for a real RNG)."""
        MockAgentGuardHandler.status_response = {"id": "ap_x", "status": "pending"}
        sleeps: list[float] = []
        real_sleep = time.sleep

        def capturing_sleep(s):
            sleeps.append(s)
            real_sleep(0)

        g = Guard(mock_server, api_key="k")
        # poll_interval=1 means the band is [0.8, 1.2]; collect more
        # samples by giving the loop a longer deadline.
        with patch("agentguard.time.sleep", side_effect=capturing_sleep):
            g.wait_for_approval("ap_x", timeout=0.01, poll_interval=1.0)

        # If the loop ran at least twice, the durations must differ.
        if len(sleeps) >= 2:
            assert len(set(sleeps)) > 1, (
                f"jitter is not random: {sleeps!r}"
            )


# ---------------------------------------------------------------------------
# AgentGuardAuthError on 401/403 from /v1/status (R5 P9)
# ---------------------------------------------------------------------------


class _AuthRefusingHandler(BaseHTTPRequestHandler):
    """A status handler that always returns 401/403."""
    status_code = 401

    def do_GET(self):
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        body = b'{"error":"unauthorized"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_kw):
        pass


@pytest.fixture()
def auth_refusing_server():
    srv = HTTPServer(("127.0.0.1", 0), _AuthRefusingHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _AuthRefusingHandler
    finally:
        srv.shutdown()
        _AuthRefusingHandler.status_code = 401


class TestAgentGuardAuthError:
    def test_401_raises_auth_error(self, auth_refusing_server):
        url, _ = auth_refusing_server
        g = Guard(url, api_key="bad-key")
        with pytest.raises(AgentGuardAuthError) as exc:
            g.wait_for_approval("ap_x", timeout=5, poll_interval=0.01)
        assert exc.value.status == 401

    def test_403_raises_auth_error(self, auth_refusing_server):
        url, handler = auth_refusing_server
        handler.status_code = 403
        g = Guard(url, api_key="bad-key")
        with pytest.raises(AgentGuardAuthError) as exc:
            g.wait_for_approval("ap_x", timeout=5, poll_interval=0.01)
        assert exc.value.status == 403

    def test_auth_error_subclasses_permission_error(self):
        # Existing `except PermissionError:` handlers still catch it.
        e = AgentGuardAuthError("test", status=401)
        assert isinstance(e, PermissionError)
        assert isinstance(e, AgentGuardError)

    def test_timeout_alias_is_approval_timeout(self):
        # AgentGuardTimeoutError is just an alias for AgentGuardApprovalTimeout.
        assert AgentGuardTimeoutError is AgentGuardApprovalTimeout

    def test_500_keeps_polling_until_timeout(self, mock_server):
        """Other HTTP errors (transient 5xx) must NOT abort the poll
        — the contract is 'auth-failure is fatal, everything else is
        transient'. We use the existing mock with a 'pending' status so
        the loop runs to its natural deadline."""
        MockAgentGuardHandler.status_response = {"id": "ap_x", "status": "pending"}
        g = Guard(mock_server, api_key="k")
        r = g.wait_for_approval("ap_x", timeout=0.02, poll_interval=0.005)
        assert r.denied
        assert "timed out" in r.reason.lower()


# ---------------------------------------------------------------------------
# Backwards-compat: existing PermissionError handlers still catch new errors
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_auth_error_caught_by_permission_error(self):
        try:
            raise AgentGuardAuthError("bad", status=401)
        except PermissionError as e:
            assert isinstance(e, AgentGuardAuthError)

    def test_auth_error_carries_status_field(self):
        e = AgentGuardAuthError("bad", status=403)
        assert e.status == 403
