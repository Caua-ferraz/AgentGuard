"""Shared fixtures for the real-framework integration suite.

The unit-test fixture ``mock_server`` from ``tests/conftest.py`` is fine for
single-call assertions. The integration suite needs more: per-test response
queues so an agent loop that makes N tool calls can be steered through a
sequence of ALLOW / DENY / REQUIRE_APPROVAL decisions without flipping a
class-level slot in the middle of the run.

We do NOT mock the framework libraries themselves — that is the whole point
of these tests. We only mock the AgentGuard HTTP server.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Deque, Dict, List, Optional

import pytest


# ---------------------------------------------------------------------------
# A queue-driven mock that lets each test enqueue a sequence of responses
# AgentGuard would have returned. Index by call N -> response. A test that
# enqueues ``[ALLOW, DENY]`` will see the first /v1/check call return ALLOW
# and the second return DENY.
# ---------------------------------------------------------------------------


_DEFAULT_ALLOW = {"decision": "ALLOW", "reason": "test default", "matched_rule": "allow:test"}
_DEFAULT_STATUS = {"id": "ap_int", "status": "pending"}


class _IntegrationHandler(BaseHTTPRequestHandler):
    """HTTP handler with per-server response queues.

    Server-level queues live on the server instance (``self.server``), not
    on the class, so concurrent integration tests cannot stomp each other.
    """

    # Keep BaseHTTPRequestHandler quiet — we don't want stderr noise during
    # the real agent loops.
    def log_message(self, format, *args):  # noqa: A002 — base class signature
        pass

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_POST(self):  # noqa: N802 — base class API
        body = self._read_body()
        srv = self.server  # type: ignore[attr-defined]
        with srv.lock:
            srv.requests.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        if self.path == "/v1/check":
            with srv.lock:
                resp = srv.check_queue.popleft() if srv.check_queue else dict(srv.default_check)
            self._json(200, resp)
            return
        if self.path.startswith("/v1/approve/") or self.path.startswith("/v1/deny/"):
            self._json(200, {"status": "ok", "id": self.path.rsplit("/", 1)[-1]})
            return
        self._json(404, {"error": "not found"})

    def do_GET(self):  # noqa: N802
        srv = self.server  # type: ignore[attr-defined]
        if self.path.startswith("/v1/status/"):
            with srv.lock:
                resp = srv.status_queue.popleft() if srv.status_queue else dict(srv.default_status)
            self._json(200, resp)
            return
        self._json(404, {"error": "not found"})

    def _json(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _IntegrationServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with per-instance response queues.

    The unit-test handler keeps response state on a class attribute, which
    is fine for one-call tests. Integration tests need queues so they can
    enqueue a sequence (ALLOW, ALLOW, DENY, ...) for an agent loop. Putting
    the queues on the server instance also avoids cross-test contamination
    when pytest-xdist or asyncio task interleaving runs tests in parallel.
    """

    request_queue_size = 128

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.lock = threading.Lock()
        self.check_queue: Deque[dict] = deque()
        self.status_queue: Deque[dict] = deque()
        self.requests: List[dict] = []
        self.default_check: dict = dict(_DEFAULT_ALLOW)
        self.default_status: dict = dict(_DEFAULT_STATUS)


class IntegrationMock:
    """Thin facade tests use to drive the mock and inspect captured calls."""

    def __init__(self, server: _IntegrationServer, base_url: str):
        self._server = server
        self.base_url = base_url

    def enqueue_check(self, *responses: dict) -> None:
        with self._server.lock:
            for r in responses:
                self._server.check_queue.append(dict(r))

    def enqueue_status(self, *responses: dict) -> None:
        with self._server.lock:
            for r in responses:
                self._server.status_queue.append(dict(r))

    def set_default_check(self, response: dict) -> None:
        with self._server.lock:
            self._server.default_check = dict(response)

    def requests_to(self, path: str) -> List[dict]:
        with self._server.lock:
            return [r for r in self._server.requests if r["path"] == path]

    @property
    def all_requests(self) -> List[dict]:
        with self._server.lock:
            return list(self._server.requests)

    def reset(self) -> None:
        with self._server.lock:
            self._server.check_queue.clear()
            self._server.status_queue.clear()
            self._server.requests.clear()
            self._server.default_check = dict(_DEFAULT_ALLOW)
            self._server.default_status = dict(_DEFAULT_STATUS)


@pytest.fixture()
def integration_mock():
    """Boot a per-test AgentGuard mock with response queues.

    Yields an :class:`IntegrationMock` exposing ``base_url``, queue helpers
    and a list of captured requests.
    """
    server = _IntegrationServer(("127.0.0.1", 0), _IntegrationHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    facade = IntegrationMock(server, base_url)
    try:
        yield facade
    finally:
        server.shutdown()
        server.server_close()


# Convenience helpers for building canned decision payloads.

def allow(reason: str = "ok", rule: str = "allow:integration") -> dict:
    return {"decision": "ALLOW", "reason": reason, "matched_rule": rule}


def deny(reason: str = "blocked", rule: str = "deny:integration") -> dict:
    return {"decision": "DENY", "reason": reason, "matched_rule": rule}


def require_approval(approval_id: str = "ap_int", reason: str = "needs review") -> dict:
    return {
        "decision": "REQUIRE_APPROVAL",
        "reason": reason,
        "matched_rule": "require_approval:integration",
        "approval_id": approval_id,
        "approval_url": f"http://localhost:8080/dashboard?approve={approval_id}",
    }
