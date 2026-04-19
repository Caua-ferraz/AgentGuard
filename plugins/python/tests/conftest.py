"""Shared fixtures for AgentGuard Python SDK tests."""

import json
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import pytest


class MockAgentGuardHandler(BaseHTTPRequestHandler):
    """Configurable mock for the AgentGuard /v1/* endpoints.

    Class-level attributes control the response for each endpoint.
    Override them via the ``mock_server`` fixture's ``handler_class`` before
    the request arrives.

    Thread-safety note
    ------------------
    The fixture uses ``ThreadingHTTPServer`` so multiple requests can be
    served in parallel (required by concurrency tests). ``last_request_body``
    and ``last_request_headers`` are class-level slots written from every
    handler thread — they reflect whichever request wrote LAST, not any
    particular one. Tests that make a **single** call and then assert on
    these slots are fine; tests that do multiple concurrent calls must
    assert on their own results, not on this shared state.
    """

    # Default responses (overridden per-test via class attributes)
    check_response = {
        "decision": "ALLOW",
        "reason": "test policy",
        "matched_rule": "allow:test",
    }
    status_response = {"id": "ap_123", "status": "pending"}

    # Capture the last request body and headers for assertions
    last_request_body = None
    last_request_headers = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        MockAgentGuardHandler.last_request_body = body
        MockAgentGuardHandler.last_request_headers = dict(self.headers)

        if self.path == "/v1/check":
            self._json_response(200, self.check_response)
        elif self.path.startswith("/v1/approve/"):
            aid = self.path.split("/")[-1]
            self._json_response(200, {"status": "approved", "id": aid})
        elif self.path.startswith("/v1/deny/"):
            aid = self.path.split("/")[-1]
            self._json_response(200, {"status": "denied", "id": aid})
        else:
            self._json_response(404, {"error": "not found"})

    def do_GET(self):
        if self.path.startswith("/v1/status/"):
            self._json_response(200, self.status_response)
        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        pass  # suppress noisy output during tests


class _DeepBacklogHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a larger listen backlog.

    socketserver.TCPServer defaults request_queue_size to 5. Under the
    32-thread burst in test_concurrent_tool_calls the kernel was RST-ing
    the overflow connections on CI Linux runners (flaky 29/32 assertion).
    128 comfortably absorbs the burst; the effective value is capped by
    net.core.somaxconn on the host, but 128 matches Linux's common cap.
    """
    request_queue_size = 128


@pytest.fixture()
def mock_server():
    """Start a mock AgentGuard HTTP server on an OS-assigned port.

    Yields the base URL (e.g. ``http://127.0.0.1:54321``).
    Resets class-level response overrides after each test.
    """
    # ThreadingHTTPServer handles each connection on its own thread. The
    # single-threaded HTTPServer used to drop concurrent requests with
    # ConnectionResetError under load (reproduced flakily in CI); the
    # deep-backlog subclass further prevents the 32-thread burst from
    # overflowing the listen queue.
    server = _DeepBacklogHTTPServer(("127.0.0.1", 0), MockAgentGuardHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()

    # Reset class-level overrides so the next test gets clean defaults
    MockAgentGuardHandler.check_response = {
        "decision": "ALLOW",
        "reason": "test policy",
        "matched_rule": "allow:test",
    }
    MockAgentGuardHandler.status_response = {"id": "ap_123", "status": "pending"}
    MockAgentGuardHandler.last_request_body = None
    MockAgentGuardHandler.last_request_headers = None
