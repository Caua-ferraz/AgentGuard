"""Shared fixtures for AgentGuard Python SDK tests."""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


class MockAgentGuardHandler(BaseHTTPRequestHandler):
    """Configurable mock for the AgentGuard /v1/* endpoints.

    Class-level attributes control the response for each endpoint.
    Override them via the ``mock_server`` fixture's ``handler_class`` before
    the request arrives.
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


@pytest.fixture()
def mock_server():
    """Start a mock AgentGuard HTTP server on an OS-assigned port.

    Yields the base URL (e.g. ``http://127.0.0.1:54321``).
    Resets class-level response overrides after each test.
    """
    server = HTTPServer(("127.0.0.1", 0), MockAgentGuardHandler)
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
