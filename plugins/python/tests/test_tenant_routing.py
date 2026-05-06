"""Tests for the v0.5+ tenant_id constructor parameter.

The Python SDK accepts an optional ``tenant_id`` constructor kwarg that
controls whether HTTP calls go to the legacy ``/v1/...`` URL family or the
tenant-aware ``/v1/t/{tenant}/...`` family added in v0.5 (worker A7).

These tests do NOT spin up the real Go server — they exercise the URL
builder via :meth:`Guard._url` directly and via a small in-process mock
that records the request path. The Go-side routing is covered by the
``pkg/proxy/tenant_routing_test.go`` integration tests.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List

import pytest

from agentguard import Guard, LOCAL_TENANT_ID


# ---------- Direct URL-builder tests ----------


def test_legacy_url_when_no_tenant():
    """Guard with no tenant_id builds the legacy /v1/<suffix> URL."""
    g = Guard(base_url="http://example.test:8080")
    assert g._url("/check") == "http://example.test:8080/v1/check"
    assert g._url("/approve/ap_abc") == "http://example.test:8080/v1/approve/ap_abc"


def test_local_tenant_uses_legacy():
    """tenant_id="local" is treated as an alias for the legacy URL family."""
    g = Guard(base_url="http://example.test:8080", tenant_id=LOCAL_TENANT_ID)
    assert g._url("/check") == "http://example.test:8080/v1/check"
    assert g._url("/status/ap_xyz") == "http://example.test:8080/v1/status/ap_xyz"


def test_custom_tenant_in_url():
    """Non-local tenant_id triggers the /v1/t/{tenant}/... family."""
    g = Guard(base_url="http://example.test:8080", tenant_id="acme")
    assert g._url("/check") == "http://example.test:8080/v1/t/acme/check"
    assert g._url("/approve/ap_1") == "http://example.test:8080/v1/t/acme/approve/ap_1"
    assert g._url("/deny/ap_2") == "http://example.test:8080/v1/t/acme/deny/ap_2"
    assert g._url("/status/ap_3") == "http://example.test:8080/v1/t/acme/status/ap_3"
    assert g._url("/audit") == "http://example.test:8080/v1/t/acme/audit"


def test_tenant_id_is_url_quoted():
    """tenant_id values containing reserved chars are URL-quoted, not
    allowed to break the path layout."""
    g = Guard(base_url="http://example.test:8080", tenant_id="weird/tenant")
    url = g._url("/check")
    # The slash is escaped to %2F so the proxy sees a single tenant
    # segment, not a path-traversal forgery.
    assert url == "http://example.test:8080/v1/t/weird%2Ftenant/check"

    # Spaces and other reserved chars also escape.
    g2 = Guard(base_url="http://example.test:8080", tenant_id="t with spaces")
    assert g2._url("/check") == "http://example.test:8080/v1/t/t%20with%20spaces/check"


def test_env_var_default(monkeypatch):
    """AGENTGUARD_TENANT_ID populates tenant_id when no explicit kwarg."""
    monkeypatch.setenv("AGENTGUARD_TENANT_ID", "fromenv")
    g = Guard(base_url="http://example.test:8080")
    assert g.tenant_id == "fromenv"
    assert g._url("/check") == "http://example.test:8080/v1/t/fromenv/check"


def test_explicit_tenant_overrides_env(monkeypatch):
    """An explicit tenant_id kwarg wins over AGENTGUARD_TENANT_ID."""
    monkeypatch.setenv("AGENTGUARD_TENANT_ID", "fromenv")
    g = Guard(base_url="http://example.test:8080", tenant_id="explicit")
    assert g.tenant_id == "explicit"
    assert g._url("/check") == "http://example.test:8080/v1/t/explicit/check"


def test_explicit_empty_string_disables_env(monkeypatch):
    """tenant_id="" honors the caller's intent to disable an env var.

    Passing the literal empty string is distinct from passing None: it
    suppresses the env-var lookup so a scoped test can revert to the
    legacy URL family even when the developer machine has
    AGENTGUARD_TENANT_ID exported.
    """
    monkeypatch.setenv("AGENTGUARD_TENANT_ID", "fromenv")
    g = Guard(base_url="http://example.test:8080", tenant_id="")
    assert g.tenant_id == ""
    assert g._url("/check") == "http://example.test:8080/v1/check"


def test_local_alias_after_env(monkeypatch):
    """tenant_id="local" suppresses the /v1/t/local prefix even when the
    env var would otherwise route through the tenant-aware family."""
    monkeypatch.setenv("AGENTGUARD_TENANT_ID", "acme")
    g = Guard(base_url="http://example.test:8080", tenant_id="local")
    # Caller explicitly chose "local"; the URL is the legacy form.
    assert g._url("/check") == "http://example.test:8080/v1/check"


# ---------- End-to-end via mock HTTP server ----------


class _PathCaptureHandler(BaseHTTPRequestHandler):
    """Records every request path so tests can assert on URL routing.

    Returns a 200 with a deterministic JSON body so Guard.check decodes
    successfully regardless of the URL.
    """

    paths: List[str] = []

    def _record(self) -> None:
        _PathCaptureHandler.paths.append(self.path)

    def do_POST(self) -> None:  # noqa: N802
        self._record()
        body = json.dumps({"decision": "ALLOW", "reason": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        body = json.dumps({"id": "ap_x", "status": "pending"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002, ARG002
        pass


@pytest.fixture()
def path_capture_server():
    """Start a mock HTTP server that records every request path."""
    _PathCaptureHandler.paths = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PathCaptureHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_check_uses_legacy_path_for_local_tenant(path_capture_server):
    """Legacy URL is used when tenant_id is unset, even with real HTTP."""
    g = Guard(base_url=path_capture_server, agent_id="alice")
    g.check("shell", command="ls -la")
    assert _PathCaptureHandler.paths[-1] == "/v1/check"


def test_check_uses_tenant_path_for_custom_tenant(path_capture_server):
    """Custom tenant_id routes through /v1/t/{tenant}/check."""
    g = Guard(base_url=path_capture_server, agent_id="alice", tenant_id="acme")
    g.check("shell", command="ls -la")
    assert _PathCaptureHandler.paths[-1] == "/v1/t/acme/check"


def test_approve_routes_through_tenant_path(path_capture_server):
    """approve() honors tenant_id."""
    g = Guard(
        base_url=path_capture_server,
        agent_id="alice",
        tenant_id="acme",
        api_key="k",
    )
    g.approve("ap_xyz")
    assert _PathCaptureHandler.paths[-1] == "/v1/t/acme/approve/ap_xyz"


def test_deny_routes_through_tenant_path(path_capture_server):
    """deny() honors tenant_id."""
    g = Guard(
        base_url=path_capture_server,
        agent_id="alice",
        tenant_id="acme",
        api_key="k",
    )
    g.deny("ap_xyz")
    assert _PathCaptureHandler.paths[-1] == "/v1/t/acme/deny/ap_xyz"


def test_wait_for_approval_routes_through_tenant_path(path_capture_server):
    """wait_for_approval polls the tenant-aware /status URL."""
    g = Guard(
        base_url=path_capture_server,
        agent_id="alice",
        tenant_id="acme",
        api_key="k",
    )
    # Mock returns "pending"; wait once and bail out via the timeout.
    g.wait_for_approval("ap_xyz", timeout=1, poll_interval=0)
    # We can't assume exactly one poll fired before the deadline; assert
    # every recorded path matches the tenant-aware shape.
    assert _PathCaptureHandler.paths
    for p in _PathCaptureHandler.paths:
        assert p == "/v1/t/acme/status/ap_xyz", (
            f"unexpected path {p!r}; expected tenant-aware status URL"
        )
