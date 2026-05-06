"""End-to-end MCP gateway integration tests (Phase 3 — AT).

A15's ``test_mcp_gateway.py`` drives the gateway with a ``_FakeUpstream``
test double for speed. The contribution of this file: spawn the gateway
against a *real* downstream MCP server (via subprocess) and drive an
``initialize`` → ``tools/list`` → ``tools/call`` flow end-to-end. This
catches regressions where the gateway's stdio bridge mishandles framing,
buffering, or shutdown — invisible to the in-process test.

Why a Python stub server instead of ``npx -y
@modelcontextprotocol/server-everything``?
  - ``npx`` is not reliably on the PATH for every CI runner.
  - The MCP team's reference servers shift versions, which would make
    this test flaky.
  - We control exactly what the stub returns, so failures point at the
    gateway, not the upstream.

The stub lives at ``tests/integration/_mcp_stub_server.py``. It speaks
the MCP-stdio JSON-RPC subset the gateway needs (initialize, tools/list,
tools/call, notifications/*).

Closes the v0.5 plan AT brief item: "Real MCP server gating ... write a
tiny Python MCP-stdio stub server you write in
``tests/integration/_mcp_stub_server.py``. Drive the gateway against it.
Send a ``tools/list``, ``tools/call``, etc. Assert AgentGuard gates each
call."
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from agentguard import Guard
from agentguard.adapters.mcp import GuardedMCPGateway

from .conftest import allow, deny


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helper — locate the stub server module path so we can spawn a Python
# subprocess that runs it on stdio.
# ---------------------------------------------------------------------------


def _stub_command() -> list[str]:
    """Build the argv that invokes the stub server through the test runner's
    Python interpreter. This is OS-portable and avoids relying on entry
    points / installed scripts.
    """
    stub_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "_mcp_stub_server.py",
    )
    return [sys.executable, stub_path]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGatewayAgainstRealStub:
    """Spawn the stub MCP server and drive the gateway through it."""

    def test_initialize_forwarded_to_real_upstream(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-gw-init")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            resp = gw.handle({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            })
        finally:
            gw._upstream.close()

        assert resp["id"] == 1
        assert resp["result"]["serverInfo"]["name"] == "at-mcp-stub"
        # The gateway DOES NOT consult AgentGuard for initialize — we
        # don't gate the lifecycle handshake.
        assert len(integration_mock.requests_to("/v1/check")) == 0

    def test_tools_list_forwards_full_set(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-gw-list")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            resp = gw.handle({
                "jsonrpc": "2.0", "id": 7, "method": "tools/list",
            })
        finally:
            gw._upstream.close()

        names = sorted(t["name"] for t in resp["result"]["tools"])
        assert names == ["echo", "http_get", "read_file"]
        # tools/list is NOT gated — the agent only asks "what tools exist?"
        assert len(integration_mock.requests_to("/v1/check")) == 0

    def test_tools_call_allow_forwards_to_upstream(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-gw-allow")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            # Drive the lazy tools/list refresh first so scope cache is warm.
            gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
            resp = gw.handle({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "hi"}},
            })
        finally:
            gw._upstream.close()

        # Upstream's response landed unchanged.
        assert resp["id"] == 8
        text = resp["result"]["content"][0]["text"]
        assert text == "echoed: hi"
        # Exactly one /v1/check call before the call was forwarded.
        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 1, f"expected 1 gate call, got {bodies!r}"

    def test_tools_call_deny_does_not_forward(self, integration_mock):
        integration_mock.set_default_check(deny(reason="rule:no-shell"))
        guard = Guard(integration_mock.base_url, agent_id="at-gw-deny")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
            resp = gw.handle({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "evil"}},
            })
        finally:
            gw._upstream.close()

        # The gateway returned an isError result without forwarding.
        assert resp["id"] == 9
        assert resp["result"]["isError"] is True
        text = resp["result"]["content"][0]["text"]
        assert "denied" in text.lower()
        assert "rule:no-shell" in text

    def test_path_argument_routes_through_filesystem_scope(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-gw-fs")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
            gw.handle({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/etc/hosts"},
                },
            })
        finally:
            gw._upstream.close()

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        # tools/list is not gated, so only the tools/call check is recorded.
        assert len(bodies) == 1
        assert bodies[0]["scope"] == "filesystem"
        assert bodies[0]["path"] == "/etc/hosts"

    def test_url_argument_routes_through_network_scope(self, integration_mock):
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-gw-net")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
            gw.handle({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "http_get",
                    "arguments": {"url": "https://api.example.com/v1/x"},
                },
            })
        finally:
            gw._upstream.close()

        bodies = [
            json.loads(r["body"])
            for r in integration_mock.requests_to("/v1/check")
        ]
        assert len(bodies) == 1
        assert bodies[0]["scope"] == "network"
        assert bodies[0]["url"] == "https://api.example.com/v1/x"
        assert bodies[0]["domain"] == "api.example.com"

    def test_sequential_calls_each_check_independently(self, integration_mock):
        """Three tools/call frames in a row → three /v1/check calls. The
        upstream subprocess must survive all three round-trips."""
        # First two ALLOW, third DENY — the gateway must propagate each
        # decision independently and not poison subsequent calls.
        integration_mock.enqueue_check(
            allow(),
            allow(),
            deny(reason="quota"),
        )
        guard = Guard(integration_mock.base_url, agent_id="at-gw-seq")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
            r1 = gw.handle({
                "jsonrpc": "2.0", "id": 21, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "first"}},
            })
            r2 = gw.handle({
                "jsonrpc": "2.0", "id": 22, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "second"}},
            })
            r3 = gw.handle({
                "jsonrpc": "2.0", "id": 23, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "third"}},
            })
        finally:
            gw._upstream.close()

        # First two went through; third was denied.
        assert r1["result"]["content"][0]["text"] == "echoed: first"
        assert r2["result"]["content"][0]["text"] == "echoed: second"
        assert r3["result"]["isError"] is True
        # Three checks total.
        assert len(integration_mock.requests_to("/v1/check")) == 3

    def test_notifications_do_not_emit_responses(self, integration_mock):
        """``notifications/initialized`` must not produce a stdout response
        (notifications are MCP-defined as response-less)."""
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="at-gw-notif")
        gw = GuardedMCPGateway(upstream=_stub_command(), guard=guard)
        try:
            out = gw.handle({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })
        finally:
            gw._upstream.close()

        assert out is None
