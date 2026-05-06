"""Tests for the MCP gateway preview shipped in v0.5 (worker A15).

The gateway spawns a downstream MCP server via stdio, brokers JSON-RPC
frames between the client and the downstream, and gates every
``tools/call`` through AgentGuard.

Closes R7 E6 partial: ``python -m agentguard.adapters.mcp --upstream ...``
is now a real entry point with tools registered via the upstream, not
the empty-server footgun. Full multi-upstream + capability merging is
deferred to v0.6 (Phase 4B Gateway).
"""

import json
import sys
import threading
import time
from typing import Any, Dict, List, Optional

import pytest

from agentguard import Guard
from agentguard.adapters.mcp import (
    GuardedMCPGateway,
    GuardedMCPServer,
    _UpstreamProcess,
)
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# Tiny in-memory upstream that mimics _UpstreamProcess's Popen API.
# Used to drive the gateway without spawning a real subprocess.
# ---------------------------------------------------------------------------


class _FakeUpstream:
    """Test double for :class:`_UpstreamProcess`.

    Exposes the same .request() / .close() surface the gateway calls.
    Records every frame the gateway forwarded so tests can assert
    forwarding semantics.

    The handler callable maps ``method`` → response (dict) or None for
    notifications. Tests can replace it per-case.
    """

    def __init__(self):
        self.calls: List[dict] = []
        self.tools: List[dict] = [
            {"name": "read_file", "description": "Read a file", "inputSchema": {}},
            {"name": "write_file", "description": "Write a file", "inputSchema": {}},
        ]
        self._closed = False
        self.fail_next = False

    def request(self, frame: dict, timeout: float = 30.0) -> Optional[dict]:
        self.calls.append(frame)
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated upstream failure")
        method = frame.get("method", "")
        req_id = frame.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "fake-upstream", "version": "1.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }
        if method == "tools/list":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"tools": self.tools},
            }
        if method == "tools/call":
            tool_name = (frame.get("params") or {}).get("name", "")
            args = (frame.get("params") or {}).get("arguments", {})
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"upstream ran {tool_name} with {json.dumps(args)}"}],
                },
            }
        if method.startswith("notifications/"):
            return None
        return {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"upstream: unknown method {method}"},
        }

    def close(self) -> None:
        self._closed = True


# ---------------------------------------------------------------------------
# Gateway behavior
# ---------------------------------------------------------------------------


@pytest.fixture()
def gateway_with_fake(mock_server):
    """Build a gateway whose upstream is a _FakeUpstream.

    Wires real Guard + MockAgentGuardHandler so /v1/check responses can
    be configured per test.
    """
    guard = Guard(mock_server, agent_id="gateway-test")
    fake = _FakeUpstream()
    gw = GuardedMCPGateway(upstream=["echo", "ignored"], guard=guard)
    # Replace the spawned process with our fake.
    gw._upstream.close()  # terminate the real echo subprocess immediately
    gw._upstream = fake
    return gw, fake


class TestGatewayInit:
    def test_empty_upstream_rejected(self):
        with pytest.raises(ValueError, match="upstream"):
            GuardedMCPGateway(upstream=[])


class TestGatewayInitialize:
    def test_initialize_forwarded_to_upstream(self, gateway_with_fake):
        gw, fake = gateway_with_fake
        resp = gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        })
        assert resp["result"]["serverInfo"]["name"] == "fake-upstream"
        # The gateway forwarded the frame verbatim.
        assert fake.calls[-1]["method"] == "initialize"


class TestGatewayToolsList:
    def test_tools_list_forwarded(self, gateway_with_fake):
        gw, fake = gateway_with_fake
        resp = gw.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [t["name"] for t in resp["result"]["tools"]]
        assert names == ["read_file", "write_file"]


class TestGatewayToolsCall:
    def test_allow_forwards_to_upstream(self, gateway_with_fake):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        gw, fake = gateway_with_fake

        # Trigger the lazy tools/list refresh first so scope cache is populated.
        gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
        fake.calls.clear()

        resp = gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/etc/hosts"}},
        })
        # Upstream got the call.
        assert any(c.get("method") == "tools/call" for c in fake.calls)
        assert "upstream ran read_file" in resp["result"]["content"][0]["text"]

    def test_deny_does_not_forward(self, gateway_with_fake):
        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
        gw, fake = gateway_with_fake

        gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
        fake.calls.clear()

        resp = gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/secret"}},
        })
        assert resp["result"]["isError"] is True
        # No tools/call frame was forwarded after the deny decision.
        assert all(c.get("method") != "tools/call" for c in fake.calls)
        assert "denied" in resp["result"]["content"][0]["text"].lower()

    def test_require_approval_does_not_forward(self, gateway_with_fake):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_xyz",
            "approval_url": "http://approve/ap_xyz",
        }
        gw, fake = gateway_with_fake

        gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
        fake.calls.clear()

        resp = gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "/tmp/x"}},
        })
        assert resp["result"]["isError"] is True
        # Approval URL surfaces in the response so the MCP client can render it.
        assert "ap_xyz" in resp["result"]["content"][0]["text"]
        assert all(c.get("method") != "tools/call" for c in fake.calls)

    def test_path_argument_upgrades_scope_to_filesystem(self, gateway_with_fake):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        gw, fake = gateway_with_fake

        gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})

        gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "filesystem"
        assert body["path"] == "/tmp/x"

    def test_url_argument_upgrades_scope_to_network(self, gateway_with_fake):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        gw, fake = gateway_with_fake

        # Add a network-flavoured tool to the fake.
        fake.tools.append({"name": "fetch", "description": "fetch", "inputSchema": {}})
        gw.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})

        gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "fetch", "arguments": {"url": "https://api.example.com/x"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "network"
        assert body["domain"] == "api.example.com"

    def test_upstream_failure_returns_internal_error(self, gateway_with_fake):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        gw, fake = gateway_with_fake
        # Pre-populate the scope cache so the lazy `tools/list` refresh
        # inside `_gate_tools_call` does not eat our `fail_next` flag.
        gw._tool_scope["read_file"] = "shell"

        fake.fail_next = True
        resp = gw.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/x"}},
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32603
        assert "upstream" in resp["error"]["message"].lower()


class TestGatewayNotifications:
    def test_notifications_initialized_returns_none(self, gateway_with_fake):
        gw, fake = gateway_with_fake
        out = gw.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert out is None
        # Forwarded to upstream so it sees the lifecycle event.
        assert any(c.get("method") == "notifications/initialized" for c in fake.calls)


# ---------------------------------------------------------------------------
# _process_frame robustness — survive malformed / handler-throwing frames
# ---------------------------------------------------------------------------


class TestServerFrameRobustness:
    def test_malformed_json_does_not_crash(self, mock_server, capsys):
        """A bad frame is logged and dropped; the next valid frame still
        gets a response. R5 E6 / S9 regression coupon."""
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("ping", "", handler=lambda **_: "pong", scope="shell")

        import io
        from unittest.mock import patch as _patch

        stdin = io.StringIO()
        stdin.write("{bad-json\n")
        stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "ping", "arguments": {}},
        }) + "\n")
        stdin.seek(0)
        stdout = io.StringIO()

        with _patch("agentguard.adapters.mcp.sys.stdin", stdin), \
             _patch("agentguard.adapters.mcp.sys.stdout", stdout):
            s.run()

        # Only the valid frame produced a response.
        lines = [l for l in stdout.getvalue().splitlines() if l]
        assert len(lines) == 1
        assert json.loads(lines[0])["id"] == 1
        # The malformed frame was logged to stderr.
        err = capsys.readouterr().err
        assert "malformed JSON frame" in err

    def test_handler_exception_yields_internal_error_response(self, mock_server, capsys):
        """When ``_handle_request`` raises (not the wrapped handler — the
        request *router* itself), the server emits a JSON-RPC -32603
        Internal error response and keeps reading."""
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)

        # Force _handle_request to throw on the first frame.
        original = s._handle_request
        calls = {"n": 0}

        def boom(req):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("router boom")
            return original(req)

        s._handle_request = boom  # type: ignore[assignment]

        import io
        from unittest.mock import patch as _patch

        stdin = io.StringIO()
        stdin.write(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "initialize"}) + "\n")
        stdin.write(json.dumps({"jsonrpc": "2.0", "id": 100, "method": "initialize"}) + "\n")
        stdin.seek(0)
        stdout = io.StringIO()

        with _patch("agentguard.adapters.mcp.sys.stdin", stdin), \
             _patch("agentguard.adapters.mcp.sys.stdout", stdout):
            s.run()

        responses = [json.loads(l) for l in stdout.getvalue().splitlines() if l]
        # First frame got an internal-error response; second frame succeeded.
        assert responses[0]["id"] == 99
        assert responses[0]["error"]["code"] == -32603
        assert responses[1]["id"] == 100
        assert "result" in responses[1]
        # Stderr captured the handler exception.
        err = capsys.readouterr().err
        assert "router boom" in err


# ---------------------------------------------------------------------------
# Redactor application on synthesized commands (R7 T7)
# ---------------------------------------------------------------------------


class TestSynthesizedCommandRedaction:
    def test_synthesized_command_redacts_secret_kv(self, mock_server):
        """A shell-scope tool with no `command` argument synthesizes
        ``f"{tool} {json.dumps(args)}"``; if the args carry a literal
        ``password=hunter2`` style token it must be redacted before it
        reaches /v1/check (audit log + DENY reason echo)."""
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("custom_thing", "", handler=lambda **_: "", scope="shell")

        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "custom_thing",
                "arguments": {"flags": "--password=hunter2 --user=root"},
            },
        })

        body = json.loads(MockAgentGuardHandler.last_request_body)
        # Synthesized command was forwarded to the policy server.
        cmd = body.get("command", "")
        # Either the value is replaced by [REDACTED] or the whole `password=hunter2`
        # match is collapsed; the regex is `(secret|token|password|api_key)\s*=\s*\S+`
        # so 'hunter2' must NOT appear.
        assert "hunter2" not in cmd, f"secret leaked into command: {cmd!r}"
        assert "[REDACTED]" in cmd

    def test_caller_supplied_command_also_redacted(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("run", "", handler=lambda **_: "", scope="shell")

        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "run",
                "arguments": {"command": "curl -H 'Authorization: Bearer sk-abc123xyz'"},
            },
        })

        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert "sk-abc123xyz" not in body["command"]
        assert "[REDACTED]" in body["command"]
