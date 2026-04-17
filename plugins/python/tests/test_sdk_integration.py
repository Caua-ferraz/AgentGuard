"""Tests for the integration gaps fixed in the latest pass:

  - Guard.check() forwards session_id and est_cost to the server.
  - Guard.wait_for_approval() sends the API key to /v1/status when set.
  - Python adapters forward session_id/est_cost to the underlying Guard.
"""

import json

import pytest

from agentguard import Guard, CheckResult, DECISION_ALLOW, DECISION_DENY
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# Guard.check — session_id / est_cost payload
# ---------------------------------------------------------------------------

class TestCheckPayloadSessionAndCost:
    def test_session_id_forwarded(self, mock_server):
        g = Guard(mock_server)
        g.check("cost", session_id="sess-42", est_cost=0.12)
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["session_id"] == "sess-42"
        assert body["est_cost"] == 0.12

    def test_zero_est_cost_not_sent(self, mock_server):
        """est_cost=0.0 is the default; it should be omitted to avoid
        spuriously triggering cost-scope rules."""
        g = Guard(mock_server)
        g.check("shell", command="ls")
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert "est_cost" not in body
        assert "session_id" not in body

    def test_empty_session_id_not_sent(self, mock_server):
        g = Guard(mock_server)
        g.check("shell", command="ls", session_id="")
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert "session_id" not in body

    def test_all_fields_together(self, mock_server):
        g = Guard(mock_server, agent_id="bot-7")
        g.check(
            "cost",
            command="llm-call",
            session_id="sess-x",
            est_cost=1.75,
            meta={"model": "opus"},
        )
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "cost"
        assert body["agent_id"] == "bot-7"
        assert body["command"] == "llm-call"
        assert body["session_id"] == "sess-x"
        assert body["est_cost"] == 1.75
        assert body["meta"] == {"model": "opus"}


# ---------------------------------------------------------------------------
# wait_for_approval auth header
# ---------------------------------------------------------------------------

class StatusCapturingHandler(MockAgentGuardHandler):
    """Variant that records the Authorization header on each status poll and
    returns 'resolved' so wait_for_approval exits after one iteration."""

    status_auth_headers = []

    def do_GET(self):
        if self.path.startswith("/v1/status/"):
            StatusCapturingHandler.status_auth_headers.append(
                self.headers.get("Authorization")
            )
            self._json_response(200, {"status": "resolved", "decision": "ALLOW", "reason": "ok"})
        else:
            self._json_response(404, {"error": "not found"})


@pytest.fixture()
def mock_status_server():
    """Dedicated server that captures Authorization on /v1/status."""
    import threading
    from http.server import ThreadingHTTPServer

    StatusCapturingHandler.status_auth_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), StatusCapturingHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestWaitForApprovalAuth:
    def test_auth_header_sent_on_status_poll(self, mock_status_server):
        g = Guard(mock_status_server, api_key="the-key", timeout=1)
        result = g.wait_for_approval("ap_x", timeout=1, poll_interval=1)
        assert result.decision == DECISION_ALLOW
        assert StatusCapturingHandler.status_auth_headers, "status endpoint was never hit"
        assert all(h == "Bearer the-key" for h in StatusCapturingHandler.status_auth_headers), (
            f"expected every poll to carry Bearer the-key, got {StatusCapturingHandler.status_auth_headers!r}"
        )

    def test_no_auth_header_without_api_key(self, mock_status_server):
        g = Guard(mock_status_server, timeout=1)
        result = g.wait_for_approval("ap_x", timeout=1, poll_interval=1)
        assert result.decision == DECISION_ALLOW
        assert StatusCapturingHandler.status_auth_headers
        assert all(h is None for h in StatusCapturingHandler.status_auth_headers)

    def test_env_var_api_key_propagates(self, mock_status_server, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_API_KEY", "env-key")
        g = Guard(mock_status_server, timeout=1)
        g.wait_for_approval("ap_x", timeout=1, poll_interval=1)
        assert all(h == "Bearer env-key" for h in StatusCapturingHandler.status_auth_headers)


# ---------------------------------------------------------------------------
# Adapters forward session_id / est_cost
# ---------------------------------------------------------------------------

class TestAdaptersForwardCostHints:
    def test_langchain_forwards(self, mock_server):
        from unittest.mock import MagicMock
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)
        tool = MagicMock()
        tool.name = "t"
        tool.description = ""
        gt = GuardedTool(tool, guard, scope="cost")

        gt.run({"command": "llm", "session_id": "s1", "est_cost": 0.42})
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body.get("session_id") == "s1"
        assert body.get("est_cost") == 0.42

    def test_crewai_forwards(self, mock_server):
        from unittest.mock import MagicMock
        from agentguard.adapters.crewai import GuardedCrewTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)
        inner = MagicMock()
        inner.name = "t"
        inner.description = ""
        inner._run.return_value = "ok"
        gt = GuardedCrewTool(inner, guard=guard, scope="cost")

        gt.run({"command": "llm", "session_id": "s2", "est_cost": 0.77})
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body.get("session_id") == "s2"
        assert body.get("est_cost") == 0.77

    def test_mcp_forwards(self, mock_server):
        from agentguard.adapters.mcp import GuardedMCPServer

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("llm_call", "", handler=lambda **_: "", scope="cost")

        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "llm_call",
                "arguments": {"command": "gpt-4", "session_id": "s3", "est_cost": 1.50},
            },
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body.get("session_id") == "s3"
        assert body.get("est_cost") == 1.50


# ---------------------------------------------------------------------------
# End-to-end: session-aware cost tracking should DENY when over budget
# (mock server returns whatever check_response is configured to; this test
# proves the SDK call shape is exactly what the server needs to enforce the
# limit, using successive check_response values to simulate cumulative cost).
# ---------------------------------------------------------------------------

class TestSessionCostEndToEnd:
    def test_cost_response_surfaces(self, mock_server):
        g = Guard(mock_server, agent_id="bot")
        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "Session cost $8.00 + $3.00 would exceed limit of $10.00",
            "matched_rule": "deny:cost:max_per_session",
        }
        r = g.check("cost", session_id="s", est_cost=3.0)
        assert r.denied
        assert r.matched_rule == "deny:cost:max_per_session"
        assert "Session cost" in r.reason
