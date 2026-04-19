"""Tests for the core Guard client and CheckResult dataclass."""

import json

import pytest

from agentguard import (
    CheckResult,
    Guard,
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    FAIL_MODE_ALLOW,
    FAIL_MODE_DENY,
)
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# CheckResult property tests
# ---------------------------------------------------------------------------

class TestCheckResult:
    def test_allowed(self):
        r = CheckResult(decision=DECISION_ALLOW, reason="ok")
        assert r.allowed is True
        assert r.denied is False
        assert r.needs_approval is False

    def test_denied(self):
        r = CheckResult(decision=DECISION_DENY, reason="blocked")
        assert r.allowed is False
        assert r.denied is True
        assert r.needs_approval is False

    def test_needs_approval(self):
        r = CheckResult(decision=DECISION_REQUIRE_APPROVAL, reason="requires approval")
        assert r.allowed is False
        assert r.denied is False
        assert r.needs_approval is True

    def test_default_optional_fields(self):
        r = CheckResult(decision=DECISION_ALLOW, reason="ok")
        assert r.matched_rule == ""
        assert r.approval_id == ""
        assert r.approval_url == ""


# ---------------------------------------------------------------------------
# Guard constructor tests
# ---------------------------------------------------------------------------

class TestGuardInit:
    def test_default_url(self):
        g = Guard()
        assert g.base_url == DEFAULT_BASE_URL

    def test_explicit_url(self):
        g = Guard("http://custom:9090")
        assert g.base_url == "http://custom:9090"

    def test_trailing_slash_stripped(self):
        g = Guard("http://custom:9090/")
        assert g.base_url == "http://custom:9090"

    def test_env_var_url(self, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_URL", "http://env-host:1234")
        g = Guard()
        assert g.base_url == "http://env-host:1234"

    def test_explicit_url_overrides_env(self, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_URL", "http://env-host:1234")
        g = Guard("http://explicit:5555")
        assert g.base_url == "http://explicit:5555"

    def test_default_timeout(self):
        g = Guard()
        assert g.timeout == DEFAULT_TIMEOUT

    def test_custom_timeout(self):
        g = Guard(timeout=30)
        assert g.timeout == 30


# ---------------------------------------------------------------------------
# Guard.check() tests
# ---------------------------------------------------------------------------

class TestGuardCheck:
    def test_check_allow(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "ALLOW",
            "reason": "allowed by policy",
            "matched_rule": "allow:shell:*",
        }
        g = Guard(mock_server)
        result = g.check("shell", command="ls -la")
        assert result.allowed
        assert result.reason == "allowed by policy"
        assert result.matched_rule == "allow:shell:*"

    def test_check_deny(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked by policy",
            "matched_rule": "deny:shell:rm",
        }
        g = Guard(mock_server)
        result = g.check("shell", command="rm -rf /")
        assert result.denied
        assert result.reason == "blocked by policy"

    def test_check_require_approval(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs human review",
            "approval_id": "ap_abc123",
            "approval_url": "http://localhost:8080/v1/approve/ap_abc123",
        }
        g = Guard(mock_server)
        result = g.check("shell", command="sudo reboot")
        assert result.needs_approval
        assert result.approval_id == "ap_abc123"
        assert result.approval_url != ""

    def test_check_unreachable_fails_closed(self):
        g = Guard("http://127.0.0.1:1", timeout=1)  # port 1 = unreachable
        result = g.check("shell", command="echo hi")
        assert result.denied
        assert "unreachable" in result.reason.lower()

    def test_check_unreachable_fail_open(self):
        """fail_mode='allow' turns unreachable into ALLOW.

        Locks the Phase-5.1 parity-prep contract: the default is still
        'deny' (see test_check_unreachable_fails_closed), and an explicit
        'allow' is required to opt into fail-open — mirroring the TS SDK
        where `failMode: 'allow'` has always been an explicit opt-in.
        """
        g = Guard("http://127.0.0.1:1", timeout=1, fail_mode=FAIL_MODE_ALLOW)
        result = g.check("shell", command="echo hi")
        assert result.allowed
        assert "allow" in result.reason.lower()

    def test_fail_mode_invalid_raises(self):
        with pytest.raises(ValueError):
            Guard(fail_mode="maybe")

    def test_fail_mode_defaults_to_deny(self):
        g = Guard()
        assert g.fail_mode == FAIL_MODE_DENY

    def test_check_sends_correct_payload(self, mock_server):
        g = Guard(mock_server, agent_id="test-agent")
        g.check("filesystem", action="write", path="/tmp/test.txt", meta={"key": "val"})
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "filesystem"
        assert body["agent_id"] == "test-agent"
        assert body["action"] == "write"
        assert body["path"] == "/tmp/test.txt"
        assert body["meta"] == {"key": "val"}

    def test_check_omits_empty_fields(self, mock_server):
        g = Guard(mock_server)
        g.check("shell", command="ls")
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert "path" not in body
        assert "domain" not in body
        assert "url" not in body
        assert "meta" not in body


# ---------------------------------------------------------------------------
# Guard.approve() / Guard.deny() tests
# ---------------------------------------------------------------------------

class TestGuardActions:
    def test_approve_success(self, mock_server):
        g = Guard(mock_server)
        assert g.approve("ap_123") is True

    def test_deny_success(self, mock_server):
        g = Guard(mock_server)
        assert g.deny("ap_123") is True

    def test_approve_unreachable(self):
        g = Guard("http://127.0.0.1:1", timeout=1)
        assert g.approve("ap_123") is False

    def test_deny_unreachable(self):
        g = Guard("http://127.0.0.1:1", timeout=1)
        assert g.deny("ap_123") is False


# ---------------------------------------------------------------------------
# Auth header tests (H9)
# ---------------------------------------------------------------------------

class TestGuardAuth:
    def test_approve_sends_auth_header(self, mock_server):
        g = Guard(mock_server, api_key="my-secret")
        g.approve("ap_123")
        assert MockAgentGuardHandler.last_request_headers is not None
        assert MockAgentGuardHandler.last_request_headers.get("Authorization") == "Bearer my-secret"

    def test_deny_sends_auth_header(self, mock_server):
        g = Guard(mock_server, api_key="my-secret")
        g.deny("ap_123")
        assert MockAgentGuardHandler.last_request_headers is not None
        assert MockAgentGuardHandler.last_request_headers.get("Authorization") == "Bearer my-secret"

    def test_approve_no_auth_header_without_key(self, mock_server):
        g = Guard(mock_server)
        g.approve("ap_123")
        assert MockAgentGuardHandler.last_request_headers is not None
        assert MockAgentGuardHandler.last_request_headers.get("Authorization") is None

    def test_api_key_from_env(self, mock_server, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_API_KEY", "env-secret")
        g = Guard(mock_server)
        g.approve("ap_123")
        assert MockAgentGuardHandler.last_request_headers.get("Authorization") == "Bearer env-secret"

    def test_explicit_key_overrides_env(self, mock_server, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_API_KEY", "env-secret")
        g = Guard(mock_server, api_key="explicit-secret")
        g.approve("ap_123")
        assert MockAgentGuardHandler.last_request_headers.get("Authorization") == "Bearer explicit-secret"
