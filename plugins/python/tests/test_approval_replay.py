"""Approval replay through the SDK (review finding R1).

Contract under test: after ``wait_for_approval`` resolves ALLOW, the
``@guarded(wait_for_approval=True)`` wrapper must replay the approval
through ``/v1/check`` with ``approval_id`` set — the only call that spends
the one-shot capability, applies ``--approval-validity``, reserves cost and
audits the execution — and must run the wrapped function only if that
replay allows. Acting on the status poll alone is the bug these tests pin.

Every test asserts on the exact sequence of HTTP requests the mock server
saw, so a wrapper that skips the replay (the pre-fix behaviour) fails.
"""

import json

import pytest

from agentguard import (
    Guard,
    guarded,
    AgentGuardApprovalRequired,
    AgentGuardDenied,
)
from tests.conftest import MockAgentGuardHandler


REQUIRE = {
    "decision": "REQUIRE_APPROVAL",
    "reason": "needs review",
    "approval_id": "ap_first",
    "approval_url": "http://example.com/approve/ap_first",
}
RESOLVED_ALLOW = {"id": "ap_first", "status": "resolved", "decision": "ALLOW", "reason": "human approved"}


def _checks():
    """Decoded bodies of every /v1/check the mock saw, in order."""
    return [
        json.loads(r["body"])
        for r in MockAgentGuardHandler.request_log
        if r["method"] == "POST" and r["path"] == "/v1/check"
    ]


class TestCheckApprovalIdOnTheWire:
    def test_approval_id_is_sent_when_given(self, mock_server):
        g = Guard(mock_server, agent_id="bot")
        g.check("shell", command="ls", approval_id="ap_xyz")
        body = _checks()[-1]
        assert body["approval_id"] == "ap_xyz"
        assert body["scope"] == "shell" and body["command"] == "ls"

    def test_approval_id_is_omitted_by_default(self, mock_server):
        g = Guard(mock_server)
        g.check("shell", command="ls")
        assert "approval_id" not in _checks()[-1]

    def test_empty_approval_id_is_omitted(self, mock_server):
        g = Guard(mock_server)
        g.check("shell", command="ls", approval_id="")
        assert "approval_id" not in _checks()[-1]


class TestGuardedReplaysTheApproval:
    def test_replays_with_approval_id_before_running(self, mock_server):
        MockAgentGuardHandler.check_response_queue = [
            REQUIRE,
            {"decision": "ALLOW", "reason": "approved", "matched_rule": "allow:approved"},
        ]
        MockAgentGuardHandler.status_response_queue = [RESOLVED_ALLOW]
        g = Guard(mock_server, agent_id="bot")
        runs = []

        @guarded("shell", guard=g, wait_for_approval=True, approval_timeout=5, approval_poll_interval=0.01)
        def deploy(cmd):
            runs.append(cmd)
            return "deployed"

        assert deploy("sudo deploy") == "deployed"
        assert runs == ["sudo deploy"]

        checks = _checks()
        assert len(checks) == 2, "expected the original check and exactly one replay"
        first, replay = checks
        assert "approval_id" not in first
        assert replay["approval_id"] == "ap_first"
        # Same shape as the original so the server's shape guard matches.
        assert replay["scope"] == first["scope"] == "shell"
        assert replay["command"] == first["command"] == "sudo deploy"
        assert replay["agent_id"] == first["agent_id"] == "bot"
        # Order: check, status poll(s), replay — the replay comes after the poll.
        paths = [(r["method"], r["path"]) for r in MockAgentGuardHandler.request_log]
        assert paths[0] == ("POST", "/v1/check")
        assert paths[-1] == ("POST", "/v1/check")
        assert any(m == "GET" and p.startswith("/v1/status/ap_first") for m, p in paths[1:-1])

    def test_replay_forwards_decorator_kwargs(self, mock_server):
        MockAgentGuardHandler.check_response_queue = [REQUIRE, {"decision": "ALLOW", "reason": "ok"}]
        MockAgentGuardHandler.status_response_queue = [RESOLVED_ALLOW]
        g = Guard(mock_server)

        @guarded("cost", guard=g, wait_for_approval=True, approval_poll_interval=0.01,
                 est_cost=12.5, session_id="sess-9")
        def spend(cmd):
            return "spent"

        assert spend("train") == "spent"
        first, replay = _checks()
        for body in (first, replay):
            assert body["est_cost"] == 12.5 and body["session_id"] == "sess-9"
        assert replay["approval_id"] == "ap_first"

    def test_function_never_runs_when_replay_is_denied(self, mock_server):
        MockAgentGuardHandler.check_response_queue = [
            REQUIRE,
            {"decision": "DENY", "reason": "policy changed", "matched_rule": "deny:shell:sudo"},
        ]
        MockAgentGuardHandler.status_response_queue = [RESOLVED_ALLOW]
        g = Guard(mock_server)
        runs = []

        @guarded("shell", guard=g, wait_for_approval=True, approval_poll_interval=0.01)
        def deploy(cmd):
            runs.append(cmd)

        with pytest.raises(AgentGuardDenied) as excinfo:
            deploy("sudo deploy")
        assert runs == [], "a denied replay must not run the function"
        assert excinfo.value.result.matched_rule == "deny:shell:sudo"
        assert len(_checks()) == 2

    def test_refused_replay_raises_required_with_new_id_and_never_waits_again(self, mock_server):
        # The server refused the replay (consumed/expired) and re-entered
        # the approval flow under a new id.
        MockAgentGuardHandler.check_response_queue = [
            REQUIRE,
            {
                "decision": "REQUIRE_APPROVAL",
                "reason": "needs review",
                "approval_id": "ap_second",
                "approval_url": "http://example.com/approve/ap_second",
            },
        ]
        # If the wrapper waited a second time this would let it through —
        # the test proves it does not.
        MockAgentGuardHandler.status_response_queue = [
            RESOLVED_ALLOW,
            {"id": "ap_second", "status": "resolved", "decision": "ALLOW"},
        ]
        g = Guard(mock_server)
        runs = []

        @guarded("shell", guard=g, wait_for_approval=True, approval_poll_interval=0.01)
        def deploy(cmd):
            runs.append(cmd)

        with pytest.raises(AgentGuardApprovalRequired) as excinfo:
            deploy("sudo deploy")
        assert runs == []
        assert excinfo.value.approval_id == "ap_second"
        assert "ap_second" in excinfo.value.approval_url
        assert "requires approval" in str(excinfo.value)
        assert len(_checks()) == 2, "no third check: the wrapper must not loop"
        status_polls = [r for r in MockAgentGuardHandler.request_log if r["method"] == "GET"]
        assert all(r["path"].endswith("/ap_first") for r in status_polls), \
            "the wrapper must not poll the new id on its own"

    def test_resolved_deny_still_does_not_replay(self, mock_server):
        MockAgentGuardHandler.check_response_queue = [REQUIRE]
        MockAgentGuardHandler.status_response_queue = [
            {"id": "ap_first", "status": "resolved", "decision": "DENY", "reason": "human denied"},
        ]
        g = Guard(mock_server)

        @guarded("shell", guard=g, wait_for_approval=True, approval_poll_interval=0.01)
        def deploy(cmd):
            return "ran"

        with pytest.raises(AgentGuardDenied):
            deploy("sudo deploy")
        assert len(_checks()) == 1, "a human DENY needs no replay"

    def test_without_wait_the_wrapper_raises_immediately_and_never_replays(self, mock_server):
        MockAgentGuardHandler.check_response_queue = [REQUIRE]
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def deploy(cmd):
            return "ran"

        with pytest.raises(AgentGuardApprovalRequired):
            deploy("sudo deploy")
        assert len(_checks()) == 1


class TestWaitForApprovalPollRobustness:
    def test_non_json_status_body_keeps_polling(self, mock_server):
        MockAgentGuardHandler.status_raw_queue = [
            (200, "text/html", b"<html>gateway error page</html>"),
        ]
        MockAgentGuardHandler.status_response_queue = [RESOLVED_ALLOW]
        g = Guard(mock_server)
        r = g.wait_for_approval("ap_first", timeout=5, poll_interval=0.01)
        assert r.allowed
        polls = [x for x in MockAgentGuardHandler.request_log if x["method"] == "GET"]
        assert len(polls) >= 2, "the garbage body must be retried, not raised"

    def test_empty_status_body_keeps_polling(self, mock_server):
        MockAgentGuardHandler.status_raw_queue = [(200, "application/json", b"")]
        MockAgentGuardHandler.status_response_queue = [RESOLVED_ALLOW]
        g = Guard(mock_server)
        r = g.wait_for_approval("ap_first", timeout=5, poll_interval=0.01)
        assert r.allowed
