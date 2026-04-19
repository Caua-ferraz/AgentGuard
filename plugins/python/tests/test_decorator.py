"""Tests for the @guarded decorator."""

import pytest

from agentguard import (
    Guard,
    guarded,
    AgentGuardError,
    AgentGuardDenied,
    AgentGuardApprovalRequired,
    AgentGuardApprovalTimeout,
)
from tests.conftest import MockAgentGuardHandler


class TestGuardedDecorator:
    def test_allows_execution(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "ALLOW",
            "reason": "ok",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return f"executed: {cmd}"

        assert my_func("ls") == "executed: ls"

    def test_blocks_on_deny(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "not allowed",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return f"executed: {cmd}"

        with pytest.raises(PermissionError, match="Action denied"):
            my_func("rm -rf /")

    def test_blocks_on_approval_needed(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://example.com/approve/123",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return f"executed: {cmd}"

        with pytest.raises(PermissionError, match="requires approval"):
            my_func("sudo reboot")

    def test_preserves_function_metadata(self, mock_server):
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def documented_function(cmd):
            """This function has docs."""
            return cmd

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This function has docs."

    def test_passes_first_arg_as_command(self, mock_server):
        """The decorator should send args[0] as the 'command' in the check."""
        MockAgentGuardHandler.check_response = {
            "decision": "ALLOW",
            "reason": "ok",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def run(cmd):
            return cmd

        run("echo hello")

        import json
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["command"] == "echo hello"


class TestGuardedTypedExceptions:
    """Verify the v0.5.0 typed-exception API.

    Each typed class extends ``PermissionError`` so the v0.4.x pattern
    ``except PermissionError:`` keeps working. New callers can catch the
    specific subclass and inspect structured fields.
    """

    def test_deny_raises_agentguard_denied_with_result(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "not allowed",
            "matched_rule": "deny:shell:rm",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return cmd

        with pytest.raises(AgentGuardDenied) as excinfo:
            my_func("rm -rf /")

        # Carries the originating CheckResult with the matched rule visible.
        assert excinfo.value.result is not None
        assert excinfo.value.result.denied
        assert excinfo.value.result.matched_rule == "deny:shell:rm"
        # Still a PermissionError for backward compat.
        assert isinstance(excinfo.value, PermissionError)

    def test_approval_required_raises_typed_exception(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_abc",
            "approval_url": "http://example.com/approve/ap_abc",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return cmd

        with pytest.raises(AgentGuardApprovalRequired) as excinfo:
            my_func("sudo reboot")

        assert excinfo.value.approval_id == "ap_abc"
        assert excinfo.value.approval_url == "http://example.com/approve/ap_abc"
        assert excinfo.value.result is not None
        assert excinfo.value.result.needs_approval
        # v0.4.1 message format preserved.
        assert "requires approval" in str(excinfo.value)
        # Backward-compat: still catchable as PermissionError.
        assert isinstance(excinfo.value, PermissionError)

    def test_permission_error_still_catches_denied(self, mock_server):
        """v0.4.x callers using ``except PermissionError:`` must still catch."""
        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "blocked",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return cmd

        caught = False
        try:
            my_func("rm -rf /")
        except PermissionError:
            caught = True
        assert caught

    def test_permission_error_still_catches_approval_required(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_xyz",
            "approval_url": "http://example.com/approve/ap_xyz",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return cmd

        caught = False
        try:
            my_func("sudo reboot")
        except PermissionError:
            caught = True
        assert caught

    def test_all_typed_exceptions_inherit_agentguard_error(self):
        assert issubclass(AgentGuardDenied, AgentGuardError)
        assert issubclass(AgentGuardApprovalRequired, AgentGuardError)
        assert issubclass(AgentGuardApprovalTimeout, AgentGuardError)
        assert issubclass(AgentGuardError, PermissionError)


class TestGuardedWaitForApproval:
    """Opt-in ``wait_for_approval=True`` dispatches on the resolved decision.

    The mock server's ``status_response`` controls what
    :meth:`Guard.wait_for_approval` observes on each poll.
    """

    def test_waits_and_runs_on_allow(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_wait1",
            "approval_url": "http://example.com/approve/ap_wait1",
        }
        MockAgentGuardHandler.status_response = {
            "id": "ap_wait1",
            "status": "resolved",
            "decision": "ALLOW",
            "reason": "human approved",
        }
        g = Guard(mock_server)

        calls = []

        @guarded(
            "shell",
            guard=g,
            wait_for_approval=True,
            approval_timeout=2,
            approval_poll_interval=1,
        )
        def my_func(cmd):
            calls.append(cmd)
            return "ran"

        assert my_func("deploy") == "ran"
        assert calls == ["deploy"]

    def test_waits_and_raises_on_deny(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_wait2",
            "approval_url": "http://example.com/approve/ap_wait2",
        }
        MockAgentGuardHandler.status_response = {
            "id": "ap_wait2",
            "status": "resolved",
            "decision": "DENY",
            "reason": "human denied",
        }
        g = Guard(mock_server)

        @guarded(
            "shell",
            guard=g,
            wait_for_approval=True,
            approval_timeout=2,
            approval_poll_interval=1,
        )
        def my_func(cmd):
            return cmd

        with pytest.raises(AgentGuardDenied) as excinfo:
            my_func("deploy")
        assert "human denied" in str(excinfo.value)
        assert excinfo.value.result is not None
        assert excinfo.value.result.denied

    def test_waits_and_raises_on_timeout(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_wait3",
            "approval_url": "http://example.com/approve/ap_wait3",
        }
        # status stays "pending" → wait_for_approval returns its synthetic
        # "Approval timed out" DENY after the deadline.
        MockAgentGuardHandler.status_response = {
            "id": "ap_wait3",
            "status": "pending",
        }
        g = Guard(mock_server)

        @guarded(
            "shell",
            guard=g,
            wait_for_approval=True,
            approval_timeout=1,
            approval_poll_interval=1,
        )
        def my_func(cmd):
            return cmd

        with pytest.raises(AgentGuardApprovalTimeout) as excinfo:
            my_func("deploy")
        assert excinfo.value.approval_id == "ap_wait3"
        assert "timed out" in str(excinfo.value)
