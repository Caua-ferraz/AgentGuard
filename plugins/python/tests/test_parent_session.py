"""parent_session_id: the session that started this one.

The Guard sends it as ``parent_session_id`` on /v1/check so the server's
sessions API can link a sub-agent's session to the orchestrator's. It is
optional on the wire: when unset the request body must not carry the key.
"""

import io
import json

import pytest

from agentguard import Guard
from agentguard import core
from agentguard.adapters._common import ConflictingToolInput, extract_check_params
from agentguard.decorators import guarded


class _FakeResponse(io.BytesIO):
    status = 200
    headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def sent(monkeypatch):
    """Capture the JSON body of every /v1/check the Guard sends."""
    bodies = []

    def fake_urlopen(req, timeout=None):
        bodies.append(json.loads(req.data))
        return _FakeResponse(b'{"decision":"ALLOW","reason":"ok"}')

    monkeypatch.setattr(core.request, "urlopen", fake_urlopen)
    return bodies


@pytest.mark.parametrize(
    "guard_parent, call_parent, want",
    [
        (None, "", None),
        ("orch-1", "", "orch-1"),
        (None, "orch-2", "orch-2"),
        ("orch-1", "orch-2", "orch-2"),  # the per-call value wins
    ],
)
def test_parent_session_id_on_the_wire(sent, guard_parent, call_parent, want):
    g = Guard(base_url="http://example.test", agent_id="sub", parent_session_id=guard_parent)
    g.check("shell", command="ls", session_id="sub-1", parent_session_id=call_parent)
    body = sent[-1]
    assert body["session_id"] == "sub-1"
    if want is None:
        assert "parent_session_id" not in body
    else:
        assert body["parent_session_id"] == want


def test_adapters_never_take_parent_session_id_from_tool_input():
    # The model writes tool arguments; it must not choose the audit parent.
    params = extract_check_params(
        {"command": "ls", "session_id": "sub-1", "parent_session_id": "orch"}
    )
    assert params == {"command": "ls", "session_id": "sub-1"}


def test_alias_conflicts_still_raise():
    with pytest.raises(ConflictingToolInput):
        extract_check_params({"command": "ls", "cmd": "rm -rf /", "parent_session_id": "x"})


def test_langchain_single_parent_session_key_is_gated_as_a_command(mock_server):
    # A one-key input under an unrecognised name is promoted to the command
    # and checked; "parent_session_id" gets no exemption from that.
    pytest.importorskip("langchain_core")
    from langchain_core.tools import Tool

    from agentguard.adapters.langchain import GuardedTool
    from tests.conftest import MockAgentGuardHandler

    MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
    guard = Guard(mock_server, parent_session_id="orch")
    ran = []
    tool = Tool.from_function(name="run", description="runs", func=lambda text: ran.append(text))
    gt = GuardedTool(tool, guard, scope="shell")

    with pytest.raises(PermissionError):
        gt.invoke({"parent_session_id": "rm -rf /"})

    body = json.loads(MockAgentGuardHandler.last_request_body)
    assert body["command"] == "rm -rf /"
    assert body["parent_session_id"] == "orch"  # the Guard's, not the model's
    assert ran == []


def test_guarded_accepts_parent_session_id(sent):
    g = Guard(base_url="http://example.test", agent_id="sub")

    @guarded("shell", guard=g, session_id="sub-1", parent_session_id="orch")
    def run(cmd):
        return "ran"

    assert run("ls") == "ran"
    assert sent[-1]["parent_session_id"] == "orch"
