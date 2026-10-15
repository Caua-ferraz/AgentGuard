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
from agentguard.adapters._common import extract_check_params
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


def test_adapters_lift_parent_session_id():
    params = extract_check_params(
        {"command": "ls", "session_id": "sub-1", "parent_session_id": "orch"}
    )
    assert params["session_id"] == "sub-1"
    assert params["parent_session_id"] == "orch"


def test_guarded_accepts_parent_session_id(sent):
    g = Guard(base_url="http://example.test", agent_id="sub")

    @guarded("shell", guard=g, session_id="sub-1", parent_session_id="orch")
    def run(cmd):
        return "ran"

    assert run("ls") == "ran"
    assert sent[-1]["parent_session_id"] == "orch"
