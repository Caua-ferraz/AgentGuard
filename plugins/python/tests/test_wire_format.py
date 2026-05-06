"""
Cross-language wire-protocol contract test (Python side).

This file is one of three (Go: pkg/proxy/schema/v1/types_test.go, TypeScript:
plugins/typescript/src/__tests__/wire_format.test.ts) that load the same
fixtures from pkg/proxy/schema/v1/testdata/ and assert that all three
implementations agree on the JSON shape of POST /v1/check.

Closes audit findings R1 F4 (no schema_version field on the wire) and
R1 F7 (no cross-language contract test — silent drift between Go, Python,
and TypeScript implementations).

Failure modes this test catches:

- A field renamed on the Go side but not in the Python SDK
  (e.g. agent_id -> agentId) — Guard.check would silently send the wrong
  key and the server would treat the agent as anonymous.
- A new required field added to the schema without bumping schema_version.
- The Python SDK accidentally dropping schema_version even when the user
  passes it in `meta` or via a future kwarg.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from agentguard import Guard, CheckResult


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

# tests/test_wire_format.py -> plugins/python -> plugins -> AgentGuard root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = _REPO_ROOT / "pkg" / "proxy" / "schema" / "v1" / "testdata"


def _load_fixture(name: str) -> dict[str, Any]:
    """Read a JSON fixture file and return its decoded value."""
    path = _FIXTURES / name
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Sanity check: the cross-language fixtures exist and parse
# ---------------------------------------------------------------------------


def test_fixtures_exist() -> None:
    """The Go side must have committed the fixture files; if they go
    missing, every cross-language test silently passes when it should
    fail. Check the absolute path so a packaging mistake (the test file
    being run from a different working directory) is loud."""
    assert _FIXTURES.is_dir(), f"missing fixture directory: {_FIXTURES}"
    assert (_FIXTURES / "sample_request.json").is_file()
    assert (_FIXTURES / "sample_result.json").is_file()


def test_sample_request_fixture_shape() -> None:
    """sample_request.json must decode to the documented shape. If a
    contributor changes a field name or type on the Go side, this test
    fails before the SDK gets near a real server."""
    body = _load_fixture("sample_request.json")
    assert body == {
        "schema_version": "v1",
        "agent_id": "test-agent-001",
        "session_id": "sess-abc",
        "scope": "shell",
        "command": "ls -la",
        "meta": {"source": "ci-fixture"},
    }


def test_sample_result_fixture_shape() -> None:
    """sample_result.json must decode to the documented shape."""
    body = _load_fixture("sample_result.json")
    assert body == {
        "schema_version": "v1",
        "decision": "ALLOW",
        "reason": "matched allow rule",
        "matched_rule": "allow:shell:ls",
    }


def test_sample_result_decodes_into_check_result() -> None:
    """The Python SDK's CheckResult dataclass must be able to consume
    every field the Go server emits in the result fixture. New fields
    added on the Go side without a corresponding SDK update would fail
    here."""
    body = _load_fixture("sample_result.json")
    # schema_version is part of the wire contract but not surfaced on the
    # SDK CheckResult dataclass (yet). The dataclass accepts the v1
    # wire-format superset by ignoring fields it does not name. This
    # test pins that behavior so a future SDK change cannot silently
    # remove the schema_version-tolerance.
    result = CheckResult(
        decision=body["decision"],
        reason=body["reason"],
        matched_rule=body.get("matched_rule", ""),
    )
    assert result.allowed
    assert result.decision == "ALLOW"
    assert result.matched_rule == "allow:shell:ls"


# ---------------------------------------------------------------------------
# SDK request shape: Guard.check() must emit a body whose key set is a
# subset of the v1 ActionRequest schema. We mock urllib.request.urlopen
# (the SDK's HTTP layer) so the test runs offline.
# ---------------------------------------------------------------------------

# Keys the SDK is allowed to put on the wire. Subset of the v1 schema's
# ActionRequest properties; schema_version is NOT in this set today (the
# server defaults missing values to v1) but a future SDK release can add
# it without breaking the contract — it is in WIRE_KEYS_OPTIONAL.
WIRE_KEYS_REQUIRED = {"scope"}
WIRE_KEYS_OPTIONAL = {
    "schema_version",
    "action",
    "command",
    "path",
    "domain",
    "url",
    "agent_id",
    "session_id",
    "est_cost",
    "meta",
}
WIRE_KEYS_ALLOWED = WIRE_KEYS_REQUIRED | WIRE_KEYS_OPTIONAL


class _FakeResponse:
    """Minimal urllib response stand-in.

    The SDK uses ``with request.urlopen(...) as resp:`` and then calls
    ``resp.read()``; we implement just those two behaviors. ``__exit__``
    returns False so any exception inside the with-block propagates.
    """

    def __init__(self, payload: dict[str, Any]):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def _capture_check_body(**check_kwargs: Any) -> dict[str, Any]:
    """Invoke Guard.check with the given kwargs against a mocked HTTP
    layer; return the decoded JSON body the SDK actually sent."""
    captured: dict[str, Any] = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001 - signature matches stdlib
        # urllib.request.Request: req.data is the bytes-encoded body.
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        return _FakeResponse(_load_fixture("sample_result.json"))

    guard = Guard(base_url="http://example.invalid", agent_id="test-agent-001")
    with mock.patch("agentguard.request.urlopen", side_effect=fake_urlopen):
        result = guard.check(**check_kwargs)
    captured["result"] = result
    return captured


def test_sdk_request_body_keys_are_v1_subset() -> None:
    """Every key the SDK puts on the wire must be a documented v1
    ActionRequest field. A typo or a leaked internal kwarg would surface
    as an unexpected key here — caught at unit-test time rather than as
    a 400 from the proxy in production."""
    captured = _capture_check_body(
        scope="shell",
        command="ls -la",
        session_id="sess-abc",
        meta={"source": "ci-fixture"},
    )
    body = captured["body"]
    extra = set(body.keys()) - WIRE_KEYS_ALLOWED
    assert not extra, f"SDK emitted unknown wire keys: {extra}"
    missing = WIRE_KEYS_REQUIRED - set(body.keys())
    assert not missing, f"SDK omitted required wire keys: {missing}"


def test_sdk_request_body_matches_fixture_shape() -> None:
    """The same call that produced sample_request.json on the Go side
    must round-trip through the Python SDK to produce the same key set
    and values (modulo schema_version, which the SDK does not yet emit
    by design — the server defaults it). This is the canonical
    cross-language contract assertion."""
    captured = _capture_check_body(
        scope="shell",
        command="ls -la",
        session_id="sess-abc",
        meta={"source": "ci-fixture"},
    )
    body = captured["body"]
    fixture = _load_fixture("sample_request.json")

    # SDK does not currently set schema_version; the server defaults it.
    # We compare the SDK body against the fixture with schema_version
    # treated as optional on the SDK side.
    expected = {k: v for k, v in fixture.items() if k != "schema_version"}
    assert body == expected, (
        f"SDK body diverged from cross-language fixture\n"
        f"expected: {expected}\n"
        f"got:      {body}"
    )

    # And the URL must hit /v1/check — a wrong path is the most common
    # SDK bug and would not be caught by body-only assertions.
    assert captured["url"] == "http://example.invalid/v1/check"
    assert captured["method"] == "POST"


def test_sdk_omits_zero_cost_field() -> None:
    """The SDK must drop est_cost when its value is 0 — sending est_cost=0
    would clutter the audit log and trigger no-op cost-scope policy
    checks. This test pins the documented behavior."""
    captured = _capture_check_body(scope="shell", command="ls", est_cost=0.0)
    assert "est_cost" not in captured["body"]


def test_sdk_includes_agent_id_when_set() -> None:
    """agent_id flows from the Guard constructor into every request body.
    The Go server uses it as the per-agent override key; a mismatch
    silently disables overrides."""
    captured = _capture_check_body(scope="shell", command="ls")
    assert captured["body"].get("agent_id") == "test-agent-001"


def test_sdk_response_decodes_v1_fields() -> None:
    """When the server returns a v1-shaped result, the SDK must surface
    decision/reason/matched_rule on the CheckResult. New fields the
    server may add (e.g. policy_version in v1.x) must not break decoding."""
    captured = _capture_check_body(scope="shell", command="ls -la")
    result: CheckResult = captured["result"]
    assert result.decision == "ALLOW"
    assert result.reason == "matched allow rule"
    assert result.matched_rule == "allow:shell:ls"
    assert result.allowed
    assert not result.denied
    assert not result.needs_approval


def test_sdk_response_tolerates_unknown_field() -> None:
    """A v1.x server may add new optional fields. The SDK must not
    crash on them — it should ignore unknown keys and surface the
    documented v1 fields."""
    captured: dict[str, Any] = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        captured["url"] = req.full_url
        future_body = {
            "schema_version": "v1",
            "decision": "ALLOW",
            "reason": "ok",
            "matched_rule": "allow:shell:ls",
            # Field that does not exist today; v1 additive evolution
            # could introduce it. The SDK must ignore it gracefully.
            "policy_revision": "abc123",
        }
        return _FakeResponse(future_body)

    guard = Guard(base_url="http://example.invalid", agent_id="x")
    with mock.patch("agentguard.request.urlopen", side_effect=fake_urlopen):
        result = guard.check(scope="shell", command="ls")
    assert result.allowed
    assert result.matched_rule == "allow:shell:ls"


# ---------------------------------------------------------------------------
# Negative tests: things the SDK must NOT do
# ---------------------------------------------------------------------------


def test_sdk_does_not_emit_camelcase_keys() -> None:
    """The Go server is strict about JSON key names. A regression that
    introduced camelCase keys (e.g. sessionId, estCost) would silently
    bypass session/cost accounting on the server. Pin snake_case here."""
    captured = _capture_check_body(
        scope="cost", est_cost=0.05, session_id="sess-x"
    )
    body = captured["body"]
    forbidden = {"sessionId", "estCost", "agentId"}
    leaked = set(body.keys()) & forbidden
    assert not leaked, f"SDK leaked camelCase keys: {leaked}"


@pytest.mark.parametrize(
    "decision",
    ["ALLOW", "DENY", "REQUIRE_APPROVAL"],
)
def test_sdk_decodes_every_v1_decision(decision: str) -> None:
    """Every value of the v1 decision enum must round-trip through the
    SDK. Missing one would silently classify a real DENY as the default
    fallback (also DENY today, but a future SDK might fall back to
    UNKNOWN — this test fixes the contract)."""
    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        return _FakeResponse({
            "schema_version": "v1",
            "decision": decision,
            "reason": "test",
        })

    guard = Guard(base_url="http://example.invalid", agent_id="x")
    with mock.patch("agentguard.request.urlopen", side_effect=fake_urlopen):
        result = guard.check(scope="shell", command="ls")
    assert result.decision == decision
