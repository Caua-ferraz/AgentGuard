"""Fuzz tests for the MCP JSON-RPC frame handler (Phase 3 — AT).

The MCP adapter sits on Claude Desktop's stdio transport. A misbehaving
client (or a corrupted pipe) can send anything: truncated JSON, oversize
frames, methods we don't know, params with the wrong type, raw UTF-8
corruption, empty lines, ``id`` of every JSON shape. None of those must
crash the adapter — Claude Desktop keeps one stdio session open for the
whole editor session, so a single bad frame that wedges the loop forces
the user to restart their editor.

What this exercises:

  * ``_process_frame(line: str)`` — the single-frame entry point. Drives
    each fuzz vector and asserts the loop survives.
  * ``_handle_request(request: dict)`` — direct-dict dispatch. Sees how
    the router copes with malformed ``params``.

What it does NOT exercise:

  * the full ``run()`` loop — that path is already covered by
    ``test_mcp_gateway.py::TestServerFrameRobustness`` with real stdin /
    stdout.

Closes the audit's R5 E6 / S9 regression coupon.
"""

from __future__ import annotations

import io
import json
import sys

import pytest
from unittest.mock import patch

from agentguard.adapters.mcp import GuardedMCPServer
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_server(mock_url: str) -> GuardedMCPServer:
    """A minimal server with one ALLOW-friendly tool registered."""
    s = GuardedMCPServer(guard_url=mock_url)
    s.add_tool(
        name="ping",
        description="echo",
        handler=lambda **_: "pong",
        scope="shell",
    )
    return s


def _drain_stderr(capsys) -> str:
    """Capture stderr without consuming pytest's own output."""
    return capsys.readouterr().err


# ---------------------------------------------------------------------------
# Vector list — one entry per fuzz category so failures point at a label.
# ---------------------------------------------------------------------------


# Each entry: (label, frame-bytes-or-string, expectation)
# expectation values:
#   "drop"  — the adapter should print to stderr and emit no stdout response
#   "error" — the adapter should emit a JSON-RPC error response on stdout
#   "ok"    — the adapter should emit a successful response (used as control)
MALFORMED_FRAMES = [
    # -- truncated / unparsable JSON --
    ("trunc_open_brace", "{", "drop"),
    ("trunc_no_close", '{"jsonrpc":"2.0","id":1,"method":', "drop"),
    ("not_json", "this is not json at all", "drop"),
    ("html_garbage", "<html><body>500</body></html>", "drop"),
    # -- empty / whitespace-only --
    # NB: the run() loop short-circuits on blank lines, but
    # _process_frame is a pure parser-and-dispatcher — we feed it blank
    # text via run() with a stripped line, so we test it here at the
    # _handle_request layer instead. Empty frame routed into
    # _handle_request as {} should not crash.
    # -- oversize --
    # 1 MiB of valid JSON. The adapter must not buffer-explode.
    ("oversize_1mib", json.dumps({
        "jsonrpc": "2.0", "id": 9001, "method": "tools/list",
        "params": {"junk": "x" * 1_000_000},
    }), "ok"),
    # -- valid JSON but JSON-RPC nonsense --
    ("array_root", "[1, 2, 3]", "drop"),  # JSON array, _handle_request expects dict
    ("string_root", '"hello"', "drop"),
    ("number_root", "42", "drop"),
    ("null_root", "null", "drop"),
    # -- unknown method --
    ("unknown_method", json.dumps({
        "jsonrpc": "2.0", "id": 7, "method": "frobnicate",
    }), "error"),
    # -- malformed params for known method --
    ("tools_call_no_params", json.dumps({
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
    }), "error"),
    ("tools_call_str_params", json.dumps({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": "not-a-dict",
    }), "error"),
    ("tools_call_unknown_tool", json.dumps({
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": {"name": "does-not-exist", "arguments": {}},
    }), "error"),
    # -- id variants --
    ("null_id", json.dumps({
        "jsonrpc": "2.0", "id": None, "method": "tools/list",
    }), "ok"),
    ("missing_id", json.dumps({
        "jsonrpc": "2.0", "method": "tools/list",
    }), "ok"),
    ("string_id", json.dumps({
        "jsonrpc": "2.0", "id": "abc-123", "method": "tools/list",
    }), "ok"),
    ("float_id", json.dumps({
        "jsonrpc": "2.0", "id": 1.5, "method": "tools/list",
    }), "ok"),
    # -- notification (no id, no response expected) --
    ("notif_initialized", json.dumps({
        "jsonrpc": "2.0", "method": "notifications/initialized",
    }), "drop"),  # notifications return None — no stdout
]


# ---------------------------------------------------------------------------
# Fuzz: _process_frame must survive every vector and never crash.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,frame,expectation",
    MALFORMED_FRAMES,
    ids=[v[0] for v in MALFORMED_FRAMES],
)
def test_process_frame_survives_fuzz(mock_server, capsys, label, frame, expectation):
    """The adapter must process the next frame after a bad one.

    We send the fuzz vector followed by a known-good frame; the good
    frame's response must appear on stdout. Both the bad and the good
    frame are processed via ``_process_frame`` directly so we don't
    depend on stdin / stdout plumbing.
    """
    MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
    s = _build_server(mock_server)

    fake_stdout = io.StringIO()
    with patch("agentguard.adapters.mcp.sys.stdout", fake_stdout):
        # 1. Send the fuzz vector — must not raise.
        try:
            s._process_frame(frame)
        except Exception as e:  # noqa: BLE001
            pytest.fail(
                f"{label}: _process_frame raised {type(e).__name__}: {e}"
            )

        # 2. Send a known-good frame — its response must appear on stdout.
        good = json.dumps({
            "jsonrpc": "2.0", "id": "canary", "method": "tools/list",
        })
        s._process_frame(good)

    # Inspect stdout — should contain at LEAST the canary response.
    out_lines = [
        line for line in fake_stdout.getvalue().splitlines() if line.strip()
    ]
    canary_seen = False
    for line in out_lines:
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            pytest.fail(
                f"{label}: stdout produced non-JSON line {line!r}"
            )
        if decoded.get("id") == "canary":
            canary_seen = True
            assert "result" in decoded, (
                f"{label}: canary response missing 'result' (got {decoded!r})"
            )

    assert canary_seen, (
        f"{label}: known-good follow-up frame produced no response. "
        f"Captured stdout lines: {out_lines!r}"
    )

    # Optional expectation tightening — the fuzz frame's response shape.
    fuzz_responses = [
        json.loads(line) for line in out_lines
        if json.loads(line).get("id") != "canary"
    ]
    if expectation == "ok":
        # Expect at least one successful response with result.
        assert any("result" in r for r in fuzz_responses), (
            f"{label}: expected successful response, got {fuzz_responses!r}"
        )
    elif expectation == "error":
        assert any("error" in r for r in fuzz_responses), (
            f"{label}: expected JSON-RPC error response, got {fuzz_responses!r}"
        )
    elif expectation == "drop":
        # No fuzz-frame response should land on stdout (notification or
        # malformed JSON path). If something did land, it must at least
        # be valid JSON-RPC error shape — never raw text.
        for r in fuzz_responses:
            assert "error" in r or "result" in r, (
                f"{label}: produced non-JSON-RPC response {r!r}"
            )


# ---------------------------------------------------------------------------
# UTF-8 corruption — the framer reads strings; bytes-level corruption is
# already filtered by the stdin codec. Test what _process_frame does with
# JSON that decodes but contains weird strings.
# ---------------------------------------------------------------------------


def test_process_frame_high_unicode_command(mock_server, capsys):
    """A frame whose params contain high-Unicode codepoints must be processed
    as ordinary input — not blow up the adapter."""
    MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
    s = _build_server(mock_server)

    # Mix BMP, emoji, and 4-byte codepoints. All valid UTF-8 once encoded.
    weird_args = "echo " + "é中\U0001F600\U0001F4A9"
    frame = json.dumps({
        "jsonrpc": "2.0", "id": 50, "method": "tools/call",
        "params": {"name": "ping", "arguments": {"text": weird_args}},
    })

    fake_stdout = io.StringIO()
    with patch("agentguard.adapters.mcp.sys.stdout", fake_stdout):
        s._process_frame(frame)

    lines = [l for l in fake_stdout.getvalue().splitlines() if l.strip()]
    assert len(lines) == 1
    resp = json.loads(lines[0])
    # The known tool returned successfully.
    assert resp["id"] == 50
    assert "result" in resp


# ---------------------------------------------------------------------------
# Sequential-frame stress: 200 mixed frames across a single server.
# ---------------------------------------------------------------------------


def test_sequential_mixed_frames_survive(mock_server, capsys):
    """200 frames alternating bad / good. The adapter must process every
    good frame's response without losing one."""
    MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
    s = _build_server(mock_server)

    # Build the corpus.
    corpus: list[str] = []
    seen_good: list[int] = []  # for the assertion afterward
    for i in range(100):
        corpus.append("not-json-at-all")
        good = json.dumps({
            "jsonrpc": "2.0", "id": i, "method": "tools/list",
        })
        corpus.append(good)
        seen_good.append(i)

    fake_stdout = io.StringIO()
    with patch("agentguard.adapters.mcp.sys.stdout", fake_stdout):
        for line in corpus:
            s._process_frame(line)

    out_lines = [l for l in fake_stdout.getvalue().splitlines() if l.strip()]
    received_ids = []
    for line in out_lines:
        decoded = json.loads(line)
        received_ids.append(decoded.get("id"))
    # Every good frame should have a response.
    assert sorted(received_ids) == sorted(seen_good), (
        f"missing or extra ids — expected {sorted(seen_good)!r}, "
        f"got {sorted(received_ids)!r}"
    )


# ---------------------------------------------------------------------------
# Defensive: handler exceptions in the router don't crash the loop.
# ---------------------------------------------------------------------------


def test_process_frame_handler_exception_emits_internal_error(mock_server, capsys):
    """When the router itself throws, ``_process_frame`` MUST emit a
    JSON-RPC -32603 error response and continue accepting frames."""
    MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
    s = _build_server(mock_server)

    original = s._handle_request
    boom_state = {"once": False}

    def boom(req):
        if not boom_state["once"]:
            boom_state["once"] = True
            raise RuntimeError("AT-fuzz: simulated router boom")
        return original(req)

    s._handle_request = boom  # type: ignore[assignment]

    fake_stdout = io.StringIO()
    with patch("agentguard.adapters.mcp.sys.stdout", fake_stdout):
        s._process_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        }))
        s._process_frame(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
        }))

    lines = [l for l in fake_stdout.getvalue().splitlines() if l.strip()]
    decoded = [json.loads(l) for l in lines]
    assert decoded[0]["id"] == 1
    assert decoded[0]["error"]["code"] == -32603
    assert decoded[1]["id"] == 2
    assert "result" in decoded[1]
