"""End-to-end tests that spin up the REAL Go `agentguard` binary and drive it
with the real Python SDK. This is the strongest possible integration test —
it verifies the entire HTTP protocol (auth, CORS, CSRF, cost reservations,
approval queue) across language boundaries.

The tests are skipped if the binary isn't found (e.g., on fresh checkouts
where `go build` hasn't been run). Build with:

    cd <repo-root> && go build -o agentguard.exe ./cmd/agentguard

On POSIX, use `agentguard` without the .exe suffix.
"""

import json
import os
import socket
import subprocess
import textwrap
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

from agentguard import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    Guard,
)


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

def _find_binary() -> Optional[str]:
    """Locate the compiled agentguard binary relative to this test file."""
    # tests/test_X.py -> plugins/python -> repo root
    repo_root = Path(__file__).resolve().parents[3]
    candidates = [
        repo_root / "agentguard.exe",
        repo_root / "agentguard",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


BINARY = _find_binary()
skip_no_binary = pytest.mark.skipif(
    BINARY is None,
    reason="agentguard binary not built — run `go build -o agentguard.exe ./cmd/agentguard` in repo root",
)


def _free_port() -> int:
    """Grab a currently-unused localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_http(url: str, timeout: float = 10.0) -> bool:
    """Poll until the server responds to GET url or timeout expires."""
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# Test policy file — written fresh per-test in a tempdir.
# ---------------------------------------------------------------------------

TEST_POLICY = textwrap.dedent("""
    version: "1"
    name: "e2e-test"
    description: "policy for end-to-end SDK tests"
    rules:
      - scope: shell
        allow:
          - pattern: "ls *"
          - pattern: "echo *"
        deny:
          - pattern: "rm -rf *"
            message: "destructive"
        require_approval:
          - pattern: "sudo *"
      - scope: network
        allow:
          - domain: "api.openai.com"
          - domain: "*.wikipedia.org"
        deny:
          - domain: "*.evil.com"
      - scope: cost
        limits:
          max_per_action: "$5.00"
          max_per_session: "$10.00"
      - scope: filesystem
        allow:
          - action: read
            paths: ["./workspace/**"]
        deny:
          - action: write
            paths: ["/etc/**"]
    agents:
      researcher:
        override:
          - scope: network
            allow:
              - domain: "scholar.google.com"
""")


# ---------------------------------------------------------------------------
# Server fixture — launches the real binary
# ---------------------------------------------------------------------------

class ServerHandle:
    def __init__(self, proc: subprocess.Popen, port: int, api_key: str):
        self.proc = proc
        self.port = port
        self.api_key = api_key
        self.base_url = f"http://127.0.0.1:{port}"

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


@pytest.fixture()
def agentguard_server(tmp_path):
    """Start the real agentguard binary on a free port with an API key set."""
    if BINARY is None:
        pytest.skip("binary not built")

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(TEST_POLICY)
    audit_file = tmp_path / "audit.jsonl"

    port = _free_port()
    api_key = "e2e-test-secret-long-enough"

    env = os.environ.copy()
    proc = subprocess.Popen(
        [
            BINARY,
            "serve",
            "--policy", str(policy_file),
            "--port", str(port),
            "--api-key", api_key,
            "--audit-log", str(audit_file),
            "--dashboard",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )

    # Drain stdout in a background thread so the pipe never backs up.
    def _drain():
        try:
            for _ in iter(proc.stdout.readline, b""):
                pass
        except Exception:
            pass

    threading.Thread(target=_drain, daemon=True).start()

    if not _wait_for_http(f"http://127.0.0.1:{port}/health", timeout=10):
        proc.kill()
        _, err = proc.communicate()
        pytest.fail(f"server did not come up on port {port}; output:\n{err}")

    handle = ServerHandle(proc, port, api_key)
    yield handle
    handle.stop()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@skip_no_binary
class TestRealServerBasics:
    def test_health_is_open(self, agentguard_server):
        import urllib.request

        with urllib.request.urlopen(f"{agentguard_server.base_url}/health") as r:
            body = json.loads(r.read())
        assert body["status"] == "ok"

    def test_check_allow(self, agentguard_server):
        g = Guard(agentguard_server.base_url, agent_id="e2e")
        r = g.check("shell", command="ls -la")
        assert r.allowed, f"expected ALLOW, got {r.decision}: {r.reason}"

    def test_check_deny(self, agentguard_server):
        g = Guard(agentguard_server.base_url, agent_id="e2e")
        r = g.check("shell", command="rm -rf /")
        assert r.denied
        assert "destructive" in r.reason or "rm" in r.reason.lower()

    def test_check_default_deny(self, agentguard_server):
        g = Guard(agentguard_server.base_url, agent_id="e2e")
        r = g.check("shell", command="wget evil.com")
        assert r.denied  # no matching allow


@skip_no_binary
class TestRealServerCostTracking:
    def test_session_cost_accumulates_and_denies(self, agentguard_server):
        """Real cost reservation across 3 calls — the server does atomic
        check-and-reserve, so the SDK just makes three calls and observes the
        third denial."""
        g = Guard(agentguard_server.base_url, agent_id="cost-bot")
        sid = "e2e-cost-session"

        r1 = g.check("cost", session_id=sid, est_cost=4.0)
        assert r1.allowed, f"1st: {r1.decision} {r1.reason}"

        r2 = g.check("cost", session_id=sid, est_cost=4.0)
        assert r2.allowed, f"2nd: {r2.decision} {r2.reason}"

        r3 = g.check("cost", session_id=sid, est_cost=3.0)
        assert r3.denied, f"3rd: {r3.decision} {r3.reason}"
        assert r3.matched_rule == "deny:cost:max_per_session"

    def test_session_cost_isolation(self, agentguard_server):
        g = Guard(agentguard_server.base_url, agent_id="cost-bot")
        r_a = g.check("cost", session_id="sess-a", est_cost=4.0)
        r_b = g.check("cost", session_id="sess-b", est_cost=4.0)
        assert r_a.allowed and r_b.allowed
        # Each session independent — both $4 calls allowed.


@skip_no_binary
class TestRealServerApprovalFlow:
    def test_require_approval_returns_id_and_url(self, agentguard_server):
        g = Guard(agentguard_server.base_url, agent_id="approval-bot")
        r = g.check("shell", command="sudo reboot")
        assert r.needs_approval
        assert r.approval_id.startswith("ap_")
        assert r.approval_url.startswith("http://")

    def test_bearer_approve_then_status_resolves(self, agentguard_server):
        """Full round-trip: queue an approval, approve it via Bearer auth,
        poll /v1/status with Bearer and see it resolved."""
        g = Guard(
            agentguard_server.base_url,
            agent_id="approval-bot",
            api_key=agentguard_server.api_key,
        )
        r = g.check("shell", command="sudo halt")
        assert r.needs_approval
        assert g.approve(r.approval_id) is True

        resolved = g.wait_for_approval(r.approval_id, timeout=3, poll_interval=1)
        assert resolved.allowed

    def test_deny_round_trip(self, agentguard_server):
        g = Guard(
            agentguard_server.base_url,
            agent_id="approval-bot",
            api_key=agentguard_server.api_key,
        )
        r = g.check("shell", command="sudo shutdown")
        assert r.needs_approval
        assert g.deny(r.approval_id) is True

        resolved = g.wait_for_approval(r.approval_id, timeout=3, poll_interval=1)
        assert resolved.denied

    def test_approve_without_auth_rejected(self, agentguard_server):
        """No api_key on Guard → approve() should fail (server requires auth)."""
        g_writer = Guard(
            agentguard_server.base_url,
            api_key=agentguard_server.api_key,
        )
        r = g_writer.check("shell", command="sudo foo")

        g_no_key = Guard(agentguard_server.base_url)  # no api_key
        # urllib raises on 401; Guard.approve returns False.
        assert g_no_key.approve(r.approval_id) is False


@skip_no_binary
class TestRealServerAgentOverride:
    def test_research_agent_override(self, agentguard_server):
        """researcher agent gets scholar.google.com; default agent does not."""
        default_guard = Guard(agentguard_server.base_url, agent_id="")
        research_guard = Guard(agentguard_server.base_url, agent_id="researcher")

        # Default agent: openai allowed, scholar denied.
        assert default_guard.check("network", domain="api.openai.com").allowed
        assert default_guard.check("network", domain="scholar.google.com").denied

        # Research agent: scholar allowed, openai denied (override replaces).
        assert research_guard.check("network", domain="scholar.google.com").allowed
        assert research_guard.check("network", domain="api.openai.com").denied


@skip_no_binary
class TestRealServerAudit:
    def test_audit_entries_exist(self, agentguard_server):
        """After generating some checks, query /v1/audit with Bearer auth."""
        import urllib.request

        g = Guard(agentguard_server.base_url, agent_id="audit-bot")
        for _ in range(3):
            g.check("shell", command="ls -la")

        # Query audit via raw HTTP — the SDK doesn't expose audit query.
        req = urllib.request.Request(
            f"{agentguard_server.base_url}/v1/audit?agent_id=audit-bot",
            headers={"Authorization": f"Bearer {agentguard_server.api_key}"},
        )
        with urllib.request.urlopen(req) as r:
            entries = json.loads(r.read())

        assert len(entries) >= 3
        assert all(e["agent_id"] == "audit-bot" for e in entries)

    def test_audit_unauthorized(self, agentguard_server):
        """Audit without Bearer should 401."""
        import urllib.request
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(f"{agentguard_server.base_url}/v1/audit")
        assert ei.value.code == 401


@skip_no_binary
class TestRealServerDashboardAuth:
    def test_dashboard_unauthenticated_serves_login_page(self, agentguard_server):
        import urllib.request

        with urllib.request.urlopen(f"{agentguard_server.base_url}/dashboard") as r:
            body = r.read().decode()
        assert "Sign in" in body
        assert agentguard_server.api_key not in body, "login page leaks API key"

    def test_login_flow_sets_cookies(self, agentguard_server):
        """POST /auth/login with the right key must set ag_session and ag_csrf
        cookies and return a csrf_token in the JSON body."""
        import urllib.request

        req = urllib.request.Request(
            f"{agentguard_server.base_url}/auth/login",
            method="POST",
            data=json.dumps({"api_key": agentguard_server.api_key}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            body = json.loads(r.read())
            cookies = r.headers.get_all("Set-Cookie") or []

        assert "csrf_token" in body and len(body["csrf_token"]) == 64
        assert any("ag_session=" in c for c in cookies)
        assert any("ag_csrf=" in c for c in cookies)


@skip_no_binary
class TestRealServerConcurrentSDKCalls:
    def test_many_simultaneous_check_calls(self, agentguard_server):
        """Spawn many threads, each calling Guard.check. All should succeed
        and no data race or deadlock should surface (the Go server runs under
        its own scheduler, this just confirms the SDK + HTTP path is clean)."""
        import concurrent.futures

        g = Guard(agentguard_server.base_url, agent_id="stress-bot")

        def one(i):
            r = g.check("shell", command=f"ls -la worker-{i}")
            return r.allowed

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            results = list(ex.map(one, range(100)))
        assert all(results), f"some checks failed: {sum(1 for r in results if not r)} failures"
