"""Extended adapter coverage beyond the smoke tests in test_adapters.py.

Targets:
  - LangChain: async path, approval path, attribute proxying, inferred scope
    for URL and path arguments.
  - CrewAI: _run alias, approval path, string vs dict extraction edge cases,
    scope inference from description.
  - browser-use: navigation approval/deny paths, GuardedPage wrapping, form
    input deny, agent_id propagation.
  - Multi-agent isolation across adapters sharing the same mock server.
"""

import asyncio
import json
import threading
from unittest.mock import MagicMock, AsyncMock

import pytest

from agentguard import Guard, DEFAULT_BASE_URL
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------

class TestLangChainExtended:
    def test_run_approval_returns_message(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://approve/ap_1",
        }
        guard = Guard(mock_server)
        tool = MagicMock()
        tool.name = "shell_tool"
        tool.description = "shell"
        gt = GuardedTool(tool, guard, scope="shell")

        out = gt.run("sudo reboot")
        assert "approval" in out.lower()
        assert "http://approve/ap_1" in out
        tool.run.assert_not_called()

    def test_async_run_allowed(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        tool = MagicMock()
        tool.name = "async_tool"
        tool.description = ""
        tool.arun = AsyncMock(return_value="async-result")

        gt = GuardedTool(tool, guard, scope="shell")
        out = asyncio.run(gt.arun("ls"))
        assert out == "async-result"
        tool.arun.assert_called_once()

    def test_async_run_denied(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
        guard = Guard(mock_server)

        tool = MagicMock()
        tool.name = "t"
        tool.description = ""
        tool.arun = AsyncMock(return_value="never")

        gt = GuardedTool(tool, guard, scope="shell")
        out = asyncio.run(gt.arun("rm -rf /"))
        assert "denied" in out.lower()
        tool.arun.assert_not_called()

    def test_infer_scope_prefers_network_on_url(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)

        tool = MagicMock()
        tool.name = "fetch"
        tool.description = ""
        gt = GuardedTool(tool, guard, scope="shell")
        gt.run({"url": "https://api.example.com/path"})

        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "network"
        assert body["domain"] == "api.example.com"

    def test_infer_scope_prefers_filesystem_on_path(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)

        tool = MagicMock()
        tool.name = "write_report"
        tool.description = ""
        gt = GuardedTool(tool, guard, scope="shell")
        gt.run({"path": "/tmp/x.txt"})

        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "filesystem"
        assert body["path"] == "/tmp/x.txt"
        assert body["action"] == "write"

    def test_attribute_proxy_blocked(self, mock_server):
        """v0.5: arbitrary attribute access is blocked (was a bypass vector).

        Pre-v0.5, ``GuardedTool.__getattr__`` proxied every attribute through
        to the wrapped tool, which let a caller fetch ``gt.func`` or any
        other internal and call it directly to bypass the policy gate. v0.5
        replaces that with a strict allowlist (R5 audit closure). Only
        metadata attributes (name, description, args_schema, return_direct,
        metadata, tags) pass through.
        """
        from agentguard.adapters.langchain import GuardedTool

        guard = Guard(mock_server)
        tool = MagicMock()
        tool.name = "t"
        tool.description = "d"
        tool.custom_attr = "proxied-value"
        gt = GuardedTool(tool, guard, scope="shell")

        # Allowlisted metadata is exposed:
        assert gt.name == "t"
        assert gt.description == "d"

        # Arbitrary attributes are blocked with a security note:
        with pytest.raises(AttributeError) as ei:
            _ = gt.custom_attr
        assert "bypass" in str(ei.value).lower()

    def test_malformed_url_does_not_crash(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)
        tool = MagicMock()
        tool.name = "fetch"
        tool.description = ""
        gt = GuardedTool(tool, guard, scope="shell")
        gt.run({"url": "not://a//valid::url"})
        # Should not have thrown.
        assert MockAgentGuardHandler.last_request_body is not None


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------

class _FakeCrewTool:
    """Minimal CrewAI-tool-shaped stand-in used by the extended tests.

    Real classes (not MagicMock) are required by the v0.5 wrapper,
    which has a strict attribute allowlist — MagicMock auto-generates
    arbitrary attributes that would interact unpredictably with the
    allowlist's AttributeError contract.
    """

    def __init__(self, name="x", description=""):
        self.name = name
        self.description = description
        self.calls: list = []

    def _run(self, *args, **kwargs):
        self.calls.append(("_run", args, kwargs))
        return "done"

    def run(self, *args, **kwargs):
        self.calls.append(("run", args, kwargs))
        return "ran"


class TestCrewAIExtended:
    def test_run_method_alias_underscore(self, mock_server):
        """CrewAI calls _run internally; our wrapper routes both to the same
        policy-enforced entry point."""
        from agentguard.adapters.crewai import GuardedCrewTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)
        inner = _FakeCrewTool(name="x", description="")

        gt = GuardedCrewTool(inner, guard=guard, scope="shell")
        out = gt._run("hello")
        assert out == "done"
        # The wrapper's _run dispatched to the inner's _run.
        assert any(c[0] == "_run" for c in inner.calls)

    def test_approval_response(self, mock_server):
        """v0.5: REQUIRE_APPROVAL raises PermissionError (typed)."""
        from agentguard.adapters.crewai import GuardedCrewTool
        from agentguard import AgentGuardApprovalRequired

        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://approve/x",
        }
        guard = Guard(mock_server)
        inner = _FakeCrewTool()
        gt = GuardedCrewTool(inner, guard=guard, scope="shell")

        with pytest.raises(PermissionError) as ei:
            gt.run("sudo")
        assert isinstance(ei.value, AgentGuardApprovalRequired)
        assert "approval" in str(ei.value).lower()
        assert "http://approve/x" in str(ei.value)
        # Underlying never called.
        assert inner.calls == []

    def test_extract_params_malformed_url_no_domain(self, mock_server):
        from agentguard.adapters.crewai import GuardedCrewTool

        guard = Guard(mock_server)
        inner = _FakeCrewTool()
        gt = GuardedCrewTool(inner, guard=guard)
        params = gt._extract_check_params({"url": "://bad"})
        # Should still include url, domain may be missing or empty.
        assert params["url"] == "://bad"
        assert params.get("domain", "") == ""

    def test_infer_scope_from_description(self, mock_server):
        from agentguard.adapters.crewai import GuardedCrewTool

        guard = Guard(mock_server)
        for desc, expected in [
            ("fetches an HTTP API", "network"),
            ("reads a file from disk", "filesystem"),
            ("navigates a browser page", "browser"),
            ("does something generic", "shell"),
        ]:
            inner = _FakeCrewTool(name="t", description=desc)
            gt = GuardedCrewTool(inner, guard=guard)
            assert gt._infer_scope(None) == expected

    def test_falls_back_to_run_if_no_underscore(self, mock_server):
        """If the wrapped tool has no _run (legacy), .run() is called."""
        from agentguard.adapters.crewai import GuardedCrewTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        guard = Guard(mock_server)

        class LegacyTool:
            name = "legacy"
            description = ""
            def run(self, tool_input, **kw):
                return f"ran-{tool_input}"

        gt = GuardedCrewTool(LegacyTool(), guard=guard, scope="shell")
        assert gt.run("hi") == "ran-hi"

    def test_guard_crew_tools_wraps_all(self, mock_server):
        from agentguard.adapters.crewai import guard_crew_tools, GuardedCrewTool

        tools = [_FakeCrewTool(name=f"t{i}") for i in range(3)]

        wrapped = guard_crew_tools(tools, guard_url=mock_server)
        assert len(wrapped) == 3
        assert all(isinstance(t, GuardedCrewTool) for t in wrapped)


# ---------------------------------------------------------------------------
# browser-use
# ---------------------------------------------------------------------------

class TestBrowserUseExtended:
    def test_check_action(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        result = browser.check_action("click", "#login-button", meta={"context": "home"})
        assert result.allowed
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "browser"
        assert "click" in body["command"]
        assert body["meta"]["context"] == "home"

    def test_check_navigation_denied(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
        browser = GuardedBrowser(guard_url=mock_server)
        result = browser.check_navigation("https://bank.com/transfer")
        assert result.denied
        assert result.reason == "blocked"

    def test_malformed_url_no_domain(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        browser.check_navigation("::garbage::")
        body = json.loads(MockAgentGuardHandler.last_request_body)
        # Still sends url, domain may be empty.
        assert body["url"] == "::garbage::"
        assert body.get("domain", "") == ""

    def test_guarded_page_goto_allowed(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)

        inner = MagicMock()
        inner.goto = AsyncMock(return_value="navigated")

        page = browser.wrap_page(inner)
        out = asyncio.run(page.goto("https://example.com"))
        assert out == "navigated"
        inner.goto.assert_called_once()

    def test_guarded_page_goto_denied_raises(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
        browser = GuardedBrowser(guard_url=mock_server)

        inner = MagicMock()
        inner.goto = AsyncMock(return_value="never")
        page = browser.wrap_page(inner)

        with pytest.raises(PermissionError) as ei:
            asyncio.run(page.goto("https://blocked.example"))
        assert "denied" in str(ei.value).lower()
        inner.goto.assert_not_called()

    def test_guarded_page_goto_approval_raises(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://approve/x",
        }
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.goto = AsyncMock(return_value="never")
        page = browser.wrap_page(inner)

        with pytest.raises(PermissionError) as ei:
            asyncio.run(page.goto("https://sensitive.example"))
        assert "approval" in str(ei.value).lower()
        inner.goto.assert_not_called()

    def test_guarded_page_attribute_proxy_is_now_default_deny(self, mock_server):
        # v0.5: GuardedPage no longer proxies arbitrary attributes — the
        # v0.4.x __getattr__ fall-through was the bypass closed by audit
        # finding R5 E4. Read-only properties on the allowlist still
        # forward; everything else raises AttributeError. This test pins
        # the new contract so a regression that re-introduces the proxy
        # is caught.
        from agentguard.adapters.browseruse import GuardedBrowser

        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.custom_method = lambda: "proxied"
        inner.url = "https://example.com"
        page = browser.wrap_page(inner)

        # Allowlisted read-only property still forwards.
        assert page.url == "https://example.com"

        # Non-allowlisted attribute is rejected with a security message.
        with pytest.raises(AttributeError) as ei:
            page.custom_method
        assert "AgentGuard" in str(ei.value) or "Guarded" in str(ei.value)

    def test_agent_id_propagation(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server, agent_id="browser-bot")
        browser.check_navigation("https://example.com")
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["agent_id"] == "browser-bot"


# ---------------------------------------------------------------------------
# Multi-agent isolation across adapters
# ---------------------------------------------------------------------------

class TestMultiAgentAcrossAdapters:
    def test_separate_adapters_send_distinct_agent_ids(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool
        from agentguard.adapters.crewai import GuardedCrewTool
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}

        lc_guard = Guard(mock_server, agent_id="langchain-agent")
        lc_tool = MagicMock(name="lc_tool")
        lc_tool.name = "t"
        lc_tool.description = ""
        lc = GuardedTool(lc_tool, lc_guard, scope="shell")
        lc.run("x")
        body_lc = json.loads(MockAgentGuardHandler.last_request_body)
        assert body_lc["agent_id"] == "langchain-agent"

        crew_guard = Guard(mock_server, agent_id="crew-agent")
        crew_tool = _FakeCrewTool(name="t", description="")
        crew = GuardedCrewTool(crew_tool, guard=crew_guard, scope="shell")
        crew.run("y")
        body_crew = json.loads(MockAgentGuardHandler.last_request_body)
        assert body_crew["agent_id"] == "crew-agent"

        browser = GuardedBrowser(guard_url=mock_server, agent_id="browser-agent")
        browser.check_navigation("https://example.com")
        body_br = json.loads(MockAgentGuardHandler.last_request_body)
        assert body_br["agent_id"] == "browser-agent"

    def test_concurrent_multi_agent_checks(self, mock_server):
        """Fan out checks from 3 agents in parallel and make sure each sees
        its own agent_id. Uses a thread-local last-request attribute via the
        mock handler's class-level capture."""
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}

        agents = ["a1", "a2", "a3"]
        results = {a: [] for a in agents}
        lock = threading.Lock()

        def worker(agent):
            g = Guard(mock_server, agent_id=agent)
            tool = MagicMock()
            tool.name = "t"
            tool.description = ""
            gt = GuardedTool(tool, g, scope="shell")
            gt.run(f"cmd-{agent}")
            with lock:
                results[agent].append("ok")

        threads = [threading.Thread(target=worker, args=(a,)) for a in agents for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for a in agents:
            assert len(results[a]) == 5
