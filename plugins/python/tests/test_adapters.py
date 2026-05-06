"""Unit tests for framework adapters.

These tests mock the underlying frameworks to avoid importing langchain/crewai/etc.
"""

import json
from unittest.mock import MagicMock

import pytest

from agentguard import Guard, DEFAULT_BASE_URL
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# LangChain adapter
# ---------------------------------------------------------------------------

class TestLangChainAdapter:
    def test_guarded_tool_run_allowed(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        mock_tool = MagicMock()
        mock_tool.name = "shell_tool"
        mock_tool.description = "runs shell commands"
        mock_tool.run.return_value = "output"

        gt = GuardedTool(mock_tool, guard, scope="shell")
        result = gt.run("ls -la")

        assert result == "output"
        mock_tool.run.assert_called_once_with("ls -la")

    def test_guarded_tool_run_denied(self, mock_server):
        from agentguard.adapters.langchain import GuardedTool

        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "dangerous command",
        }
        guard = Guard(mock_server)

        mock_tool = MagicMock()
        mock_tool.name = "shell_tool"
        mock_tool.description = "runs shell commands"

        gt = GuardedTool(mock_tool, guard, scope="shell")
        result = gt.run("rm -rf /")

        assert "denied" in result.lower()
        mock_tool.run.assert_not_called()

    def test_toolkit_infer_scope(self):
        from agentguard.adapters.langchain import GuardedToolkit

        tk = GuardedToolkit(tools=[], guard_url=DEFAULT_BASE_URL)

        mock_tool = MagicMock()
        mock_tool.name = "http_request"
        mock_tool.description = "makes API calls"
        assert tk._infer_scope(mock_tool) == "network"

        mock_tool.name = "read_file"
        mock_tool.description = "reads a file from disk"
        assert tk._infer_scope(mock_tool) == "filesystem"

        mock_tool.name = "navigate"
        mock_tool.description = "browser page navigation"
        assert tk._infer_scope(mock_tool) == "browser"

        mock_tool.name = "exec"
        mock_tool.description = "run a bash command"
        assert tk._infer_scope(mock_tool) == "shell"

        mock_tool.name = "custom"
        mock_tool.description = "does something"
        assert tk._infer_scope(mock_tool) == "shell"  # default


# ---------------------------------------------------------------------------
# CrewAI adapter
# ---------------------------------------------------------------------------

class TestCrewAIAdapter:
    """Smoke tests for the CrewAI adapter. The full hardening test
    suite — including modern API gating (invoke/ainvoke/__call__),
    strict allowlist enforcement, and real-CrewAI integration — lives
    in tests/test_crewai.py. These tests are the legacy-API coupon.
    """

    def test_guarded_crew_tool_delegates(self, mock_server):
        from agentguard.adapters.crewai import GuardedCrewTool

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        guard = Guard(mock_server)

        # Use a real class (not MagicMock) because the v0.5 wrapper has
        # a strict attribute allowlist; MagicMock auto-generates random
        # attributes which would either pass or fail the allowlist
        # nondeterministically.
        class _Tool:
            name = "search"
            description = "search the web"

            def _run(self, *args, **kwargs):
                return "results"

        gt = GuardedCrewTool(_Tool(), guard=guard, scope="network")
        result = gt.run("query")

        assert result == "results"

    def test_extract_check_params_dict(self, mock_server):
        from agentguard.adapters.crewai import GuardedCrewTool

        guard = Guard(mock_server)

        class _Tool:
            name = "tool"
            description = ""

        gt = GuardedCrewTool(_Tool(), guard=guard)
        params = gt._extract_check_params({"command": "echo hi", "path": "/tmp/x"})
        assert params["command"] == "echo hi"
        assert params["path"] == "/tmp/x"

    def test_extract_check_params_string(self, mock_server):
        from agentguard.adapters.crewai import GuardedCrewTool

        guard = Guard(mock_server)

        class _Tool:
            name = "tool"
            description = ""

        gt = GuardedCrewTool(_Tool(), guard=guard)
        params = gt._extract_check_params("echo hello")
        assert params["command"] == "echo hello"


# ---------------------------------------------------------------------------
# browser-use adapter
# ---------------------------------------------------------------------------

class TestBrowserUseAdapter:
    def test_check_navigation(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        browser = GuardedBrowser(guard_url=mock_server)

        result = browser.check_navigation("https://example.com/page")
        assert result.allowed

        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "browser"
        assert body["domain"] == "example.com"
        assert body["url"] == "https://example.com/page"

    def test_check_form_input(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "PII"}
        browser = GuardedBrowser(guard_url=mock_server)

        result = browser.check_form_input(
            "https://bank.com/login", "password", "secret123"
        )
        assert result.denied

        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "data"
        assert body["domain"] == "bank.com"


# ---------------------------------------------------------------------------
# MCP adapter
# ---------------------------------------------------------------------------

class TestMCPAdapter:
    def test_handle_initialize(self):
        from agentguard.adapters.mcp import GuardedMCPServer, MCP_PROTOCOL_VERSION

        server = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        response = server._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        })

        assert response["id"] == 1
        result = response["result"]
        assert result["protocolVersion"] == MCP_PROTOCOL_VERSION
        assert result["serverInfo"]["name"] == "agentguard"

    def test_handle_tools_list(self):
        from agentguard.adapters.mcp import GuardedMCPServer

        server = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        server.add_tool("my_tool", "A test tool", handler=lambda: "ok")

        response = server._handle_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        })

        tools = response["result"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "my_tool"

    def test_handle_unknown_method(self):
        from agentguard.adapters.mcp import GuardedMCPServer

        server = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        response = server._handle_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "unknown/method",
            "params": {},
        })

        assert "error" in response
        assert response["error"]["code"] == -32601
