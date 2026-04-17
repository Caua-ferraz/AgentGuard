"""Comprehensive tests for the AgentGuard MCP adapter.

Covers every JSON-RPC method the server implements, each decision branch
of tools/call, scope inference, argument parsing edge cases, and the stdio
run-loop.
"""

import io
import json
import threading
from unittest.mock import patch

import pytest

from agentguard import DEFAULT_BASE_URL, Guard
from agentguard.adapters.mcp import (
    GuardedMCPServer,
    MCP_PROTOCOL_VERSION,
    SDK_VERSION,
    ToolDefinition,
)
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# ToolDefinition
# ---------------------------------------------------------------------------

class TestToolDefinition:
    def test_defaults(self):
        td = ToolDefinition(name="t", description="d")
        assert td.name == "t"
        assert td.description == "d"
        assert td.scope == "shell"
        assert td.input_schema == {"type": "object", "properties": {}}

    def test_custom_schema(self):
        schema = {"type": "object", "required": ["x"], "properties": {"x": {"type": "string"}}}
        td = ToolDefinition(name="t", description="d", input_schema=schema, scope="network")
        assert td.input_schema == schema
        assert td.scope == "network"


# ---------------------------------------------------------------------------
# Constructor / configuration
# ---------------------------------------------------------------------------

class TestServerInit:
    def test_defaults(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        assert s._server_name == "agentguard"
        assert s._server_version == SDK_VERSION
        assert s._tools == {}
        assert s._handlers == {}
        assert isinstance(s._guard, Guard)

    def test_inject_guard(self, mock_server):
        guard = Guard(mock_server, agent_id="custom")
        s = GuardedMCPServer(guard=guard)
        assert s._guard is guard

    def test_custom_server_identity(self):
        s = GuardedMCPServer(
            guard_url=DEFAULT_BASE_URL,
            server_name="my-mcp",
            server_version="9.9.9",
        )
        assert s._server_name == "my-mcp"
        assert s._server_version == "9.9.9"


# ---------------------------------------------------------------------------
# initialize
# ---------------------------------------------------------------------------

class TestInitialize:
    def test_protocol_version(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        })
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION

    def test_server_info(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        info = resp["result"]["serverInfo"]
        assert info["name"] == "agentguard"
        assert info["version"] == SDK_VERSION

    def test_capabilities(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        caps = resp["result"]["capabilities"]
        assert "tools" in caps
        assert caps["tools"]["listChanged"] is False


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------

class TestToolsList:
    def test_empty(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert resp["result"]["tools"] == []

    def test_multiple_tools_listed(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        s.add_tool("a", "alpha", handler=lambda: "A")
        s.add_tool("b", "beta", handler=lambda: "B", scope="network",
                   input_schema={"type": "object", "required": ["x"]})
        s.add_tool("c", "gamma", handler=lambda: "C")

        resp = s._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = resp["result"]["tools"]
        names = [t["name"] for t in tools]
        assert sorted(names) == ["a", "b", "c"]

        # Schema preserved verbatim.
        b = next(t for t in tools if t["name"] == "b")
        assert b["description"] == "beta"
        assert b["inputSchema"]["required"] == ["x"]


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------

class TestToolsCall:
    def test_allowed_dict_args(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}

        s = GuardedMCPServer(guard_url=mock_server)

        received = {}
        def handler(**kwargs):
            received.update(kwargs)
            return "ok"

        s.add_tool("echo", "echoes", handler=handler, scope="shell")
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"command": "ls -la"}},
        })

        assert "error" not in resp
        assert resp["result"]["content"][0]["text"] == "ok"
        # The tool handler received the raw arguments unchanged.
        assert received == {"command": "ls -la"}

        # The policy server saw a shell-scoped check with the agent's command.
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "shell"
        assert body["command"] == "ls -la"

    def test_allowed_non_string_output_serialized(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("get_obj", "returns a dict", handler=lambda: {"x": 1}, scope="shell")

        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_obj", "arguments": {}},
        })

        content = resp["result"]["content"][0]["text"]
        assert json.loads(content) == {"x": 1}

    def test_denied_returns_error_content(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}

        s = GuardedMCPServer(guard_url=mock_server)

        calls = []
        s.add_tool("danger", "danger", handler=lambda **_: calls.append(1), scope="shell")

        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "danger", "arguments": {"command": "rm -rf /"}},
        })

        assert resp["result"]["isError"] is True
        assert "denied" in resp["result"]["content"][0]["text"].lower()
        assert calls == [], "denied tool must not execute"

    def test_require_approval_returns_approval_url(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_id": "ap_xyz",
            "approval_url": "http://approve/ap_xyz",
        }

        s = GuardedMCPServer(guard_url=mock_server)

        s.add_tool("sensitive", "maybe", handler=lambda **_: "never", scope="shell")
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "sensitive", "arguments": {"command": "sudo"}},
        })

        text = resp["result"]["content"][0]["text"]
        assert resp["result"]["isError"] is True
        assert "approval" in text.lower()
        assert "http://approve/ap_xyz" in text

    def test_unknown_tool(self, mock_server):
        s = GuardedMCPServer(guard_url=mock_server)
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32602
        assert "Unknown tool" in resp["error"]["message"]

    def test_handler_exception_wrapped(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)

        def boom(**_):
            raise RuntimeError("kaboom")

        s.add_tool("boom", "explodes", handler=boom, scope="shell")
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "boom", "arguments": {}},
        })
        assert resp["result"]["isError"] is True
        assert "kaboom" in resp["result"]["content"][0]["text"]

    def test_non_dict_arguments_still_invokes(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)

        observed = []
        def h(arg):
            observed.append(arg)
            return "done"

        s.add_tool("raw", "", handler=h, scope="shell")
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "raw", "arguments": "hello"},  # a string, not a dict
        })
        # Falls through to handler(arguments) when not a dict.
        assert observed == ["hello"]
        assert "error" not in resp


# ---------------------------------------------------------------------------
# Scope inference (_infer_check_params + tools/call scope selection)
# ---------------------------------------------------------------------------

class TestScopeInference:
    def test_url_triggers_network_scope(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("fetch", "", handler=lambda **_: "", scope="shell")

        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "fetch", "arguments": {"url": "https://api.example.com/x"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        # scope auto-upgraded to network, domain parsed from URL.
        assert body["scope"] == "network"
        assert body["domain"] == "api.example.com"
        assert body["url"] == "https://api.example.com/x"

    def test_path_triggers_filesystem_scope(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("read_file", "", handler=lambda **_: "", scope="shell")

        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "filesystem"
        assert body["path"] == "/tmp/x"
        # Action inferred from tool name.
        assert body["action"] == "read"

    def test_file_path_alias(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("write_doc", "", handler=lambda **_: "", scope="shell")
        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "write_doc", "arguments": {"file_path": "/tmp/out.txt"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["path"] == "/tmp/out.txt"
        assert body["action"] == "write"

    def test_delete_action_inferred_from_remove(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("remove_tmp", "", handler=lambda **_: "", scope="shell")
        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "remove_tmp", "arguments": {"path": "/tmp/x"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["action"] == "delete"

    def test_shell_scope_fallback_uses_tool_name_and_args(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("custom_thing", "", handler=lambda **_: "", scope="shell")
        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "custom_thing", "arguments": {"a": 1, "b": "x"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "shell"
        assert body["command"].startswith("custom_thing ")
        # The JSON-serialized arguments must be present so the policy can see them.
        assert '"a": 1' in body["command"]
        assert '"b": "x"' in body["command"]

    def test_domain_from_arguments(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("curl_tool", "", handler=lambda **_: "", scope="shell")
        s._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "curl_tool", "arguments": {"domain": "example.com"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["scope"] == "network"
        assert body["domain"] == "example.com"


# ---------------------------------------------------------------------------
# notifications & unknown methods
# ---------------------------------------------------------------------------

class TestProtocolEdges:
    def test_notifications_initialized_returns_none(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        })
        assert resp is None

    def test_unknown_method(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "no/such/method",
        })
        assert resp["error"]["code"] == -32601
        assert "no/such/method" in resp["error"]["message"]

    def test_missing_method_treated_as_unknown(self):
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        resp = s._handle_request({"jsonrpc": "2.0", "id": 1})
        assert "error" in resp


# ---------------------------------------------------------------------------
# stdio run-loop
# ---------------------------------------------------------------------------

class TestRunLoop:
    def test_run_processes_requests(self, mock_server):
        """Feed JSON-RPC lines over stdin and verify stdout contains responses."""
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}

        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("ping", "", handler=lambda **_: "pong", scope="shell")

        stdin = io.StringIO()
        stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        stdin.write("\n")  # empty line should be ignored
        stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "ping", "arguments": {}},
        }) + "\n")
        stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        stdin.write("{bad json\n")  # must be tolerated
        stdin.seek(0)

        stdout = io.StringIO()

        with patch("agentguard.adapters.mcp.sys.stdin", stdin), \
             patch("agentguard.adapters.mcp.sys.stdout", stdout):
            s.run()

        lines = [l for l in stdout.getvalue().splitlines() if l]
        # Two responses: initialize (id=1) and tools/call (id=2). The
        # notifications/initialized message and the bad JSON must produce no output.
        assert len(lines) == 2
        ids = sorted(json.loads(l)["id"] for l in lines)
        assert ids == [1, 2]

    def test_run_handles_multiple_tool_calls_in_order(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server)

        log = []
        s.add_tool("t", "", handler=lambda **kw: (log.append(kw.get("n", 0)), "ok")[1], scope="shell")

        stdin_lines = []
        for i in range(5):
            stdin_lines.append(json.dumps({
                "jsonrpc": "2.0", "id": i,
                "method": "tools/call",
                "params": {"name": "t", "arguments": {"n": i}},
            }))
        stdin = io.StringIO("\n".join(stdin_lines) + "\n")
        stdout = io.StringIO()

        with patch("agentguard.adapters.mcp.sys.stdin", stdin), \
             patch("agentguard.adapters.mcp.sys.stdout", stdout):
            s.run()

        assert log == [0, 1, 2, 3, 4]
        responses = [json.loads(l) for l in stdout.getvalue().splitlines() if l]
        assert [r["id"] for r in responses] == [0, 1, 2, 3, 4]


# ---------------------------------------------------------------------------
# Capacity & multi-agent
# ---------------------------------------------------------------------------

class TestCapacity:
    def test_many_tools_registered(self):
        """Register a lot of tools and make sure tools/list returns them all."""
        s = GuardedMCPServer(guard_url=DEFAULT_BASE_URL)
        for i in range(500):
            s.add_tool(f"tool_{i}", f"desc {i}", handler=lambda **_: "", scope="shell")
        resp = s._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert len(resp["result"]["tools"]) == 500

    def test_concurrent_tool_calls(self, mock_server):
        """Fire many concurrent tool calls; all must see an auth-tagged header
        (if configured) and return responses without dropping any."""
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}

        s = GuardedMCPServer(guard_url=mock_server)
        s.add_tool("t", "", handler=lambda **_: "ok", scope="shell")

        results = []
        def worker(i):
            results.append(s._handle_request({
                "jsonrpc": "2.0", "id": i,
                "method": "tools/call",
                "params": {"name": "t", "arguments": {"command": f"cmd-{i}"}},
            }))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 32
        for r in results:
            assert "error" not in r
            assert r["result"]["content"][0]["text"] == "ok"

    def test_multi_agent_isolation(self, mock_server):
        """Different GuardedMCPServer instances using different agent_ids must
        each send their own agent_id to the policy server."""
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}

        g_a = Guard(mock_server, agent_id="agent-a")
        g_b = Guard(mock_server, agent_id="agent-b")
        s_a = GuardedMCPServer(guard=g_a)
        s_b = GuardedMCPServer(guard=g_b)

        for srv, name in [(s_a, "ta"), (s_b, "tb")]:
            srv.add_tool(name, "", handler=lambda **_: "", scope="shell")

        s_a._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "ta", "arguments": {"command": "a"}},
        })
        body_a = json.loads(MockAgentGuardHandler.last_request_body)
        assert body_a["agent_id"] == "agent-a"

        s_b._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "tb", "arguments": {"command": "b"}},
        })
        body_b = json.loads(MockAgentGuardHandler.last_request_body)
        assert body_b["agent_id"] == "agent-b"


# ---------------------------------------------------------------------------
# Auth propagation (agent_id + no api_key leak)
# ---------------------------------------------------------------------------

class TestAuthPropagation:
    def test_agent_id_forwarded_on_check(self, mock_server):
        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        s = GuardedMCPServer(guard_url=mock_server, agent_id="mcp-test")
        s.add_tool("t", "", handler=lambda **_: "", scope="shell")

        s._handle_request({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"command": "ls"}},
        })
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["agent_id"] == "mcp-test"
