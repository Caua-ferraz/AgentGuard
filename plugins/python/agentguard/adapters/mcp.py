"""
AgentGuard MCP (Model Context Protocol) Adapter

Provides an MCP-compatible tool server that wraps existing tools with AgentGuard
policy enforcement. This allows any MCP-compatible client (Claude Desktop,
Cursor, etc.) to have its tool calls guarded by policy.

Usage as an MCP server (stdio transport):

    python -m agentguard.adapters.mcp --policy configs/default.yaml

Or programmatically:

    from agentguard.adapters.mcp import GuardedMCPServer

    server = GuardedMCPServer(
        guard_url="http://localhost:8080",
        agent_id="mcp-agent",
    )
    server.add_tool(my_tool_definition, my_tool_handler)
    server.run()

MCP config (claude_desktop_config.json / .cursor/mcp.json):

    {
      "mcpServers": {
        "agentguard": {
          "command": "python",
          "args": ["-m", "agentguard.adapters.mcp", "--guard-url", "http://localhost:8080"]
        }
      }
    }
"""

import json
import sys
from typing import Any, Callable, Dict, List, Optional
from agentguard import Guard, CheckResult, DEFAULT_BASE_URL

# MCP protocol constants
MCP_PROTOCOL_VERSION = "2024-11-05"
SDK_VERSION = "0.4.1"


class ToolDefinition:
    """Defines an MCP tool that can be guarded."""

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Optional[dict] = None,
        scope: str = "shell",
    ):
        self.name = name
        self.description = description
        self.input_schema = input_schema or {"type": "object", "properties": {}}
        self.scope = scope


class GuardedMCPServer:
    """MCP server that enforces AgentGuard policies on tool calls.

    This implements the MCP stdio transport protocol. Tool calls are checked
    against the AgentGuard proxy before execution.
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "mcp-agent",
        server_name: str = "agentguard",
        server_version: str = SDK_VERSION,
    ):
        self._guard = guard or Guard(guard_url, agent_id=agent_id)
        self._tools: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, Callable] = {}
        self._server_name = server_name
        self._server_version = server_version

    def add_tool(
        self,
        name: str,
        description: str,
        handler: Callable,
        input_schema: Optional[dict] = None,
        scope: str = "shell",
    ):
        """Register a tool with the MCP server.

        Args:
            name: Tool name
            description: Human-readable description
            handler: Function to call when the tool is invoked
            input_schema: JSON Schema for the tool's input
            scope: AgentGuard policy scope for this tool
        """
        self._tools[name] = ToolDefinition(name, description, input_schema, scope)
        self._handlers[name] = handler

    def _infer_check_params(self, tool: ToolDefinition, arguments: dict) -> dict:
        """Extract policy-relevant parameters from tool arguments."""
        params = {}

        if "command" in arguments or "cmd" in arguments:
            params["command"] = arguments.get("command", arguments.get("cmd", ""))
        elif tool.scope == "shell":
            # Use the full arguments as the command representation
            params["command"] = f"{tool.name} {json.dumps(arguments)}"

        if "url" in arguments:
            params["url"] = arguments["url"]
            try:
                from urllib.parse import urlparse
                parsed = urlparse(arguments["url"])
                if parsed.hostname:
                    params["domain"] = parsed.hostname
            except Exception:
                pass

        if "path" in arguments or "file_path" in arguments:
            params["path"] = arguments.get("path", arguments.get("file_path", ""))
            name_lower = tool.name.lower()
            if "read" in name_lower or "get" in name_lower:
                params["action"] = "read"
            elif "write" in name_lower or "save" in name_lower:
                params["action"] = "write"
            elif "delete" in name_lower or "remove" in name_lower:
                params["action"] = "delete"

        if "domain" in arguments:
            params["domain"] = arguments["domain"]

        # Forward session/cost hints so cost-scope guardrails work via MCP.
        if "session_id" in arguments:
            params["session_id"] = arguments["session_id"]
        if "est_cost" in arguments:
            params["est_cost"] = arguments["est_cost"]

        return params

    def _handle_request(self, request: dict) -> dict:
        """Handle a single JSON-RPC request."""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            # MCP clients advertise their protocol version in params. We pin to
            # MCP_PROTOCOL_VERSION and do not yet negotiate — real negotiation
            # is a v0.5.0 design item. If the client wants a different version
            # (usually newer), log a single WARN to stderr so operators can
            # see version drift, then respond with our pinned version. stdout
            # is reserved for JSON-RPC on the stdio transport, so the warning
            # MUST go to stderr.
            client_version = params.get("protocolVersion") if isinstance(params, dict) else None
            if client_version and client_version != MCP_PROTOCOL_VERSION:
                sys.stderr.write(
                    f"WARN agentguard.mcp: client requested protocolVersion "
                    f"{client_version!r}, pinning to {MCP_PROTOCOL_VERSION!r} "
                    f"(negotiation is a v0.5.0 design item)\n"
                )
                sys.stderr.flush()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": self._server_name,
                        "version": self._server_version,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            }

        if method == "tools/list":
            tools_list = []
            for tool in self._tools.values():
                tools_list.append({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                })
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            return self._call_tool(req_id, tool_name, arguments)

        if method == "notifications/initialized":
            # Notification, no response needed
            return None

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }

    def _call_tool(self, req_id: Any, tool_name: str, arguments: dict) -> dict:
        """Execute a tool call with policy enforcement."""
        if tool_name not in self._tools:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
            }

        tool = self._tools[tool_name]
        handler = self._handlers[tool_name]

        # Policy check
        check_params = self._infer_check_params(tool, arguments)
        scope = tool.scope
        if check_params.get("domain") or check_params.get("url"):
            scope = "network"
        if check_params.get("path"):
            scope = "filesystem"

        result = self._guard.check(scope, **check_params)

        if result.denied:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"[AgentGuard] Action denied: {result.reason}",
                        }
                    ],
                    "isError": True,
                },
            }

        if result.needs_approval:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"[AgentGuard] Action requires approval.\n"
                                f"Reason: {result.reason}\n"
                                f"Approve at: {result.approval_url}"
                            ),
                        }
                    ],
                    "isError": True,
                },
            }

        # Action allowed — execute the handler
        try:
            output = handler(**arguments) if isinstance(arguments, dict) else handler(arguments)
            if not isinstance(output, str):
                output = json.dumps(output, default=str)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": output}],
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error: {e}"}],
                    "isError": True,
                },
            }

    def run(self):
        """Run the MCP server on stdio (blocking)."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                continue

            response = self._handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()


def main():
    """Entry point for running as `python -m agentguard.adapters.mcp`."""
    import argparse

    parser = argparse.ArgumentParser(description="AgentGuard MCP Server")
    parser.add_argument("--guard-url", default="http://localhost:8080", help="AgentGuard proxy URL")
    parser.add_argument("--agent-id", default="mcp-agent", help="Agent identifier")
    args = parser.parse_args()

    server = GuardedMCPServer(guard_url=args.guard_url, agent_id=args.agent_id)

    # The MCP server starts with no tools — downstream MCP proxies or
    # configurations add tools dynamically via the protocol. For standalone
    # usage, users import GuardedMCPServer and call add_tool().
    server.run()


if __name__ == "__main__":
    main()
