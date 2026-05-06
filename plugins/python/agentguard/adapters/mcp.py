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
import re
import sys
from typing import Any, Callable, Dict, List, Optional
from agentguard import Guard, CheckResult, DEFAULT_BASE_URL

# MCP protocol constants
MCP_PROTOCOL_VERSION = "2024-11-05"
SDK_VERSION = "0.4.1"

# Secret patterns mirrored from pkg/notify/notify.go's DefaultRedactor. The
# MCP adapter forwards handler exception text back to the client as a
# content block; raw exception strings can carry bearer tokens, AWS keys,
# or credentials embedded in KEY=value form. Keeping this list in sync with
# the Go-side redactor means MCP egress matches webhook/Slack egress
# hygiene. A fresh `list()` so external callers who mutate it don't
# accidentally blank out redaction for the whole process.
_REDACT_PATTERNS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]+"),
    re.compile(r"(?i)(secret|token|password|api[_\-]?key)\s*=\s*\S+"),
]


def _redact(text: str) -> str:
    """Scrub obvious secret patterns from a string before returning it to
    the MCP client. Mirrors pkg/notify.DefaultRedactor. Returns the input
    unchanged when empty or when no pattern matches.
    """
    if not text:
        return text
    for p in _REDACT_PATTERNS:
        text = p.sub("[REDACTED]", text)
    return text


def _infer_check_params_for(tool: "ToolDefinition", arguments: dict) -> dict:
    """Free-function counterpart of :meth:`GuardedMCPServer._infer_check_params`.

    Both the in-process server and the gateway need identical inference +
    redaction. Defining the logic once at module scope keeps the gateway
    from awkwardly invoking the unbound server method on a non-server
    ``self`` (the v0.5 R7 E6 gateway preview is its own class).
    """
    from urllib.parse import urlparse  # local import — only used here

    params: Dict[str, Any] = {}

    if "command" in arguments or "cmd" in arguments:
        raw_cmd = arguments.get("command", arguments.get("cmd", ""))
        params["command"] = _redact(raw_cmd) if isinstance(raw_cmd, str) else raw_cmd
    elif tool.scope == "shell":
        params["command"] = _redact(f"{tool.name} {json.dumps(arguments)}")

    if "url" in arguments:
        params["url"] = arguments["url"]
        try:
            parsed = urlparse(arguments["url"])
            if parsed.hostname:
                params["domain"] = parsed.hostname
        except Exception:
            # urlparse practically never raises but defensive — a malformed
            # URL must not crash the policy check.
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

    if "session_id" in arguments:
        params["session_id"] = arguments["session_id"]
    if "est_cost" in arguments:
        params["est_cost"] = arguments["est_cost"]

    return params


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
        """Delegate to :func:`_infer_check_params_for`.

        Kept as a method for back-compat with any subclass / test that
        already binds it; the real logic (and v0.5 R7 T7 redaction) lives
        in the module-level helper so :class:`GuardedMCPGateway` can
        reuse it without instantiating a server.
        """
        return _infer_check_params_for(tool, arguments)

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
            # The client is an arbitrary MCP consumer (Claude Desktop,
            # Cursor, a script); any secret embedded in the exception
            # message would cross that trust boundary. Log the raw text
            # to stderr for operator diagnostics, return only a redacted
            # copy + the exception type over the wire.
            sys.stderr.write(
                f"agentguard.mcp: tool {tool_name!r} handler raised "
                f"{type(e).__name__}: {e}\n"
            )
            sys.stderr.flush()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": f"Error ({type(e).__name__}): {_redact(str(e))}",
                    }],
                    "isError": True,
                },
            }

    def run(self):
        """Run the MCP server on stdio (blocking).

        v0.5 (R5 E6, S9): each frame is processed inside a guard so that
        a single malformed JSON line, a handler exception, or a
        downstream-side error does not crash the adapter. Claude Desktop
        (and similar long-lived MCP clients) keep one stdio session open
        for the whole session — surviving a bad frame means the user
        does not have to restart their editor every time a tool throws.

        Behavior:
        - blank / whitespace-only line: dropped silently (back-compat).
        - JSON parse error: log to stderr, drop the frame. Best-effort
          JSON-RPC parse-error response is not emitted because the bad
          frame had no recoverable id.
        - handler raises: log to stderr, emit a JSON-RPC -32603
          "Internal error" response with whichever id was recoverable
          (``null`` if not). The adapter keeps reading the next frame.
        """
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            self._process_frame(line)

    def _process_frame(self, line: str) -> None:
        """Parse and dispatch a single JSON-RPC stdin frame.

        Split out from :meth:`run` so tests can drive it directly without
        building a full stdin/stdout transport.
        """
        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stderr.write(
                f"agentguard.mcp: dropping malformed JSON frame: {e}\n"
            )
            sys.stderr.flush()
            return

        try:
            response = self._handle_request(request)
        except Exception as e:
            # Recover the request id if the frame at least parsed.
            req_id = request.get("id") if isinstance(request, dict) else None
            sys.stderr.write(
                f"agentguard.mcp: handler raised {type(e).__name__}: {e}\n"
            )
            sys.stderr.flush()
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error ({type(e).__name__})",
                },
            }

        if response is not None:
            try:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except (BrokenPipeError, OSError) as e:
                # Client closed stdout — log once and exit the loop on the
                # next iteration. Don't try to write more responses to a
                # dead pipe.
                sys.stderr.write(
                    f"agentguard.mcp: stdout write failed ({type(e).__name__}); "
                    f"client likely closed the connection\n"
                )
                sys.stderr.flush()


class _UpstreamProcess:
    """Spawn a downstream MCP server and bridge JSON-RPC frames.

    Used by :class:`GuardedMCPGateway` to forward ``tools/list`` /
    ``tools/call`` / ``initialize`` to a real upstream MCP server while
    AgentGuard sits in the middle of every ``tools/call`` and decides
    whether to forward.

    The bridge is intentionally synchronous: one request, one response,
    matching the stdio JSON-RPC pattern Claude Desktop and Cursor use.
    Server-initiated notifications (``listChanged`` etc.) are not
    forwarded; capability merging and namespaced tool prefixes are
    deferred to v0.6's full Gateway implementation. v0.5 is a single
    upstream, request/response only.
    """

    def __init__(self, command: list, env: Optional[dict] = None):
        import subprocess  # local import keeps the SDK importable
                           # even on Pythons where subprocess is gated.
        self._cmd = command
        self._env = env
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,    # surface upstream logs to the operator
            env=env,
            text=True,
            bufsize=1,            # line-buffered; matches MCP stdio
        )

    def request(self, frame: dict, timeout: float = 30.0) -> Optional[dict]:
        """Send a JSON-RPC frame and read the matching response.

        Returns ``None`` for notifications (no ``id`` in the request) and
        for cases where the upstream closed the pipe. Raises ``RuntimeError``
        on transport failure so :class:`GuardedMCPGateway` can surface a
        JSON-RPC -32603 internal error to its own client instead of
        crashing the bridge.
        """
        if self._proc.poll() is not None:
            raise RuntimeError(
                f"upstream MCP server exited with code {self._proc.returncode}"
            )

        try:
            assert self._proc.stdin is not None  # nosec
            self._proc.stdin.write(json.dumps(frame) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise RuntimeError(f"upstream stdin write failed: {e}") from e

        # Notifications (no id) get no response.
        if "id" not in frame:
            return None

        try:
            assert self._proc.stdout is not None  # nosec
            line = self._proc.stdout.readline()
        except OSError as e:
            raise RuntimeError(f"upstream stdout read failed: {e}") from e

        if not line:
            raise RuntimeError("upstream MCP server closed stdout")
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"upstream emitted non-JSON frame: {line!r}"
            ) from e

    def close(self) -> None:
        """Terminate the upstream process. Safe to call repeatedly."""
        if self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()


class GuardedMCPGateway:
    """Single-upstream MCP gateway with AgentGuard in the middle.

    v0.5 deliverable previewing the full Phase 4B Gateway. Spawns one
    downstream MCP server (e.g. ``npx -y @modelcontextprotocol/server-filesystem``),
    answers ``tools/list`` by forwarding to the downstream, and gates
    every ``tools/call`` through ``Guard.check`` before forwarding.

    Limitations (closed in v0.6):
    - Single upstream — no capability merging.
    - No tool-name prefix / namespace separation.
    - Server-initiated notifications (``notifications/tools/list_changed``)
      are not forwarded.
    - No prompts/resources support — only ``tools/*`` is gated.

    Use :class:`GuardedMCPServer` directly when you want to register
    tools in code.
    """

    # Methods we always forward verbatim to the upstream.
    _FORWARD_METHODS = frozenset({
        "initialize",
        "tools/list",
        # Per-tool details / list-related extensions land here; safe to
        # forward as long as we still gate tools/call below.
    })

    def __init__(
        self,
        upstream: list,
        guard: Optional[Guard] = None,
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "mcp-gateway",
        env: Optional[dict] = None,
    ):
        if not upstream:
            raise ValueError("upstream command is required for the gateway")
        self._guard = guard or Guard(guard_url, agent_id=agent_id)
        self._upstream = _UpstreamProcess(upstream, env=env)
        # Cached tool list so we can apply scope inference per-tool. Refreshed
        # lazily via a ``tools/list`` round-trip.
        self._tool_scope: Dict[str, str] = {}

    def _refresh_tool_scopes(self) -> None:
        """Pull ``tools/list`` from the upstream and cache the names.

        Scope defaults to ``"shell"`` for unknown tools; ``_infer_check_params``
        upgrades to ``network`` / ``filesystem`` based on argument keys, so the
        default is mostly cosmetic. We do NOT try to read the description or
        schema to guess a smarter scope — keep the gateway simple in v0.5.
        """
        try:
            resp = self._upstream.request({
                "jsonrpc": "2.0",
                "id": "ag-internal-list",
                "method": "tools/list",
            })
        except RuntimeError:
            return
        if not resp or "result" not in resp:
            return
        for tool in resp["result"].get("tools", []) or []:
            name = tool.get("name")
            if isinstance(name, str):
                self._tool_scope.setdefault(name, "shell")

    def _gate_tools_call(self, frame: dict) -> dict:
        """Run AgentGuard on a ``tools/call`` frame; forward iff ALLOW."""
        params = frame.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {}) or {}
        req_id = frame.get("id")

        # Lazy: refresh scopes on first call so we know which tools exist.
        if not self._tool_scope:
            self._refresh_tool_scopes()
        scope = self._tool_scope.get(tool_name, "shell")

        # Reuse the shared inference + redaction helper.
        td = ToolDefinition(name=tool_name, description="", scope=scope)
        check_params = _infer_check_params_for(td, arguments)
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
                    "content": [{
                        "type": "text",
                        "text": f"[AgentGuard] Action denied: {result.reason}",
                    }],
                    "isError": True,
                },
            }
        if result.needs_approval:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": (
                            f"[AgentGuard] Action requires approval.\n"
                            f"Reason: {result.reason}\n"
                            f"Approve at: {result.approval_url}"
                        ),
                    }],
                    "isError": True,
                },
            }

        # ALLOW — forward the original frame to the upstream and relay its
        # response verbatim back to the client.
        try:
            return self._upstream.request(frame) or {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32603, "message": "upstream returned no response"},
            }
        except RuntimeError as e:
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32603, "message": f"upstream error: {e}"},
            }

    def handle(self, frame: dict) -> Optional[dict]:
        """Route one JSON-RPC frame.

        Returns the response to write back, or ``None`` for notifications.
        """
        method = frame.get("method", "")
        if method == "tools/call":
            return self._gate_tools_call(frame)
        if method in self._FORWARD_METHODS:
            try:
                return self._upstream.request(frame)
            except RuntimeError as e:
                return {
                    "jsonrpc": "2.0",
                    "id": frame.get("id"),
                    "error": {"code": -32603, "message": f"upstream error: {e}"},
                }
        if method.startswith("notifications/"):
            # Forward upstream so it sees `notifications/initialized` etc.
            # No response expected.
            try:
                self._upstream.request(frame)
            except RuntimeError:
                pass
            return None
        # Anything else — let upstream answer; if it doesn't, fall back to
        # method-not-found.
        try:
            resp = self._upstream.request(frame)
            if resp is not None:
                return resp
        except RuntimeError:
            pass
        return {
            "jsonrpc": "2.0",
            "id": frame.get("id"),
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }

    def run(self) -> None:
        """Run the gateway on stdio until stdin closes."""
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    frame = json.loads(line)
                except json.JSONDecodeError as e:
                    sys.stderr.write(
                        f"agentguard.mcp.gateway: dropping malformed frame: {e}\n"
                    )
                    sys.stderr.flush()
                    continue
                response = self.handle(frame)
                if response is not None:
                    try:
                        sys.stdout.write(json.dumps(response) + "\n")
                        sys.stdout.flush()
                    except (BrokenPipeError, OSError):
                        return
        finally:
            self._upstream.close()


def main():
    """Entry point for running as ``python -m agentguard.adapters.mcp``.

    Modes:
      - ``--upstream "<command...>"`` — gateway mode (R7 E6). Spawns the
        downstream MCP server given by the command, bridges JSON-RPC,
        and gates ``tools/call`` through AgentGuard. Example:
        ``python -m agentguard.adapters.mcp --guard-url http://localhost:8080
        --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"``.
      - no ``--upstream`` — empty-server mode. The original v0.4.x
        behavior, retained for back-compat with subclasses that
        ``register tools in code``. Emits a stderr WARN so an operator
        following the docs literally sees that no tools are registered
        (instead of silently exposing a tool-less server to Claude
        Desktop).
    """
    import argparse
    import shlex

    parser = argparse.ArgumentParser(description="AgentGuard MCP Server / Gateway")
    parser.add_argument(
        "--guard-url", default="http://localhost:8080",
        help="AgentGuard proxy URL",
    )
    parser.add_argument(
        "--agent-id", default="mcp-agent",
        help="Agent identifier",
    )
    parser.add_argument(
        "--upstream", default="",
        help=(
            "Downstream MCP server command (string passed through shlex.split). "
            "When set, runs in gateway mode: AgentGuard sits between the MCP "
            "client and this upstream and gates every tools/call. "
            "When unset, runs an empty server (programmatic use only)."
        ),
    )
    args = parser.parse_args()

    if args.upstream:
        cmd = shlex.split(args.upstream)
        gateway = GuardedMCPGateway(
            upstream=cmd,
            guard_url=args.guard_url,
            agent_id=args.agent_id,
        )
        gateway.run()
        return

    # Empty-server mode: warn the operator. Without --upstream and without
    # programmatic add_tool() calls, this server has zero tools and is
    # useless to a connected MCP client. The warning gives a clear hint.
    sys.stderr.write(
        "WARN agentguard.mcp: starting with NO tools registered. "
        "Pass --upstream '<command>' to run as a gateway in front of an "
        "existing MCP server, or import GuardedMCPServer programmatically "
        "and call add_tool() before run(). See docs/ADAPTERS.md.\n"
    )
    sys.stderr.flush()
    server = GuardedMCPServer(guard_url=args.guard_url, agent_id=args.agent_id)
    server.run()


if __name__ == "__main__":
    main()
