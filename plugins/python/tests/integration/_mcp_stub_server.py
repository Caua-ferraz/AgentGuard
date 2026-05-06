"""A tiny Python MCP-stdio stub server used by the AT integration tests.

Why we ship our own stub instead of `npx -y @modelcontextprotocol/server-everything`:

  1. ``npx`` is not always on a CI runner's PATH (Linux containers strip it).
  2. The first invocation downloads the package over the network, which
     is flaky on offline / firewalled CI.
  3. We need a deterministic reply set the gateway test can assert against.

This stub speaks the MCP JSON-RPC stdio framing:

  * Reads one JSON-RPC frame per stdin line.
  * Responds on stdout with one JSON-RPC frame per line.
  * Logs any internal noise to stderr so it does not corrupt the framing.

Tools advertised:
  - ``echo`` (scope-agnostic; takes a ``message``)
  - ``read_file`` (path-style; AgentGuard upgrades scope to filesystem)
  - ``http_get`` (URL-style; AgentGuard upgrades scope to network)

Run as: ``python -m tests.integration._mcp_stub_server`` from the SDK root.
"""

from __future__ import annotations

import json
import sys


_TOOLS = [
    {
        "name": "echo",
        "description": "Echo a message back to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from disk.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "http_get",
        "description": "Fetch a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
]


def _handle(req: dict) -> dict | None:
    method = req.get("method", "")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "at-mcp-stub", "version": "1.0"},
                "capabilities": {"tools": {"listChanged": False}},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": list(_TOOLS)},
        }

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "echo":
            text = f"echoed: {args.get('message', '')}"
        elif name == "read_file":
            text = f"upstream read_file({args.get('path', '')})"
        elif name == "http_get":
            text = f"upstream http_get({args.get('url', '')})"
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"unknown tool: {name}"},
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": text}]},
        }

    if method.startswith("notifications/"):
        # MCP notifications get no response.
        return None

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"unknown method: {method}"},
    }


def main() -> None:  # pragma: no cover - subprocess entry point
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"stub: malformed JSON ({e})\n")
            sys.stderr.flush()
            continue
        try:
            resp = _handle(req)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"stub: handler error {type(e).__name__}: {e}\n")
            sys.stderr.flush()
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32603, "message": "internal stub error"},
            }
        if resp is not None:
            try:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                break


if __name__ == "__main__":
    main()
