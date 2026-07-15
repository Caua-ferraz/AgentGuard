"""Shared check-parameter extraction for the framework adapters.

LangChain, CrewAI and MCP all reduce a tool invocation to the same
``Guard.check`` keyword arguments (command, url, domain, path, action,
session_id, est_cost). The extraction lives here once so the adapters
cannot drift apart; each adapter keeps only its framework-specific
glue (input normalisation, error surfacing, redaction).
"""

from typing import Any
from urllib.parse import urlparse


def domain_from_url(url: Any) -> str:
    """Best-effort hostname extraction; "" when absent or malformed."""
    if not isinstance(url, str):
        return ""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def infer_path_action(tool_name: Any) -> str:
    """Map a tool-name verb to the canonical filesystem action
    ("read"/"write"/"delete"), or "" when no verb matches. Mirrors the
    Go side's gateclient.InferFilesystemAction verb groups.
    """
    if not isinstance(tool_name, str):
        return ""
    name_lower = tool_name.lower()
    if "read" in name_lower or "get" in name_lower:
        return "read"
    if "write" in name_lower or "save" in name_lower or "create" in name_lower:
        return "write"
    if "delete" in name_lower or "remove" in name_lower:
        return "delete"
    return ""


def extract_check_params(tool_input: Any, tool_name: Any = None) -> dict:
    """Reduce a str/dict tool input to ``Guard.check`` keyword params.

    A bare string is treated as a shell command. For dicts, recognised
    keys are projected (command/cmd, url + derived domain,
    path/file_path + action inferred from the tool-name verb,
    session_id, est_cost); everything else is ignored.
    """
    params: dict = {}
    if isinstance(tool_input, str):
        params["command"] = tool_input
    elif isinstance(tool_input, dict):
        if "command" in tool_input or "cmd" in tool_input:
            params["command"] = tool_input.get(
                "command", tool_input.get("cmd", "")
            )
        if "url" in tool_input:
            params["url"] = tool_input["url"]
            domain = domain_from_url(tool_input["url"])
            if domain:
                params["domain"] = domain
        if "path" in tool_input or "file_path" in tool_input:
            params["path"] = tool_input.get(
                "path", tool_input.get("file_path", "")
            )
            action = infer_path_action(tool_name)
            if action:
                params["action"] = action
        if "session_id" in tool_input:
            params["session_id"] = tool_input["session_id"]
        if "est_cost" in tool_input:
            params["est_cost"] = tool_input["est_cost"]
    return params
