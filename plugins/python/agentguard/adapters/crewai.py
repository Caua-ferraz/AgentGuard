"""
AgentGuard CrewAI Adapter

Wraps CrewAI tools so every invocation passes through AgentGuard policy checks.

Usage:
    from agentguard.adapters.crewai import GuardedCrewTool, guard_crew_tools

    # Wrap a single tool
    guarded = GuardedCrewTool(my_tool, guard_url="http://localhost:8080")

    # Wrap all tools for a crew
    tools = guard_crew_tools(
        tools=[tool_a, tool_b],
        guard_url="http://localhost:8080",
        agent_id="my-crew-agent",
    )
"""

from typing import Any, List, Optional
from agentguard import Guard, DEFAULT_BASE_URL


class GuardedCrewTool:
    """Wraps a CrewAI BaseTool with AgentGuard policy enforcement.

    CrewAI tools implement a `_run` method and expose `name` and `description`.
    This wrapper intercepts `_run` and `run` to check the policy first.
    """

    def __init__(
        self,
        tool: Any,
        guard: Optional[Guard] = None,
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "",
        scope: str = "shell",
    ):
        self._tool = tool
        self._guard = guard or Guard(guard_url, agent_id=agent_id)
        self._scope = scope

        # Preserve original tool metadata
        self.name = getattr(tool, "name", type(tool).__name__)
        self.description = getattr(tool, "description", "")
        if hasattr(tool, "args_schema"):
            self.args_schema = tool.args_schema

    def _infer_scope(self, tool_input: Any) -> str:
        """Infer scope from the tool input."""
        combined = f"{self.name} {self.description}".lower()
        if any(kw in combined for kw in ["http", "api", "fetch", "request", "url", "web"]):
            return "network"
        if any(kw in combined for kw in ["file", "read", "write", "directory", "path"]):
            return "filesystem"
        if any(kw in combined for kw in ["browser", "navigate", "click", "page"]):
            return "browser"
        return self._scope

    def _extract_check_params(self, tool_input: Any) -> dict:
        """Extract parameters for the policy check from tool input."""
        params = {}
        if isinstance(tool_input, str):
            params["command"] = tool_input
        elif isinstance(tool_input, dict):
            if "command" in tool_input or "cmd" in tool_input:
                params["command"] = tool_input.get("command", tool_input.get("cmd", ""))
            if "url" in tool_input:
                params["url"] = tool_input["url"]
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(tool_input["url"])
                    if parsed.hostname:
                        params["domain"] = parsed.hostname
                except Exception:
                    pass
            if "path" in tool_input or "file_path" in tool_input:
                params["path"] = tool_input.get("path", tool_input.get("file_path", ""))
            # Forward session/cost hints for cost-scope guardrails.
            if "session_id" in tool_input:
                params["session_id"] = tool_input["session_id"]
            if "est_cost" in tool_input:
                params["est_cost"] = tool_input["est_cost"]
        return params

    def run(self, tool_input: Any = "", **kwargs) -> Any:
        """Run the tool after checking with AgentGuard."""
        params = self._extract_check_params(tool_input)
        scope = self._infer_scope(tool_input)
        result = self._guard.check(scope, **params)

        if result.allowed:
            # CrewAI tools use _run internally
            if hasattr(self._tool, "_run"):
                return self._tool._run(tool_input, **kwargs)
            return self._tool.run(tool_input, **kwargs)
        elif result.needs_approval:
            return (
                f"[AgentGuard] Action requires approval. "
                f"Approve at: {result.approval_url}\n"
                f"Reason: {result.reason}"
            )
        else:
            return (
                f"[AgentGuard] Action denied.\n"
                f"Reason: {result.reason}"
            )

    def _run(self, *args, **kwargs) -> Any:
        """CrewAI calls _run internally."""
        return self.run(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to the wrapped tool."""
        return getattr(self._tool, name)


def guard_crew_tools(
    tools: List[Any],
    guard_url: str = "http://localhost:8080",
    agent_id: str = "",
    default_scope: str = "shell",
) -> List[GuardedCrewTool]:
    """Wrap a list of CrewAI tools with AgentGuard enforcement.

    Args:
        tools: List of CrewAI tools to guard
        guard_url: URL of the AgentGuard proxy
        agent_id: Identifier for this agent in audit logs
        default_scope: Default policy scope

    Returns:
        List of GuardedCrewTool instances
    """
    guard = Guard(guard_url, agent_id=agent_id)
    return [
        GuardedCrewTool(tool, guard=guard, scope=default_scope)
        for tool in tools
    ]
