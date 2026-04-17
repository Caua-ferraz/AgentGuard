"""
AgentGuard LangChain Adapter

Wraps LangChain tools so every invocation passes through AgentGuard policy checks.

Usage:
    from agentguard.adapters.langchain import GuardedToolkit

    toolkit = GuardedToolkit(
        tools=my_tools,
        guard_url="http://localhost:8080",
        agent_id="my-langchain-agent",
    )

    agent = create_react_agent(llm, toolkit.tools, prompt)
"""

from typing import Any, List, Optional
from agentguard import Guard, CheckResult, DEFAULT_BASE_URL


class GuardedTool:
    """Wraps a LangChain tool with AgentGuard policy enforcement."""

    def __init__(self, tool: Any, guard: Guard, scope: str = "shell"):
        self._tool = tool
        self._guard = guard
        self._scope = scope

        # Preserve the original tool's metadata
        self.name = tool.name
        self.description = tool.description
        if hasattr(tool, "args_schema"):
            self.args_schema = tool.args_schema

    def _infer_check_params(self, tool_input: Any) -> dict:
        """Extract meaningful parameters from tool input for policy checking."""
        params = {}

        if isinstance(tool_input, str):
            params["command"] = tool_input
        elif isinstance(tool_input, dict):
            if "command" in tool_input or "cmd" in tool_input:
                params["command"] = tool_input.get("command", tool_input.get("cmd", ""))
            if "url" in tool_input:
                params["url"] = tool_input["url"]
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(tool_input["url"])
                    if parsed.hostname:
                        params["domain"] = parsed.hostname
                except Exception:
                    pass
            if "path" in tool_input or "file_path" in tool_input:
                params["path"] = tool_input.get("path", tool_input.get("file_path", ""))
                # Infer action from tool name
                name_lower = self.name.lower()
                if "read" in name_lower or "get" in name_lower:
                    params["action"] = "read"
                elif "write" in name_lower or "save" in name_lower or "create" in name_lower:
                    params["action"] = "write"
                elif "delete" in name_lower or "remove" in name_lower:
                    params["action"] = "delete"
            # Forward session/cost hints so cost-scope guardrails work.
            if "session_id" in tool_input:
                params["session_id"] = tool_input["session_id"]
            if "est_cost" in tool_input:
                params["est_cost"] = tool_input["est_cost"]

        return params

    def _infer_scope(self, params: dict) -> str:
        """Infer the appropriate policy scope from the parameters."""
        if params.get("domain") or params.get("url"):
            return "network"
        if params.get("path"):
            return "filesystem"
        return self._scope

    def run(self, tool_input: Any, **kwargs) -> Any:
        """Run the tool after checking with AgentGuard."""
        params = self._infer_check_params(tool_input)
        scope = self._infer_scope(params)

        result = self._guard.check(scope, **params)

        if result.allowed:
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

    async def arun(self, tool_input: Any, **kwargs) -> Any:
        """Async version — policy check is synchronous, tool execution is async."""
        params = self._infer_check_params(tool_input)
        scope = self._infer_scope(params)

        result = self._guard.check(scope, **params)

        if result.allowed:
            return await self._tool.arun(tool_input, **kwargs)
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

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to the wrapped tool."""
        return getattr(self._tool, name)


class GuardedToolkit:
    """Wraps a list of LangChain tools with AgentGuard enforcement.

    Args:
        tools: List of LangChain tools to guard
        guard_url: URL of the AgentGuard proxy
        agent_id: Identifier for this agent in audit logs
        default_scope: Default policy scope for tools that can't be auto-detected
    """

    def __init__(
        self,
        tools: List[Any],
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "",
        default_scope: str = "shell",
    ):
        self._guard = Guard(guard_url, agent_id=agent_id)
        self._default_scope = default_scope
        self._tools = [
            GuardedTool(tool, self._guard, scope=self._infer_scope(tool))
            for tool in tools
        ]

    def _infer_scope(self, tool: Any) -> str:
        """Try to infer the policy scope from the tool's name/description."""
        name = getattr(tool, "name", "").lower()
        desc = getattr(tool, "description", "").lower()
        combined = f"{name} {desc}"

        if any(kw in combined for kw in ["http", "api", "fetch", "request", "url", "web"]):
            return "network"
        if any(kw in combined for kw in ["file", "read", "write", "directory", "path"]):
            return "filesystem"
        if any(kw in combined for kw in ["browser", "navigate", "click", "page"]):
            return "browser"
        if any(kw in combined for kw in ["shell", "command", "exec", "terminal", "bash"]):
            return "shell"

        return self._default_scope

    @property
    def tools(self) -> List[GuardedTool]:
        """The guarded tool list — drop-in replacement for unguarded tools."""
        return self._tools
