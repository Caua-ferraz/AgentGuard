"""AgentGuard framework adapters.

Available adapters:
    - langchain: Wraps LangChain tools with policy enforcement
    - crewai: Wraps CrewAI tools with policy enforcement
    - browseruse: Wraps browser-use actions with policy enforcement
    - mcp: MCP-compatible server that enforces policies on tool calls
    - openai_agents: Gates OpenAI Agents SDK function tools (guard_tools)
      and provides an SDK tool input guardrail
"""
