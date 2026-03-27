# AgentGuard Python SDK

Lightweight Python client for [AgentGuard](https://github.com/Caua-ferraz/AgentGuard) — the firewall for AI agents.

## Install

```bash
pip install agentguard

# With framework adapters
pip install agentguard[langchain]
pip install agentguard[crewai]
pip install agentguard[browser-use]
pip install agentguard[all]
```

## Quick Start

```python
from agentguard import Guard

guard = Guard("http://localhost:8080", agent_id="my-agent")

# Check before executing
result = guard.check("shell", command="rm -rf ./old_data")

if result.allowed:
    execute(command)
elif result.needs_approval:
    print(f"Approve at: {result.approval_url}")
else:
    print(f"Blocked: {result.reason}")
```

## Framework Adapters

### LangChain

```python
from agentguard.adapters.langchain import GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="langchain-agent",
)

agent = create_react_agent(llm, toolkit.tools, prompt)
```

### CrewAI

```python
from agentguard.adapters.crewai import guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_crew_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)
```

### browser-use

```python
from agentguard.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080")

result = browser.check_navigation("https://example.com")
if result.allowed:
    await page.goto("https://example.com")
```

### MCP

```python
from agentguard.adapters.mcp import GuardedMCPServer

server = GuardedMCPServer(guard_url="http://localhost:8080")
server.add_tool("my_tool", "Description", handler=my_handler)
server.run()  # Starts stdio MCP server
```

## API Reference

### `Guard(base_url, agent_id="")`
- `check(scope, *, action, command, path, domain, url, meta)` — Check an action against policy
- `approve(approval_id)` — Approve a pending action
- `deny(approval_id)` — Deny a pending action
- `wait_for_approval(approval_id, timeout=300)` — Block until resolved

### `CheckResult`
- `.allowed` — True if action is permitted
- `.denied` — True if action is blocked
- `.needs_approval` — True if human approval required
- `.decision` — Raw decision string
- `.reason` — Explanation
- `.approval_url` — URL to approve (when applicable)

### `@guarded(scope, guard=None)` decorator
Wraps a function so it's checked before execution.

## License

Apache 2.0
