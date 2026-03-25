"""
AgentGuard Quick Start Example

Demonstrates how to guard a simple AI agent that can run shell commands
and make API calls. Start AgentGuard first:

    agentguard serve --policy configs/default.yaml --dashboard

Then run this script:

    python examples/quickstart.py
"""

from agentguard import Guard

def main():
    # Connect to AgentGuard
    guard = Guard("http://localhost:8080", agent_id="quickstart-demo")

    print("=" * 60)
    print("  AgentGuard Quick Start Demo")
    print("=" * 60)
    print()

    # --- Test 1: Safe command (should be ALLOWED) ---
    print("[1] Checking: ls -la ./workspace")
    result = guard.check("shell", command="ls -la ./workspace")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    print()

    # --- Test 2: Dangerous command (should be DENIED) ---
    print("[2] Checking: rm -rf /")
    result = guard.check("shell", command="rm -rf /")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    print()

    # --- Test 3: Sudo command (should REQUIRE APPROVAL) ---
    print("[3] Checking: sudo apt install vim")
    result = guard.check("shell", command="sudo apt install vim")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    if result.needs_approval:
        print(f"    Approve:  {result.approval_url}")
    print()

    # --- Test 4: Allowed API call ---
    print("[4] Checking: network call to api.openai.com")
    result = guard.check("network", domain="api.openai.com")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    print()

    # --- Test 5: Blocked API call ---
    print("[5] Checking: network call to db.production.internal")
    result = guard.check("network", domain="db.production.internal")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    print()

    # --- Test 6: File read (allowed) ---
    print("[6] Checking: read ./workspace/data.csv")
    result = guard.check("filesystem", action="read", path="./workspace/data.csv")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    print()

    # --- Test 7: File write to system dir (denied) ---
    print("[7] Checking: write /etc/crontab")
    result = guard.check("filesystem", action="write", path="/etc/crontab")
    print(f"    Decision: {result.decision}")
    print(f"    Reason:   {result.reason}")
    print()

    print("=" * 60)
    print("  Done! Check the dashboard at http://localhost:8080/dashboard")
    print("=" * 60)


if __name__ == "__main__":
    main()
