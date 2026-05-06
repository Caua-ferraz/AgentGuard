"""Real-framework integration tests for AgentGuard SDK adapters.

These tests are gated behind ``@pytest.mark.integration`` and exercise full
agent loops against the actual upstream framework libraries. They are
deselected from the default ``pytest`` run and only execute via the
``integration-tests`` CI job (see ``.github/workflows/ci.yml``).

Each test file in this package skips itself entirely if the corresponding
framework is not importable, so running the integration suite without the
extras installed is a no-op rather than a failure.
"""
