"""
AgentGuard Python SDK

Lightweight client for checking actions against AgentGuard policies.

Usage:
    from agentguard import Guard

    guard = Guard("http://localhost:8080")
    result = guard.check("shell", command="rm -rf ./data")

    if result.allowed:
        execute(command)
    elif result.needs_approval:
        print(f"Approve at: {result.approval_url}")
    else:
        print(f"Blocked: {result.reason}")

Layout: the :class:`Guard` client, :class:`CheckResult`, exceptions and
constants live in :mod:`agentguard.core`; the ``@guarded`` decorator in
:mod:`agentguard.decorators`; framework integrations in
:mod:`agentguard.adapters`. Everything public is re-exported here —
import from the package root.
"""

# Back-compat module aliases. The pre-split __init__ imported these
# stdlib modules directly, which made e.g. ``agentguard.request`` and
# ``agentguard.time`` valid mock.patch targets ("agentguard.request.
# urlopen", "agentguard.time.sleep", ...). Patching through these names
# mutates the shared stdlib module, so it intercepts agentguard.core's
# calls exactly as it did before the split. Do not remove without a
# deprecation cycle.
import functools  # noqa: F401
import json  # noqa: F401
import logging  # noqa: F401
import os  # noqa: F401
import random  # noqa: F401
import time  # noqa: F401
from urllib import request, error  # noqa: F401
from urllib.parse import quote as urlquote  # noqa: F401

from agentguard.core import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_APPROVAL_TIMEOUT,
    DEFAULT_POLL_INTERVAL,
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    ENDPOINT_CHECK,
    ENDPOINT_APPROVE,
    ENDPOINT_DENY,
    ENDPOINT_STATUS,
    LOCAL_TENANT_ID,
    FAIL_MODE_DENY,
    FAIL_MODE_ALLOW,
    AgentGuardError,
    AgentGuardDenied,
    AgentGuardApprovalRequired,
    AgentGuardApprovalTimeout,
    AgentGuardAuthError,
    AgentGuardTimeoutError,
    CheckResult,
    Guard,
    log,
)
from agentguard.decorators import guarded

# Public API surface. Everything else is internal.
__all__ = [
    "Guard",
    "CheckResult",
    "guarded",
    "AgentGuardError",
    "AgentGuardDenied",
    "AgentGuardApprovalRequired",
    "AgentGuardApprovalTimeout",
    "AgentGuardAuthError",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_APPROVAL_TIMEOUT",
    "DEFAULT_POLL_INTERVAL",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DECISION_REQUIRE_APPROVAL",
    "LOCAL_TENANT_ID",
    "FAIL_MODE_DENY",
    "FAIL_MODE_ALLOW",
]
