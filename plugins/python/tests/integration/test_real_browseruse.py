"""Real browser-use / Playwright integration tests (Phase 3 — A14).

Drives a real Playwright Chromium browser through ``GuardedPage`` and
asserts every gated method routes through ``/v1/check``. The framework
is real; only the AgentGuard server is mocked.

Closes audit findings R5 P1 (real-framework canary), R5 P2/P3/P4 (modern
browser API gating), R1 F1 (version-floor bound), and the dynamic side
of R5 E4.

These tests carry both ``@pytest.mark.integration`` and
``@pytest.mark.playwright`` so a CI job that cannot install Chromium
binaries can deselect them with ``-m "integration and not playwright"``.
The CI integration-tests job runs ``playwright install --with-deps
chromium`` before invoking pytest.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# browser-use 0.4 was the first release on the modern browser_use.Browser
# API surface. Older versions are skipped rather than mis-tested.
browser_use = pytest.importorskip("browser_use", minversion="0.4")
playwright = pytest.importorskip("playwright", minversion="1.40")
playwright_async_api = pytest.importorskip("playwright.async_api")

from agentguard import Guard  # noqa: E402
from agentguard.adapters.browseruse import (  # noqa: E402
    GuardedBrowser,
    GuardedPage,
)

from .conftest import allow, deny  # noqa: E402


pytestmark = [pytest.mark.integration, pytest.mark.playwright]


# A tiny static page served via a data: URL so we don't need a webserver.
# The form has two fields and an evaluate-able JS context, which is all
# the gated methods need. data: URLs are RFC-7595 valid for navigation.
_DATA_URL = (
    "data:text/html,"
    "<html><body>"
    "<form>"
    "<input id='email' name='email'/>"
    "<input id='password' name='password' type='password'/>"
    "<button id='submit' type='button'>Go</button>"
    "</form>"
    "<script>window.AGENTGUARD_TEST = 42;</script>"
    "</body></html>"
)


# ---------------------------------------------------------------------------
# Fixtures — boot Playwright once per test for isolation. Slower than
# session-scoped, but stops cross-test page state from leaking.
# ---------------------------------------------------------------------------


@pytest.fixture()
def real_page():
    """Yield a real Playwright Page driven from a sync wrapper.

    Playwright's primary API is async; we adapt to a per-test event loop
    so the integration tests stay synchronous from pytest's perspective.
    Returns a tuple ``(page, run)`` where ``run(coro)`` schedules a
    coroutine on the same loop as the page.
    """
    from playwright.async_api import async_playwright

    loop = asyncio.new_event_loop()
    pw = loop.run_until_complete(async_playwright().start())
    try:
        browser = loop.run_until_complete(pw.chromium.launch(headless=True))
        context = loop.run_until_complete(browser.new_context())
        page = loop.run_until_complete(context.new_page())

        def run(coro):
            return loop.run_until_complete(coro)

        try:
            yield page, run
        finally:
            run(page.close())
            run(context.close())
            run(browser.close())
    finally:
        loop.run_until_complete(pw.stop())
        loop.close()


# ---------------------------------------------------------------------------
# Full flow — goto, evaluate, click on a real page.
# ---------------------------------------------------------------------------


class TestRealBrowserUseFullFlow:
    def test_real_browser_use_full_navigation_flow(self, integration_mock, real_page):
        """Navigate to a real page, evaluate JS, click a button.

        Each gated method must consult ``/v1/check`` exactly once.
        """
        integration_mock.set_default_check(allow())
        page, run = real_page

        guard = Guard(integration_mock.base_url, agent_id="bu-int")
        gp = GuardedPage(page, guard)

        run(gp.goto(_DATA_URL))
        result = run(gp.evaluate("window.AGENTGUARD_TEST"))
        assert result == 42
        run(gp.click("#submit"))

        bodies = [
            json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")
        ]
        # Three gated calls — one per real action.
        assert len(bodies) == 3
        assert bodies[0]["action"] == "goto"
        # evaluate routes through scope=browser; click routes through browser too.
        assert all(b["scope"] == "browser" for b in bodies)


class TestRealBrowserUseFormInput:
    def test_real_browser_use_form_fill_routes_through_data_scope(
        self, integration_mock, real_page
    ):
        """``GuardedPage.fill`` routes through the ``data`` scope so PII
        rules can fire independently of broader navigation rules.
        """
        integration_mock.set_default_check(allow())
        page, run = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-int-fill")
        gp = GuardedPage(page, guard)

        run(gp.goto(_DATA_URL))
        # fill goes through the data scope. The redaction contract
        # ensures the password value never lands in the request body verbatim.
        run(gp.fill("#password", "hunter2-shortvalue"))

        bodies = [
            json.loads(r["body"]) for r in integration_mock.requests_to("/v1/check")
        ]
        # First check is the goto (browser scope); second is the fill (data scope).
        assert bodies[0]["scope"] == "browser"
        assert bodies[1]["scope"] == "data"
        # The literal short value is allowed through (no redaction trigger),
        # but the meta carries the field name for operator-side rules.
        assert bodies[1]["meta"]["field"] == "#password"


class TestRealBrowserUseFormInputRedaction:
    def test_long_value_replaced_with_length_marker(self, integration_mock):
        """Long values must be replaced with ``<redacted; len=N>`` BEFORE
        the request body leaves the SDK — the engine never sees the raw value.
        """
        # No real page needed for this contract test — the redaction
        # happens entirely in GuardedBrowser.check_form_input.
        integration_mock.set_default_check(allow())
        guard = Guard(integration_mock.base_url, agent_id="bu-int-redact")
        gb = GuardedBrowser(guard=guard)

        long_value = "x" * 500  # > 256-char threshold
        gb.check_form_input("https://example.com", "essay", long_value)

        body = json.loads(integration_mock.requests_to("/v1/check")[-1]["body"])
        assert body["scope"] == "data"
        assert body["command"] == f"<redacted; len={len(long_value)}>"
        assert long_value not in body["command"]


class TestRealBrowserUseEvaluateGated:
    def test_real_browser_use_evaluate_gated(self, integration_mock, real_page):
        integration_mock.set_default_check(allow())
        page, run = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-int-eval")
        gp = GuardedPage(page, guard)

        run(gp.goto(_DATA_URL))
        result = run(gp.evaluate("1 + 2"))
        assert result == 3
        # Two gated calls: goto + evaluate.
        assert len(integration_mock.requests_to("/v1/check")) == 2


class TestRealBrowserUseDeny:
    def test_real_browser_use_goto_denied_raises(self, integration_mock, real_page):
        """A DENY on goto must raise PermissionError BEFORE Playwright runs."""
        integration_mock.set_default_check(deny(reason="rule:no-extern"))
        page, run = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-int-deny")
        gp = GuardedPage(page, guard)

        with pytest.raises(PermissionError) as ei:
            run(gp.goto("https://blocked.example.com"))
        assert "denied" in str(ei.value).lower()


class TestRealBrowserUseAllowlist:
    def test_real_browser_use_arbitrary_method_blocked(self, integration_mock, real_page):
        """``screenshot`` is NOT in the GuardedPage gated set; calling it
        must AttributeError rather than silently fall through.
        """
        integration_mock.set_default_check(allow())
        page, _ = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-int-allow")
        gp = GuardedPage(page, guard)

        with pytest.raises(AttributeError) as ei:
            _ = gp.screenshot
        # The adapter should mention security or bypass in the message.
        msg = str(ei.value).lower()
        assert "bypass" in msg or "blocks" in msg or "not in" in msg or "security" in msg

    def test_url_property_passes_through(self, integration_mock, real_page):
        """``url`` is on the read-only allowlist — it must pass through."""
        integration_mock.set_default_check(allow())
        page, run = real_page
        guard = Guard(integration_mock.base_url, agent_id="bu-int-allow")
        gp = GuardedPage(page, guard)

        run(gp.goto(_DATA_URL))
        # Reading the url property must not require a check.
        before = len(integration_mock.requests_to("/v1/check"))
        _ = gp.url
        after = len(integration_mock.requests_to("/v1/check"))
        assert before == after
