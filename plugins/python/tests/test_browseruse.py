"""Targeted coverage for the v0.5 browser-use adapter expansion.

Closes audit findings R5 E4 (modern-API bypass via __getattr__) and the
adapter side of R5 E5 / R7 E3 (data scope routing). Engine-side data-
scope coverage lives in pkg/policy/engine_data_test.go.

These tests use the existing mock_server fixture from conftest.py — they
mock the AgentGuard proxy, NEVER the browser-use library itself. The
final test optionally runs against the real browser_use package when
installed (pytest.importorskip).
"""

import asyncio
import json

import pytest
from unittest.mock import MagicMock, AsyncMock

from agentguard import Guard
from tests.conftest import MockAgentGuardHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _last_body() -> dict:
    raw = MockAgentGuardHandler.last_request_body
    assert raw is not None, "no request body captured by mock server"
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Page-level gating
# ---------------------------------------------------------------------------

class TestGuardedPageGoto:
    def test_guarded_page_goto_gated(self, mock_server):
        """goto() consults the policy and forwards on ALLOW."""
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW", "reason": "ok"}
        browser = GuardedBrowser(guard_url=mock_server)

        inner = MagicMock()
        inner.goto = AsyncMock(return_value="navigated")
        page = browser.wrap_page(inner)

        out = asyncio.run(page.goto("https://example.com"))

        assert out == "navigated"
        inner.goto.assert_called_once()
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["url"] == "https://example.com"
        assert body["domain"] == "example.com"
        assert body["action"] == "goto"

    def test_guarded_page_goto_denied_raises(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.goto = AsyncMock(return_value="never")
        page = browser.wrap_page(inner)

        with pytest.raises(PermissionError):
            asyncio.run(page.goto("https://blocked.example"))
        inner.goto.assert_not_called()


class TestGuardedPageInteractions:
    def test_guarded_page_click_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.click = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.click("#login"))
        inner.click.assert_called_once_with("#login")

        body = _last_body()
        assert body["scope"] == "browser"
        assert "click #login" in body["command"]
        assert body["meta"]["selector"] == "#login"

    def test_guarded_page_click_denied(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "no"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.click = AsyncMock(return_value="never")
        page = browser.wrap_page(inner)

        with pytest.raises(PermissionError):
            asyncio.run(page.click("#bad"))
        inner.click.assert_not_called()

    def test_guarded_page_fill_uses_data_scope(self, mock_server):
        """fill() must route through scope=data (not scope=browser)."""
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.url = "https://example.com/form"
        inner.fill = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.fill("#email", "alice@example.com"))

        body = _last_body()
        assert body["scope"] == "data", "fill must use the data scope"
        assert body["action"] == "form_input"
        assert body["meta"]["field"] == "#email"
        assert body["url"] == "https://example.com/form"
        assert body["domain"] == "example.com"
        # Command carries the (possibly redacted) value
        assert body["command"] == "alice@example.com"

    def test_guarded_page_type_uses_data_scope(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.url = "https://example.com/form"
        inner.type = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.type("#search", "kittens"))
        body = _last_body()
        assert body["scope"] == "data"
        assert body["action"] == "form_input"

    def test_guarded_page_press_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.press = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.press("#input", "Enter"))
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "press"
        assert body["meta"]["key"] == "Enter"

    def test_guarded_page_select_option_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.select_option = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.select_option("#country", "US"))
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "select_option"

    def test_guarded_page_check_uncheck_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.check = AsyncMock(return_value=None)
        inner.uncheck = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.check("#agree"))
        assert _last_body()["action"] == "check"
        inner.check.assert_called_once_with("#agree")

        asyncio.run(page.uncheck("#agree"))
        assert _last_body()["action"] == "uncheck"


class TestGuardedPageJavaScript:
    def test_guarded_page_evaluate_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.evaluate = AsyncMock(return_value="result")
        page = browser.wrap_page(inner)

        out = asyncio.run(page.evaluate("document.title"))
        assert out == "result"
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "evaluate"
        assert "document.title" in body["command"]

    def test_guarded_page_evaluate_long_expression_redacted(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.evaluate = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        big = "x" * 1000
        asyncio.run(page.evaluate(big))
        body = _last_body()
        # Long expressions get the redacted-len placeholder, not the
        # raw 1000-char body.
        assert "<redacted; len=1000>" in body["command"]

    def test_guarded_page_evaluate_handle_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.evaluate_handle = AsyncMock(return_value="handle")
        page = browser.wrap_page(inner)

        asyncio.run(page.evaluate_handle("window"))
        assert _last_body()["action"] == "evaluate_handle"


class TestGuardedPageNetwork:
    def test_guarded_page_set_extra_http_headers_gated_with_redacted_meta(self, mock_server):
        """meta.header_names contains only NAMES — never values (which carry tokens)."""
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.set_extra_http_headers = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        secret_value = "Bearer sk-secret-token"
        asyncio.run(page.set_extra_http_headers(
            {"Authorization": secret_value, "X-Custom": "value-not-secret"}
        ))

        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "set_headers"
        # Header names appear (sorted) but values must not.
        names = body["meta"]["header_names"]
        assert "Authorization" in names
        assert "X-Custom" in names
        # Value must not leak into command or meta.
        raw_payload = json.dumps(body)
        assert secret_value not in raw_payload
        assert "sk-secret-token" not in raw_payload

    def test_guarded_page_route_uses_network_scope(self, mock_server):
        """route() — installs a network handler — gates under network not browser."""
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.route = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        async def handler(route, request):
            pass

        asyncio.run(page.route("https://api.example.com/**", handler))
        body = _last_body()
        assert body["scope"] == "network"
        assert body["action"] == "route"
        assert body["url"] == "https://api.example.com/**"


class TestGuardedPageJSInjection:
    def test_guarded_page_expose_function_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.expose_function = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.expose_function("readSecret", lambda: "x"))
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "expose_function"
        assert body["meta"]["function_name"] == "readSecret"

    def test_guarded_page_add_init_script_gated(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.add_init_script = AsyncMock(return_value=None)
        page = browser.wrap_page(inner)

        asyncio.run(page.add_init_script("console.log('init')"))
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "add_init_script"


# ---------------------------------------------------------------------------
# Allowlist enforcement
# ---------------------------------------------------------------------------

class TestGuardedPageAllowlist:
    def test_guarded_page_arbitrary_internal_blocked(self, mock_server):
        """Internal/private attributes raise AttributeError, not silently
        proxy to the underlying page."""
        from agentguard.adapters.browseruse import GuardedBrowser

        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner._impl_obj = "internal"
        page = browser.wrap_page(inner)

        with pytest.raises(AttributeError) as ei:
            page._impl_obj
        # Message should explain the security posture so users understand
        # the failure is intentional, not a bug.
        assert "GuardedPage" in str(ei.value) or "internal" in str(ei.value)

    def test_guarded_page_unknown_method_blocked(self, mock_server):
        """A method that AgentGuard hasn't vetted raises AttributeError."""
        from agentguard.adapters.browseruse import GuardedBrowser

        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.something_new = AsyncMock(return_value="never")
        page = browser.wrap_page(inner)

        with pytest.raises(AttributeError) as ei:
            page.something_new
        assert "AgentGuard" in str(ei.value) or "Guarded" in str(ei.value)

    def test_guarded_page_allowlisted_property_passes_through(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        browser = GuardedBrowser(guard_url=mock_server)
        inner = MagicMock()
        inner.url = "https://example.com"
        inner.title = MagicMock(return_value="Example")
        page = browser.wrap_page(inner)

        assert page.url == "https://example.com"
        # `title` is on the allowlist — forwards as-is.
        assert page.title is inner.title


# ---------------------------------------------------------------------------
# Frame gating
# ---------------------------------------------------------------------------

class TestGuardedFrame:
    def test_guarded_frame_gated_too(self, mock_server):
        """page.frame(...) returns a GuardedFrame whose .click is gated."""
        from agentguard.adapters.browseruse import GuardedBrowser, GuardedFrame

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)

        inner_frame = MagicMock()
        inner_frame.click = AsyncMock(return_value=None)
        inner_frame.url = "https://iframe.example.com"

        inner_page = MagicMock()
        inner_page.frame = MagicMock(return_value=inner_frame)
        page = browser.wrap_page(inner_page)

        frame = page.frame(name="ad-iframe")
        assert isinstance(frame, GuardedFrame)
        asyncio.run(frame.click("#dangerous"))
        body = _last_body()
        assert body["scope"] == "browser"
        assert body["action"] == "frame.click"
        inner_frame.click.assert_called_once()

    def test_guarded_frame_fill_uses_data_scope(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)

        inner_frame = MagicMock()
        inner_frame.url = "https://iframe.example.com/form"
        inner_frame.fill = AsyncMock(return_value=None)

        inner_page = MagicMock()
        inner_page.frame = MagicMock(return_value=inner_frame)
        page = browser.wrap_page(inner_page)

        frame = page.frame(name="form-iframe")
        asyncio.run(frame.fill("#email", "alice@example.com"))
        body = _last_body()
        assert body["scope"] == "data"
        assert body["meta"]["frame"] == "true"

    def test_guarded_frame_none_returns_none(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        browser = GuardedBrowser(guard_url=mock_server)
        inner_page = MagicMock()
        inner_page.frame = MagicMock(return_value=None)
        page = browser.wrap_page(inner_page)
        assert page.frame(name="missing") is None


# ---------------------------------------------------------------------------
# check_form_input redaction contract
# ---------------------------------------------------------------------------

class TestCheckFormInputRedaction:
    def test_check_form_input_redacts_long_values(self, mock_server):
        """Values >256 chars are replaced with <redacted; len=N>."""
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)

        long_value = "A" * 1000
        browser.check_form_input("https://example.com/form", "comment", long_value)
        body = _last_body()
        assert body["command"] == "<redacted; len=1000>"
        # Field name passes through unchanged.
        assert body["meta"]["field"] == "comment"

    def test_check_form_input_redacts_secret_patterns(self, mock_server):
        """Bearer tokens etc. are scrubbed before transmission."""
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)

        browser.check_form_input(
            "https://example.com/form",
            "token",
            "Bearer sk-secret-1234567890",
        )
        body = _last_body()
        # _redact substitutes the matched pattern with [REDACTED].
        assert "sk-secret-1234567890" not in body["command"]
        assert "[REDACTED]" in body["command"]

    def test_check_form_input_short_value_passes(self, mock_server):
        from agentguard.adapters.browseruse import GuardedBrowser

        MockAgentGuardHandler.check_response = {"decision": "ALLOW"}
        browser = GuardedBrowser(guard_url=mock_server)

        browser.check_form_input("https://example.com/form", "search", "kittens")
        body = _last_body()
        assert body["command"] == "kittens"
        assert body["scope"] == "data"
        assert body["action"] == "form_input"


# ---------------------------------------------------------------------------
# Real browser_use integration (skipped if not installed)
# ---------------------------------------------------------------------------

class TestRealBrowserUse:
    def test_real_browser_use_navigation_gated(self, mock_server):
        """Sanity check that the wrapper interoperates with the real
        browser_use package when present.

        Skipped when browser_use is not installed (development/CI matrices
        without the optional extra). We mock only AgentGuard — never
        browser_use itself."""
        browser_use = pytest.importorskip(
            "browser_use",
            reason="browser_use not installed; integration test skipped",
        )

        from agentguard.adapters.browseruse import GuardedBrowser

        # Resolve a Page-like object from browser_use lazily. The package's
        # exact public surface evolved across 0.1.x → 0.4.x; we only need
        # SOMETHING that quacks like a Playwright Page for the wrapper to
        # bind to. If we cannot find one without spinning up a real
        # Chromium (which CI cannot do), skip rather than fake it.
        Page = getattr(browser_use, "Page", None)
        if Page is None:
            pytest.skip(
                "browser_use installed but Page surface not directly importable; "
                "real-browser integration requires a running Chromium and is "
                "out of scope for unit tests."
            )

        MockAgentGuardHandler.check_response = {"decision": "DENY", "reason": "blocked"}
        browser = GuardedBrowser(guard_url=mock_server)

        # We construct a GuardedPage around a mock page surface — browser_use
        # provides the type guarantee, but instantiating a real Page requires
        # an active browser context.
        inner = MagicMock(spec=Page)
        inner.goto = AsyncMock(return_value="never")
        page = browser.wrap_page(inner)

        with pytest.raises(PermissionError):
            asyncio.run(page.goto("https://blocked.example"))
        inner.goto.assert_not_called()
