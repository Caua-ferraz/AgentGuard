"""
AgentGuard browser-use Adapter

Wraps browser-use / Playwright actions so navigation, clicks, form inputs,
JS evaluation, and other side-effectful Page methods pass through AgentGuard
policy checks before execution.

Usage:
    from agentguard.adapters.browseruse import GuardedBrowser

    browser = GuardedBrowser(
        guard_url="http://localhost:8080",
        agent_id="my-browser-agent",
    )

    # Manual one-shot checks
    result = browser.check_navigation("https://example.com")
    if result.allowed:
        await page.goto("https://example.com")

    # Wrap a Playwright Page so every gated method is checked automatically
    guarded = browser.wrap_page(real_page)
    await guarded.goto("https://example.com")    # scope=browser
    await guarded.click("#login")                # scope=browser
    await guarded.fill("#email", "alice@x.com")  # scope=data
    await guarded.evaluate("window.cookies")     # scope=browser

Design notes
------------
- **Composition over subclassing.** Playwright's Page class is a runtime-
  generated proxy with no stable subclass contract; subclassing leaks
  implementation details and breaks across Playwright minor versions.
  GuardedPage holds the underlying Page as ``self._page`` and exposes only
  the methods listed in :data:`_GATED_METHODS` plus a small allowlist of
  read-only properties via :data:`_ALLOWED_PASSTHROUGH`.
- **Default deny on attribute access.** Anything not on the allowlist
  raises ``AttributeError`` with a security explanation. A permissive
  ``__getattr__`` would silently fall through to
  ``self._page.click(...)`` and leave every action method un-gated, so
  the wrapper never adds one.
- **Form values are redacted before transmission.** ``check_form_input``
  passes the field NAME through (operators need it for audit context)
  but rewrites long values to ``<redacted; len=N>`` so audit logs do not
  accumulate raw PII / credentials. Short values are still scrubbed
  through :func:`agentguard.adapters.mcp._redact` for the standard secret
  patterns (Bearer tokens, AWS keys, ``secret=...`` pairs, etc.).

The data-scope contract is pinned by pkg/policy/engine_data_test.go
on the engine side.
"""

from typing import Any, Optional
from urllib.parse import urlparse

from agentguard import Guard, CheckResult, DEFAULT_BASE_URL
from agentguard.adapters.mcp import _redact

# Maximum length of a raw form value passed through to the policy check.
# Above this, the value is replaced with a `<redacted; len=N>` placeholder
# so audit logs do not accumulate large blobs of potentially-PII text.
# Tuned to be just past common form values (passwords, names, emails) but
# short of textarea / paste-buffer abuse.
_FORM_VALUE_MAX_LEN = 256

# Read-only Playwright Page properties that GuardedPage forwards directly.
# Adding a new entry here is a deliberate choice: each one is something the
# user code legitimately reads after a check has happened (e.g. assert the
# final URL after goto). Anything NOT on this list raises AttributeError.
#
# `context` is included because customers need it to read cookies,
# storage state, and browser-level config; gating it makes the adapter
# useless for any non-trivial workflow. Treat the surface as advisory:
# a user determined to bypass can always reach into self._page directly.
_ALLOWED_PASSTHROUGH = frozenset({
    "url",
    "title",
    "content",
    "viewport_size",
    "is_closed",
    "main_frame",
    "context",
})


class GuardedBrowser:
    """Policy-enforced wrapper for browser-use automation.

    browser-use exposes a Browser/BrowserContext that agents drive. This class
    provides guard methods that should be called before performing browser actions.
    It can also wrap a browser-use Browser / Playwright Page instance to
    intercept calls automatically via :meth:`wrap_page`.
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        guard_url: str = DEFAULT_BASE_URL,
        agent_id: str = "",
        browser: Any = None,
    ):
        self._guard = guard or Guard(guard_url, agent_id=agent_id)
        self._browser = browser

    def check_navigation(self, url: str) -> CheckResult:
        """Check if navigation to a URL is allowed by policy."""
        domain = ""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            pass

        return self._guard.check("browser", url=url, domain=domain)

    def check_action(self, action: str, target: str = "", meta: Optional[dict] = None) -> CheckResult:
        """Check a browser action (click, type, etc.) against policy.

        Args:
            action: The action type (e.g., "click", "type", "screenshot")
            target: The target selector or URL
            meta: Additional context
        """
        return self._guard.check(
            "browser",
            command=f"{action} {target}".strip(),
            meta=meta,
        )

    def check_form_input(self, url: str, field_name: str, value: str) -> CheckResult:
        """Check if typing into a form field is allowed.

        Routes through the ``data`` scope so PII / credential rules can fire
        independently of the broader ``browser`` scope. The field NAME is
        passed through verbatim — operators need it to write meaningful
        deny rules ("never submit a value to a field named 'password'").
        The VALUE is redacted before transmission:

        - Empty / whitespace values are passed through unchanged.
        - Values longer than :data:`_FORM_VALUE_MAX_LEN` (256 chars) are
          replaced with ``<redacted; len=N>`` so audit logs cannot
          accumulate paste-buffer-sized PII.
        - Shorter values run through :func:`agentguard.adapters.mcp._redact`
          to scrub the standard secret patterns (Bearer tokens, AWS keys,
          ``secret=...`` pairs, ``ghp_...``, ``xox?-...``) before the
          string lands in the policy command field.

        Why pass the field name through but redact the value? Operators
        write rules like ``deny: pattern: "*ssn:*"`` against the value and
        ``meta.field`` filters against the name. The name is stable
        metadata; the value is unbounded user data. Conflating the two
        makes audit logs both noisy (full values in every entry) and
        un-targetable (no way to write a name-based rule).
        """
        domain = ""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            pass

        if value is None:
            value = ""
        if len(value) > _FORM_VALUE_MAX_LEN:
            command = f"<redacted; len={len(value)}>"
        else:
            command = _redact(value)

        return self._guard.check(
            "data",
            url=url,
            domain=domain,
            command=command,
            action="form_input",
            meta={"field": field_name, "url": url},
        )

    def wrap_page(self, page: Any) -> "GuardedPage":
        """Wrap a Playwright Page object with policy enforcement.

        Returns a :class:`GuardedPage` whose action methods (goto, click,
        fill, evaluate, set_extra_http_headers, route, expose_function,
        add_init_script, ...) are gated through the AgentGuard proxy.
        """
        return GuardedPage(page, self._guard)


def _domain_from_url(url: str) -> str:
    """Best-effort hostname extraction; never raises."""
    if not url:
        return ""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _enforce(result: CheckResult, action_label: str) -> None:
    """Raise PermissionError when a check did not return ALLOW.

    Centralised so every gated method shares the same message format and
    REQUIRE_APPROVAL surfaces the approval URL consistently.
    """
    if result.allowed:
        return
    if result.needs_approval:
        raise PermissionError(
            f"[AgentGuard] {action_label} requires approval. "
            f"Approve at: {result.approval_url}"
        )
    raise PermissionError(f"[AgentGuard] {action_label} denied: {result.reason}")


class GuardedPage:
    """Wraps a Playwright Page to enforce policies on every action.

    Gated methods are explicit attributes on this class (see the bodies
    below). Anything else is rejected via ``__getattr__`` against
    :data:`_ALLOWED_PASSTHROUGH`. A permissive ``__getattr__`` that
    proxied every attribute access would let ``page.click(...)``,
    ``page.fill(...)``, ``page.evaluate(...)`` flow through to the raw
    Page without ever consulting the policy — so we never add one.

    Read-only properties listed in :data:`_ALLOWED_PASSTHROUGH` (url,
    title, content, viewport_size, is_closed, main_frame, context) are
    forwarded so callers can read final state after a gated call. Frame
    accessors return :class:`GuardedFrame` instances.
    """

    def __init__(self, page: Any, guard: Guard):
        # Use object.__setattr__ to avoid triggering our own __setattr__
        # contract checks (we don't override __setattr__, but this is
        # defensive in case a subclass adds one later).
        self._page = page
        self._guard = guard

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def goto(self, url: str, **kwargs: Any) -> Any:
        """Navigate to a URL after policy check (scope=browser)."""
        result = self._guard.check(
            "browser",
            url=url,
            domain=_domain_from_url(url),
            action="goto",
        )
        _enforce(result, f"Navigation to {url}")
        return await self._page.goto(url, **kwargs)

    # ------------------------------------------------------------------
    # Element interaction (clicks, keyboard, selection)
    # ------------------------------------------------------------------

    async def click(self, selector: str, **kwargs: Any) -> Any:
        """Click an element after policy check (scope=browser)."""
        result = self._guard.check(
            "browser",
            command=f"click {selector}",
            action="click",
            meta={"selector": selector},
        )
        _enforce(result, f"click({selector})")
        return await self._page.click(selector, **kwargs)

    async def fill(self, selector: str, value: str, **kwargs: Any) -> Any:
        """Fill a form field — uses the data scope so PII rules fire.

        Routes through :meth:`GuardedBrowser.check_form_input` so the
        redaction contract applies. ``selector`` becomes the field name in
        the audit ``meta.field``.
        """
        url = ""
        try:
            url = self._page.url or ""
        except Exception:
            pass
        # Re-use the form-input redaction contract.
        domain = _domain_from_url(url)
        if value is None:
            value = ""
        if len(value) > _FORM_VALUE_MAX_LEN:
            command = f"<redacted; len={len(value)}>"
        else:
            command = _redact(value)
        result = self._guard.check(
            "data",
            url=url,
            domain=domain,
            command=command,
            action="form_input",
            meta={"field": selector, "url": url},
        )
        _enforce(result, f"fill({selector})")
        return await self._page.fill(selector, value, **kwargs)

    async def type(self, selector: str, text: str, **kwargs: Any) -> Any:
        """Type text into a field — same gating as fill (scope=data)."""
        url = ""
        try:
            url = self._page.url or ""
        except Exception:
            pass
        domain = _domain_from_url(url)
        if text is None:
            text = ""
        if len(text) > _FORM_VALUE_MAX_LEN:
            command = f"<redacted; len={len(text)}>"
        else:
            command = _redact(text)
        result = self._guard.check(
            "data",
            url=url,
            domain=domain,
            command=command,
            action="form_input",
            meta={"field": selector, "url": url},
        )
        _enforce(result, f"type({selector})")
        return await self._page.type(selector, text, **kwargs)

    async def press(self, selector: str, key: str, **kwargs: Any) -> Any:
        """Press a key on an element after policy check (scope=browser).

        Key presses do not carry user-typed payload — they are control
        signals. Gated under browser, not data.
        """
        result = self._guard.check(
            "browser",
            command=f"press {selector} {key}",
            action="press",
            meta={"selector": selector, "key": key},
        )
        _enforce(result, f"press({selector}, {key})")
        return await self._page.press(selector, key, **kwargs)

    async def select_option(self, selector: str, value: Any, **kwargs: Any) -> Any:
        """Select a <select> option after policy check (scope=browser)."""
        result = self._guard.check(
            "browser",
            command=f"select_option {selector}",
            action="select_option",
            meta={"selector": selector, "value": str(value)[:_FORM_VALUE_MAX_LEN]},
        )
        _enforce(result, f"select_option({selector})")
        return await self._page.select_option(selector, value, **kwargs)

    async def check(self, selector: str, **kwargs: Any) -> Any:
        """Check a checkbox after policy check (scope=browser)."""
        result = self._guard.check(
            "browser",
            command=f"check {selector}",
            action="check",
            meta={"selector": selector},
        )
        _enforce(result, f"check({selector})")
        return await self._page.check(selector, **kwargs)

    async def uncheck(self, selector: str, **kwargs: Any) -> Any:
        """Uncheck a checkbox after policy check (scope=browser)."""
        result = self._guard.check(
            "browser",
            command=f"uncheck {selector}",
            action="uncheck",
            meta={"selector": selector},
        )
        _enforce(result, f"uncheck({selector})")
        return await self._page.uncheck(selector, **kwargs)

    # ------------------------------------------------------------------
    # JS execution
    # ------------------------------------------------------------------

    async def evaluate(self, expression: str, *args: Any, **kwargs: Any) -> Any:
        """Run JS in the page after policy check (scope=browser).

        The full expression is redacted before transmission — script
        bodies frequently embed tokens or selectors that overlap secret
        patterns. Long expressions are also truncated to keep audit
        entries bounded.
        """
        snippet = expression
        if snippet is None:
            snippet = ""
        if len(snippet) > _FORM_VALUE_MAX_LEN:
            snippet = f"<redacted; len={len(snippet)}>"
        else:
            snippet = _redact(snippet)
        result = self._guard.check(
            "browser",
            command=f"evaluate {snippet}",
            action="evaluate",
            meta={"expression": snippet},
        )
        _enforce(result, "evaluate()")
        return await self._page.evaluate(expression, *args, **kwargs)

    async def evaluate_handle(self, expression: str, *args: Any, **kwargs: Any) -> Any:
        """Run JS and return a handle after policy check (scope=browser)."""
        snippet = expression
        if snippet is None:
            snippet = ""
        if len(snippet) > _FORM_VALUE_MAX_LEN:
            snippet = f"<redacted; len={len(snippet)}>"
        else:
            snippet = _redact(snippet)
        result = self._guard.check(
            "browser",
            command=f"evaluate_handle {snippet}",
            action="evaluate_handle",
            meta={"expression": snippet},
        )
        _enforce(result, "evaluate_handle()")
        return await self._page.evaluate_handle(expression, *args, **kwargs)

    # ------------------------------------------------------------------
    # Network / headers / interception
    # ------------------------------------------------------------------

    async def set_extra_http_headers(self, headers: dict) -> Any:
        """Set extra HTTP headers after policy check (scope=browser).

        ``meta.headers`` carries only the header NAMES — values are NOT
        forwarded because Authorization, Cookie, and similar fields
        commonly contain bearer tokens and session secrets that should
        not land in the audit log.
        """
        names = sorted(headers.keys()) if isinstance(headers, dict) else []
        result = self._guard.check(
            "browser",
            command=f"set_extra_http_headers {','.join(names)}",
            action="set_headers",
            meta={"header_names": ",".join(names)},
        )
        _enforce(result, "set_extra_http_headers()")
        return await self._page.set_extra_http_headers(headers)

    async def route(self, url_pattern: Any, handler: Any, **kwargs: Any) -> Any:
        """Install a network route handler after policy check.

        The URL pattern is gated under the ``network`` scope because the
        intercept will affect every matching request — operators may want
        to allowlist/denylist that surface separately from page actions.
        """
        pattern_str = str(url_pattern)
        result = self._guard.check(
            "network",
            url=pattern_str,
            domain=_domain_from_url(pattern_str),
            action="route",
            meta={"pattern": pattern_str},
        )
        _enforce(result, f"route({pattern_str})")
        return await self._page.route(url_pattern, handler, **kwargs)

    # ------------------------------------------------------------------
    # JS-injection surface
    # ------------------------------------------------------------------

    async def expose_function(self, name: str, callback: Any) -> Any:
        """Expose a Python callable to page-side JS (scope=browser).

        Highly privileged: any code in the page can now invoke ``callback``
        with attacker-controlled arguments. Gated under browser/expose_function
        so policies can deny it entirely for low-privilege agents.
        """
        result = self._guard.check(
            "browser",
            command=f"expose_function {name}",
            action="expose_function",
            meta={"function_name": name},
        )
        _enforce(result, f"expose_function({name})")
        return await self._page.expose_function(name, callback)

    async def add_init_script(self, script: Any = None, **kwargs: Any) -> Any:
        """Inject JS that runs on every navigation (scope=browser).

        The script body is redacted/truncated like :meth:`evaluate`.
        Path-based injection (the ``path=`` kwarg) is forwarded but the
        path is included in the meta for audit visibility.
        """
        snippet = ""
        if isinstance(script, str):
            snippet = script
        elif "script" in kwargs and isinstance(kwargs["script"], str):
            snippet = kwargs["script"]
        if snippet is None:
            snippet = ""
        path = kwargs.get("path") or ""
        if len(snippet) > _FORM_VALUE_MAX_LEN:
            snippet = f"<redacted; len={len(snippet)}>"
        else:
            snippet = _redact(snippet)
        result = self._guard.check(
            "browser",
            command=f"add_init_script {snippet}",
            action="add_init_script",
            meta={"script": snippet, "path": str(path)},
        )
        _enforce(result, "add_init_script()")
        if script is not None:
            return await self._page.add_init_script(script, **kwargs)
        return await self._page.add_init_script(**kwargs)

    # ------------------------------------------------------------------
    # Frame access
    # ------------------------------------------------------------------

    def frame(self, *args: Any, **kwargs: Any) -> Optional["GuardedFrame"]:
        """Return a GuardedFrame wrapping the matched Playwright Frame."""
        f = self._page.frame(*args, **kwargs)
        if f is None:
            return None
        return GuardedFrame(f, self._guard)

    @property
    def frames(self) -> list:
        """Return a list of GuardedFrame for every Playwright frame."""
        return [GuardedFrame(f, self._guard) for f in self._page.frames]

    # ------------------------------------------------------------------
    # Allowlisted attribute access (read-only properties only)
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Expose only the names in :data:`_ALLOWED_PASSTHROUGH`.

        Anything else raises ``AttributeError`` with a security
        explanation. The default-deny posture is intentional: silently
        proxying unknown attributes to ``self._page`` would let modern
        Playwright APIs (route, expose_function, ...) skip every gate.
        Adding a new method to the gated surface is preferable to
        widening the allowlist.
        """
        # Avoid infinite recursion when our own internals are accessed
        # before __init__ completes.
        if name.startswith("_"):
            raise AttributeError(
                f"GuardedPage forbids access to internal attribute {name!r} "
                "(security: see browseruse.py allowlist)"
            )
        if name in _ALLOWED_PASSTHROUGH:
            return getattr(self._page, name)
        raise AttributeError(
            f"GuardedPage does not expose {name!r}. "
            "Either it is a gated method (call it directly), or it is a "
            "Page surface AgentGuard has not yet vetted. To unblock, "
            "either add a gated wrapper method to GuardedPage or extend "
            "_ALLOWED_PASSTHROUGH after a security review. Reaching into "
            "the raw Page via ._page bypasses every policy check."
        )


class GuardedFrame:
    """Wraps a Playwright Frame to gate its action methods.

    Mirrors the GuardedPage surface for the subset that Frames support
    (Frames don't expose route, expose_function, set_extra_http_headers,
    or add_init_script — those are page-level only). Read-only
    properties on Frames are forwarded directly via __getattr__'s
    allowlist.
    """

    _ALLOWED_FRAME_PASSTHROUGH = frozenset({
        "url",
        "name",
        "is_detached",
        "parent_frame",
        "page",
    })

    def __init__(self, frame: Any, guard: Guard):
        self._frame = frame
        self._guard = guard

    async def goto(self, url: str, **kwargs: Any) -> Any:
        result = self._guard.check(
            "browser",
            url=url,
            domain=_domain_from_url(url),
            action="frame.goto",
        )
        _enforce(result, f"frame.goto({url})")
        return await self._frame.goto(url, **kwargs)

    async def click(self, selector: str, **kwargs: Any) -> Any:
        result = self._guard.check(
            "browser",
            command=f"frame.click {selector}",
            action="frame.click",
            meta={"selector": selector},
        )
        _enforce(result, f"frame.click({selector})")
        return await self._frame.click(selector, **kwargs)

    async def fill(self, selector: str, value: str, **kwargs: Any) -> Any:
        url = ""
        try:
            url = self._frame.url or ""
        except Exception:
            pass
        domain = _domain_from_url(url)
        if value is None:
            value = ""
        if len(value) > _FORM_VALUE_MAX_LEN:
            command = f"<redacted; len={len(value)}>"
        else:
            command = _redact(value)
        result = self._guard.check(
            "data",
            url=url,
            domain=domain,
            command=command,
            action="form_input",
            meta={"field": selector, "url": url, "frame": "true"},
        )
        _enforce(result, f"frame.fill({selector})")
        return await self._frame.fill(selector, value, **kwargs)

    async def type(self, selector: str, text: str, **kwargs: Any) -> Any:
        url = ""
        try:
            url = self._frame.url or ""
        except Exception:
            pass
        domain = _domain_from_url(url)
        if text is None:
            text = ""
        if len(text) > _FORM_VALUE_MAX_LEN:
            command = f"<redacted; len={len(text)}>"
        else:
            command = _redact(text)
        result = self._guard.check(
            "data",
            url=url,
            domain=domain,
            command=command,
            action="form_input",
            meta={"field": selector, "url": url, "frame": "true"},
        )
        _enforce(result, f"frame.type({selector})")
        return await self._frame.type(selector, text, **kwargs)

    async def evaluate(self, expression: str, *args: Any, **kwargs: Any) -> Any:
        snippet = expression
        if snippet is None:
            snippet = ""
        if len(snippet) > _FORM_VALUE_MAX_LEN:
            snippet = f"<redacted; len={len(snippet)}>"
        else:
            snippet = _redact(snippet)
        result = self._guard.check(
            "browser",
            command=f"frame.evaluate {snippet}",
            action="frame.evaluate",
            meta={"expression": snippet},
        )
        _enforce(result, "frame.evaluate()")
        return await self._frame.evaluate(expression, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(
                f"GuardedFrame forbids access to internal attribute {name!r}"
            )
        if name in self._ALLOWED_FRAME_PASSTHROUGH:
            return getattr(self._frame, name)
        raise AttributeError(
            f"GuardedFrame does not expose {name!r}. "
            "Either it is a gated method (call it directly), or it is a "
            "Frame surface AgentGuard has not yet vetted."
        )
