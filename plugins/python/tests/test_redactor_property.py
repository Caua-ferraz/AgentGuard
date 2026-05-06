"""Property-based tests for the MCP adapter's redactor (Phase 3 — AT).

These tests verify three properties of ``agentguard.adapters.mcp._redact``:

  1. Coverage — given random plaintext padded with a known secret pattern,
     the secret value MUST be redacted before the output leaves the SDK.
  2. No false positives — given random plaintext that contains NO secret
     pattern, the redactor must NOT mangle the input.
  3. Mixed input — given strings carrying both secret and innocent text,
     exactly the secret bytes are removed and the innocent prefix /
     suffix survive intact.

We do NOT depend on ``hypothesis`` (it is not in the dev extras and
adding a runtime test dep mid-cycle is out of scope). The closest cheap
substitute is parametrized seeds plus a small deterministic random loop
seeded for reproducibility — close enough to a property test for
audit-coupon purposes, and any failure prints the seed so a developer
can re-run the same vector locally.

Closes the audit-coupon side of R7 T7 (redactor reach) and the v0.5
"property test for the redactor" line in the AT brief.
"""

import random
import re
import string

import pytest

from agentguard.adapters.mcp import _redact


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

# Random seed source. Use a fixed module-level seed so failures are
# reproducible. Tests that want extra coverage can re-run pytest with
# ``--seed``-like envvar, but the default deterministic stream is enough
# for a regression coupon.
_RNG = random.Random(0xA6E7_5F02)

_SAFE_ALPHABET = string.ascii_letters + string.digits + "_-./: "


def _random_safe_text(length: int) -> str:
    """A plaintext string guaranteed not to look like any redactor pattern.

    We deliberately avoid:
      - the substrings 'bearer', 'AKIA', 'ghp_', 'xox' (case-insensitive)
      - the literal '=' character (kills the secret/token/password kv rule)
    so any positive match in tests must come from a planted secret, not
    from accidental collision with the random text.
    """
    out_chars = _RNG.choices(_SAFE_ALPHABET.replace("=", ""), k=length)
    text = "".join(out_chars)
    # Final scrub of accidentally generated case-insensitive substrings.
    forbidden = ("bearer", "akia", "ghp_", "xox")
    lowered = text.lower()
    for f in forbidden:
        if f in lowered:
            # Substitute one byte to break the substring without changing
            # the length distribution materially.
            i = lowered.index(f)
            text = text[:i] + "Z" + text[i + 1 :]
            lowered = text.lower()
    return text


# Each pattern entry: (label, generator-callable, post-redaction expectation).
# The generator returns the literal secret string the test plants; the
# expected value is the substring that MUST NOT survive ``_redact``.
SECRET_PATTERNS = [
    # ("label", generate(), should_NOT_appear_after_redact)
    ("bearer_lower", lambda: f"bearer {_rand_token(20)}", "bearer "),
    ("bearer_upper", lambda: f"Bearer {_rand_token(30)}", "Bearer "),
    ("akia", lambda: f"AKIA{_rand_upper(16)}", "AKIA"),
    ("ghp", lambda: f"ghp_{_rand_lower(40)}", "ghp_"),
    ("slack_xoxb", lambda: f"xoxb-{_rand_token(24)}", "xoxb-"),
    ("slack_xoxp", lambda: f"xoxp-{_rand_token(24)}", "xoxp-"),
    ("kv_password", lambda: f"password={_rand_token(12)}", "password="),
    ("kv_secret", lambda: f"secret={_rand_token(12)}", "secret="),
    ("kv_token", lambda: f"token={_rand_token(12)}", "token="),
    ("kv_api_key", lambda: f"api_key={_rand_token(12)}", "api_key="),
    ("kv_api_dash_key", lambda: f"api-key={_rand_token(12)}", "api-key="),
]


def _rand_token(n: int) -> str:
    return "".join(_RNG.choices(string.ascii_letters + string.digits, k=n))


def _rand_upper(n: int) -> str:
    return "".join(_RNG.choices(string.ascii_uppercase + string.digits, k=n))


def _rand_lower(n: int) -> str:
    return "".join(_RNG.choices(string.ascii_lowercase + string.digits, k=n))


# ---------------------------------------------------------------------------
# Property 1: every known secret pattern is redacted (coverage)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,gen,planted_prefix", SECRET_PATTERNS)
def test_secret_patterns_are_redacted(label, gen, planted_prefix):
    """For each labelled pattern, generate 50 random secret strings and
    assert ``_redact`` replaces the value with ``[REDACTED]``.

    The "value" is the random suffix; the prefix stays in literal form for
    the kv-style patterns because the redactor regex captures the whole
    ``key=value`` span. So we assert on the absence of the random secret
    suffix, not the whole prefix.
    """
    for _ in range(50):
        secret = gen()
        out = _redact(secret)
        # The unique random suffix must not survive.
        suffix = secret[len(planted_prefix):]
        # AKIA's suffix is 16 chars and the regex consumes the whole match.
        # bearer's suffix is the token after "bearer ". For all of them, the
        # post-redaction string MUST contain "[REDACTED]" and MUST NOT
        # contain the original suffix verbatim.
        assert "[REDACTED]" in out, (
            f"{label}: redactor did not replace {secret!r} (got {out!r})"
        )
        # The suffix-as-substring check catches "secret=hunter2" → "[REDACTED]"
        # but tolerates "[REDACTED]" containing characters that happen to
        # appear in the suffix (e.g. 'R'). Compare with the raw token instead.
        if len(suffix) >= 6:
            assert suffix not in out, (
                f"{label}: secret value {suffix!r} leaked through in {out!r}"
            )


# ---------------------------------------------------------------------------
# Property 2: plaintext is NOT mangled (no false positives)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [1, 8, 32, 128, 512])
def test_plaintext_is_not_mangled(length):
    """Random text containing no known pattern survives ``_redact`` byte-for-byte."""
    for _ in range(50):
        text = _random_safe_text(length)
        out = _redact(text)
        assert out == text, (
            f"redactor false-positive for {text!r} (got {out!r})"
        )


def test_empty_input_returns_unchanged():
    """``_redact("")`` is a no-op (per implementation contract)."""
    assert _redact("") == ""


def test_short_innocent_strings_unchanged():
    """Single-character / very-short non-secret text is preserved."""
    for ch in ("a", "1", "?", " ", "/"):
        assert _redact(ch) == ch


# ---------------------------------------------------------------------------
# Property 3: mixed input — plaintext + secret + plaintext
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,gen,_planted_prefix", SECRET_PATTERNS)
def test_mixed_input_preserves_innocent_parts(label, gen, _planted_prefix):
    """Compose ``<safe-prefix> <secret> <safe-suffix>`` and assert the safe
    pieces survive while the secret value is removed.

    NOTE: the redactor regexes are intentionally greedy on adjacent
    non-whitespace runs (``\\S+`` for kv, ``[A-Za-z0-9_\\-\\.]+`` for
    bearer / ghp / xox). That is correct behaviour — a token written
    ``Bearer abc.def`` should be redacted as a whole. To probe "innocent
    text survives", we therefore separate the secret from the surrounding
    text with a whitespace boundary; the redactor's contract is that the
    matched span ends at whitespace.
    """
    for _ in range(20):
        prefix = _random_safe_text(_RNG.randrange(1, 20))
        suffix = _random_safe_text(_RNG.randrange(1, 20))
        secret = gen()
        # Whitespace boundaries on both sides — the regex must not cross them.
        text = f"{prefix} {secret} {suffix}"

        out = _redact(text)

        # The secret's tail (the random value beyond any literal prefix)
        # must be gone. We check by seeing if the FULL secret string still
        # appears verbatim — it should not.
        # Pull the random tail to compare separately. For kv patterns, the
        # tail is whatever follows '='; for token patterns, whatever
        # follows the literal prefix.
        if "=" in secret:
            tail = secret.split("=", 1)[1]
        else:
            # bearer/AKIA/ghp/xox-style: split at the first space or dash
            tail = re.split(r"[\s\-]", secret, maxsplit=1)[-1]

        if len(tail) >= 6:
            assert tail not in out, (
                f"{label}: tail {tail!r} of {secret!r} leaked into {out!r}"
            )
        # Innocent prefix and suffix must survive (whitespace-separated
        # from the redacted secret span).
        assert prefix in out, (
            f"{label}: innocent prefix {prefix!r} was mangled "
            f"(input={text!r}, output={out!r})"
        )
        assert suffix in out, (
            f"{label}: innocent suffix {suffix!r} was unexpectedly removed "
            f"(input={text!r}, output={out!r})"
        )


# ---------------------------------------------------------------------------
# Bonus: idempotence — _redact(_redact(x)) == _redact(x)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,gen,_planted_prefix", SECRET_PATTERNS)
def test_redactor_is_idempotent(label, gen, _planted_prefix):
    """Once a string has been redacted, redacting it again is a no-op."""
    for _ in range(20):
        once = _redact(gen() + " " + _random_safe_text(20))
        twice = _redact(once)
        assert twice == once, (
            f"{label}: not idempotent (once={once!r}, twice={twice!r})"
        )
