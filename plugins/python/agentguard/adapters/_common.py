"""Shared check-parameter extraction for the framework adapters.

LangChain, CrewAI, MCP and the OpenAI Agents SDK all reduce a tool
invocation to the same ``Guard.check`` keyword arguments (command, url,
domain, path, action, session_id, est_cost). The extraction lives here once so the adapters
cannot drift apart; each adapter keeps only its framework-specific
glue (input normalisation, error surfacing, redaction).
"""

from typing import Any, Tuple
from urllib.parse import urlparse

from agentguard.core import DECISION_DENY, CheckResult


# Keys that name the same check parameter. A model writes the tool
# arguments, so it can send two of them at once; which one the tool
# actually reads depends on the tool's signature, not on this table.
_ALIASES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("command", ("command", "cmd")),
    ("path", ("path", "file_path")),
)


class ConflictingToolInput(ValueError):
    """Two alias keys for one check parameter carry different values.

    ``{"command": "ls", "cmd": "rm -rf /"}`` sent to a tool whose
    parameter is ``cmd`` would otherwise be checked as ``ls`` and run as
    ``rm -rf /``. The extractor cannot know which key the tool reads, so
    it refuses to pick one; adapters turn this into a DENY via
    :func:`conflict_denial`.
    """

    def __init__(self, param: str, keys: Tuple[str, ...]):
        self.param = param
        self.keys = keys
        names = " and ".join(repr(k) for k in keys)
        super().__init__(
            f"conflicting values for {param!r} in tool arguments "
            f"({names}); refusing to guess which one the tool uses"
        )


def conflict_denial(err: ConflictingToolInput) -> CheckResult:
    """The DENY an adapter reports for a :class:`ConflictingToolInput`.

    Decided locally, without a server round-trip: no policy can make an
    ambiguous input safe to check.
    """
    return CheckResult(decision=DECISION_DENY, reason=str(err))


def _same_value(a: Any, b: Any) -> bool:
    # type() as well as ==, so 1 / True / 1.0 do not count as the same.
    return type(a) is type(b) and a == b


def check_alias_conflicts(tool_input: Any) -> None:
    """Raise :class:`ConflictingToolInput` if a dict input sets two alias
    keys (command/cmd, path/file_path) to different values."""
    if not isinstance(tool_input, dict):
        return
    for param, keys in _ALIASES:
        present = tuple(k for k in keys if k in tool_input)
        if len(present) < 2:
            continue
        first = tool_input[present[0]]
        if any(not _same_value(first, tool_input[k]) for k in present[1:]):
            raise ConflictingToolInput(param, present)


def domain_from_url(url: Any) -> str:
    """Best-effort hostname extraction; "" when absent or malformed."""
    if not isinstance(url, str):
        return ""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


# Filesystem-action verb groups. These MUST stay byte-identical to the Go
# transports' gateclient.InferFilesystemAction (pkg/internal/gateclient/
# gateclient.go): same verbs, same groups, same precedence (read, then
# write, then delete). Parity is pinned by two mirrored test tables —
# plugins/python/tests/test_action_parity.py and
# pkg/internal/gateclient/gateclient_test.go. Edit both sides together.
_READ_PREFIXES = ("read", "list", "get", "stat", "cat", "find", "glob")
_WRITE_PREFIXES = ("write", "edit", "create", "append", "save", "copy", "move")
_DELETE_PREFIXES = ("delete", "remove", "unlink", "rm")


def infer_path_action(tool_name: Any) -> str:
    """Map a tool-name verb to the canonical filesystem action
    ("read"/"write"/"delete"), or "" when no verb matches.

    Mirrors the Go transports' gateclient.InferFilesystemAction exactly:
    a case-insensitive ``strings.HasPrefix`` (Python ``str.startswith``)
    against these verb groups, checked in this order —

        read   = read, list, get, stat, cat, find, glob
        write  = write, edit, create, append, save, copy, move
        delete = delete, remove, unlink, rm

    Prefix (not substring) matching is deliberate: it avoids the false
    positives substring matching produces that Go never makes — e.g.
    "set_target" contains "get" but does not START with it, and
    "undelete_x" contains "delete" but does not start with it. Both
    correctly yield "" here, matching Go. Parity is pinned by
    plugins/python/tests/test_action_parity.py, whose table mirrors
    pkg/internal/gateclient/gateclient_test.go.
    """
    if not isinstance(tool_name, str):
        return ""
    name_lower = tool_name.lower()
    if name_lower.startswith(_READ_PREFIXES):
        return "read"
    if name_lower.startswith(_WRITE_PREFIXES):
        return "write"
    if name_lower.startswith(_DELETE_PREFIXES):
        return "delete"
    return ""


def extract_check_params(tool_input: Any, tool_name: Any = None) -> dict:
    """Reduce a str/dict tool input to ``Guard.check`` keyword params.

    A bare string is treated as a shell command. For dicts, recognised
    keys are projected (command/cmd, url + derived domain,
    path/file_path + action inferred from the tool-name verb,
    session_id, est_cost); everything else is ignored.

    Raises:
        ConflictingToolInput: two alias keys (command/cmd or
            path/file_path) are both present with different values.
            Callers must treat this as DENY (see :func:`conflict_denial`).
    """
    check_alias_conflicts(tool_input)
    params: dict = {}
    if isinstance(tool_input, str):
        params["command"] = tool_input
    elif isinstance(tool_input, dict):
        if "command" in tool_input or "cmd" in tool_input:
            params["command"] = tool_input.get(
                "command", tool_input.get("cmd", "")
            )
        if "url" in tool_input:
            params["url"] = tool_input["url"]
            domain = domain_from_url(tool_input["url"])
            if domain:
                params["domain"] = domain
        if "path" in tool_input or "file_path" in tool_input:
            params["path"] = tool_input.get(
                "path", tool_input.get("file_path", "")
            )
            action = infer_path_action(tool_name)
            if action:
                params["action"] = action
        if "session_id" in tool_input:
            params["session_id"] = tool_input["session_id"]
        if "est_cost" in tool_input:
            params["est_cost"] = tool_input["est_cost"]
    return params
