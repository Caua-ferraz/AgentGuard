"""Filesystem-action inference parity: Python SDK <-> Go transports.

The Python adapters (infer_path_action in agentguard.adapters._common) and
the Go transports (gateclient.InferFilesystemAction) must map a tool name to
the SAME filesystem `action` ("read"/"write"/"delete"/""), otherwise an
`action:`-keyed filesystem policy rule fires on one transport and not the
other for the same tool call.

The table below is the SAME (tool_name -> action) table pinned on the Go
side in pkg/internal/gateclient/gateclient_test.go (TestInferFilesystemAction).
When you add or change a verb in one place, change it in the other and update
BOTH tables — this test and that Go test are the tripwire.

This module imports ONLY agentguard.adapters._common, so it runs without
langchain / crewai / mcp (or any framework dependency) installed.
"""

from agentguard.adapters._common import infer_path_action


# Mirror of gateclient_test.go's TestInferFilesystemAction table. Keep in sync.
GO_PARITY_TABLE = {
    "read_file": "read",
    "list_files": "read",
    "get_file": "read",
    "stat_file": "read",
    "cat": "read",
    "find_files": "read",
    "glob": "read",
    "write_file": "write",
    "edit_file": "write",
    "create_dir": "write",
    "append_file": "write",
    "delete_file": "delete",
    "remove_dir": "delete",
    "unlink": "delete",
    "unknown": "",
}

# Extra regression cases for verbs the substring implementation used to miss
# (edit/append/copy/move/unlink/rm*/list/stat/cat/find/glob). These are the
# tool names that previously sent NO action through the Python SDK while the
# Go transports DID send one.
REGRESSION_TABLE = {
    "edit_file": "write",
    "append_file": "write",
    "copy_file": "write",
    "move_file": "write",
    "unlink": "delete",
    "rmdir": "delete",  # "rm" prefix
    "rm": "delete",
    "list_files": "read",
    "stat_file": "read",
    "cat": "read",
    "find_files": "read",
    "glob": "read",
}

# False-positive guards: substring matching (the old behavior) wrongly mapped
# these; prefix matching (Go's HasPrefix, our str.startswith) does not.
FALSE_POSITIVE_TABLE = {
    "set_target": "",   # contains "get" but does not START with it
    "undelete_x": "",   # contains "delete" but does not START with it
    "forget": "",       # contains "get"
    "overwrite": "",    # contains "write"
}


def test_go_parity_table():
    """Every pinned Go case maps identically in Python."""
    for tool_name, expected in GO_PARITY_TABLE.items():
        assert infer_path_action(tool_name) == expected, (
            f"infer_path_action({tool_name!r}) diverged from Go parity table"
        )


def test_regression_cases_previously_missed_by_substring():
    for tool_name, expected in REGRESSION_TABLE.items():
        assert infer_path_action(tool_name) == expected, (
            f"infer_path_action({tool_name!r}) regressed"
        )


def test_false_positive_guards():
    for tool_name, expected in FALSE_POSITIVE_TABLE.items():
        assert infer_path_action(tool_name) == expected, (
            f"infer_path_action({tool_name!r}) should be {expected!r} "
            f"(prefix, not substring, matching)"
        )


def test_non_string_input_is_empty():
    for bad in (None, 123, ["read_file"], {"name": "read_file"}, object()):
        assert infer_path_action(bad) == ""


def test_case_insensitive():
    # HasPrefix is applied to strings.ToLower(toolName) on the Go side; we
    # lowercase too, so mixed case still resolves.
    assert infer_path_action("READ_File") == "read"
    assert infer_path_action("Write_Thing") == "write"
    assert infer_path_action("DELETE_it") == "delete"


if __name__ == "__main__":
    # Allow a framework-free smoke run without pytest installed.
    for table in (GO_PARITY_TABLE, REGRESSION_TABLE, FALSE_POSITIVE_TABLE):
        for name, want in table.items():
            got = infer_path_action(name)
            assert got == want, f"{name!r}: got {got!r}, want {want!r}"
    for bad in (None, 123, ["x"], {"a": 1}):
        assert infer_path_action(bad) == ""
    print("action-parity smoke OK")
