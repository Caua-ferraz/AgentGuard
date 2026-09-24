"""agentguard.__version__ is exported and in step with the other version strings."""

import pathlib
import re

import agentguard
from agentguard.adapters.mcp import SDK_VERSION

PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_version_is_exported():
    assert "__version__" in agentguard.__all__
    assert re.fullmatch(r"\d+\.\d+\.\d+", agentguard.__version__)


def test_version_matches_pyproject_and_sdk_version():
    # scripts/bump-version.sh rewrites all three together.
    m = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.MULTILINE)
    assert m, "no version in pyproject.toml"
    assert agentguard.__version__ == m.group(1) == SDK_VERSION
