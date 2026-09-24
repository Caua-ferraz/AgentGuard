"""The CrewAI adapter refuses CrewAI below 1.0 (tool dispatch bypassed the gate)."""

import importlib.metadata

import pytest

crewai_adapter = pytest.importorskip("agentguard.adapters.crewai")
pytest.importorskip("crewai")


@pytest.mark.parametrize("found,refused", [("0.193.2", True), ("0.80.0", True), ("1.0.0", False), ("1.15.22", False)])
def test_require_supported_crewai(monkeypatch, found, refused):
    real_version = importlib.metadata.version

    def fake_version(name):
        return found if name == "crewai" else real_version(name)

    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    if refused:
        with pytest.raises(ImportError, match=r"requires crewai>=1\.0"):
            crewai_adapter._require_supported_crewai()
    else:
        crewai_adapter._require_supported_crewai()
