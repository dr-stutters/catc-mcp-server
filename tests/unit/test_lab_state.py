"""scripts/lab_state.py helpers: secrets never reach the output; only 'not found' counts as absent."""

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

SPEC = importlib.util.spec_from_file_location(
    "lab_state", Path(__file__).resolve().parents[2] / "scripts" / "lab_state.py"
)
assert SPEC and SPEC.loader
lab_state: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab_state)


def test_scrub_masks_lab_secrets(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("LAB_CLI_PASSWORD", "Sup3rS3cret!")
    monkeypatch.setenv("LAB_SNMP_RO", "ro-community-x")
    lab_state.say(
        "catc_create_global_credential: rejected body {'password': 'Sup3rS3cret!', 'c': 'ro-community-x'}"
    )
    out = capsys.readouterr().out
    assert "Sup3rS3cret!" not in out and "ro-community-x" not in out and "***" in out


def test_absent_only_for_not_found() -> None:
    assert lab_state.absent(ToolError("catc_get_site: No site 'Global/x'. Use catc_get_site_hierarchy"))
    assert lab_state.absent(ToolError("Not found (404): GET /x"))
    assert not lab_state.absent(ToolError("Authentication failed (401)"))
    assert not lab_state.absent(ToolError("Timed out waiting for task"))
