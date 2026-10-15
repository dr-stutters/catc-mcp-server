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


def test_pnp_dhcp_option43_and_lines() -> None:
    import importlib.util
    import json
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "pnp_dhcp", Path(__file__).parents[2] / "scripts" / "pnp_dhcp.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert bytes.fromhex(mod.option43("198.18.128.11")).decode() == "5A1D;B2;K4;I198.18.128.11;J80"
    conf = mod.conf("198.18.128.11")
    assert "static_lease 52:54:00:cd:30:df 198.18.128.172" in conf and conf[-1].startswith("opt 43 ")
    assert json.dumps(mod.lines("198.18.128.11"))  # serialisable for mcp_call.py
