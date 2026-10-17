"""D37 live: a compliance policy requiring `service password-encryption` (built from a CLI line) on
the area above CATC_LIVE_BUILDING; router 1 keeps the line and router 2 loses it (a template deploy of
`no service password-encryption`). catc_compliance_report shows router 2 with the rule violation and
catc_config_drift shows it against router 1 as the golden device and against a baseline template.
Router 2 gets the line back; every mcp-d37-* object is removed."""

import asyncio
import contextlib
from typing import Any

import pytest
from fastmcp import Client

from .conftest import BUILDING, need, parent_site
from .test_live_phase2 import R1, R2, RUN, routers  # noqa: F401 - fixture
from .test_live_writes import apply, call

pytestmark = pytest.mark.live
SITE = parent_site(BUILDING)
LINE = "service password-encryption"


async def _template(c: Client, proj: str, name: str, content: str) -> str:  # type: ignore[type-arg]
    await apply(
        c,
        "catc_create_template",
        {"project": proj, "name": name, "device_families": ["Routers"], "content": content},
    )
    await apply(c, "catc_commit_template", {"template": f"{proj}/{name}", "comment": "d37"})
    return f"{proj}/{name}"


async def _deploy(c: Client, template: str, device: str) -> None:  # type: ignore[type-arg]
    done = await apply(c, "catc_deploy_template", {"template": template, "devices": [device]})
    assert done["deployment"]["status"] == "SUCCESS", done


async def test_password_encryption_policy_report_and_drift(
    lab_rw: Client,  # type: ignore[type-arg]
    routers: dict[str, Any],  # noqa: F811
) -> None:
    need("CATC_LIVE_BUILDING")
    policy, proj = f"mcp-d37-pwenc-{RUN}", f"mcp-d37-{RUN}"
    r1, r2 = routers[R1]["hostname"], routers[R2]["hostname"]
    rule = {
        "name": "password-encryption",
        "description": "Passwords must be stored encrypted",
        "device_families": ["Routers", "Switches and Hubs"],
        "suggested_fix": LINE,
        "require_lines": [LINE],
        "severity": "MAJOR",
    }
    await apply(lab_rw, "catc_create_template_project", {"name": proj})
    try:
        created = await apply(
            lab_rw, "catc_create_compliance_policy", {"name": policy, "rules": [rule], "sites": [SITE]}
        )
        assert created["status"] == "ACTIVE", created
        # Policy authoring beyond create: add a second rule, then remove it again.
        extra = {"name": "no-telnet-placeholder", "forbid_lines": ["mcp-d37 never configured"]}
        upd = await apply(lab_rw, "catc_update_compliance_policy", {"policy": policy, "add_rules": [extra]})
        assert upd["rulesCount"] == 2, upd
        upd = await apply(
            lab_rw, "catc_update_compliance_policy", {"policy": policy, "remove_rules": [extra["name"]]}
        )
        assert upd["rulesCount"] == 1, upd
        got = await call(lab_rw, "catc_get_compliance_policy", {"policy": policy})
        cond = got["rules"][0]["conditions"][0]
        assert cond["violation_when"] == "does_not_match" and cond["value"].startswith("^service"), got

        baseline = await _template(lab_rw, proj, "mcp-d37-baseline", f"{LINE}\n")
        on = await _template(lab_rw, proj, "mcp-d37-pwenc-on", f"{LINE}\n")
        off = await _template(lab_rw, proj, "mcp-d37-pwenc-off", f"no {LINE}\n")
        await _deploy(lab_rw, on, R1)
        await _deploy(lab_rw, off, R2)
        await apply(lab_rw, "catc_resync_devices", {"devices": [R1, R2]})

        report: dict[str, Any] = {}
        for _ in range(18):
            await asyncio.sleep(20)
            await apply(lab_rw, "catc_run_compliance", {"devices": [R1, R2]})
            await asyncio.sleep(30)
            report = await call(lab_rw, "catc_compliance_report", {"site": SITE})
            bad = {b["device"]: b for b in report.get("non_compliant", [])}
            if r2 in bad and bad[r2].get("rule_violations"):
                break
        bad = {b["device"]: b for b in report.get("non_compliant", [])}
        assert r2 in bad, report
        assert any(v.get("rule") == "password-encryption" for v in bad[r2]["rule_violations"]), bad[r2]
        assert not any(
            v.get("rule") == "password-encryption" for v in bad.get(r1, {}).get("rule_violations", [])
        ), bad.get(r1)
        assert any(r["rule"] == "password-encryption" for r in report["by_rule"]), report
        print("REPORT", report)

        drift: dict[str, Any] = {}
        for _ in range(15):
            drift = await call(
                lab_rw,
                "catc_config_drift",
                {"against": "golden", "golden_device": R1, "devices": [R2], "only": ["^service "]},
            )
            if drift.get("drifted") == [r2]:
                break
            await asyncio.sleep(20)
        assert drift["drifted"] == [r2], drift
        assert LINE in drift["results"][0]["missing"], drift
        print("DRIFT golden", drift)

        tdrift = await call(
            lab_rw, "catc_config_drift", {"against": "template", "template": baseline, "devices": [R1, R2]}
        )
        assert tdrift["drifted"] == [r2] and tdrift["in_line"] == [r1], tdrift
        print("DRIFT template", tdrift)
    finally:
        with contextlib.suppress(Exception):
            await _deploy(lab_rw, f"{proj}/mcp-d37-pwenc-on", R2)
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_template_project", {"project": proj})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_compliance_policy", {"policy": policy})
