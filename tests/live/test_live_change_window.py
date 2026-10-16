"""D10 live: walk the `catc_change_window` prompt on CATC_LIVE_ROUTER1 + CATC_LIVE_ROUTER2.

Baseline -> preview per device -> deploy mcp-test-dayn/mcp-test-loopback -> deployment status ->
CLI check -> config diff -> compliance -> negation rollback (a generated template) -> CLI check.
Needs both routers Managed and the committed template mcp-test-dayn/mcp-test-loopback (docs/live-tests.md,
prerequisite objects). Leaves nothing
behind: the rollback removes the loopback and the rollback template's project is deleted."""

import asyncio
import contextlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .conftest import ROUTER1, ROUTER2, need
from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

DEVICES = [ROUTER1, ROUTER2]
TEMPLATE = "mcp-test-dayn/mcp-test-loopback"
LOOP = 79
PARAMS = {"loop_id": LOOP, "desc": "mcp-test-change-window", "ip": "10.79.79.1"}


async def _show(c: Client, cmd: str) -> dict[str, str]:  # type: ignore[type-arg]
    out = await call(c, "catc_run_show_commands", {"devices": DEVICES, "commands": [cmd]})
    return {str(r.get("device") or r.get("hostname")): json.dumps(r.get("output")) for r in out["results"]}


async def _managed(c: Client) -> bool:  # type: ignore[type-arg]
    for d in DEVICES:
        try:
            dev = await call(c, "catc_get_device", {"device": d})
        except ToolError:
            return False
        if dev.get("reachabilityStatus") != "Reachable" or dev.get("collectionStatus") != "Managed":
            return False
    return True


async def test_change_window_on_routers(lab_rw: Client) -> None:  # type: ignore[type-arg]
    need("CATC_LIVE_ROUTER1", "CATC_LIVE_ROUTER2")
    if not await _managed(lab_rw):
        pytest.skip(f"{DEVICES} not Reachable and Managed in Catalyst Center")
    window_end = (datetime.now(UTC) + timedelta(hours=1)).isoformat(timespec="minutes")
    prompt = await lab_rw.get_prompt(
        "catc_change_window",
        {
            "template": TEMPLATE,
            "targets": ",".join(DEVICES),
            "window_end": window_end,
            "params": json.dumps(PARAMS),
        },
    )
    text = prompt.messages[0].content.text  # type: ignore[union-attr]
    assert "`catc_deploy_template`" in text and window_end in text

    # 1. Baseline.
    baseline: dict[str, Any] = {}
    for d in DEVICES:
        issues = await call(
            lab_rw, "catc_list_issues", {"device": d, "priority": ["P1", "P2"], "response_format": "json"}
        )
        comp = await call(lab_rw, "catc_get_compliance_detail", {"device": d})
        arch = await call(
            lab_rw,
            "catc_list_config_archive",
            {"device": d, "file_type": "RUNNINGCONFIG", "response_format": "json"},
        )
        baseline[d] = {"issues": issues.get("returned", 0), "comp": comp, "archive": arch["results"]}
        assert arch["results"], f"{d} has no archived running config"
    # 2. Template is committed; 3. preview renders per device.
    tpl = await call(lab_rw, "catc_get_template", {"template": TEMPLATE})
    assert tpl.get("versions"), "template is not committed"
    for d in DEVICES:
        pv = await call(
            lab_rw, "catc_preview_template", {"template": TEMPLATE, "params": PARAMS, "device": d}
        )
        assert f"Loopback{LOOP}" in json.dumps(pv)
    # 4. Rails: 2 devices <= 10, window open.
    assert len(DEVICES) <= 10 and datetime.fromisoformat(window_end) > datetime.now(UTC)

    proj = f"mcp-test-cw-{RUN}"
    deployed = False
    try:
        # 5-6. Deploy + status + CLI check.
        deployed = True  # set first: a partial push must still be rolled back
        done = await apply(
            lab_rw,
            "catc_deploy_template",
            {"template": TEMPLATE, "devices": DEVICES, "params": PARAMS, "force_push": True},
        )
        dep = done["deployment"]
        assert dep["status"] == "SUCCESS", done
        dep_id = done.get("deployment_id")
        if dep_id:
            st = await call(lab_rw, "catc_get_template_deployment", {"deployment_id": dep_id})
            assert "SUCCESS" in json.dumps(st)
        shown = await _show(lab_rw, f"show running-config interface Loopback{LOOP}")
        assert all("10.79.79.1" in v for v in shown.values()), shown

        # 7. Config diff: the archive gets a new version from the config-change syslog or a resync.
        await apply(lab_rw, "catc_resync_devices", {"devices": DEVICES})
        deadline = time.monotonic() + 480
        pending = set(DEVICES)
        while pending and time.monotonic() < deadline:
            await asyncio.sleep(30)
            for d in list(pending):
                diff = await call(lab_rw, "catc_compare_device_configs", {"device": d})
                if f"+interface Loopback{LOOP}" in str(diff.get("diff", "")):
                    pending.discard(d)
        assert not pending, f"no archived diff with Loopback{LOOP} for {pending}"

        # 8. Compliance run after the change.
        await apply(lab_rw, "catc_run_compliance", {"devices": DEVICES})
        for d in DEVICES:
            assert await call(lab_rw, "catc_get_compliance_detail", {"device": d})
        # 9. Issue diff (informational; a loopback must not raise new P1/P2 issues).
        for d in DEVICES:
            now = await call(
                lab_rw, "catc_list_issues", {"device": d, "priority": ["P1", "P2"], "response_format": "json"}
            )
            assert now.get("returned", 0) <= baseline[d]["issues"], now
    finally:
        # 10. Rollback plan (negation), executed.
        if deployed:
            await apply(lab_rw, "catc_create_template_project", {"name": proj})
            ref = f"{proj}/mcp-test-cw-rollback"
            await apply(
                lab_rw,
                "catc_create_template",
                {
                    "project": proj,
                    "name": "mcp-test-cw-rollback",
                    "device_families": ["Routers"],
                    "content": f"no interface Loopback{LOOP}\n",
                },
            )
            await apply(lab_rw, "catc_commit_template", {"template": ref, "comment": "rollback"})
            rb = await apply(lab_rw, "catc_deploy_template", {"template": ref, "devices": DEVICES})
            assert rb["deployment"]["status"] == "SUCCESS", rb
            with contextlib.suppress(ToolError):
                await apply(lab_rw, "catc_delete_template_project", {"project": proj})
    shown = await _show(lab_rw, "show ip interface brief")
    assert all(f"Loopback{LOOP}" not in v for v in shown.values()), shown
