"""D2 live tests: catc_recent_activity / catc_list_event_notifications against the lab.

The link test shuts GigabitEthernet2 of CATC_LIVE_ROUTER2 (its OSPF link to CATC_LIVE_ROUTER1) with a
throwaway Catalyst Center template, waits for the issue/syslog to show up in catc_recent_activity,
and brings the link back up. It skips when the routers are unset or not managed and reachable."""

import asyncio
import contextlib
import time
from typing import Any

import pytest
from fastmcp import Client

from .test_live_phase2 import R2, RUN, area, routers  # noqa: F401 - fixtures
from .test_live_writes import apply, call, raw  # noqa: F401 - raw is a fixture

pytestmark = pytest.mark.live


async def test_reads_shape(lab: Client) -> None:  # type: ignore[type-arg]
    out = await call(
        lab, "catc_list_event_notifications", {"hours": 72, "limit": 5, "response_format": "json"}
    )
    assert all(r.get("type") != "AUDIT_LOG" for r in out["results"])
    act = await call(lab, "catc_recent_activity", {"hours": 24, "limit": 20, "response_format": "json"})
    assert set(act["counts"]) | set(act.get("errors", {})) == {"issue", "event", "notification", "audit"}
    assert not act.get("errors"), act.get("errors")


async def _deploy(lab_rw: Client, proj: str, name: str, content: str) -> None:  # type: ignore[type-arg]
    await apply(
        lab_rw,
        "catc_create_template",
        {"project": proj, "name": name, "device_families": ["Routers"], "content": content},
    )
    ref = f"{proj}/{name}"
    await apply(lab_rw, "catc_commit_template", {"template": ref, "comment": "mcp live test"})
    done = await apply(lab_rw, "catc_deploy_template", {"template": ref, "devices": [R2]})
    assert done["deployment"]["status"] == "SUCCESS", done


async def test_link_down_shows_in_recent_activity(
    lab_rw: Client,  # type: ignore[type-arg]
    routers: dict[str, Any],  # noqa: F811
) -> None:
    proj = f"mcp-test-act-{RUN}"
    await apply(lab_rw, "catc_create_template_project", {"name": proj})
    started = time.monotonic()
    try:
        await _deploy(lab_rw, proj, "mcp-test-gi2-down", "interface GigabitEthernet2\n shutdown\n")
        seen: dict[str, Any] = {}
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            mins = (time.monotonic() - started) / 3600 + 0.1
            act = await call(
                lab_rw, "catc_recent_activity", {"device": R2, "hours": mins, "response_format": "json"}
            )
            rows = act["results"]
            seen["event"] = [r for r in rows if r["source"] == "event" and "GigabitEthernet2" in str(r)]
            seen["alert"] = [r for r in rows if r["source"] in ("issue", "notification")]
            if seen["event"] and seen["alert"]:
                break
            await asyncio.sleep(30)
        assert seen.get("event"), f"no syslog event for Gi2 on {R2}"
        assert seen.get("alert"), "no issue/notification for the link going down"
    finally:
        with contextlib.suppress(Exception):
            await _deploy(lab_rw, proj, "mcp-test-gi2-up", "interface GigabitEthernet2\n no shutdown\n")
        await apply(lab_rw, "catc_delete_template_project", {"project": proj})


async def test_site_settings_change_in_audit(lab_rw: Client, area: str) -> None:  # type: ignore[type-arg]  # noqa: F811
    await apply(lab_rw, "catc_update_site_settings", {"site": area, "banner": f"mcp-test act {RUN}"})
    rows: list[dict[str, Any]] = []
    for _ in range(10):
        act = await call(
            lab_rw,
            "catc_recent_activity",
            {"site": area, "sources": ["audit"], "hours": 0.5, "response_format": "json"},
        )
        rows = act["results"]
        if rows:
            break
        await asyncio.sleep(15)
    assert rows, "the settings change didn't show in the site's audit log"
