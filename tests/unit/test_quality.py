"""Operator-eyes pass (D25/D26): ghost devices in Assurance, issue rows that name their device,
grouped repeats, and template deploys that only target applicable device families."""

import time
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server
from catc_mcp.tools.assurance import group_issues, issue_row
from catc_mcp.tools.dangerous import split_applicable, template_families

from .conftest import make_settings
from .test_read_tools import DEV_ID, DEVICE
from .test_safety import DEV2, TID, mock_inventory, mock_template, preview

GONE = "99999999-0000-0000-0000-000000000000"
NOW = int(time.time() * 1000)


async def call(name: str, args: dict[str, Any]) -> Any:
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content else r.content[0].text  # type: ignore[union-attr]


def raw_issue(iid: str, entity: str, name: str = "switch_issue_reboot", **kw: Any) -> dict[str, Any]:
    return {
        "issueId": iid,
        "name": name,
        "summary": 'Device has rebooted due to "reload".',
        "priority": "P2",
        "status": "active",
        "entityType": "network device",
        "entityId": entity,
        "mostRecentOccurredTime": NOW - 3 * 3600 * 1000,
        "firstOccurredTime": NOW - 4 * 3600 * 1000,
        **kw,
    }


def test_issue_row_names_device_and_age() -> None:
    row = issue_row(
        raw_issue(
            "i1",
            DEV_ID,
            additionalAttributes=[
                {"key": "nwDeviceName", "value": "edge-sw1.lab.local"},
                {"key": "_count", "value": "4"},
            ],
        ),
        now_ms=NOW,
    )
    assert row["device"] == "edge-sw1.lab.local" and row["id"] == "i1"
    assert row["last_seen"].startswith("3h") and row["occurrenceCount"] == "4"
    assert isinstance(row["mostRecentOccurredTime"], str)


def test_group_issues_keeps_newest_and_all_ids() -> None:
    old = issue_row(raw_issue("old", DEV_ID, mostRecentOccurredTime=NOW - 9 * 3600 * 1000))
    new = issue_row(raw_issue("new", DEV_ID))
    other = issue_row(raw_issue("x", DEV_ID, name="OSPF_Down", summary="OSPF down"))
    out = group_issues([old, other, new])
    reboot = next(g for g in out if g["name"] == "switch_issue_reboot")
    assert reboot["ids"] == ["new", "old"] and reboot["times_raised"] == 2 and "id" not in reboot
    assert reboot["last_seen"].startswith("3h")
    assert next(g for g in out if g["name"] == "OSPF_Down")["id"] == "x"


async def test_list_issues_device_column_and_ghosts(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={
            "response": [
                raw_issue("i1", DEV_ID),
                raw_issue("i2", GONE, additionalAttributes=[{"key": "nwDeviceName", "value": "old-sw"}]),
            ],
            "page": {"count": 2},
        }
    )
    out = await call("catc_list_issues", {"response_format": "json"})
    rows = {r["id"]: r for r in out["results"]}
    assert rows["i1"]["device"] == DEVICE["hostname"]  # from the inventory when the issue doesn't say
    assert rows["i2"]["device"] == "old-sw (not in inventory)"
    assert "old-sw (not in inventory)" in out["note"]


async def test_device_health_leaves_out_deleted_devices(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dna/intent/api/v1/device-health").respond(
        json={
            "response": [
                {"name": "edge-sw1", "uuid": DEV_ID, "overallHealth": 10},
                {"name": "ghost-sw", "uuid": GONE, "overallHealth": -1, "issueCount": 3},
            ],
            "totalCount": 2,
        }
    )
    out = await call("catc_list_device_health", {"response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["edge-sw1"]
    assert "ghost-sw" in out["left_out"] and "-1" in out["note"]


async def test_device_health_kept_when_inventory_lookup_fails(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/network-device").respond(500, text="boom")
    api.get("/dna/intent/api/v1/device-health").respond(
        json={"response": [{"name": "ghost-sw", "uuid": GONE}], "totalCount": 1}
    )
    out = await call("catc_list_device_health", {"response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["ghost-sw"] and "left_out" not in out


def test_split_applicable_by_family() -> None:
    fams = template_families({"deviceTypes": [{"productFamily": "Routers"}]})
    router = {"id": "r", "family": "Routers"}
    wlc = {"id": "w", "family": "Wireless Controller"}
    assert split_applicable([router, wlc], fams) == ([router], [wlc])
    assert split_applicable([router, wlc], set()) == ([router, wlc], [])


async def test_deploy_skips_devices_outside_template_families(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)  # a 'Switches and Hubs' template
    router = {**DEV2, "family": "Routers"}

    def by_id(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": router})

    api.get(f"/dna/intent/api/v1/network-device/{DEV2['id']}").mock(side_effect=by_id)
    out = await preview("catc_deploy_template", {"template": TID, "devices": [DEV_ID, DEV2["id"]]})
    assert out["status"] == "preview" and out["blast_radius"] == 1
    assert out["preview"]["devices"] == [f"{DEVICE['hostname']} ({DEVICE['managementIpAddress']})"]
    assert out["preview"]["targets"]["skipped_not_applicable"] == ["edge-sw2 (10.0.0.12) - Routers"]


async def test_deploy_refuses_when_nothing_applies(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    api.get(f"/dna/intent/api/v1/network-device/{DEV2['id']}").respond(
        json={"response": {**DEV2, "family": "Routers"}}
    )
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        r = await c.call_tool(
            "catc_deploy_template", {"template": TID, "devices": [DEV2["id"]]}, raise_on_error=False
        )
    assert r.is_error and "device families" in r.content[0].text  # type: ignore[union-attr]
