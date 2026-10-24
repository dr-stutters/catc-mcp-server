"""D118: catc_snapshot / catc_compare_snapshot on the core snapshot contract (C53), from recorded
3.2.2 read shapes (tests/fixtures/snapshot_d118.json): an unchanged re-read compares as "No change",
an access port shut on mcp-sw1 is named on the right items, scope and per-section failures."""

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from catc_mcp._core.snapshot import MAX_CHARS, digest
from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import mock_sites, run

FIX = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "snapshot_d118.json").read_text())
SITE_ID = {s["nameHierarchy"]: s["id"] for s in FIX["sites"]}
SW1 = "86f3fc55-04cc-47ca-944e-cee0888bb398"
# Devices the compliance API returns per site id (the site and below).
COMPLIANCE_AT = {
    SITE_ID["Global"]: None,
    SITE_ID["Global/mcp-test-lab"]: None,
    SITE_ID["Global/mcp-test-lab/mcp-test-nac"]: {SW1},
}


def page(rows: list[dict[str, Any]], total_key: str = "page") -> dict[str, Any]:
    if total_key == "totalCount":
        return {"version": "1.0", "totalCount": len(rows), "response": rows}
    return {"response": rows, "page": {"limit": 25, "offset": 1, "count": len(rows)}, "version": "1.0"}


def under(rows: list[dict[str, Any]], field: str, q: httpx.QueryParams) -> list[dict[str, Any]]:
    want = q.get("siteHierarchy")
    if not want:
        return rows
    return [r for r in rows if str(r.get(field) or "").startswith(want.rstrip("*"))]


class Lab:
    """The fake appliance; `state` picks the recorded state ('healthy', 'reread', 'degraded')."""

    def __init__(self, api: respx.MockRouter) -> None:
        self.state = "healthy"
        self.fail: set[str] = set()
        mock_sites(api, FIX["sites"])
        api.get("/dna/intent/api/v1/network-device").mock(side_effect=self.inventory)
        api.get("/dna/intent/api/v1/device-health").mock(side_effect=self.device_health)
        api.get("/dna/data/api/v1/siteHealthSummaries").mock(side_effect=self.site_health)
        api.get(url__regex=r"/dna/intent/api/v1/compliance/sites/[^/]+/networkDevices").mock(
            side_effect=self.compliance
        )
        self.issues_route = api.get("/dna/data/api/v1/assuranceIssues").mock(side_effect=self.issues)

    def rows(self, name: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = FIX[self.state][name]
        return rows

    def inventory(self, request: httpx.Request) -> httpx.Response:
        ids = set(request.url.params.get("id", "").split(","))
        return httpx.Response(200, json={"response": [d for d in FIX["inventory"] if d["id"] in ids]})

    def device_health(self, request: httpx.Request) -> httpx.Response:
        if "device_health" in self.fail:
            return httpx.Response(500, json={"message": "assurance unavailable"})
        return httpx.Response(200, json=page(self.rows("device_health"), "totalCount"))

    def site_health(self, request: httpx.Request) -> httpx.Response:
        if "site_health" in self.fail:
            return httpx.Response(500, json={"message": "assurance unavailable"})
        return httpx.Response(
            200, json=page(under(self.rows("site_health"), "siteHierarchy", request.url.params))
        )

    def compliance(self, request: httpx.Request) -> httpx.Response:
        m = re.search(r"/compliance/sites/([^/]+)/networkDevices", request.url.path)
        assert m
        only = COMPLIANCE_AT[m.group(1)]
        rows = [r for r in self.rows("compliance") if only is None or r["networkDeviceId"] in only]
        if int(request.url.params.get("offset", "1")) > 1:
            rows = []
        return httpx.Response(200, json={"response": rows, "version": "1.0"})

    def issues(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=page(under(self.rows("issues"), "siteHierarchy", request.url.params)))


@pytest.fixture
def lab(api: respx.MockRouter) -> Lab:
    return Lab(api)


def server() -> Any:
    return create_server(make_settings())


async def test_snapshot_blob_shape(lab: Lab) -> None:
    async with Client(server()) as c:
        blob = await run(c, "catc_snapshot", {})
    assert blob["snapshot"] == 1 and blob["prefix"] == "catc" and blob["scope"] == {}
    assert blob["digest"] == digest(blob)
    assert len(json.dumps(blob, separators=(",", ":"))) < MAX_CHARS
    sec = blob["sections"]
    assert set(sec) == {"devices", "sites", "compliance", "issues"}
    devices = sec["devices"]["items"]
    # dmvpn-hub has a health record but is no longer in the inventory: left out.
    assert set(devices) == {"device:mcp-sw1.mcp.lab", "device:r1.mcp.lab", "device:mcp-catc-wlc.mcp.lab"}
    assert devices["device:mcp-sw1.mcp.lab"] == {
        "ok": True,
        "state": "REACHABLE",
        "health": 10,
        "version": "17.18.2",
        "site": "Global/mcp-test-lab/mcp-test-nac",
    }
    assert "health" not in devices["device:mcp-catc-wlc.mcp.lab"]  # -1 = not computed
    assert sec["devices"]["metrics"]["health"] == {"better": "higher", "tolerance": 1, "limit": 8}
    assert sec["sites"]["items"]["Global/mcp-test-lab/mcp-test-nac"] == {
        "ok": True,
        "devices": 1,
        "devices_healthy_pct": 100,
        "clients": 8,
    }
    assert "ok" not in sec["sites"]["items"]["Global/mcp-test-lab/mcp-test-bldg/mcp-test-floor1"]
    assert sec["compliance"]["items"]["device:r1.mcp.lab"] == {
        "ok": True,
        "state": "COMPLIANT",
        "running_config": "COMPLIANT",
        "network_settings": "COMPLIANT",
        "eox": "NOT_APPLICABLE",
    }
    issue = sec["issues"]["items"]["router_wan_link_flapping|r1.mcp.lab"]
    assert issue["ok"] is False and issue["state"] == "P2" and "flapped" in issue["label"]
    # Nothing volatile in any item: no timestamps, counts or CPU scores.
    text = json.dumps(sec)
    for volatile in ("1792", "cpu", "occurrence", "issueCount", "last_seen"):
        assert volatile not in text
    params = lab.issues_route.calls.last.request.url.params
    assert params.get_list("priority") == ["P1", "P2"] and params["status"] == "active"
    assert "siteHierarchy" not in params


async def test_unchanged_network_compares_as_no_change(lab: Lab) -> None:
    async with Client(server()) as c:
        before = await run(c, "catc_snapshot", {"site": "Global/mcp-test-lab"})
        lab.state = "reread"  # timestamps, counters, CPU and client counts moved; a repeat issue
        result = await run(c, "catc_compare_snapshot", {"before": before})
        again = await run(c, "catc_compare_snapshot", {"before": json.dumps(before), "after": before})
    assert result["verdict"].startswith("No change"), result
    assert result["counts"] == {"major": 0, "minor": 0, "info": 0}
    assert not result.get("changes") and "notes" not in result
    assert result["unchanged_items"] > 10
    assert again["verdict"].startswith("No change")


async def test_degraded_site_names_the_right_items(lab: Lab) -> None:
    async with Client(server()) as c:
        before = await run(c, "catc_snapshot", {"site": "Global/mcp-test-lab"})
        lab.state = "degraded"  # access port shut on mcp-sw1
        after = await run(c, "catc_snapshot", {"site": "Global/mcp-test-lab"})
        result = await run(c, "catc_compare_snapshot", {"before": before, "after": after})
    majors = {
        (ch["section"], ch["item"], ch["kind"]) for ch in result["changes"] if ch["severity"] == "major"
    }
    assert majors == {
        ("devices", "device:mcp-sw1.mcp.lab", "degraded"),
        ("compliance", "device:mcp-sw1.mcp.lab", "degraded"),
        ("issues", "switch_interface_down|mcp-sw1.mcp.lab", "added"),
        ("sites", "Global/mcp-test-lab", "degraded"),
        ("sites", "Global/mcp-test-lab/mcp-test-nac", "degraded"),
    }
    assert result["counts"]["major"] == 5 and result["counts"]["minor"] == 0
    dev = next(ch for ch in result["changes"] if ch["section"] == "devices")
    assert "healthy -> unhealthy" in dev["what"] and "health 10 -> 3 (past the limit 8)" in dev["what"]
    comp = next(ch for ch in result["changes"] if ch["section"] == "compliance")
    assert "state COMPLIANT -> NON_COMPLIANT" in comp["what"]
    assert "running_config COMPLIANT -> NON_COMPLIANT" in comp["what"]
    issue = next(ch for ch in result["changes"] if ch["section"] == "issues")
    assert "GigabitEthernet1/0/2 is down" in issue["what"]


async def test_site_scope_narrows_every_section(lab: Lab) -> None:
    async with Client(server()) as c:
        blob = await run(c, "catc_snapshot", {"site": "mcp-test-nac"})
    assert blob["scope"] == {"site": "Global/mcp-test-lab/mcp-test-nac"}
    sec = blob["sections"]
    assert set(sec["devices"]["items"]) == {"device:mcp-sw1.mcp.lab"}
    assert set(sec["sites"]["items"]) == {"Global/mcp-test-lab/mcp-test-nac"}
    assert set(sec["compliance"]["items"]) == {"device:mcp-sw1.mcp.lab"}
    assert sec["issues"]["items"] == {}
    assert (
        lab.issues_route.calls.last.request.url.params["siteHierarchy"] == "Global/mcp-test-lab/mcp-test-nac*"
    )


async def test_failed_section_is_unreadable_not_fatal(lab: Lab) -> None:
    async with Client(server()) as c:
        before = await run(c, "catc_snapshot", {"site": "Global/mcp-test-lab"})
        lab.fail = {"site_health"}
        after = await run(c, "catc_snapshot", {"site": "Global/mcp-test-lab"})
        result = await run(c, "catc_compare_snapshot", {"before": before, "after": after})
    assert after["sections"]["sites"]["items"] == {} and "500" in after["sections"]["sites"]["error"]
    assert after["sections"]["devices"]["items"]
    assert [(ch["severity"], ch["kind"], ch["section"]) for ch in result["changes"]] == [
        ("minor", "unreadable", "sites")
    ]


async def test_compare_refuses_another_servers_blob(lab: Lab) -> None:
    async with Client(server()) as c:
        blob = await run(c, "catc_snapshot", {})
        foreign = {**blob, "prefix": "ise"}
        res = await c.call_tool(
            "catc_compare_snapshot", {"before": foreign, "after": blob}, raise_on_error=False
        )
    assert res.is_error and "not 'catc'" in res.content[0].text  # type: ignore[union-attr]
