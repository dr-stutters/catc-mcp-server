"""D92: SD-Access health (respx). fabricSummary is the 3.2.2 lab appliance's live answer with no fabric
(2026-10-21); the site, VN and transit rows follow the 3.2.2 Data API schema."""

from typing import Any

import httpx
import respx

from catc_mcp.tools.sda_health import dimensions, problems

from .test_read_tools import call

DATA = "/dna/data/api/v1"
EMPTY_SUMMARY = {
    "response": {
        "protocolSummaries": [
            {
                "fabricSiteGoodHealthCount": 0,
                "fabricSiteCount": 0,
                "fabricSiteGoodHealthPercentage": 0.0,
                "l3VnCount": 0,
                "l2VnGoodHealthPercentage": None,
                "transitNetworkCount": 0,
                "fabricDeviceCount": 0,
                "p1IssueCount": 0,
                "p2IssueCount": 0,
                "p3IssueCount": 0,
                "networkSegmentProtocol": None,
            }
        ]
    },
    "version": "1.0",
}
SITE = {
    "id": "fs-1",
    "name": "mcp-test-fabric",
    "siteHierarchy": "Global/mcp-test-lab/mcp-test-fabric",
    "goodHealthPercentage": 50,
    "goodHealthDeviceCount": 1,
    "fairHealthDeviceCount": 0,
    "poorHealthDeviceCount": 1,
    "totalHealthDeviceCount": 2,
    "associatedL3VnCount": 2,
    "controlPlaneGoodHealthDeviceCount": 1,
    "controlPlanePoorHealthDeviceCount": 0,
    "controlPlaneFairHealthDeviceCount": 0,
    "controlPlaneTotalHealthDeviceCount": 1,
    "controlPlaneGoodHealthPercentage": 100,
    "lispSessionGoodHealthDeviceCount": 1,
    "lispSessionPoorHealthDeviceCount": 1,
    "lispSessionFairHealthDeviceCount": 0,
    "lispSessionTotalHealthDeviceCount": 2,
    "lispSessionGoodHealthPercentage": 50,
    "ctsEnvDataDownloadGoodHealthDeviceCount": 1,
    "ctsEnvDataDownloadFairHealthDeviceCount": 1,
    "ctsEnvDataDownloadPoorHealthDeviceCount": 0,
    "ctsEnvDataDownloadTotalHealthDeviceCount": 2,
    "bgpPeerInfraVnScoreGoodHealthPercentage": 100,
    "bgpPeerInfraVnTotalHealthDeviceCount": 0,
    "portChannelTotalHealthDeviceCount": 0,
}
VN = {
    "id": "vn-1",
    "name": "MCP_VN",
    "layer": "Layer3",
    "vnid": 4099,
    "totalFabricSites": 1,
    "totalEndpoints": 2,
    "goodHealthPercentage": 100,
    "goodHealthDeviceCount": 2,
    "totalHealthDeviceCount": 2,
    "vnExitGoodHealthDeviceCount": 1,
    "vnExitTotalDeviceCount": 1,
    "vnExitHealthPercentage": 100,
    "multiCastTotalDeviceCount": 0,
}


def test_dimensions_group_irregular_keys() -> None:
    dims = dimensions(SITE)
    assert dims[""] == {"good": 1, "fair": 0, "poor": 1, "total": 2, "pct": 50}
    assert dims["lispSession"] == {"good": 1, "poor": 1, "fair": 0, "total": 2, "pct": 50}
    assert "portChannel" not in dims and "bgpPeerInfraVn" not in dims  # nothing counted
    assert problems({d: v for d, v in dims.items() if d}) == [
        "lispSession: 1 poor of 2",
        "ctsEnvDataDownload: 1 fair of 2",
    ]
    vn = dimensions(VN)
    assert vn["vnExit"] == {"good": 1, "total": 1, "pct": 100}


def mock(
    api: respx.MockRouter, *, sites: list[dict[str, Any]], vns: list[dict[str, Any]], summary: Any
) -> None:
    api.get(f"{DATA}/fabricSummary").respond(json=summary)
    api.get(f"{DATA}/fabricSiteHealthSummaries").respond(
        json={"response": sites, "page": {"limit": 100, "offset": 1, "count": len(sites)}, "version": "1.0.0"}
    )
    api.get(f"{DATA}/virtualNetworkHealthSummaries").respond(
        json={"response": vns, "page": {"limit": 100, "offset": 1, "count": len(vns)}, "version": "1.0.0"}
    )
    api.get(f"{DATA}/transitNetworkHealthSummaries").respond(
        json={"response": [], "page": {"limit": 100, "offset": 1, "count": 0}, "version": "1.0.0"}
    )


async def test_empty_appliance(api: respx.MockRouter) -> None:
    mock(api, sites=[], vns=[], summary=EMPTY_SUMMARY)
    out = await call("catc_fabric_health")
    assert out["verdict"].startswith("No SD-Access fabric sites")
    assert out["fabric_sites"] == [] and out["transits"] == [] and out["summary"]["fabricSiteCount"] == 0


async def test_site_vn_and_trend(api: respx.MockRouter) -> None:
    summary = {
        "response": {
            "protocolSummaries": [
                {**EMPTY_SUMMARY["response"]["protocolSummaries"][0], "fabricSiteCount": 1, "p1IssueCount": 1}
            ]
        }
    }
    mock(api, sites=[SITE], vns=[VN], summary=summary)
    trend = api.get(f"{DATA}/fabricSiteHealthSummaries/fs-1/trendAnalytics").respond(
        json={
            "response": [
                {
                    "timestamp": 1,
                    "attributes": [{"name": "goodHealthPercentage", "value": 100}, {"name": "x", "value": 1}],
                },
                {"timestamp": 2, "attributes": [{"name": "goodHealthPercentage", "value": 50}]},
            ]
        }
    )
    out = await call(
        "catc_fabric_health",
        {
            "fabric_site": "Global/mcp-test-lab/mcp-test-fabric/",
            "hours": 2,
            "trend_interval": "1hour",
            "include": ["virtual_networks"],
        },
    )
    q = next(
        c.request.url.params for c in api.calls if c.request.url.path.endswith("/fabricSiteHealthSummaries")
    )
    assert (
        q["siteHierarchy"] == "Global/mcp-test-lab/mcp-test-fabric"
        and int(q["endTime"]) - int(q["startTime"]) == 7_200_000
    )
    site = out["fabric_sites"][0]
    assert site["health"] == {"good": 1, "fair": 0, "poor": 1, "total": 2, "pct": 50}
    assert site["problems"][0] == "lispSession: 1 poor of 2"
    assert out["verdict"] == (
        "1 fabric site(s), 1 P1/P2 issue(s): mcp-test-fabric: 50% good (1/2 devices good); "
        "lispSession: 1 poor of 2, ctsEnvDataDownload: 1 fair of 2"
    )
    assert out["virtual_networks"][0]["problems"] == [] and "transits" not in out
    assert trend.calls[0].request.url.params["trendInterval"] == "1 hour"
    assert site["trend"] == [
        {"timestamp": 1, "goodHealthPercentage": 100},
        {"timestamp": 2, "goodHealthPercentage": 50},
    ]


async def test_section_errors_are_reported(api: respx.MockRouter) -> None:
    mock(api, sites=[], vns=[], summary=EMPTY_SUMMARY)
    api.get(f"{DATA}/transitNetworkHealthSummaries").mock(
        return_value=httpx.Response(500, json={"message": "boom"})
    )
    out = await call("catc_fabric_health")
    assert "transits" in out["errors"] and out["fabric_sites"] == []
