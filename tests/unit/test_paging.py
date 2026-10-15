"""Per-endpoint page caps through `fetch_page(max_page=...)` and lists without a total (D1)."""

from typing import Any

import httpx
import respx

from catc_mcp.client import data_total

from .test_read_tools import call


def _numbered(request: httpx.Request, *, total: int, one_based: bool, envelope: str | None) -> Any:
    q = request.url.params
    start = int(q["offset"]) - (1 if one_based else 0)
    n = int(q["limit"])
    rows = [{"id": f"r{i}", "timestamp": 1_700_000_000_000 - i} for i in range(start, min(start + n, total))]
    if envelope is None:
        return httpx.Response(200, json=rows)
    return httpx.Response(200, json={"response": rows, envelope: {"count": total}})


def test_data_total() -> None:
    assert data_total({"response": [], "page": {"count": 7}}) == 7
    assert data_total({"response": [], "totalCount": 9}) == 9
    assert data_total({"response": []}) is None
    assert data_total([1, 2]) is None


async def test_issue_page_cap_25(api: respx.MockRouter) -> None:
    route = api.get("/dna/data/api/v1/assuranceIssues").mock(
        side_effect=lambda r: _numbered(r, total=60, one_based=True, envelope="page")
    )
    out = await call("catc_list_issues", {"limit": 60, "response_format": "json"})
    limits = [int(c.request.url.params["limit"]) for c in route.calls]
    offsets = [int(c.request.url.params["offset"]) for c in route.calls]
    assert max(limits) <= 25 and offsets == [1, 26, 51]
    assert out["returned"] == 60 and out["total"] == 60


async def test_event_page_cap_20(api: respx.MockRouter) -> None:
    route = api.get("/dna/data/api/v1/assuranceEvents").mock(
        side_effect=lambda r: _numbered(r, total=45, one_based=True, envelope="page")
    )
    out = await call(
        "catc_list_events", {"device_family": "Routers", "limit": 45, "response_format": "json"}
    )
    limits = [int(c.request.url.params["limit"]) for c in route.calls]
    assert limits == [20, 20, 5]
    assert out["returned"] == 45


async def test_device_health_cap_500_and_total(api: respx.MockRouter) -> None:
    def health(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        start = int(q["offset"]) - 1
        rows = [{"name": f"d{i}"} for i in range(start, min(start + int(q["limit"]), 700))]
        return httpx.Response(200, json={"response": rows, "totalCount": 700})

    route = api.get("/dna/intent/api/v1/device-health").mock(side_effect=health)
    out = await call("catc_list_device_health", {"limit": 500, "offset": 100, "response_format": "json"})
    assert [int(c.request.url.params["limit"]) for c in route.calls] == [500]
    assert out["total"] == 700 and out["next_offset"] == 600


async def test_audit_zero_based_cap_25_without_total(api: respx.MockRouter) -> None:
    route = api.get("/dna/data/api/v1/event/event-series/audit-logs").mock(
        side_effect=lambda r: _numbered(r, total=100, one_based=False, envelope=None)
    )
    out = await call("catc_list_audit_logs", {"limit": 30, "offset": 5, "response_format": "json"})
    params = [(int(c.request.url.params["offset"]), int(c.request.url.params["limit"])) for c in route.calls]
    assert params == [(5, 25), (30, 5)]
    # No total from the API, but the page was full: the result must say there may be more.
    assert out["returned"] == 30
    assert out.get("next_offset") == 35
    assert "total" not in out


async def test_pnp_without_total_keeps_next_offset(api: respx.MockRouter) -> None:
    def pnp(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        n = int(q["limit"])
        return httpx.Response(
            200, json=[{"deviceInfo": {"serialNumber": f"S{i}", "state": "Unclaimed"}} for i in range(n)]
        )

    api.get("/dna/intent/api/v1/onboarding/pnp-device").mock(side_effect=pnp)
    out = await call("catc_list_pnp_devices", {"limit": 3, "response_format": "json"})
    assert out["returned"] == 3
    assert out.get("next_offset") == 3
