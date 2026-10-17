"""D38 live tests: the assurance analytics tools against the lab (read-only).

The outage check (shut CATC_LIVE_ROUTER2 GigabitEthernet2 for ~15 minutes, bring it back, then run
these) is a manual step: Catalyst Center needs minutes to raise and resolve the issues and land the
trend buckets, longer than a test should wait. Without a recent outage the tests check shapes only."""

from typing import Any

import pytest
from fastmcp import Client

from .conftest import need
from .test_live_writes import call

pytestmark = pytest.mark.live


async def test_network_trend_and_top_problems(lab: Client[Any]) -> None:
    trend = await call(lab, "catc_health_trend", {"hours": 6})
    assert trend["network_devices_healthy"]["samples"] > 0, trend
    top = await call(lab, "catc_top_problems", {"hours": 6})
    assert isinstance(top["results"], list)
    for row in top["results"]:
        assert row.get("issues") or row.get("worst_health", 10) < 8, row


async def test_device_trend_recurrence_and_ai(lab: Client[Any]) -> None:
    (router,) = need("CATC_LIVE_ROUTER2")
    dev = await call(lab, "catc_health_trend", {"scope": "device", "target": router, "hours": 6})
    assert "health" in dev and isinstance(dev["issue_periods"], list)
    rec = await call(lab, "catc_issue_recurrence", {"hours": 168, "min_times": 1, "device": router})
    assert all(g["times_opened"] >= 1 for g in rec["recurring"])
    ai = await call(lab, "catc_ai_insights", {"hours": 24})
    assert ai["status"] in ("available", "unavailable") and (ai.get("reason") or ai.get("insights"))


async def test_site_health_report(lab: Client[Any]) -> None:
    (building,) = need("CATC_LIVE_BUILDING")
    out = await call(lab, "catc_site_health_report", {"site": building, "hours": 6})
    assert out["site"].endswith(building.rsplit("/", 1)[-1])
    for key in ("now", "trend", "problem_devices", "problem_clients", "issues", "ai_insights", "verdict"):
        assert key in out, key
    assert "unavailable" not in out["trend"], out["trend"]
