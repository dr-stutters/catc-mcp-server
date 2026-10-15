"""Live reports (D16): an Inventory / All Data CSV report filtered to Routers, run now, downloaded and
deleted. Catalyst Center 3.2.2 on dCloud takes several minutes per execution, so the test waits up to
15 minutes."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live


async def test_inventory_report(lab_rw: Client[Any]) -> None:
    name = f"mcp-test-report-{RUN}"
    view = await call(lab_rw, "catc_get_report_view", {"group": "Inventory", "view": "All Data"})
    assert "CSV" in view["formats"] and any(f["name"] == "DeviceFamily" for f in view["filters"])
    await apply(
        lab_rw,
        "catc_create_report",
        {"name": name, "group": "Inventory", "view": "All Data", "filters": {"DeviceFamily": ["Routers"]}},
    )
    try:
        content = None
        for _ in range(45):
            with contextlib.suppress(ToolError):
                content = await call(lab_rw, "catc_get_report_content", {"report": name})
                break
            await asyncio.sleep(20)
        assert content, "the report execution didn't finish in 15 minutes"
        text = content["content"]
        assert "Device Family,Routers" in text and "Cisco Catalyst 8000V" in text
    finally:
        await apply(lab_rw, "catc_delete_report", {"report": name})
