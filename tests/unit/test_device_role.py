"""catc_set_device_role over PUT network-device/brief (respx; body per the 3.2.2 spec: id, role, roleSource).

Live 2026-10-22 (lab mcp-catc-fabric2): bcp2 had been auto-classified ACCESS, so its layer 2 handoff failed;
setting it to BORDER ROUTER (MANUAL) over this endpoint fixed it.
"""

import json
from typing import Any

import httpx
import pytest
import respx

from .test_read_tools import DEVICE
from .test_safety import DEV2, preview
from .test_write_tools import preview_then_apply, task_ok

ROLE = "/dna/intent/api/v1/network-device/brief"


class Inventory:
    """Devices by management IP or id; a PUT to network-device/brief changes the record unless `sticky` (an
    appliance that accepts the task but keeps the old role)."""

    def __init__(self, api: respx.MockRouter, devices: list[dict[str, Any]], sticky: bool = False) -> None:
        self.devices = {str(d["id"]): dict(d) for d in devices}
        self.puts: list[Any] = []
        self.sticky = sticky
        api.get("/dna/intent/api/v1/network-device").mock(side_effect=self.query)
        for i in self.devices:
            api.get(f"/dna/intent/api/v1/network-device/{i}").mock(
                side_effect=lambda r, i=i: httpx.Response(200, json={"response": self.devices[i]})
            )
        api.put(ROLE).mock(side_effect=self.put)
        task_ok(api, "tr")

    def query(self, request: httpx.Request) -> httpx.Response:
        ip = request.url.params.get("managementIpAddress")
        return httpx.Response(
            200, json={"response": [d for d in self.devices.values() if d["managementIpAddress"] == ip]}
        )

    def put(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.puts.append(body)
        if not self.sticky:
            self.devices[body["id"]].update(role=body["role"], roleSource=body["roleSource"])
        return httpx.Response(202, json={"response": {"taskId": "tr"}})


ACCESS = {**DEVICE, "role": "ACCESS", "roleSource": "AUTO"}
ACCESS2 = {**DEV2, "role": "ACCESS", "roleSource": "AUTO"}


async def test_set_role_preview_then_apply(api: respx.MockRouter) -> None:
    inv = Inventory(api, [ACCESS, ACCESS2])
    args = {"devices": ["10.0.0.11", "10.0.0.12"], "role": "border_router"}
    out, done = await preview_then_apply("catc_set_device_role", args)  # write tier: no dangerous needed
    assert (
        out["action"] == "Set the inventory role of 2 device(s) to BORDER ROUTER" and out["blast_radius"] == 2
    )
    assert out["preview"]["devices"][0] == {
        "device": "edge-sw1.lab.local (10.0.0.11)",
        "from": "ACCESS (AUTO)",
        "to": "BORDER ROUTER (MANUAL)",
    }
    assert inv.puts == [
        {"id": DEVICE["id"], "role": "BORDER ROUTER", "roleSource": "MANUAL"},
        {"id": DEV2["id"], "role": "BORDER ROUTER", "roleSource": "MANUAL"},
    ]
    rows = done["result"]["devices"]
    assert [(r["role"], r["role_source"]) for r in rows] == [("BORDER ROUTER", "MANUAL")] * 2
    assert rows[0]["task"]["task_id"] == "tr" and "warning" not in rows[0]


async def test_devices_already_pinned_are_skipped(api: respx.MockRouter) -> None:
    inv = Inventory(api, [ACCESS, {**DEV2, "role": "BORDER ROUTER", "roleSource": "MANUAL"}])
    out, done = await preview_then_apply(
        "catc_set_device_role", {"devices": ["10.0.0.11", "10.0.0.12"], "role": "BORDER ROUTER"}
    )
    assert out["blast_radius"] == 1 and out["preview"]["unchanged"] == ["edge-sw2 (10.0.0.12)"]
    assert done and [p["id"] for p in inv.puts] == [DEVICE["id"]]


async def test_auto_role_is_pinned(api: respx.MockRouter) -> None:
    """The same role with source AUTO is still a change: MANUAL stops the automatic reclassification."""
    Inventory(api, [{**ACCESS, "role": "BORDER ROUTER"}])
    out, _ = await preview_then_apply(
        "catc_set_device_role", {"devices": ["10.0.0.11"], "role": "BORDER ROUTER"}
    )
    assert out["status"] == "preview" and out["preview"]["devices"][0]["from"] == "BORDER ROUTER (AUTO)"


@pytest.mark.parametrize(
    ("devices", "role", "needle"),
    [
        ([ACCESS], "SPINE", "Unknown role 'SPINE'"),
        ([{**ACCESS, "role": "CORE", "roleSource": "MANUAL"}], "core", "Nothing to change"),
    ],
)
async def test_blockers(api: respx.MockRouter, devices: list[dict[str, Any]], role: str, needle: str) -> None:
    inv = Inventory(api, devices)
    out, _ = await preview_then_apply("catc_set_device_role", {"devices": ["10.0.0.11"], "role": role})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not inv.puts


async def test_device_limit(api: respx.MockRouter) -> None:
    Inventory(api, [ACCESS, ACCESS2])
    out = await preview(
        "catc_set_device_role",
        {"devices": ["10.0.0.11", "10.0.0.12"], "role": "DISTRIBUTION"},
        max_devices_per_change=1,
    )
    assert out["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE=1" in " ".join(out["blockers"])


async def test_role_not_read_back_is_reported(api: respx.MockRouter) -> None:
    Inventory(api, [ACCESS], sticky=True)
    _, done = await preview_then_apply("catc_set_device_role", {"devices": ["10.0.0.11"], "role": "CORE"})
    row = done["result"]["devices"][0]
    assert row["role"] == "ACCESS" and "reads the role back as ACCESS, not CORE" in row["warning"]
