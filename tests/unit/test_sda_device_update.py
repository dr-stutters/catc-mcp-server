"""D103: a fabric border's updatable settings (respx). Payloads follow the 3.2.2 spec's PUT
sda/fabricDevices: roles, local AS, default exit and route import are not updatable (re-sent as read),
priority 1-9, prepend 1-10."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import DEV_ID
from .test_safety import mock_inventory
from .test_sda import FID, flow
from .test_write_tools import task_ok

SDA = "/dna/intent/api/v1/sda"
L3 = {"localAutonomousSystemNumber": "65001", "isDefaultExit": True, "importExternalRoutes": True}
BORDER = {
    "id": "fd-b",
    "networkDeviceId": DEV_ID,
    "fabricId": FID,
    "deviceRoles": ["BORDER_NODE", "CONTROL_PLANE_NODE"],
    "borderDeviceSettings": {"borderTypes": ["LAYER_3"], "layer3Settings": dict(L3)},
}


class Lab:
    def __init__(self, api: respx.MockRouter, me: dict[str, Any]) -> None:
        self.puts: list[Any] = []
        mock_inventory(api)
        api.get(f"{SDA}/fabricSites").respond(json={"response": [{"id": FID}]})
        api.get(f"{SDA}/fabricDevices").respond(json={"response": [me]})
        api.put(f"{SDA}/fabricDevices").mock(side_effect=self.put)
        task_ok(api, "tu")

    def put(self, request: httpx.Request) -> httpx.Response:
        self.puts.append(json.loads(request.content))
        return httpx.Response(202, json={"response": {"taskId": "tu"}})


async def test_priority_prepend_and_l2(api: respx.MockRouter) -> None:
    lab = Lab(api, BORDER)
    args = {"device": "edge-sw1", "border_priority": 2, "prepend_as_count": 3, "layer2_border": True}
    preview, done = await flow("catc_update_fabric_device", args)
    assert set(preview["preview"]["changes"]) == {
        "borderPriority",
        "prependAutonomousSystemCount",
        "borderTypes",
    }
    assert done
    body = lab.puts[0][0]
    # The fixed fields go back exactly as read
    assert body["deviceRoles"] == BORDER["deviceRoles"] and body["id"] == "fd-b" and body["fabricId"] == FID
    assert body["borderDeviceSettings"] == {
        "borderTypes": ["LAYER_2", "LAYER_3"],
        "layer3Settings": {**L3, "borderPriority": 2, "prependAutonomousSystemCount": 3},
    }


async def test_read_back_defaults_outside_the_put_ranges_are_left_out(api: respx.MockRouter) -> None:
    me = {
        **BORDER,
        "borderDeviceSettings": {
            "borderTypes": ["LAYER_3", "LAYER_2"],
            "layer3Settings": {**L3, "borderPriority": 10, "prependAutonomousSystemCount": 0},
        },
    }
    lab = Lab(api, me)
    _, done = await flow("catc_update_fabric_device", {"device": "edge-sw1", "layer2_border": False})
    l3 = lab.puts[0][0]["borderDeviceSettings"]["layer3Settings"]
    assert done and "borderPriority" not in l3 and "prependAutonomousSystemCount" not in l3 and l3 == L3
    assert lab.puts[0][0]["borderDeviceSettings"]["borderTypes"] == ["LAYER_3"]


@pytest.mark.parametrize(
    ("current", "warned"),
    [
        (None, True),  # added without a priority
        (10, True),  # the unset default as Catalyst Center reads it back
        (2, False),  # already set: 1-9 either way
    ],
)
async def test_first_priority_is_one_way(api: respx.MockRouter, current: int | None, warned: bool) -> None:
    """D111: 3.2.2 refuses borderPriority 10 (NCHS20769, live 2026-10-22): the preview says so."""
    l3 = {**L3, **({"borderPriority": current} if current is not None else {})}
    Lab(api, {**BORDER, "borderDeviceSettings": {"borderTypes": ["LAYER_3"], "layer3Settings": l3}})
    preview, _ = await flow("catc_update_fabric_device", {"device": "edge-sw1", "border_priority": 3})
    effects = " ".join(preview["side_effects"])
    assert ("NCHS20769" in effects) is warned and "re-provisions" in effects


async def test_one_way_warning_only_for_priority(api: respx.MockRouter) -> None:
    Lab(api, BORDER)
    preview, _ = await flow("catc_update_fabric_device", {"device": "edge-sw1", "prepend_as_count": 2})
    assert "NCHS20769" not in " ".join(preview["side_effects"])


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"border_priority": None}, "Nothing to change"),
        ({"bgp_router_id": "not-an-ip"}, "not an IPv4 address"),
    ],
)
async def test_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    lab = Lab(api, BORDER)
    out, _ = await flow("catc_update_fabric_device", {"device": "edge-sw1", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.puts


async def test_not_a_border(api: respx.MockRouter) -> None:
    Lab(api, {**BORDER, "deviceRoles": ["EDGE_NODE"], "borderDeviceSettings": None})
    with pytest.raises(ToolError, match="is not a border: on 3.2.2 only"):
        await flow("catc_update_fabric_device", {"device": "edge-sw1", "border_priority": 2})


async def test_not_a_fabric_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(f"{SDA}/fabricSites").respond(json={"response": [{"id": FID}]})
    api.get(f"{SDA}/fabricDevices").respond(json={"response": []})
    with pytest.raises(ToolError, match="is not a fabric device"):
        await flow("catc_update_fabric_device", {"device": "edge-sw1", "border_priority": 2})


def test_removed_parameters() -> None:
    """Roles, AS, default exit and route import are not updatable on 3.2.2: the tool doesn't offer them."""
    import inspect

    from catc_mcp.tools import sda_device_update

    src = inspect.getsource(sda_device_update)
    for name in ("roles:", "border_asn:", "default_exit:", "import_external_routes:"):
        assert name not in src
