"""D90: SD-Access authentication templates (respx); payloads follow the 3.2.2 spec."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp._core.testing import call_tool

from .test_read_tools import AREA, BLDG, GLOBAL
from .test_sda import FID, flow, server
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"


def profile(name: str, **kw: Any) -> dict[str, Any]:
    base = {
        "id": f"prof-{name.split()[0].lower()}",
        "fabricId": FID,
        "authenticationProfileName": name,
        "authenticationOrder": "dot1x",
        "dot1xToMabFallbackTimeout": 21,
        "wakeOnLan": False,
        "numberOfHosts": "Unlimited",
        "isVoiceVlanEnabled": False,
    }
    if name == "Closed Authentication":
        base["isBpduGuardEnabled"] = True
    if name == "Low Impact":
        base["preAuthAcl"] = {
            "enabled": True,
            "implicitAction": "DENY",
            "description": "Low Impact pre-auth ACL",
            "accessContracts": [{"action": "PERMIT", "protocol": "UDP", "port": "BOOTPS"}],
        }
    return {**base, **kw}


class Fabric:
    """A fabric site whose default template and profiles change when PUT, like the appliance."""

    def __init__(self, api: respx.MockRouter, default: str = "Closed Authentication") -> None:
        self.site = {
            "id": FID,
            "siteId": BLDG["id"],
            "authenticationProfileName": default,
            "isPubSubEnabled": True,
        }
        self.profiles = [
            profile("Closed Authentication"),
            profile("Open Authentication"),
            profile("Low Impact"),
        ]
        self.puts: list[tuple[str, Any]] = []
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": [self.site]})
        )
        api.get(f"{SDA}/authenticationProfiles").mock(side_effect=self.get_profiles)
        api.get(f"{SDA}/fabricDevices").respond(
            json={
                "response": [
                    {
                        "id": "fd1",
                        "networkDeviceId": "d1",
                        "fabricId": FID,
                        "deviceRoles": ["CONTROL_PLANE_NODE"],
                    },
                    {"id": "fd2", "networkDeviceId": "d2", "fabricId": FID, "deviceRoles": ["EDGE_NODE"]},
                    {"id": "fd3", "networkDeviceId": "d3", "fabricId": FID, "deviceRoles": ["EDGE_NODE"]},
                ]
            }
        )
        api.get(f"{SDA}/portAssignments").respond(
            json={
                "response": [
                    {
                        "interfaceName": "Gi1/0/3",
                        "networkDeviceId": "d2",
                        "connectedDeviceType": "USER_DEVICE",
                    },
                    {
                        "interfaceName": "Gi1/0/4",
                        "networkDeviceId": "d2",
                        "connectedDeviceType": "USER_DEVICE",
                        "authenticateTemplateName": "Open Authentication",
                    },
                    {
                        "interfaceName": "Gi1/0/9",
                        "networkDeviceId": "d3",
                        "connectedDeviceType": "ACCESS_POINT",
                    },
                ]
            }
        )
        # the preview names the edges ('hostname (IP)'); d2/d3 aren't in the inventory, so they stay ids
        api.get("/dna/intent/api/v1/network-device").respond(
            json={"response": [{"id": "d2", "hostname": "edge-a", "managementIpAddress": "10.0.0.2"}]}
        )
        api.put(f"{SDA}/fabricSites").mock(side_effect=self.put_site)
        api.put(f"{SDA}/authenticationProfiles").mock(side_effect=self.put_profile)
        task_ok(api, "ta")

    def get_profiles(self, request: httpx.Request) -> httpx.Response:
        if request.url.params.get("isGlobalAuthenticationProfile") == "true":
            return httpx.Response(200, json={"response": [{**profile("Closed Authentication"), "id": "g1"}]})
        return httpx.Response(200, json={"response": self.profiles})

    def put_site(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.puts.append(("fabricSites", body))
        self.site = {**self.site, **body[0]}
        return httpx.Response(202, json={"response": {"taskId": "ta"}})

    def put_profile(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.puts.append(("authenticationProfiles", body))
        self.profiles = [body[0] if p["id"] == body[0]["id"] else p for p in self.profiles]
        return httpx.Response(202, json={"response": {"taskId": "ta"}})


async def test_get_profile(api: respx.MockRouter) -> None:
    Fabric(api)
    out = await call_tool(
        server(),
        "catc_get_fabric_authentication_profile",
        {"fabric_site": "Global/AU/SYD-1", "include_global": True},
    )
    assert out["default_template"] == "Closed Authentication" and out["edges"] == 2
    assert out["ports_on_default"] == 1  # the AP port doesn't count
    assert out["ports_overriding"] == [
        {"networkDeviceId": "d2", "interface": "Gi1/0/4", "template": "Open Authentication"}
    ]
    assert [p["authenticationProfileName"] for p in out["profiles"]][2] == "Low Impact"
    assert out["global_profiles"][0]["id"] == "g1"


async def test_change_default_template(api: respx.MockRouter) -> None:
    fab = Fabric(api)
    preview, done = await flow(
        "catc_set_fabric_authentication_profile", {"fabric_site": FID, "template": "Low Impact"}
    )
    assert preview["status"] == "preview" and preview["blast_radius"] == 2
    assert preview["action"].endswith("default template Closed Authentication -> Low Impact")
    assert preview["preview"]["ports_following_the_default"] == 1
    assert preview["preview"]["edges"] == ["edge-a (10.0.0.2)", "d3"]  # names, live finding 2026-10-22
    assert done and done["status"] == "applied"
    assert fab.puts == [
        (
            "fabricSites",
            [
                {
                    "id": FID,
                    "siteId": BLDG["id"],
                    "authenticationProfileName": "Low Impact",
                    "isPubSubEnabled": True,
                }
            ],
        )
    ]
    assert done["result"]["default_template"] == "Low Impact"


async def test_edit_settings_keeps_the_rest(api: respx.MockRouter) -> None:
    fab = Fabric(api)
    args = {
        "fabric_site": "Global/AU/SYD-1",
        "template": "Closed Authentication",
        "dot1x_to_mab_fallback_s": 10,
        "authentication_order": "mac",
    }
    preview, done = await flow("catc_set_fabric_authentication_profile", args)
    diff = preview["preview"]["changes"]["Closed Authentication profile"]
    assert diff == {
        "dot1xToMabFallbackTimeout": {"from": 21, "to": 10},
        "authenticationOrder": {"from": "dot1x", "to": "mac"},
    }
    assert done and [p[0] for p in fab.puts] == ["authenticationProfiles"]  # already the default
    body = fab.puts[0][1][0]
    assert body["id"] == "prof-closed" and body["fabricId"] == FID
    assert (
        body["isBpduGuardEnabled"] is True
        and body["wakeOnLan"] is False
        and body["numberOfHosts"] == "Unlimited"
    )
    assert "preAuthAcl" not in body
    assert done["result"]["profile"]["dot1xToMabFallbackTimeout"] == 10


async def test_low_impact_acl_and_default_in_one_go(api: respx.MockRouter) -> None:
    fab = Fabric(api)
    args = {
        "fabric_site": FID,
        "template": "Low Impact",
        "pre_auth_acl_rules": [
            {"action": "PERMIT", "protocol": "UDP", "port": "BOOTPS"},
            {"action": "PERMIT", "protocol": "TCP_UDP", "port": "DOMAIN"},
        ],
    }
    preview, done = await flow("catc_set_fabric_authentication_profile", args)
    assert len(preview["preview"]["requests"]) == 2
    assert done and [p[0] for p in fab.puts] == ["fabricSites", "authenticationProfiles"]
    acl = fab.puts[1][1][0]["preAuthAcl"]
    assert acl["implicitAction"] == "DENY" and acl["enabled"] is True and len(acl["accessContracts"]) == 2
    assert "isBpduGuardEnabled" not in fab.puts[1][1][0]


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"template": "Open Authentication", "bpdu_guard": True}, "Closed Authentication only"),
        ({"template": "Closed Authentication", "pre_auth_acl_enabled": False}, "Low Impact only"),
        ({"template": "No Authentication", "wake_on_lan": True}, "no profile settings"),
        ({"template": "Closed Authentication"}, "Nothing to change"),
        ({"template": "Closed Authentication", "dot1x_to_mab_fallback_s": 21}, "Nothing to change"),
    ],
)
async def test_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    fab = Fabric(api)
    out, _ = await flow("catc_set_fabric_authentication_profile", {"fabric_site": FID, **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not fab.puts


async def test_failed_put_is_reported(api: respx.MockRouter) -> None:
    Fabric(api)
    api.put(f"{SDA}/fabricSites").respond(202, json={"response": {"taskId": "tbad"}})
    api.get("/dna/intent/api/v1/task/tbad").respond(
        json={
            "response": {
                "isError": True,
                "endTime": 1,
                "failureReason": "NCSP10010: edge provisioning failed",
            }
        }
    )
    with pytest.raises(ToolError, match="Failed at 'default template'"):
        await flow(
            "catc_set_fabric_authentication_profile", {"fabric_site": FID, "template": "Open Authentication"}
        )
