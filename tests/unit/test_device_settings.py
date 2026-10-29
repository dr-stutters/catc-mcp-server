"""D84: accept SSH host-key changes, the SSH key policy and the resync interval (respx).

Payloads follow the bundled 3.2.2 spec (AcceptSshKey, SshKeyChangeSettings, resyncIntervalSettings). The
settings and per-device interval answers are the 3.2.2 lab's recorded shapes ({"response": {...},
"version": "1.0"}); the key-mismatch failure text is a stand-in until the live proof records it.
"""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import DEVICE
from .test_safety import mock_inventory
from .test_sda import flow
from .test_write_tools import run, task_ok

V1 = "/dna/intent/api/v1"
KEYED = {
    **DEVICE,
    "id": "33333333-2222-3333-4444-555555555555",
    "hostname": "br-rtr1.example.com",
    "managementIpAddress": "192.0.2.21",
    "reachabilityStatus": "Unreachable",
    "collectionStatus": "Could Not Synchronize",
    "errorCode": "SSH_KEY_VERIFICATION_ERROR",
    "reachabilityFailureReason": "SSH host key verification failed",
    "collectionInterval": "Global Default",
}
HEALTHY = {
    **DEVICE,
    "id": "44444444-2222-3333-4444-555555555555",
    "hostname": "br-sw1.example.com",
    "managementIpAddress": "192.0.2.22",
    "collectionStatus": "Managed",
    "collectionInterval": "Global Default",
}
SNMP_DOWN = {
    **DEVICE,
    "id": "55555555-2222-3333-4444-555555555555",
    "hostname": "br-sw2.example.com",
    "managementIpAddress": "192.0.2.23",
    "reachabilityStatus": "Unreachable",
    "collectionStatus": "Partial Collection Failure",
    "errorCode": "DEV-UNREACHED",
    "reachabilityFailureReason": "SNMP Connectivity Failed",
    "inventoryStatusDetail": '<status><general code="DEV_UNREACHED"/></status>',
    "collectionInterval": "720 Minutes",
}


def settings_route(api: respx.MockRouter, auto: bool) -> None:
    api.get(f"{V1}/networkDeviceSettings/sshKeySettings").respond(
        json={"response": {"autoAcceptSshKeys": auto}, "version": "1.0"}
    )


def interval_route(api: respx.MockRouter, dev: dict[str, Any], minutes: int) -> None:
    api.get(f"{V1}/networkDevices/{dev['id']}/resyncIntervalSettings").respond(
        json={"response": {"interval": minutes}, "version": "1.0"}
    )


def task_reply(task: str) -> httpx.Response:
    return httpx.Response(
        202, json={"response": {"taskId": task, "url": f"{V1}/tasks/{task}"}, "version": "1.0"}
    )


# --- catc_accept_ssh_key --------------------------------------------------------------------------


async def test_accept_refuses_devices_without_a_key_change(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED, HEALTHY, SNMP_DOWN])
    settings_route(api, False)
    post = api.post(f"{V1}/networkDevices/acceptSshKeyChange").mock(return_value=task_reply("tk"))
    out, done = await flow("catc_accept_ssh_key", {"devices": ["192.0.2.21", "192.0.2.22", "192.0.2.23"]})
    assert out["status"] == "blocked" and done is None and post.call_count == 0
    assert len(out["blockers"]) == 2
    assert "br-sw1.example.com (192.0.2.22): not failing on an SSH host-key change" in out["blockers"][0]
    assert "reachable and managed" in out["blockers"][0]
    assert "DEV-UNREACHED; SNMP Connectivity Failed" in out["blockers"][1]


async def test_accept_posts_ids_with_resync_and_follows_the_task(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED, HEALTHY])
    settings_route(api, False)
    post = api.post(f"{V1}/networkDevices/acceptSshKeyChange").mock(return_value=task_reply("tk"))
    task_ok(api, "tk")
    preview, done = await flow("catc_accept_ssh_key", {"devices": ["br-rtr1"]})
    assert preview["status"] == "preview" and post.call_count == 1
    assert preview["action"] == "Accept the new SSH host key of 1 device(s) and resync them"
    rows = preview["preview"]["devices"]
    assert rows == [
        {
            "device": "br-rtr1.example.com (192.0.2.21)",
            "reachability": "Unreachable",
            "collection": "Could Not Synchronize",
            "failure": "SSH_KEY_VERIFICATION_ERROR",
        }
    ]
    assert any("man-in-the-middle" in s for s in preview["side_effects"])
    assert json.loads(post.calls.last.request.content) == {"networkDeviceIds": [KEYED["id"]], "resync": True}
    assert done and done["result"]["task_id"] == "tk" and done["result"]["status"] == "SUCCESS"


async def test_accept_without_resync_and_auto_accept_note(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED])
    settings_route(api, True)
    post = api.post(f"{V1}/networkDevices/acceptSshKeyChange").mock(return_value=task_reply("tk"))
    task_ok(api, "tk")
    preview, done = await flow("catc_accept_ssh_key", {"devices": [KEYED["id"]], "resync": False})
    assert preview["action"] == "Accept the new SSH host key of 1 device(s)"
    assert any("auto-accept is on" in s for s in preview["side_effects"])
    assert done and json.loads(post.calls.last.request.content)["resync"] is False


# --- SSH key settings ------------------------------------------------------------------------------


async def test_get_ssh_key_settings_lists_pending_key_changes(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED, HEALTHY, SNMP_DOWN])
    settings_route(api, False)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_get_ssh_key_settings", {})
    assert out["auto_accept_ssh_keys"] is False
    assert out["devices_with_key_change"] == [
        {
            "hostname": "br-rtr1.example.com",
            "managementIpAddress": "192.0.2.21",
            "id": KEYED["id"],
            "failure": "SSH_KEY_VERIFICATION_ERROR",
        }
    ]


async def test_set_ssh_key_settings_warns_on_auto_accept(api: respx.MockRouter) -> None:
    settings_route(api, False)
    put = api.put(f"{V1}/networkDeviceSettings/sshKeySettings").mock(return_value=task_reply("ts"))
    task_ok(api, "ts")
    preview, done = await flow("catc_set_ssh_key_settings", {"auto_accept": True})
    assert preview["action"] == "Turn on global SSH host key auto-accept"
    assert "Security posture change" in preview["side_effects"][0]
    assert preview["preview"]["before"] == {"autoAcceptSshKeys": False}
    assert done and json.loads(put.calls.last.request.content) == {"autoAcceptSshKeys": True}


async def test_set_ssh_key_settings_noop(api: respx.MockRouter) -> None:
    settings_route(api, False)
    put = api.put(f"{V1}/networkDeviceSettings/sshKeySettings").mock(return_value=task_reply("ts"))
    out, _ = await flow("catc_set_ssh_key_settings", {"auto_accept": False})
    assert out["status"] == "no_change" and put.call_count == 0


# --- resync interval --------------------------------------------------------------------------------


async def test_device_resync_interval(api: respx.MockRouter) -> None:
    mock_inventory(api, [HEALTHY])
    interval_route(api, HEALTHY, 1440)
    put = api.put(f"{V1}/networkDevices/{HEALTHY['id']}/resyncIntervalSettings").mock(
        return_value=task_reply("tr")
    )
    task_ok(api, "tr")
    preview, done = await flow("catc_set_resync_interval", {"device": "br-sw1", "minutes": 360})
    assert preview["action"] == "Set the resync interval of br-sw1.example.com (192.0.2.22) to 360 min"
    assert preview["preview"]["before"] == {"interval": 1440, "collectionInterval": "Global Default"}
    assert done and json.loads(put.calls.last.request.content) == {"interval": 360}
    # Off, and back to the global value (null in the body).
    _, done = await flow("catc_set_resync_interval", {"device": "br-sw1", "minutes": 0})
    assert done and json.loads(put.calls.last.request.content) == {"interval": 0}


async def test_device_resync_interval_reset_and_bounds(api: respx.MockRouter) -> None:
    mock_inventory(api, [HEALTHY, SNMP_DOWN])
    interval_route(api, HEALTHY, 1440)
    interval_route(api, SNMP_DOWN, 720)
    put = api.put(f"{V1}/networkDevices/{SNMP_DOWN['id']}/resyncIntervalSettings").mock(
        return_value=task_reply("tr")
    )
    task_ok(api, "tr")
    out, _ = await flow("catc_set_resync_interval", {"device": "br-sw1", "minutes": None})
    assert out["status"] == "no_change"
    out, _ = await flow("catc_set_resync_interval", {"device": "br-sw1", "minutes": 100})
    assert out["status"] == "blocked" and "360-1440 minutes" in out["blockers"][0]
    preview, done = await flow("catc_set_resync_interval", {"device": "br-sw2"})
    assert preview["action"].endswith("to the global interval")
    assert done and json.loads(put.calls.last.request.content) == {"interval": None}


async def test_global_resync_interval(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED, HEALTHY, SNMP_DOWN])
    interval_route(api, KEYED, 1440)
    put = api.put(f"{V1}/networkDevices/resyncIntervalSettings").mock(return_value=task_reply("tg"))
    override = api.post(f"{V1}/networkDevices/resyncIntervalSettings/override").mock(
        return_value=task_reply("tg")
    )
    task_ok(api, "tg")
    out, _ = await flow("catc_set_resync_interval", {"minutes": 1440})
    assert out["status"] == "no_change"
    out, _ = await flow("catc_set_resync_interval", {})
    assert out["status"] == "blocked" and "Give the global interval" in out["blockers"][0]
    preview, done = await flow("catc_set_resync_interval", {"minutes": 720})
    assert preview["action"] == "Set the global resync interval to 720 min"
    assert preview["blast_radius"] == 2 and preview["preview"]["before"] == {"global_interval": 1440}
    assert preview["preview"]["devices_with_own_interval"] == [
        {"hostname": "br-sw2.example.com", "managementIpAddress": "192.0.2.23", "interval": "720 Minutes"}
    ]
    assert done and json.loads(put.calls.last.request.content) == {"interval": 720}
    assert override.call_count == 0


async def test_global_override_needs_dangerous(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED, SNMP_DOWN])
    interval_route(api, KEYED, 1440)
    put = api.put(f"{V1}/networkDevices/resyncIntervalSettings").mock(return_value=task_reply("tg"))
    override = api.post(f"{V1}/networkDevices/resyncIntervalSettings/override").mock(
        return_value=task_reply("tg")
    )
    task_ok(api, "tg")
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(c, "catc_set_resync_interval", {"minutes": 720, "override_devices": True})
    assert out["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in out["blockers"][0]
    preview, done = await flow("catc_set_resync_interval", {"minutes": 720, "override_devices": True})
    assert (
        preview["action"]
        == "Set the global resync interval to 720 min and reset 1 device(s) to the global interval"
    )
    assert preview["blast_radius"] == 2
    assert done and put.call_count == 1 and override.call_count == 1
    assert override.calls.last.request.content in (b"", b"null")
    assert [s["task_id"] for s in done["result"]["steps"]] == ["tg", "tg"]


# --- hints ------------------------------------------------------------------------------------------


async def test_get_device_hints_at_key_change(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED, HEALTHY])
    for d in (KEYED, HEALTHY):
        api.get(f"{V1}/networkDevices/{d['id']}").respond(
            json={"response": {"id": d["id"]}, "version": "1.0"}
        )
    async with Client(create_server(make_settings())) as c:
        keyed = await run(c, "catc_get_device", {"device": "br-rtr1"})
        healthy = await run(c, "catc_get_device", {"device": "br-sw1"})
    assert keyed["ssh_key_change"]["hint"].startswith("SSH key changed: accept with catc_accept_ssh_key")
    assert "ssh_key_change" not in healthy


async def test_device_360_hints_at_key_change(api: respx.MockRouter) -> None:
    mock_inventory(api, [KEYED])
    did = KEYED["id"]
    for path in (
        f"/dna/data/api/v1/networkDevices/{did}",
        f"{V1}/interface/network-device/{did}",
        f"{V1}/compliance",
        f"{V1}/eox-status/device/{did}",
        f"{V1}/sda/provisionDevices",
    ):
        api.get(path).respond(json={"response": [], "version": "1.0"})
    api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_device_360", {"device": "192.0.2.21"})
    assert out["device"]["ssh_key_change"] == {
        "failure": "SSH_KEY_VERIFICATION_ERROR",
        "hint": "SSH key changed: accept with catc_accept_ssh_key (check the change was expected first)",
    }
