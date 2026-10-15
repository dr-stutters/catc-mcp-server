"""D11: PnP claim/reset/delete and RMA tools (respx-mocked): payloads, blockers, previews."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from catc_mcp.server import create_server
from catc_mcp.tools import pnp

from .conftest import make_settings
from .test_read_tools import BLDG, DEV_ID, DEVICE, GLOBAL
from .test_write_tools import mock_sites, run, task_ok

PNP_ID = "6a0b1c2d3e4f5a6b7c8d9e0f"
TPL_ID = "11111111-2222-3333-4444-555555555555"
PNP_DEV = {
    "id": PNP_ID,
    "deviceInfo": {
        "serialNumber": "96KJVQ53WGV",
        "pid": "C8000V",
        "state": "Unclaimed",
        "onbState": "Connecting",
    },
}
TEMPLATE = {
    "templateId": TPL_ID,
    "name": "mcp-test-day0",
    "projectName": "Onboarding Configuration",
    "versionsInfo": [{"version": "1"}],
}


def rw() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


def mock_pnp(api: respx.MockRouter, dev: dict[str, Any]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        sn = request.url.params.get("serialNumber")
        hit = [dev] if sn in (None, dev["deviceInfo"]["serialNumber"]) else []
        return httpx.Response(200, json=hit)

    api.get("/dna/intent/api/v1/onboarding/pnp-device").mock(side_effect=handler)
    api.get(f"/dna/intent/api/v1/onboarding/pnp-device/{PNP_ID}").respond(json=dev)


def mock_template(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[TEMPLATE])
    api.get(f"/dna/intent/api/v1/template-programmer/template/{TPL_ID}").respond(
        json={
            "id": TPL_ID,
            "templateContent": "hostname {{ hostname }}\n",
            "templateParams": [{"parameterName": "hostname"}],
            "versionsInfo": [{"version": "1"}],
        }
    )


async def test_claim_body_and_missing_variable_blocker(api: respx.MockRouter) -> None:
    mock_pnp(api, PNP_DEV)
    mock_sites(api, [GLOBAL, BLDG])
    mock_template(api)
    claim = api.post("/dna/intent/api/v1/onboarding/pnp-device/site-claim").respond(
        json={"response": "Device Claimed"}
    )
    base = {"device": "96KJVQ53WGV", "site": BLDG["nameHierarchy"], "template": TPL_ID, "wait": False}
    async with Client(rw()) as c:
        blocked = await run(c, "catc_claim_pnp_device", base)
        assert blocked["status"] == "blocked" and "hostname" in json.dumps(blocked["blockers"])
        args = {**base, "params": {"hostname": "br1"}}
        preview = await run(c, "catc_claim_pnp_device", args)
        assert preview["status"] == "preview" and "hostname {{ hostname }}" in json.dumps(preview)
        await run(c, "catc_claim_pnp_device", {**args, "confirm": preview["confirm"]})
    sent = json.loads(claim.calls.last.request.content)
    assert sent == {
        "deviceId": PNP_ID,
        "siteId": BLDG["id"],
        "type": "Default",
        "imageInfo": {"imageId": "", "skip": True},
        "configInfo": {"configId": TPL_ID, "configParameters": [{"key": "hostname", "value": "br1"}]},
    }


async def test_claim_blocks_claimed_device_and_area(api: respx.MockRouter) -> None:
    dev = {**PNP_DEV, "deviceInfo": {**PNP_DEV["deviceInfo"], "state": "Error"}}
    mock_pnp(api, dev)
    mock_sites(api, [GLOBAL])
    async with Client(rw()) as c:
        out = await run(c, "catc_claim_pnp_device", {"device": "96KJVQ53WGV", "site": "Global"})
    text = json.dumps(out["blockers"])
    assert "catc_reset_pnp_device" in text and "building or floor" in text


async def test_reset_and_delete_pnp(api: respx.MockRouter) -> None:
    dev = {**PNP_DEV, "deviceInfo": {**PNP_DEV["deviceInfo"], "state": "Error"}}
    mock_pnp(api, dev)
    reset = api.post("/dna/intent/api/v1/onboarding/pnp-device/reset").respond(json={"ok": True})
    delete = api.delete(f"/dna/intent/api/v1/onboarding/pnp-device/{PNP_ID}").respond(json=dev)
    async with Client(rw()) as c:
        p = await run(c, "catc_reset_pnp_device", {"device": "96KJVQ53WGV"})
        await run(c, "catc_reset_pnp_device", {"device": "96KJVQ53WGV", "confirm": p["confirm"]})
        p = await run(c, "catc_delete_pnp_device", {"device": PNP_ID})
        await run(c, "catc_delete_pnp_device", {"device": PNP_ID, "confirm": p["confirm"]})
    assert json.loads(reset.calls.last.request.content) == {"deviceResetList": [{"deviceId": PNP_ID}]}
    assert delete.call_count == 1


def mock_rma(api: respx.MockRouter, recs: list[dict[str, Any]], reachable: str = "Unreachable") -> None:
    dev = {**DEVICE, "reachabilityStatus": reachable}
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": [dev]})
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": dev})
    api.get("/dna/intent/api/v1/networkDeviceReplacements").respond(json={"response": recs})
    api.get("/dna/intent/api/v1/images").respond(
        json={"response": [{"id": "img1", "version": "17.09.04.0.123"}]}
    )
    api.get("/dna/intent/api/v1/networkDeviceConfigFiles").respond(
        json={"response": [{"id": "f1", "createdTime": 2, "fileType": "RUNNINGCONFIG"}]}
    )


async def test_mark_for_replacement(api: respx.MockRouter) -> None:
    mock_rma(api, [])
    post = api.post("/dna/intent/api/v1/device-replacement").respond(json={"response": {"taskId": "t1"}})
    task_ok(api, "t1")
    async with Client(rw()) as c:
        p = await run(c, "catc_mark_device_for_replacement", {"device": DEV_ID})
        assert p["status"] == "preview" and p["preview"]["config_archive"]["id"] == "f1"
        await run(c, "catc_mark_device_for_replacement", {"device": DEV_ID, "confirm": p["confirm"]})
    assert json.loads(post.calls.last.request.content) == [
        {"faultyDeviceId": DEV_ID, "replacementStatus": "MARKED-FOR-REPLACEMENT"}
    ]


async def test_mark_blocks_reachable_device(api: respx.MockRouter) -> None:
    mock_rma(api, [], reachable="Reachable")
    async with Client(rw()) as c:
        p = await run(c, "catc_mark_device_for_replacement", {"device": DEV_ID})
    assert p["status"] == "blocked" and "Reachable" in json.dumps(p["blockers"])


async def test_replace_device_payload_and_pid_check(api: respx.MockRouter) -> None:
    rec = {
        "id": "r1",
        "faultyDeviceSerialNumber": "FOC1234X0AB",
        "replacementStatus": "MARKED_FOR_REPLACEMENT",
    }
    mock_rma(api, [rec])
    mock_pnp(api, PNP_DEV)
    deploy = api.post("/dna/intent/api/v1/networkDeviceReplacements/workflow/deploy").respond(
        json={"response": {"taskId": "t2"}}
    )
    task_ok(api, "t2")
    async with Client(rw()) as c:
        p = await run(c, "catc_replace_device", {"faulty": DEV_ID, "replacement_serial": "96KJVQ53WGV"})
        # mock device lookup is a C9300 switch, the PnP device a C8000V
        assert p["status"] == "blocked" and "PID differs" in json.dumps(p["blockers"])
    deploy.calls.reset()


async def test_list_device_replacements(api: respx.MockRouter) -> None:
    rec = {"id": "r1", "faultyDeviceName": "r2", "replacementStatus": "REPLACED", "secret": "x"}
    api.get("/dna/intent/api/v1/networkDeviceReplacements").respond(json={"response": [rec]})
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_device_replacements", {"response_format": "json"})
    assert out["results"] == [{"id": "r1", "faultyDeviceName": "r2", "replacementStatus": "REPLACED"}]


async def test_mark_blocks_when_image_not_imported(api: respx.MockRouter) -> None:
    mock_rma(api, [])
    api.get("/dna/intent/api/v1/images").respond(json={"response": []})
    async with Client(rw()) as c:
        p = await run(c, "catc_mark_device_for_replacement", {"device": DEV_ID})
    assert p["status"] == "blocked" and "NCRM11042" in json.dumps(p["blockers"])


async def test_claim_masks_secret_params_and_survives_contact_updates(api: respx.MockRouter) -> None:
    contacts = iter(range(100))

    def pnp(request: httpx.Request) -> httpx.Response:
        dev = {**PNP_DEV, "deviceInfo": {**PNP_DEV["deviceInfo"], "lastContact": next(contacts)}}
        return httpx.Response(200, json=[dev] if "serialNumber" in request.url.params else dev)

    api.get("/dna/intent/api/v1/onboarding/pnp-device").mock(side_effect=pnp)
    mock_sites(api, [GLOBAL, BLDG])
    mock_template(api)
    claim = api.post("/dna/intent/api/v1/onboarding/pnp-device/site-claim").respond(json={"response": "ok"})
    args = {
        "device": "96KJVQ53WGV",
        "site": BLDG["nameHierarchy"],
        "template": TPL_ID,
        "params": {"hostname": "br1", "cli_password": "Pa55w0rd!", "snmp_ro": "comm-ro"},
        "wait": False,
    }
    async with Client(rw()) as c:
        preview = await run(c, "catc_claim_pnp_device", args)
        text = json.dumps(preview)
        assert "Pa55w0rd!" not in text and "comm-ro" not in text and "br1" in text
        done = await run(c, "catc_claim_pnp_device", {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied" and "Pa55w0rd!" not in json.dumps(done)
    sent = json.loads(claim.calls.last.request.content)
    assert {"key": "cli_password", "value": "Pa55w0rd!"} in sent["configInfo"]["configParameters"]


async def test_replace_sends_resolved_serial_and_ignores_stale_error(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pnp, "RMA_POLL_SECONDS", 0.01)
    dev = {**DEVICE, "reachabilityStatus": "Unreachable", "platformId": "C8000V", "family": "Routers"}
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": [dev]})
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": dev})
    api.get("/dna/intent/api/v1/networkDeviceConfigFiles").respond(json={"response": []})
    mock_pnp(api, PNP_DEV)
    stale = {
        "id": "r1",
        "faultyDeviceSerialNumber": "FOC1234X0AB",
        "replacementStatus": "ERROR",
        "replacementTime": 1,
    }
    done_rec = {**stale, "replacementStatus": "REPLACED", "replacementTime": 2}
    states = [[stale], [stale], [stale], [done_rec]]

    def recs(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": states.pop(0) if len(states) > 1 else states[0]})

    api.get("/dna/intent/api/v1/networkDeviceReplacements").mock(side_effect=recs)
    deploy = api.post("/dna/intent/api/v1/networkDeviceReplacements/workflow/deploy").respond(
        json={"response": {"taskId": "t3"}}
    )
    task_ok(api, "t3")
    server = create_server(
        make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, mcp_task_timeout=60)
    )
    async with Client(server) as c:
        p = await run(
            c, "catc_replace_device", {"faulty": DEV_ID, "replacement_serial": PNP_ID, "wait": True}
        )
        assert p["status"] == "preview", p
        states[:] = [[stale], [stale], [done_rec]]
        done = await run(
            c,
            "catc_replace_device",
            {"faulty": DEV_ID, "replacement_serial": PNP_ID, "wait": True, "confirm": p["confirm"]},
        )
    sent = json.loads(deploy.calls.last.request.content)
    assert sent == {
        "type": "ROUTER",
        "faultyDeviceSerialNumber": "FOC1234X0AB",
        "replacementDeviceSerialNumber": "96KJVQ53WGV",
    }
    assert done["result"]["replacement"][0]["replacementStatus"] == "REPLACED"
