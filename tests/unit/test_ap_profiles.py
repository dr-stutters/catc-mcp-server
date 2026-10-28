"""D127: AP join profiles and AP power profiles (respx, on the live 3.2.2 response shape)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import run, task_ok

AP = "/dna/intent/api/v1/wirelessSettings/apProfiles"
POWER = "/dna/intent/api/v1/wirelessSettings/powerProfiles"
WPROF = "/dna/intent/api/v1/wirelessProfiles"
SECRET = "Sup3rS3cret!x"


def ap_record(name: str, pid: str, **over: Any) -> dict[str, Any]:
    """An AP profile as GET /wirelessSettings/apProfiles returns it (live 3.2.2)."""
    rec: dict[str, Any] = {
        "id": pid,
        "apProfileName": name,
        "description": "Default AP Profile for IOS-XE",
        "remoteWorkerEnabled": False,
        "managementSetting": {
            "authType": "NO-AUTH",
            "dot1xUsername": "",
            "dot1xPassword": "",
            "sshEnabled": False,
            "telnetEnabled": False,
            "managementUserName": None,
            "managementPassword": None,
            "managementEnablePassword": None,
            "cdpState": True,
        },
        "awipsEnabled": False,
        "awipsForensicEnabled": False,
        "rogueDetectionSetting": {
            "rogueDetection": True,
            "rogueDetectionMinRssi": -90,
            "rogueDetectionTransientInterval": 0,
            "rogueDetectionReportInterval": 10,
        },
        "pmfDenialEnabled": False,
        "meshEnabled": False,
        "meshSetting": None,
        "apPowerProfileName": None,
        "calendarPowerProfiles": [],
        "countryCode": "unconfigured",
        "timeZone": "NOT CONFIGURED",
        "timeZoneOffsetHour": 0,
        "timeZoneOffsetMinutes": 0,
        "clientLimit": 0,
    }
    return rec | over


DEFAULTS = [
    ap_record("Default_AP_Profile_AireOS", "ap-aireos", description="Default AP Profile for AireOS"),
    ap_record("default-ap-profile", "ap-default"),
]
POWER_REC = {
    "id": "pp1",
    "profileName": "mcp-power",
    "description": "PoE budget",
    "rules": [
        {
            "sequence": 2,
            "interfaceType": "RADIO",
            "interfaceId": "6GHZ",
            "parameterType": "STATE",
            "parameterValue": "DISABLE",
        },
        {
            "sequence": 1,
            "interfaceType": "ETHERNET",
            "interfaceId": "GIGABITETHERNET1",
            "parameterType": "STATE",
            "parameterValue": "DISABLE",
        },
    ],
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def flow(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


def mock_reads(
    api: respx.MockRouter,
    aps: list[dict[str, Any]] | None = None,
    powers: list[dict[str, Any]] | None = None,
    tags: list[dict[str, Any]] | None = None,
) -> None:
    aps = DEFAULTS if aps is None else aps
    api.get(AP).respond(json={"response": aps, "version": "1.0"})
    api.get(f"{AP}/count").respond(json={"response": {"count": len(aps)}, "version": "1.0"})
    api.get(POWER).respond(json={"response": powers or [], "version": "1.0"})
    api.get(WPROF).respond(json={"response": [{"id": "wp1", "wirelessProfileName": "campus"}]})
    api.get(f"{WPROF}/wp1/siteTags").respond(json={"response": tags or []})


async def test_list_ap_profiles_live_shape(api: respx.MockRouter) -> None:
    mine = ap_record(
        "mcp-ap-profile",
        "ap-mine",
        apPowerProfileName="mcp-power",
        managementSetting={
            **DEFAULTS[1]["managementSetting"],
            "sshEnabled": True,
            "managementUserName": "apadmin",
            "managementPassword": "should-never-show",
        },
    )
    mock_reads(
        api,
        aps=[*DEFAULTS, mine],
        powers=[POWER_REC],
        tags=[{"siteTagName": "mcp-site-tag", "apProfileName": "mcp-ap-profile"}],
    )
    async with Client(server()) as c:
        out = await run(c, "catc_list_ap_profiles", {"response_format": "json"})
    assert out["total"] == 3
    rows = {r["name"]: r for r in out["results"]}
    assert set(rows) == {"Default_AP_Profile_AireOS", "default-ap-profile", "mcp-ap-profile"}
    d = rows["default-ap-profile"]
    assert d["dot1x_supplicant"] == "NO-AUTH" and d["cdp"] is True and d["rogue_min_rssi"] == -90
    assert d["ssh"] is False and d["time_zone"] == "NOT CONFIGURED"
    assert "used_by" not in d  # no site tag uses it
    m = rows["mcp-ap-profile"]
    assert m["used_by"] == ["campus / mcp-site-tag"] and m["mgmt_user"] == "apadmin"
    assert m["mgmt_password"] == "********" and "should-never-show" not in json.dumps(out)
    assert out["power_profiles"][0]["rules"] == [
        "ETHERNET GIGABITETHERNET1 STATE DISABLE",
        "RADIO 6GHZ STATE DISABLE",
    ]
    assert out["power_profiles"][0]["used_by"] == ["mcp-ap-profile"]
    assert "re-provision" in out["note"]


async def test_list_one_profile_by_name(api: respx.MockRouter) -> None:
    mock_reads(api)
    api.get(f"{AP}/ap-default").respond(json={"response": DEFAULTS[1], "version": "1.0"})
    async with Client(server()) as c:
        out = await run(c, "catc_list_ap_profiles", {"name": "default-ap-profile", "usage": False})
        assert out["ap_profile"]["id"] == "ap-default" and "used_by" not in out["ap_profile"]
        with pytest.raises(ToolError, match="No AP profile nope"):
            await run(c, "catc_list_ap_profiles", {"name": "nope"})


async def test_create_ap_profile_masks_secrets(api: respx.MockRouter) -> None:
    mock_reads(api)
    post = api.post(AP).respond(202, json={"response": {"taskId": "t1"}})
    task_ok(api, "t1")
    args = {
        "name": "mcp-ap-profile",
        "ssh": True,
        "mgmt_user": "apadmin",
        "mgmt_password": SECRET,
        "dot1x_supplicant": "EAP-FAST",
        "dot1x_user": "ap-supplicant",
        "dot1x_password": SECRET,
        "rogue_min_rssi": -80,
        "country": "au",
        "time_zone": "controller",
    }
    preview, done = await flow("catc_set_ap_profile", args)
    assert preview["status"] == "preview" and SECRET not in json.dumps(preview)
    body = preview["preview"]["body"]
    assert body["managementSetting"]["managementPassword"] == "********"
    assert body["managementSetting"]["dot1xPassword"] == "********"
    assert body["countryCode"] == "AU" and body["timeZone"] == "Controller"
    assert any("re-provision" in s for s in preview["side_effects"])
    assert any("factory reset" in s for s in preview["side_effects"])
    sent = json.loads(post.calls.last.request.content)
    assert sent["apProfileName"] == "mcp-ap-profile"
    assert sent["managementSetting"] == {
        "sshEnabled": True,
        "managementUserName": "apadmin",
        "authType": "EAP-FAST",
        "dot1xUsername": "ap-supplicant",
        "managementPassword": SECRET,
        "dot1xPassword": SECRET,
    }
    assert sent["rogueDetectionSetting"] == {"rogueDetectionMinRssi": -80}
    assert done and SECRET not in json.dumps(done)


async def test_confirm_bound_to_secret_digest(api: respx.MockRouter) -> None:
    mock_reads(api)
    post = api.post(AP).respond(202, json={"response": {"taskId": "t1"}})
    task_ok(api, "t1")
    args = {"name": "mcp-ap-profile", "mgmt_user": "apadmin", "mgmt_password": SECRET}
    async with Client(server()) as c:
        preview = await run(c, "catc_set_ap_profile", args)
        with pytest.raises(ToolError):
            await run(
                c,
                "catc_set_ap_profile",
                {**args, "mgmt_password": "Another1Secret", "confirm": preview["confirm"]},
            )
    assert post.call_count == 0


async def test_create_needs_supplicant_credentials(api: respx.MockRouter) -> None:
    mock_reads(api)
    out, _ = await flow("catc_set_ap_profile", {"name": "mcp-ap-profile", "dot1x_supplicant": "EAP-PEAP"})
    assert out["status"] == "blocked"
    assert any("dot1x_user" in b for b in out["blockers"])
    assert any("dot1x_password" in b for b in out["blockers"])
    out, _ = await flow("catc_set_ap_profile", {"name": "mcp-ap-profile", "power_profile": "nope"})
    assert out["status"] == "blocked" and "No AP power profile nope" in out["blockers"][0]


async def test_input_rules(api: respx.MockRouter) -> None:
    mock_reads(api)
    with pytest.raises(ToolError, match="8-120"):
        await flow("catc_set_ap_profile", {"name": "x", "mgmt_password": "short"})
    with pytest.raises(ToolError, match="upper case"):
        await flow("catc_set_ap_profile", {"name": "x", "mgmt_enable_password": "alllowercase1"})
    with pytest.raises(ToolError, match="country code QQ"):
        await flow("catc_set_ap_profile", {"name": "x", "country": "QQ"})
    with pytest.raises(ToolError, match="delta"):
        await flow("catc_set_ap_profile", {"name": "x", "time_zone_offset_hour": 2})
    with pytest.raises(ToolError, match="Nothing to set"):
        await flow("catc_set_ap_profile", {"name": "x"})


async def test_update_ap_profile_keeps_record(api: respx.MockRouter) -> None:
    mine = ap_record("mcp-ap-profile", "ap-mine", description="lab", countryCode="AU")
    mock_reads(api, aps=[*DEFAULTS, mine], tags=[{"siteTagName": "st1", "apProfileName": "mcp-ap-profile"}])
    put = api.put(f"{AP}/ap-mine").respond(202, json={"response": {"taskId": "t2"}})
    task_ok(api, "t2")
    preview, done = await flow(
        "catc_set_ap_profile",
        {"name": "mcp-ap-profile", "cdp": False, "time_zone": "delta", "time_zone_offset_hour": -5},
    )
    assert preview["status"] == "preview"
    changes = preview["preview"]["changes"]
    assert changes["managementSetting.cdpState"] == {"from": True, "to": False}
    assert changes["timeZone"] == {"from": "Not Configured", "to": "Delta from Controller"}
    assert "description" not in changes
    assert any("st1" in s for s in preview["side_effects"])
    sent = json.loads(put.calls.last.request.content)
    assert "id" not in sent and sent["description"] == "lab" and sent["countryCode"] == "AU"
    assert sent["managementSetting"]["cdpState"] is False
    assert "dot1xPassword" not in sent["managementSetting"]  # write-only: never echoed back empty
    assert "managementPassword" not in sent["managementSetting"]
    assert sent["timeZone"] == "Delta from Controller" and sent["timeZoneOffsetHour"] == -5
    assert "meshSetting" not in sent and sent["rogueDetectionSetting"]["rogueDetectionMinRssi"] == -90
    assert done and done["status"] != "preview"


async def test_update_unconfigured_country_left_out(api: respx.MockRouter) -> None:
    mock_reads(api)
    put = api.put(f"{AP}/ap-default").respond(202, json={"response": {"taskId": "t3"}})
    task_ok(api, "t3")
    await flow("catc_set_ap_profile", {"name": "default-ap-profile", "rogue_min_rssi": -85})
    sent = json.loads(put.calls.last.request.content)
    assert "countryCode" not in sent and sent["timeZone"] == "Not Configured"
    assert sent["rogueDetectionSetting"]["rogueDetectionMinRssi"] == -85


async def test_update_no_change_blocked(api: respx.MockRouter) -> None:
    mock_reads(api)
    out, _ = await flow("catc_set_ap_profile", {"name": "default-ap-profile", "cdp": True})
    assert out["status"] == "blocked" and "already has these settings" in out["blockers"][0]


async def test_delete_ap_profile(api: respx.MockRouter) -> None:
    mine = ap_record("mcp-ap-profile", "ap-mine")
    mock_reads(api, aps=[*DEFAULTS, mine])
    delete = api.delete(f"{AP}/ap-mine").respond(202, json={"response": {"taskId": "t4"}})
    task_ok(api, "t4")
    preview, done = await flow("catc_set_ap_profile", {"name": "mcp-ap-profile", "delete": True})
    assert preview["status"] == "preview" and preview["preview"]["method"] == "DELETE"
    assert delete.call_count == 1 and done


async def test_delete_refused_for_default_and_in_use(api: respx.MockRouter) -> None:
    mine = ap_record("mcp-ap-profile", "ap-mine")
    mock_reads(api, aps=[*DEFAULTS, mine], tags=[{"siteTagName": "st1", "apProfileName": "mcp-ap-profile"}])
    out, _ = await flow("catc_set_ap_profile", {"name": "default-ap-profile", "delete": True})
    assert out["status"] == "blocked" and "default AP profile" in out["blockers"][0]
    out, _ = await flow("catc_set_ap_profile", {"name": "mcp-ap-profile", "delete": True})
    assert out["status"] == "blocked" and "campus / st1" in out["blockers"][0]
    with pytest.raises(ToolError, match="no other settings"):
        await flow("catc_set_ap_profile", {"name": "mcp-ap-profile", "delete": True, "cdp": True})


RULES = [
    {"interface_type": "ETHERNET", "interface_id": "GIGABITETHERNET1", "parameter_type": "STATE",
     "parameter_value": "DISABLE"},
    {"interface_type": "RADIO", "interface_id": "6GHZ", "parameter_type": "SPATIALSTREAM",
     "parameter_value": "TWO_BY_TWO"},
]  # fmt: skip


async def test_create_power_profile(api: respx.MockRouter) -> None:
    mock_reads(api)
    post = api.post(POWER).respond(
        202,
        json={"response": {"taskId": "t5", "url": "/api/v1/task/t5"}, "version": "1.0"},
    )
    task_ok(api, "t5")
    preview, done = await flow("catc_set_ap_power_profile", {"name": "mcp-power", "rules": RULES})
    assert preview["status"] == "preview"
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "profileName": "mcp-power",
        "rules": [
            {
                "interfaceType": "ETHERNET",
                "interfaceId": "GIGABITETHERNET1",
                "parameterType": "STATE",
                "parameterValue": "DISABLE",
            },
            {
                "interfaceType": "RADIO",
                "interfaceId": "6GHZ",
                "parameterType": "SPATIALSTREAM",
                "parameterValue": "TWO_BY_TWO",
            },
        ],
    }
    assert done


async def test_power_rule_combinations_checked(api: respx.MockRouter) -> None:
    mock_reads(api)
    bad = [{**RULES[0], "interface_id": "6GHZ"}]
    with pytest.raises(ToolError, match="not a ETHERNET interface"):
        await flow("catc_set_ap_power_profile", {"name": "p", "rules": bad})
    bad = [{**RULES[1], "parameter_type": "SPEED", "parameter_value": "1000MBPS"}]
    with pytest.raises(ToolError, match="takes no SPEED"):
        await flow("catc_set_ap_power_profile", {"name": "p", "rules": bad})
    with pytest.raises(ToolError, match="at least one rule"):
        await flow("catc_set_ap_power_profile", {"name": "p"})


async def test_update_power_profile_keeps_rules(api: respx.MockRouter) -> None:
    user = ap_record("mcp-ap-profile", "ap-mine", apPowerProfileName="mcp-power")
    mock_reads(api, aps=[*DEFAULTS, user], powers=[POWER_REC])
    put = api.put(f"{POWER}/pp1").respond(202, json={"response": {"taskId": "t6"}})
    task_ok(api, "t6")
    preview, _ = await flow("catc_set_ap_power_profile", {"name": "mcp-power", "description": "new"})
    assert preview["preview"]["used_by_ap_profiles"] == ["mcp-ap-profile"]
    sent = json.loads(put.calls.last.request.content)
    assert sent["description"] == "new"
    assert [r["interfaceID"] for r in sent["rules"]] == ["GIGABITETHERNET1", "6GHZ"]  # in sequence order


async def test_delete_power_profile_in_use_refused(api: respx.MockRouter) -> None:
    user = ap_record(
        "mcp-ap-profile",
        "ap-mine",
        calendarPowerProfiles=[{"apPowerProfileName": "mcp-power", "calendarProfileName": "night"}],
    )
    mock_reads(api, aps=[*DEFAULTS, user], powers=[POWER_REC])
    out, _ = await flow("catc_set_ap_power_profile", {"name": "mcp-power", "delete": True})
    assert out["status"] == "blocked" and "mcp-ap-profile" in out["blockers"][0]


async def test_delete_power_profile(api: respx.MockRouter) -> None:
    mock_reads(api, powers=[POWER_REC])
    delete = api.delete(f"{POWER}/pp1").respond(202, json={"response": {"taskId": "t7"}})
    task_ok(api, "t7")
    preview, done = await flow("catc_set_ap_power_profile", {"name": "mcp-power", "delete": True})
    assert preview["status"] == "preview" and delete.call_count == 1 and done


async def test_site_tag_read_failure_is_not_unused(api: respx.MockRouter) -> None:
    mine = ap_record("mcp-ap-profile", "ap-mine")
    mock_reads(api, aps=[*DEFAULTS, mine])
    api.get(f"{WPROF}/wp1/siteTags").mock(return_value=httpx.Response(500, json={"error": "boom"}))
    delete = api.delete(f"{AP}/ap-mine")
    with pytest.raises(ToolError):
        await flow("catc_set_ap_profile", {"name": "mcp-ap-profile", "delete": True})
    assert delete.call_count == 0


async def test_list_pages_and_markdown(api: respx.MockRouter) -> None:
    mock_reads(api)
    async with Client(server()) as c:
        out = await run(c, "catc_list_ap_profiles", {"limit": 1, "offset": 1, "response_format": "json"})
        assert out["total"] == 2 and [r["name"] for r in out["results"]] == ["default-ap-profile"]
        md = await c.call_tool("catc_list_ap_profiles", {})
        assert "Default_AP_Profile_AireOS" in md.content[0].text  # type: ignore[union-attr]
