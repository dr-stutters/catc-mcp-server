"""D125: wired per-device intended configuration (respx; payloads shaped like the bundled 3.2.2 spec)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools.wired_config import diff_feature, item_key, mask, unwrap_items

from .conftest import make_settings
from .test_read_tools import DEV_ID, DEVICE
from .test_write_tools import run, task_ok

WIRED = f"/dna/intent/api/v1/wired/networkDevices/{DEV_ID}/configFeatures"
MODELS = f"{WIRED}/intended/configurationModels"
PID = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
DEPLOY_TASK = "cccccccc-1111-2222-3333-dddddddddddd"
PDC_OFF = {
    "response": {
        "errorCode": "NCCO15475",
        "message": "Bad Request.",
        "detail": "Per Device Configuration (PDC) must be enabled on the device.",
    },
    "version": "1.0",
}


def vlan(vid: int, name: str, **kw: Any) -> dict[str, Any]:
    return {"configType": "VLAN", "vlanId": vid, "name": name, "isVlanEnabled": True, **kw}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    async with Client(server()) as c:
        out: dict[str, Any] = await run(c, name, args)
    return out


async def flow(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


def mock_switch(api: respx.MockRouter, features: tuple[str, ...] = ("vlanConfig", "stpGlobalConfig")) -> None:
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": DEVICE})
    api.get(f"{WIRED}/supported/layer2").respond(
        json={"response": [{"name": f} for f in features], "version": "1.0"}
    )


def mock_feature(api: respx.MockRouter, state: str, feature: str, items: list[dict[str, Any]]) -> respx.Route:
    # The spec's shape: {"<feature>": {"items": [...]}} (no response envelope)
    return api.get(f"{WIRED}/{state}/layer2/{feature}").respond(json={feature: {"items": items}})


def mock_empty(api: respx.MockRouter) -> respx.Route:
    """Every other feature/state answers with no items (registered last: specific routes win)."""
    return api.get(url__regex=rf".*{WIRED}/(intended|deployed)/layer2/[A-Za-z]+$").respond(
        json={"response": {}, "version": "1.0"}
    )


# --- helpers ------------------------------------------------------------------------------------


def test_unwrap_items_shapes() -> None:
    items = [vlan(10, "users")]
    assert unwrap_items({"vlanConfig": {"items": items}}, "vlanConfig") == items
    assert unwrap_items({"response": {"vlanConfig": {"items": items}}}, "vlanConfig") == items
    assert unwrap_items({"response": {"features": {"vlanConfig": {"items": items}}}}, "vlanconfig") == items
    assert unwrap_items({"response": {"items": items}}, "vlanConfig") == items
    assert unwrap_items({"response": items}, "vlanConfig") == items
    assert unwrap_items({"response": {}}, "vlanConfig") == []


def test_item_keys_and_diff() -> None:
    assert item_key("vlanConfig", vlan(10, "a")) == "10"
    assert item_key("switchportInterfaceConfig", {"interfaceName": "GigabitEthernet1/0/1"}) == (
        "GigabitEthernet1/0/1"
    )
    assert item_key("stpGlobalConfig", {"stpMode": "RSTP"}) == "global"
    d = diff_feature(
        "vlanConfig",
        [vlan(10, "users"), vlan(999, "mcp-999")],
        [vlan(10, "VLAN0010"), vlan(20, "voice")],
    )
    assert d["only_intended"] == ["999"] and d["only_deployed"] == ["20"]
    assert d["changed"] == {"10": {"name": {"intended": "users", "deployed": "VLAN0010"}}}
    # nested {configType, items} lists compare regardless of order
    a = {"configType": "STP_GLOBAL", "stpInstances": {"items": [{"vlanId": 1}, {"vlanId": 2}]}}
    b = {"configType": "STP_GLOBAL", "stpInstances": {"items": [{"vlanId": 2}, {"vlanId": 1}]}}
    assert diff_feature("stpGlobalConfig", [a], [b]) == {"in_sync": 1}


def test_mask_hides_url_password() -> None:
    rec = {"databaseAgent": {"agentUrl": "ftp://user:Secr3t@192.0.2.10/snoop.db"}}
    assert "Secr3t" not in json.dumps(mask(rec)) and "ftp://user:" in json.dumps(mask(rec))


# --- read ---------------------------------------------------------------------------------------


async def test_pdc_off_is_explained(api: respx.MockRouter) -> None:
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": DEVICE})
    api.get(f"{WIRED}/supported/layer2").respond(400, json=PDC_OFF)
    out = await call("catc_get_wired_config", {"device": DEV_ID})
    assert out["per_device_configuration"] == "not enabled"
    assert "NCCO15475" in out["catc_says"] and "enable PDC in Inventory first" in out["note"]
    with pytest.raises(ToolError, match="enable PDC in Inventory first"):
        await call(
            "catc_set_wired_feature", {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 9}]}
        )
    preview = await call("catc_deploy_wired_config", {"device": DEV_ID})
    assert preview["status"] == "blocked" or preview.get("blockers")
    assert "PDC" in json.dumps(preview)


async def test_summary_counts_and_keys(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(999, "mcp-999"), vlan(10, "users")])
    mock_empty(api)
    out = await call("catc_get_wired_config", {"device": DEV_ID})
    assert out["supported_features"] == ["stpGlobalConfig", "vlanConfig"]
    assert out["features"] == {"vlanConfig": {"count": 2, "keys": ["10", "999"]}}
    assert out["no_data"] == ["stpGlobalConfig"] and out["state"] == "intended"


async def test_one_feature_and_item_filter(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "deployed", "vlanConfig", [vlan(1, "default"), vlan(10, "users")])
    out = await call(
        "catc_get_wired_config", {"device": DEV_ID, "feature": "VLANCONFIG", "state": "deployed"}
    )
    assert out["feature"] == "vlanConfig" and out["count"] == 2
    assert out["items"][1] == {"vlanId": 10, "name": "users", "isVlanEnabled": True}
    one = await call(
        "catc_get_wired_config",
        {"device": DEV_ID, "feature": "vlanConfig", "state": "deployed", "item": "10"},
    )
    assert one["count"] == 1
    with pytest.raises(ToolError, match="doesn't support vtpGlobalConfig"):
        await call("catc_get_wired_config", {"device": DEV_ID, "feature": "vtpGlobalConfig"})


async def test_diff(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(999, "mcp-999"), vlan(10, "users")])
    mock_feature(api, "deployed", "vlanConfig", [vlan(1, "default"), vlan(10, "users")])
    mock_feature(api, "intended", "stpGlobalConfig", [{"configType": "STP_GLOBAL", "stpMode": "RSTP"}])
    mock_feature(api, "deployed", "stpGlobalConfig", [{"configType": "STP_GLOBAL", "stpMode": "PVST"}])
    out = await call("catc_get_wired_config", {"device": DEV_ID, "diff": True})
    assert out["diff"]["vlanConfig"] == {"only_intended": ["999"], "in_sync": 1}
    assert out["diff"]["stpGlobalConfig"]["changed"] == {
        "global": {"stpMode": {"intended": "RSTP", "deployed": "PVST"}}
    }
    one = await call(
        "catc_get_wired_config", {"device": DEV_ID, "feature": "vlanConfig", "diff": True, "item": "10"}
    )
    assert not one.get("diff") and one["in_sync"] == ["vlanConfig"]


async def test_wlc_is_refused(api: respx.MockRouter) -> None:
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(
        json={"response": {**DEVICE, "family": "Wireless Controller"}}
    )
    with pytest.raises(ToolError, match="catc_get_wlc_config"):
        await call("catc_get_wired_config", {"device": DEV_ID})


# --- set ----------------------------------------------------------------------------------------


async def test_add_vlan_first_time_posts(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_empty(api)
    post = api.post(f"{WIRED}/intended/layer2/vlanConfig").respond(202, json={"response": {"taskId": "t1"}})
    task_ok(api, "t1")
    preview, done = await flow(
        "catc_set_wired_feature",
        {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 999, "name": "mcp-999"}]},
    )
    p = preview["preview"]
    assert p["items"]["999"]["action"] == "add" and p["items"]["999"]["source"] == "new"
    assert p["items"]["999"]["fields"]["name"] == {"from": "(not set)", "to": "mcp-999"}
    assert p["request"] == f"POST {WIRED}/intended/layer2/vlanConfig"
    assert "intended model only" in " ".join(preview["side_effects"]) and post.call_count == 1
    assert json.loads(post.calls.last.request.content) == {
        "vlanConfig": {"items": [{"configType": "VLAN", "vlanId": 999, "name": "mcp-999"}]}
    }
    assert done and done["result"]["next"] == "catc_deploy_wired_config"


async def test_merge_updates_with_put_and_keeps_others(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(10, "users")])
    mock_feature(api, "deployed", "vlanConfig", [vlan(20, "voice"), vlan(10, "users")])
    mock_empty(api)
    put = api.put(f"{WIRED}/intended/layer2/vlanConfig").respond(202, json={"response": {"taskId": "t2"}})
    task_ok(api, "t2")
    preview, done = await flow(
        "catc_set_wired_feature",
        {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 20, "name": "voice-new"}]},
    )
    item = preview["preview"]["items"]["20"]
    assert item["action"] == "add" and item["source"].startswith("deployed")
    assert item["fields"] == {"name": {"from": "voice", "to": "voice-new"}}  # the learned record is the base
    sent = json.loads(put.calls.last.request.content)["vlanConfig"]["items"]
    assert [x["vlanId"] for x in sent] == [10, 20] and sent[1]["isVlanEnabled"] is True
    assert done is not None


async def test_no_change_and_validation(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(10, "users")])
    mock_empty(api)
    same = await call(
        "catc_set_wired_feature",
        {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 10, "name": "users"}]},
    )
    assert "nothing to change" in json.dumps(same)
    for items, msg in (
        ([{"vlanId": 10, "colour": "red"}], "has no field"),
        ([{"name": "x"}], "needs vlanId"),
        ([{"vlanId": 5000}], "1-4094"),
        ([{"vlanId": 5}, {"vlanId": 5}], "given twice"),
    ):
        with pytest.raises(ToolError, match=msg):
            await call("catc_set_wired_feature", {"device": DEV_ID, "feature": "vlanConfig", "items": items})
    with pytest.raises(ToolError, match="one global record"):
        await call(
            "catc_set_wired_feature",
            {
                "device": DEV_ID,
                "feature": "stpGlobalConfig",
                "items": [{"stpMode": "RSTP"}, {"stpMode": "MST"}],
            },
        )
    with pytest.raises(ToolError, match="give no items"):
        await call(
            "catc_set_wired_feature",
            {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 1}], "mode": "delete"},
        )


async def test_remove_last_item_deletes_feature(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(999, "mcp-999")])
    mock_empty(api)
    delete = api.delete(f"{WIRED}/intended/layer2/vlanConfig").respond(
        202, json={"response": {"taskId": "t3"}}
    )
    task_ok(api, "t3")
    preview, done = await flow(
        "catc_set_wired_feature",
        {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 999}], "mode": "remove"},
    )
    assert preview["preview"]["items"] == {"999": {"action": "remove from intent"}}
    assert (
        preview["preview"]["request"].startswith("DELETE ")
        and "additive" in preview["preview"]["removal_note"]
    )
    assert delete.call_count == 1 and done is not None
    missing = await call(
        "catc_set_wired_feature",
        {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 5}], "mode": "remove"},
    )
    assert "not in the intended model" in json.dumps(missing)


async def test_replace_lists_removals(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(10, "users"), vlan(11, "printers")])
    mock_empty(api)
    preview = await call(
        "catc_set_wired_feature",
        {
            "device": DEV_ID,
            "feature": "vlanConfig",
            "items": [{"vlanId": 10, "name": "users"}],
            "mode": "replace",
        },
    )
    assert preview["preview"]["items"] == {"11": {"action": "remove from intent"}}
    assert preview["preview"]["intended_after"] == ["10"]


async def test_first_feature_falls_back_to_layer2_create(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_empty(api)
    api.post(f"{WIRED}/intended/layer2/vlanConfig").respond(
        400, json={"response": {"errorCode": "NCCO00000", "message": "Bad Request.", "detail": "no intent"}}
    )
    first = api.post(f"{WIRED}/intended/layer2").respond(202, json={"response": {"taskId": "t4"}})
    task_ok(api, "t4")
    _, done = await flow(
        "catc_set_wired_feature",
        {"device": DEV_ID, "feature": "vlanConfig", "items": [{"vlanId": 999, "name": "mcp-999"}]},
    )
    assert first.call_count == 1 and done is not None and "intended/layer2" in done["result"]["note"]
    assert json.loads(first.calls.last.request.content)["vlanConfig"]["items"][0]["vlanId"] == 999


# --- deploy -------------------------------------------------------------------------------------


def mock_model(api: respx.MockRouter, preview_items: list[dict[str, Any]]) -> dict[str, respx.Route]:
    routes = {
        "create": api.post(MODELS).respond(202, json={"response": {"taskId": PID}}),
        "gen": api.post(f"{MODELS}/{PID}/config").respond(202, json={"response": {"taskId": "t-gen"}}),
        "cli": api.get(f"{MODELS}/{PID}/config").respond(
            json={
                "response": {"networkDeviceId": DEV_ID, "status": "SUCCESS", "previewItems": preview_items},
                "version": "1.0",
            }
        ),
        "discard": api.delete(f"{MODELS}/{PID}").respond(202, json={"response": {"taskId": "t-del"}}),
        "deploy": api.post(f"{MODELS}/{PID}/deploy").respond(202, json={"response": {"taskId": DEPLOY_TASK}}),
    }
    for t in (PID, "t-gen", DEPLOY_TASK):
        task_ok(api, t)
    return routes


async def test_deploy_shows_cli_then_deploys(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_feature(api, "intended", "vlanConfig", [vlan(999, "mcp-999")])
    mock_empty(api)
    routes = mock_model(
        api, [{"name": "vlanConfig", "configType": "VLAN", "configPreview": "vlan 999\n name mcp-999\n"}]
    )
    deps = api.get(f"{WIRED}/intended/deviceDeployments").respond(
        json={
            "response": [
                {
                    "id": "dddddddd-0000-0000-0000-000000000001",
                    "activityId": DEPLOY_TASK,
                    "configGroupName": "layer2",
                    "configGroupVersion": 1,
                    "startTime": 1793015555209,
                    "endTime": 1793015565694,
                    "status": "Success",
                }
            ],
            "version": "1.0",
        }
    )
    preview, done = await flow("catc_deploy_wired_config", {"device": DEV_ID})
    p = preview["preview"]
    assert p["cli_preview"] == [
        {"name": "vlanConfig", "config_type": "VLAN", "cli": "vlan 999\n name mcp-999\n"}
    ]
    assert p["pending_changes"] == {"vlanConfig": {"only_intended": ["999"], "in_sync": 0}}
    assert p["request"] == f"POST {MODELS}/{PID}/deploy" and "intent/api/v1/intent" not in p["request"]
    assert preview["blast_radius"] == 1
    assert routes["discard"].call_count == 1  # the preview's model, not the deployed one
    assert routes["deploy"].call_count == 1 and routes["create"].call_count == 2
    assert done and done["result"]["outcome"] == "success" and done["result"]["status"] == {"Success": 1}
    assert deps.calls.last.request.url.params["deployActivityId"] == DEPLOY_TASK


async def test_deploy_blocked_on_cli_errors_and_empty_cli(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_empty(api)
    routes = mock_model(
        api, [{"name": "vlanConfig", "configType": "VLAN", "errorMessages": ["VLAN 1 cannot be modified"]}]
    )
    out = await call("catc_deploy_wired_config", {"device": DEV_ID})
    assert "VLAN 1 cannot be modified" in json.dumps(out) and "confirm" not in out
    assert routes["discard"].call_count == 1 and routes["deploy"].call_count == 0


async def test_deploy_blocked_when_model_fails(api: respx.MockRouter) -> None:
    mock_switch(api)
    mock_empty(api)
    api.post(MODELS).mock(return_value=httpx.Response(500, json={"response": {"message": "boom"}}))
    out = await call("catc_deploy_wired_config", {"device": DEV_ID})
    assert "could not build the CLI preview" in json.dumps(out) and "confirm" not in out
