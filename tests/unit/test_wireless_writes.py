"""D71: per-device wireless writes and intended deploy (respx; bodies shaped like the bundled 3.2.2 spec)."""

import json
import zlib
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools.wireless_writes import security_fields

from .conftest import make_settings
from .test_read_tools import DEV_ID
from .test_wireless import CAMPUS, POLICY_TAG, PSK_VALUE, flow, mock_campus, mock_rest_empty, mock_wlc, wlan
from .test_write_tools import run, task_ok

SETTINGS = "/dna/intent/api/v1/provisioningSettings"
NEW_PSK = "N3w-Wpa3-Passphrase"
TAG_MAPS = f"ssids/policyTags/{POLICY_TAG['id']}/policyTagWlanPolicies"
SITE_BASED = {
    "response": {
        "errorCode": "NCWS70003",
        "message": "Validation failed due to invalid request.",
        "detail": "Cannot perform the request as the device is provisioned via Site-based Network profiles",
    },
    "version": "1.0",
}


def policy(name: str, vlan: str = "1", **kw: Any) -> dict[str, Any]:
    """A policy profile record shaped like PolicyProfileResponse_17_18."""
    return {
        "id": f"{zlib.crc32(name.encode()) % 10**8:08d}-1111-2222-3333-444444444444",
        "configType": "POLICY_PROFILE",
        "deviceVersion": "17.18",
        "policyProfileName": name,
        "interfaceName": vlan,
        "policyProfileStatus": True,
        **kw,
    }


def tag_map(wlan_name: str, policy_name: str) -> dict[str, Any]:
    return {
        "id": f"{zlib.crc32((wlan_name + policy_name).encode()) % 10**8:08d}-5555-6666-7777-888888888888",
        "configType": "POLICY_TAG_WLAN_POLICY",
        "deviceVersion": "17.18",
        "policyTagName": "PT_mcp",
        "wlanPolicyWlanProfileName": wlan_name,
        "wlanPolicyPolicyProfileName": policy_name,
    }


RF_5G = {
    "id": "0000000e-aaaa-bbbb-cccc-dddddddddddd",
    "configType": "RF_PROFILE",
    "deviceVersion": "17.18",
    "rfProfileName": "Typical_Client_Density_rf_5gh",
    "rfProfileBand": "DOT11_5_GHZ_BAND",
    "rfProfileStatus": True,
    "rfProfileTxPowerMin": -10,
    "rfProfileTxPowerMax": 30,
    "rfProfileRfDcaChannelWidth": "RF_DCA_CHAN_WIDTH_BEST",
    "rfProfileMaxRadioClients": 200,
}
RF_TAG = {
    "id": "0000000d-aaaa-bbbb-cccc-dddddddddddd",
    "configType": "RF_TAG",
    "deviceVersion": "17.18",
    "rfTagTagName": "RT_mcp",
    "rfTagDot11aRfProfileName": "Typical_Client_Density_rf_5gh",
    "rfTagDot11bRfProfileName": "Typical_Client_Density_rf_24gh",
}


def writes_server(dangerous: bool = True) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=dangerous))


async def preview_only(name: str, args: dict[str, Any]) -> dict[str, Any]:
    async with Client(writes_server()) as c:
        out: dict[str, Any] = await run(c, name, args)
    return out


def ssid_update(api: respx.MockRouter, task: str = "tu") -> respx.Route:
    route = api.post(f"{CAMPUS}/intended/ssids/update").respond(202, json={"response": {"taskId": task}})
    task_ok(api, task)
    return route


async def test_set_wlan_security_wpa2_to_wpa3_masks_psk(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(api, "intended", {"ssids/wlanProfiles": [wlan("corp_profile", "corp", 17)]})
    post = ssid_update(api)
    preview, done = await flow(
        "catc_set_wlan_security",
        {"wlc": "wlc1", "wlan": "corp", "security": "WPA3_PERSONAL", "passphrase": NEW_PSK},
    )
    p = preview["preview"]
    assert p["security"] == {"current": "WPA2_PERSONAL", "new": "WPA3_PERSONAL"}
    assert p["changes"]["wpa3Enabled"] == {"from": "(not set)", "to": True}
    assert p["changes"]["authKeyMgmtSaeEnabled"]["to"] is True
    assert p["changes"]["authKeyMgmtPskEnabled"] == {"from": True, "to": False}
    assert p["changes"]["protectedManagementFrameOptions"]["to"] == "APF_VAP_PMF_REQUIRED"
    assert p["changes"]["passphrase"] == {"from": "********", "to": "******** (new)"}
    assert "intended model only" in " ".join(preview["side_effects"]) and post.call_count == 1
    sent = json.loads(post.calls.last.request.content)["wlanProfiles"]
    assert sent["op"] == "MERGE" and sent["deviceVersion"] == "17.18"
    assert sent["profileName"] == "corp_profile" and sent["wlanId"] == 17
    assert sent["passphrase"] == NEW_PSK and sent["wpa2Enabled"] is False and sent["wpa3Enabled"] is True
    assert done and done["result"]["next"] == "catc_deploy_wlc_config"
    for text in (json.dumps(preview), json.dumps(done)):
        assert NEW_PSK not in text and PSK_VALUE not in text


async def test_set_wlan_security_rules(api: respx.MockRouter) -> None:
    mock_wlc(api)
    dot1x = wlan(
        "lab_profile",
        "lab",
        18,
        authKeyMgmtPskEnabled=False,
        authKeyMgmtDot1xEnabled=True,
        passphrase="",
        wlanSecurityWpaEnabled=True,
    )
    full = wlan("corp_profile", "corp", 17, **security_fields("WPA2_PERSONAL", None))
    mock_campus(api, "intended", {"ssids/wlanProfiles": [full, dot1x]})
    ent = await preview_only(
        "catc_set_wlan_security", {"wlc": "wlc1", "wlan": "corp", "security": "WPA2_ENTERPRISE"}
    )
    assert ent["status"] != "preview" and any("method list" in b for b in ent["blockers"])
    same = await preview_only(
        "catc_set_wlan_security", {"wlc": "wlc1", "wlan": "corp", "security": "WPA2_PERSONAL"}
    )
    assert any("already WPA2_PERSONAL" in b for b in same["blockers"])
    to_psk = await preview_only(
        "catc_set_wlan_security", {"wlc": "wlc1", "wlan": "lab", "security": "WPA2_PERSONAL"}
    )
    assert any("needs a passphrase" in b and "WPA2_ENTERPRISE" in b for b in to_psk["blockers"])
    keep = await preview_only(
        "catc_set_wlan_security", {"wlc": "wlc1", "wlan": "corp", "security": "WPA2_WPA3_PERSONAL"}
    )
    assert keep["status"] == "preview" and keep["preview"]["passphrase"] == "kept"
    assert keep["preview"]["changes"]["protectedManagementFrameOptions"]["to"] == "APF_VAP_PMF_OPTIONAL"
    with pytest.raises(ToolError, match="only applies to PERSONAL"):
        await preview_only(
            "catc_set_wlan_security",
            {"wlc": "wlc1", "wlan": "lab", "security": "WPA3_ENTERPRISE", "passphrase": NEW_PSK},
        )
    with pytest.raises(ToolError, match="No WLAN guest"):
        await preview_only("catc_set_wlan_security", {"wlc": "wlc1", "wlan": "guest", "security": "OPEN"})


async def test_set_wlan_vlan_by_ssid_through_policy_tags(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(
        api,
        "intended",
        {
            "ssids/wlanProfiles": [wlan("corp_profile", "corp", 17), wlan("iot_profile", "iot", 19)],
            "ssids/policyProfiles": [policy("corp_policy"), policy("other_policy", "30")],
            "ssids/policyTags": [POLICY_TAG],
            TAG_MAPS: [tag_map("corp_profile", "corp_policy"), tag_map("iot_profile", "corp_policy")],
        },
    )
    post = ssid_update(api)
    preview, done = await flow("catc_set_wlan_vlan", {"wlc": "wlc1", "wlan": "corp", "vlan": "20"})
    p = preview["preview"]
    assert p["policy_profile"] == "corp_policy" and p["changes"] == {
        "interfaceName": {"from": "1", "to": "20"}
    }
    assert p["wlans_using_it"] == ["corp_profile (PT_mcp)", "iot_profile (PT_mcp)"]
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "policyProfiles": {
            "op": "MERGE",
            "deviceVersion": "17.18",
            "policyProfileName": "corp_policy",
            "interfaceName": "20",
        }
    }
    assert done and post.call_count == 1


async def test_set_wlan_vlan_refusals(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(
        api,
        "intended",
        {
            "ssids/wlanProfiles": [wlan("corp_profile", "corp", 17)],
            "ssids/policyProfiles": [policy("corp_policy", "20"), policy("lab_policy")],
            "ssids/policyTags": [POLICY_TAG],
            TAG_MAPS: [tag_map("corp_profile", "corp_policy"), tag_map("corp_profile", "lab_policy")],
        },
    )
    with pytest.raises(ToolError, match="maps to 2 policy profiles"):
        await preview_only("catc_set_wlan_vlan", {"wlc": "wlc1", "wlan": "corp", "vlan": "20"})
    with pytest.raises(ToolError, match="either"):
        await preview_only("catc_set_wlan_vlan", {"wlc": "wlc1", "vlan": "20"})
    with pytest.raises(ToolError, match="1-4094"):
        await preview_only(
            "catc_set_wlan_vlan", {"wlc": "wlc1", "policy_profile": "corp_policy", "vlan": "5000"}
        )
    same = await preview_only(
        "catc_set_wlan_vlan", {"wlc": "wlc1", "policy_profile": "corp_policy", "vlan": "20"}
    )
    assert any("already uses VLAN 20" in b for b in same["blockers"])


async def test_set_rf_profile(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(
        api, "intended", {"radioFrequencies/rfProfiles": [RF_5G], "radioFrequencies/rfTags": [RF_TAG]}
    )
    post = api.post(f"{CAMPUS}/intended/radioFrequencies/update").respond(
        202, json={"response": {"taskId": "tr"}}
    )
    task_ok(api, "tr")
    args = {"wlc": "wlc1", "rf_profile": RF_5G["rfProfileName"], "channel_width": "40", "tx_power_max": 17}
    preview, done = await flow("catc_set_rf_profile", args)
    p = preview["preview"]
    assert p["band"] == "DOT11_5_GHZ_BAND" and p["rf_tags_using_it"] == ["RT_mcp"]
    assert p["changes"] == {
        "rfProfileRfDcaChannelWidth": {"from": "RF_DCA_CHAN_WIDTH_BEST", "to": "RF_DCA_CHAN_WIDTH_40_MHZ"},
        "rfProfileTxPowerMax": {"from": 30, "to": 17},
    }
    sent = json.loads(post.calls.last.request.content)["rfProfiles"]
    assert sent == {
        "op": "MERGE",
        "deviceVersion": "17.18",
        "rfProfileName": RF_5G["rfProfileName"],
        "rfProfileRfDcaChannelWidth": "RF_DCA_CHAN_WIDTH_40_MHZ",
        "rfProfileTxPowerMax": 17,
    }
    assert done
    low = await preview_only("catc_set_rf_profile", {**args, "tx_power_max": -10, "tx_power_min": 5})
    assert any("would exceed the maximum" in b for b in low["blockers"])
    best = await preview_only(
        "catc_set_rf_profile",
        {"wlc": "wlc1", "rf_profile": "Typical_Client_Density_rf_5gh", "channel_width": "best"},
    )
    assert any("already has these settings" in b for b in best["blockers"])
    with pytest.raises(ToolError, match="Nothing to change"):
        await preview_only("catc_set_rf_profile", {"wlc": "wlc1", "rf_profile": "x"})


async def test_site_based_wlc_is_refused_with_why(api: respx.MockRouter) -> None:
    """Live 3.2.2: a WLC provisioned through site-based profiles answers 404 NCWS70003 on every model."""
    mock_wlc(api)
    api.get(url__regex=rf".*{CAMPUS}/(intended|deployed)/.*").respond(404, json=SITE_BASED)
    api.get(SETTINGS).respond(json={"response": {"requirePreview": False, "requireItsmApproval": False}})
    with pytest.raises(ToolError, match="Enable Per-Device Configuration"):
        await preview_only("catc_set_wlan_vlan", {"wlc": "wlc1", "wlan": "corp", "vlan": "20"})
    out = await preview_only("catc_deploy_wlc_config", {"wlc": "wlc1"})
    assert out["status"] != "preview" and any("Site-based Network profiles" in b for b in out["blockers"])


async def test_deploy_refused_while_provisioning_needs_preview(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_rest_empty(api)
    api.get(SETTINGS).respond(json={"response": {"requirePreview": True, "requireItsmApproval": False}})
    out = await preview_only("catc_deploy_wlc_config", {"wlc": "wlc1"})
    assert any("requirePreview" in b and "global" in b for b in out["blockers"])


async def test_deploy_previews_the_diff_and_reports_groups(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(api, "intended", {"ssids/policyProfiles": [policy("corp_policy", "20")]})
    mock_campus(api, "deployed", {"ssids/policyProfiles": [policy("corp_policy", "1")]})
    status = api.get(f"{CAMPUS}/intended/deviceDeployments")  # before the catch-all below
    mock_rest_empty(api)
    api.get(SETTINGS).respond(json={"response": {"requirePreview": False, "requireItsmApproval": False}})
    deploy = api.post(f"{CAMPUS}/intended/deploy").respond(202, json={"response": {"taskId": "td"}})
    act = "aaaaaaaa-1111-2222-3333-444444444444"
    task_ok(api, "td", data=act)
    group = {
        "id": "bbbbbbbb-1111-2222-3333-444444444444",
        "activityId": act,
        "configGroupName": "wireless.policy.profile",
        "configGroupVersion": 2,
        "startTime": 1792316519787,
        "endTime": 1792316534907,
        "status": "Success",
    }
    status.respond(json={"response": [group]})
    preview, done = await flow("catc_deploy_wlc_config", {"wlc": "wlc1"})
    p = preview["preview"]
    assert p["pending_changes"]["policy_profiles"]["changed"] == {
        "corp_policy": {"interfaceName": {"intended": "20", "deployed": "1"}}
    }
    assert preview["blast_radius"] == 1 and "move to a new VLAN" in " ".join(preview["side_effects"])
    assert deploy.call_count == 1 and done
    res = done["result"]
    assert res["activity_id"] == act and res["status"] == {"Success": 1}
    assert res["groups"][0]["config_group"] == "wireless.policy.profile"
    assert res["groups"][0]["started"].endswith("UTC")
    assert status.calls.last.request.url.params["deployActivityId"] == act


async def test_get_wlc_deployments(api: respx.MockRouter) -> None:
    mock_wlc(api)
    rows = [
        {
            "id": "1",
            "activityId": "a1",
            "configGroupName": "dns.server",
            "configGroupVersion": 0,
            "startTime": 1792316283230,
            "status": "Success",
        },
        {
            "id": "2",
            "activityId": "a1",
            "configGroupName": "wireless.wlan",
            "configGroupVersion": 1,
            "startTime": 1792316519787,
            "status": "Failed",
            "error": {"message": "WLAN id in use", "remedy": "Pick another WLAN id"},
        },
    ]
    api.get(f"{CAMPUS}/intended/deviceDeployments").respond(json={"response": rows})
    async with Client(writes_server()) as c:
        out = await run(c, "catc_get_wlc_deployments", {"wlc": "wlc1", "limit": 1})
    assert out["status"] == {"Success": 1, "Failed": 1} and out["more"] == 1
    newest = out["deployments"][0]
    assert newest["config_group"] == "wireless.wlan" and newest["remedy"] == "Pick another WLAN id"


async def test_staging_is_write_tier_deploy_is_dangerous(api: respx.MockRouter) -> None:
    async with Client(writes_server(dangerous=False)) as c:
        names = {t.name for t in await c.list_tools()}
    assert {"catc_set_wlan_security", "catc_set_wlan_vlan", "catc_set_rf_profile"} <= names
    assert "catc_deploy_wlc_config" not in names and "catc_get_wlc_deployments" in names
    assert DEV_ID in CAMPUS
