"""D14: wireless design and WLC provisioning (respx)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, DEV_ID, DEVICE, GLOBAL
from .test_write_tools import mock_sites, run, task_ok

SSIDS = f"/dna/intent/api/v1/sites/{GLOBAL['id']}/wirelessSettings/ssids"
PROFILES = "/dna/intent/api/v1/wirelessProfiles"
WLC = {**DEVICE, "family": "Wireless Controller", "hostname": "wlc1"}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def flow(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


async def test_create_personal_ssid_masks_passphrase(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(SSIDS).mock(
        side_effect=[
            httpx.Response(200, json={"response": []}),
            httpx.Response(200, json={"response": []}),
            httpx.Response(200, json={"response": [{"id": "s1", "ssid": "corp"}]}),
        ]
    )
    post = api.post(SSIDS).respond(202, json={"response": {"taskId": "ts"}})
    task_ok(api, "ts")
    preview, done = await flow(
        "catc_create_ssid", {"ssid": "corp", "security": "WPA2_PERSONAL", "passphrase": "Sup3rS3cret!"}
    )
    assert "Sup3rS3cret!" not in json.dumps(preview)
    body = preview["preview"]["body"]
    assert body["isAuthKeyPSK"] and body["rsnCipherSuiteCcmp128"] and body["profileName"] == "corp_profile"
    sent = json.loads(post.calls.last.request.content)
    assert sent["passphrase"] == "Sup3rS3cret!" and done and done["result"]["ssid_id"] == "s1"
    assert "Sup3rS3cret!" not in json.dumps(done)


async def test_ssid_passphrase_rules(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL])
    with pytest.raises(ToolError, match="8-63"):
        await flow("catc_create_ssid", {"ssid": "x", "security": "WPA3_PERSONAL", "passphrase": "short"})
    with pytest.raises(ToolError, match="only applies"):
        await flow(
            "catc_create_ssid", {"ssid": "x", "security": "WPA2_ENTERPRISE", "passphrase": "longenough1"}
        )


async def test_delete_ssid_in_profile_refused(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL])
    api.get(SSIDS).respond(json={"response": [{"id": "s1", "ssid": "corp"}]})
    api.get(PROFILES).respond(
        json={
            "response": [{"id": "p1", "wirelessProfileName": "campus", "ssidDetails": [{"ssidName": "corp"}]}]
        }
    )
    out, _ = await flow("catc_delete_ssid", {"ssid": "corp"})
    assert out["status"] == "blocked" and "campus" in out["blockers"][0]


async def test_create_profile_needs_defined_ssids(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL])
    api.get(SSIDS).respond(json={"response": [{"id": "s1", "ssid": "corp"}]})
    api.get(PROFILES).respond(json={"response": []})
    out, _ = await flow("catc_create_wireless_profile", {"name": "campus", "ssids": ["corp", "guest"]})
    assert out["status"] == "blocked" and "guest" in out["blockers"][0]


def mock_wlc(api: respx.MockRouter, site: str | None = "Global/AU/SYD-1") -> None:
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": [WLC]})
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": WLC})
    api.get(f"/dna/intent/api/v1/networkDevices/{DEV_ID}/assignedToSite").respond(
        json={"response": {"siteNameHierarchy": site} if site else {}}
    )
    api.get(f"/dna/intent/api/v1/wirelessControllers/{DEV_ID}/primaryManagedApLocations").respond(
        json={"response": {"managedApLocations": []}}
    )
    api.get(SSIDS).respond(json={"response": [{"id": "s1", "ssid": "corp", "passphrase": "x"}]})


async def test_provision_wlc(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(PROFILES).respond(
        json={
            "response": [{"id": "p1", "wirelessProfileName": "campus", "ssidDetails": [{"ssidName": "corp"}]}]
        }
    )
    api.get("/dna/intent/api/v1/networkProfilesForSites/p1/siteAssignments").respond(
        json={"response": [{"id": BLDG["id"]}]}
    )
    loc = api.post(f"/dna/intent/api/v1/wirelessControllers/{DEV_ID}/assignManagedApLocations").respond(
        202, json={"response": {"taskId": "ta"}}
    )
    prov = api.post(f"/dna/intent/api/v1/wirelessControllers/{DEV_ID}/provision").respond(
        202, json={"response": {"taskId": "tp"}}
    )
    task_ok(api, "ta")
    task_ok(api, "tp")
    preview, done = await flow(
        "catc_provision_wireless_controller", {"device": "wlc1", "managed_ap_locations": ["Global/AU/SYD-1"]}
    )
    assert (
        preview["preview"]["wireless_profiles_pushed"] == {"campus": ["corp"]}
        and preview["blast_radius"] == 1
    )
    assert json.loads(loc.calls.last.request.content) == {"primaryManagedAPLocationsSiteIds": [BLDG["id"]]}
    assert done and prov.call_count == 1


async def test_provision_wlc_never_provisioned(api: respx.MockRouter) -> None:
    """A WLC with no managed AP locations yet answers 400 NCWS51004; the preview treats it as none."""
    api.get(f"/dna/intent/api/v1/wirelessControllers/{DEV_ID}/primaryManagedApLocations").respond(
        400,
        json={
            "response": {
                "errorCode": "NCWS51000",
                "message": "NCWS51000: The API request has validation errors.: NCWS51004: No locations were "
                "discovered corresponding to the specified Wireless Controller",
            }
        },
    )
    mock_wlc(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(PROFILES).respond(
        json={
            "response": [{"id": "p1", "wirelessProfileName": "campus", "ssidDetails": [{"ssidName": "corp"}]}]
        }
    )
    api.get("/dna/intent/api/v1/networkProfilesForSites/p1/siteAssignments").respond(
        json={"response": [{"id": BLDG["id"]}]}
    )
    for leaf in ("provisionStatus", "ssidDetails"):
        api.get(f"/dna/intent/api/v1/wirelessControllers/{DEV_ID}/{leaf}").respond(json={"response": []})
    async with Client(server()) as c:
        out = await run(
            c,
            "catc_provision_wireless_controller",
            {"device": "wlc1", "managed_ap_locations": ["Global/AU/SYD-1"]},
        )
        state = await run(c, "catc_get_wireless_controller", {"device": "wlc1"})
    assert out["status"] == "preview" and out["preview"]["current_ap_locations_kept"] is False
    assert "unavailable" not in state


async def test_provision_wlc_blockers(api: respx.MockRouter) -> None:
    mock_wlc(api, site=None)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(PROFILES).respond(json={"response": []})
    out, _ = await flow(
        "catc_provision_wireless_controller", {"device": "wlc1", "managed_ap_locations": ["Global/AU/SYD-1"]}
    )
    text = " ".join(out["blockers"])
    assert "isn't assigned" in text and "No wireless profile" in text


async def test_delete_profile_lookup_failure_is_not_unassigned(api: respx.MockRouter) -> None:
    api.get(PROFILES).respond(json={"response": [{"id": "p1", "wirelessProfileName": "campus"}]})
    api.get("/dna/intent/api/v1/networkProfilesForSites/p1/siteAssignments").respond(
        500, json={"message": "x"}
    )
    with pytest.raises(ToolError):
        await flow("catc_delete_wireless_profile", {"name": "campus"})


async def test_passphrase_not_in_errors_or_audit(
    api: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    mock_sites(api, [GLOBAL])
    api.get(SSIDS).respond(json={"response": []})
    api.post(SSIDS).respond(400, json={"response": {"message": "bad request"}})
    with pytest.raises(ToolError) as e:
        await flow(
            "catc_create_ssid", {"ssid": "corp", "security": "WPA2_PERSONAL", "passphrase": "Sup3rS3cret!"}
        )
    assert "Sup3rS3cret!" not in str(e.value) and "Sup3rS3cret!" not in caplog.text


# --- D70: wireless feature config reads (catc_get_wlc_config) --------------------------------------------

CAMPUS = f"/dna/campus/api/v1/wirelessControllers/{DEV_ID}"
PSK_VALUE = "Wl4nPsk-S3cret"


def wlan(name: str, ssid: str, wlan_id: int, **kw: Any) -> dict[str, Any]:
    """A WLAN profile record shaped like WlanProfileResponse_17_18 in the bundled spec."""
    return {
        "id": f"0000000{wlan_id}-aaaa-bbbb-cccc-dddddddddddd",
        "configType": "WLAN_PROFILE",
        "deviceVersion": "17.18",
        "profileName": name,
        "ssid": ssid,
        "wlanId": wlan_id,
        "adminStatusEnabled": True,
        "broadcastSsidEnabled": True,
        "authKeyMgmtPskEnabled": True,
        "authKeyMgmtDot1xEnabled": False,
        "wpa2Enabled": True,
        "wlanPskKeyType": "ASCII",
        "passphrase": PSK_VALUE,
        "wepKey": "",
        "fastTransition": "ADAPTIVE",
        **kw,
    }


POLICY_TAG = {
    "id": "0000000a-aaaa-bbbb-cccc-dddddddddddd",
    "configType": "POLICY_TAG",
    "deviceVersion": "17.18",
    "policyTagName": "PT_mcp",
    "policyEntryDescription": "PolicyTagName PT_mcp",
}


def wlc_server() -> Any:
    return create_server(make_settings())


def mock_campus(
    api: respx.MockRouter, state: str, features: dict[str, list[dict[str, Any]]], fail: tuple[str, ...] = ()
) -> None:
    for path, items in features.items():
        api.get(f"{CAMPUS}/{state}/{path}").respond(json={"response": items, "version": "1.0"})
    for path in fail:
        api.get(f"{CAMPUS}/{state}/{path}").respond(500, json={"response": {"message": "boom"}})


def mock_rest_empty(api: respx.MockRouter) -> respx.Route:
    """Every other feature model answers with an empty list (registered last: specific routes win)."""
    return api.get(url__regex=rf".*{CAMPUS}/(intended|deployed)/.*").respond(
        json={"response": [], "version": "1.0"}
    )


async def wlc_call(args: dict[str, Any]) -> dict[str, Any]:
    async with Client(wlc_server()) as c:
        out: dict[str, Any] = await run(c, "catc_get_wlc_config", args)
    return out


async def test_wlc_config_summary(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(
        api,
        "intended",
        {"ssids/wlanProfiles": [wlan("corp_profile", "corp", 17), wlan("guest_profile", "guest", 18)]},
    )
    mock_campus(api, "intended", {"ssids/policyTags": [POLICY_TAG]}, fail=("radioFrequencies/rfProfiles",))
    rest = mock_rest_empty(api)
    out = await wlc_call({"wlc": "wlc1"})
    assert out["state"] == "intended" and out["wlc"].startswith("wlc1")
    assert out["features"]["wlan_profiles"] == {"count": 2, "names": ["corp_profile", "guest_profile"]}
    assert out["features"]["policy_tags"]["names"] == ["PT_mcp"]
    assert "ap_tag_configs" in out["no_data"] and "joined" not in out.get("note", "")
    assert "access points join" in out["ap_note"]
    assert "rf_profiles" in out["unavailable"]  # one family failing doesn't sink the summary
    assert PSK_VALUE not in json.dumps(out)
    # deployed-only families aren't asked for their (nonexistent) intended model
    assert not any("apTraceProfiles" in str(c.request.url) for c in rest.calls)


async def test_wlc_config_summary_unprovisioned(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_rest_empty(api)
    out = await wlc_call({"wlc": "wlc1", "state": "deployed"})
    assert not out.get("features")
    assert "provisioned" in out["note"] and "ap_trace_profiles" in out["no_data"]


async def test_wlc_config_feature_masks_and_trims(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(api, "deployed", {"ssids/wlanProfiles": [wlan("corp_profile", "corp", 17)]})
    out = await wlc_call({"wlc": "wlc1", "feature": "wlan_profiles", "state": "deployed"})
    rec = out["records"][0]
    assert rec["passphrase"] == "********" and PSK_VALUE not in json.dumps(out)
    assert rec["wlanPskKeyType"] == "ASCII"  # a key type, not a key
    assert "authKeyMgmtDot1xEnabled" not in rec and "omitted" in out  # false flags trimmed
    assert "configType" not in rec and "deviceVersion" not in rec and out["device_version"] == "17.18"
    assert "wepKey" not in rec  # unset
    full = await wlc_call(
        {"wlc": "wlc1", "feature": "wlan_profiles", "state": "deployed", "all_fields": True}
    )
    assert full["records"][0]["authKeyMgmtDot1xEnabled"] is False and "omitted" not in full


async def test_wlc_config_children_mask_mpsk_and_map_tags(api: respx.MockRouter) -> None:
    mock_wlc(api)
    rec = wlan("corp_profile", "corp", 17)
    tag_path = f"ssids/policyTags/{POLICY_TAG['id']}"
    mock_campus(
        api,
        "intended",
        {
            "ssids/policyTags": [POLICY_TAG],
            f"{tag_path}/policyTagWlanPolicies": [
                {
                    "id": "0000000b-aaaa-bbbb-cccc-dddddddddddd",
                    "configType": "POLICY_TAG_WLAN_POLICY",
                    "deviceVersion": "17.18",
                    "policyTagName": "PT_mcp",
                    "wlanPolicyPolicyProfileName": "corp_profile",
                    "wlanPolicyWlanProfileName": "corp_profile",
                }
            ],
            f"{tag_path}/policyTagRlanPolicies": [],
            "ssids/wlanProfiles": [rec],
            f"ssids/wlanProfiles/{rec['id']}/mpskKeyConfigs": [
                {"profileName": "corp_profile", "priority": 0, "key": "mpsk-S3cret!", "keyType": "ASCII"}
            ],
            f"ssids/wlanProfiles/{rec['id']}/radioPolicyConfigs": [],
        },
    )
    tags = await wlc_call({"wlc": "wlc1", "feature": "policy_tags", "children": True})
    mapping = tags["children"]["PT_mcp"]["policyTagWlanPolicies"][0]
    assert mapping["wlanPolicyWlanProfileName"] == "corp_profile" and "configType" not in mapping
    wl = await wlc_call({"wlc": "wlc1", "feature": "wlan_profiles", "children": True, "name": "corp_profile"})
    mpsk = wl["children"]["corp_profile"]["mpskKeyConfigs"][0]
    assert mpsk["key"] == "********" and mpsk["keyType"] == "ASCII"
    assert "mpsk-S3cret!" not in json.dumps(wl)


async def test_wlc_config_diff(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_campus(
        api,
        "intended",
        {
            "ssids/wlanProfiles": [
                wlan("corp_profile", "corp", 17, broadcastSsidEnabled=False),
                wlan("new_profile", "new", 19),
            ],
            "ssids/policyTags": [POLICY_TAG],
        },
    )
    mock_campus(
        api,
        "deployed",
        {
            # deployed reads the PSK back encrypted and adds device defaults the intent doesn't set
            "ssids/wlanProfiles": [
                wlan(
                    "corp_profile",
                    "corp",
                    17,
                    passphrase="0 encrypted-blob",
                    id="0000000f-aaaa-bbbb-cccc-dddddddddddd",
                    maxClientsAllowed=0,
                ),
                wlan("old_profile", "old", 20),
            ],
            "ssids/policyTags": [{**POLICY_TAG, "id": "0000000c-aaaa-bbbb-cccc-dddddddddddd"}],
        },
    )
    mock_rest_empty(api)
    out = await wlc_call({"wlc": "wlc1", "diff": True})
    d = out["diff"]["wlan_profiles"]
    assert d["only_intended"] == ["new_profile"] and d["only_deployed"] == ["old_profile"]
    assert d["changed"] == {"corp_profile": {"broadcastSsidEnabled": {"intended": False, "deployed": True}}}
    assert "policy_tags" in out["in_sync"] and "rf_profiles" not in out["in_sync"]  # empty on both sides
    text = json.dumps(out)
    assert PSK_VALUE not in text and "encrypted-blob" not in text and "passphrase" not in text


async def test_wlc_config_diff_children(api: respx.MockRouter) -> None:
    mock_wlc(api)
    tag_i, tag_d = POLICY_TAG, {**POLICY_TAG, "id": "0000000c-aaaa-bbbb-cccc-dddddddddddd"}

    def mapping(wlan_name: str) -> list[dict[str, Any]]:
        return [{"policyTagName": "PT_mcp", "wlanPolicyWlanProfileName": wlan_name, "id": wlan_name}]

    for state, tag, wl in (("intended", tag_i, "corp_profile"), ("deployed", tag_d, "lab_profile")):
        mock_campus(
            api,
            state,
            {
                "ssids/policyTags": [tag],
                f"ssids/policyTags/{tag['id']}/policyTagWlanPolicies": mapping(wl),
                f"ssids/policyTags/{tag['id']}/policyTagRlanPolicies": [],
            },
        )
    out = await wlc_call({"wlc": "wlc1", "feature": "policy_tags", "diff": True, "children": True})
    changed = out["diff"]["policy_tags"]["changed"]["PT_mcp"]["policyTagWlanPolicies"]
    assert changed["only_intended"][0]["wlanPolicyWlanProfileName"] == "corp_profile"
    assert changed["only_deployed"][0]["wlanPolicyWlanProfileName"] == "lab_profile"


async def test_wlc_config_ap_feature_empty_and_refusals(api: respx.MockRouter) -> None:
    mock_wlc(api)
    mock_rest_empty(api)
    out = await wlc_call({"wlc": "wlc1", "feature": "ap_tag_configs"})
    assert out["count"] == 0 and "No intended ap_tag_configs" in out["note"] and "join" in out["note"]
    with pytest.raises(ToolError, match="no intended model"):
        await wlc_call({"wlc": "wlc1", "feature": "ap_trace_profiles"})
    with pytest.raises(ToolError, match="apply to one"):
        await wlc_call({"wlc": "wlc1", "children": True})


async def test_wlc_config_refuses_a_switch(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": [DEVICE]})
    with pytest.raises(ToolError, match="not a wireless controller"):
        await wlc_call({"wlc": "edge-sw1.lab.local"})


async def test_wlc_config_diff_compares_auth_flags_and_keeps_duplicates(api: respx.MockRouter) -> None:
    """authKeyMgmt*Enabled look secret by name but are flags: a security-mode drift must show."""
    mock_wlc(api)
    dup = wlan("corp_profile", "corp", 21, wlanId=21)
    mock_campus(api, "intended", {"ssids/wlanProfiles": [wlan("corp_profile", "corp", 17), dup]})
    mock_campus(
        api,
        "deployed",
        {
            "ssids/wlanProfiles": [
                wlan("corp_profile", "corp", 17, authKeyMgmtPskEnabled=False, authKeyMgmtSaeEnabled=True),
                {**dup, "wlanId": 22},
            ]
        },
    )
    out = await wlc_call({"wlc": "wlc1", "feature": "wlan_profiles", "diff": True})
    changed = out["diff"]["wlan_profiles"]["changed"]
    assert changed["corp_profile"] == {"authKeyMgmtPskEnabled": {"intended": True, "deployed": False}}
    assert changed["corp_profile#2"] == {"wlanId": {"intended": 21, "deployed": 22}}


async def test_wlc_config_diff_skips_unreadable_children(api: respx.MockRouter) -> None:
    mock_wlc(api)
    tag_d = {**POLICY_TAG, "id": "0000000c-aaaa-bbbb-cccc-dddddddddddd"}
    rows = [{"policyTagName": "PT_mcp", "wlanPolicyWlanProfileName": "corp_profile"}]
    mock_campus(
        api,
        "intended",
        {
            "ssids/policyTags": [POLICY_TAG],
            f"ssids/policyTags/{POLICY_TAG['id']}/policyTagWlanPolicies": rows,
            f"ssids/policyTags/{POLICY_TAG['id']}/policyTagRlanPolicies": [],
        },
    )
    mock_campus(
        api,
        "deployed",
        {"ssids/policyTags": [tag_d], f"ssids/policyTags/{tag_d['id']}/policyTagRlanPolicies": []},
        fail=(f"ssids/policyTags/{tag_d['id']}/policyTagWlanPolicies",),
    )
    out = await wlc_call({"wlc": "wlc1", "feature": "policy_tags", "diff": True, "children": True})
    d = out["diff"]["policy_tags"]
    assert "changed" not in d  # no false "only_intended" mapping
    assert "PT_mcp/policyTagWlanPolicies" in d["not_compared"]


async def test_wlc_config_site_profile_wlc_says_so(api: respx.MockRouter) -> None:
    """Live 3.2.2: a WLC provisioned through site-based network profiles has no feature models; every read
    answers 404 NCWS70003 with this detail. One note instead of 27 errors."""
    mock_wlc(api)
    body = {
        "response": {
            "errorCode": "NCWS70003",
            "message": "Validation failed due to invalid request.",
            "detail": "Cannot perform the request as the device is provisioned via Site-based Network "
            "profiles",
        },
        "version": "1.0",
    }
    probe = api.get(url__regex=rf".*{CAMPUS}/(intended|deployed)/.*").respond(404, json=body)
    for args in (
        {"wlc": "wlc1"},
        {"wlc": "wlc1", "feature": "policy_tags", "state": "deployed"},
        {"wlc": "wlc1", "diff": True},
    ):
        out = await wlc_call(args)
        assert out["provisioning"] == "site-based network profiles" and "unavailable" not in out
        assert (
            "Site-based Network profiles" in out["catc_says"]
            and "catc_get_wireless_controller" in out["note"]
        )
    assert probe.call_count == 3  # one probe per call, nothing else


async def test_wlc_config_pages_by_100(api: respx.MockRouter) -> None:
    """3.2.2 refuses limit > 100 on the feature models (the spec says 500)."""
    mock_wlc(api)
    route = api.get(f"{CAMPUS}/intended/ssids/policyTags").respond(json={"response": [POLICY_TAG]})
    await wlc_call({"wlc": "wlc1", "feature": "policy_tags"})
    limits = {int(c.request.url.params["limit"]) for c in route.calls}
    assert limits and max(limits) <= 100
