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
