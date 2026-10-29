"""D57: credential rotation (catc_update_global_credential, catc_apply_site_credentials).

Payloads shaped like the 3.2.2 lab: v1 globalCredentials list, sites/{id}/deviceCredentials with
`_inherited=true` (inheritedSiteId/inheritedSiteName on inherited slots) and the sync status rows."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from catc_mcp.server import create_server
from catc_mcp.tools import credentials

from .conftest import make_server, make_settings
from .test_dangerous_tools import flow
from .test_phase2_tools import CREDS, mock_creds
from .test_read_tools import AREA, BLDG, GLOBAL
from .test_write_tools import mock_sites, preview_then_apply, run, task_ok

V2 = "/dna/intent/api/v2/global-credential"
APPLY = "/dna/intent/api/v1/sites/deviceCredentials/apply"
SNMPV3 = {
    "id": "aaaaaaaa-1111-0000-0000-000000000005",
    "type": "SNMPV3",
    "description": "lab-v3",
    "username": "v3user",
    "snmpMode": "AUTHPRIV",
    "authType": "SHA",
    "privacyType": "AES128",
}


def site_creds(api: respx.MockRouter, site_id: str, body: dict[str, Any]) -> respx.Route:
    return api.get(f"/dna/intent/api/v1/sites/{site_id}/deviceCredentials").respond(json={"response": body})


def site_status(api: respx.MockRouter, site_id: str, *bodies: dict[str, Any]) -> respx.Route:
    route = api.get(f"/dna/intent/api/v1/sites/{site_id}/deviceCredentials/status")
    route.side_effect = [httpx.Response(200, json={"response": b, "version": "1.0"}) for b in bodies]
    return route


def status(cli: str, n: int = 3, snmp: str | None = None) -> dict[str, Any]:
    return {
        "cli": [{"status": cli, "deviceCount": n}],
        "snmpV2Read": [{"status": snmp or cli, "deviceCount": n}],
        "snmpV2Write": [],
        "snmpV3": [],
    }


# --- catc_update_global_credential ------------------------------------------------------------


async def test_update_cli_credential_masks_and_sends_v2_body(api: respx.MockRouter) -> None:
    mock_creds(api)
    put = api.put(V2).respond(200, json={"response": {"taskId": "tu"}, "version": "1.0"})
    task_ok(api, "tu")
    args = {"credential": "CLI:lab", "password": "Pw-R0tated", "enable_password": "En-R0tated"}
    preview, done = await preview_then_apply("catc_update_global_credential", args)
    assert preview["status"] == "preview" and put.call_count == 1  # only the apply sent the PUT
    text = json.dumps(preview) + json.dumps(done)
    assert "R0tated" not in text
    assert preview["preview"]["body"]["cliCredential"]["password"] == "********"
    assert preview["preview"]["secrets_rotated"] == ["enablePassword", "password"]
    assert json.loads(put.calls.last.request.content) == {
        "cliCredential": {
            "id": CREDS[0]["id"],
            "description": "lab",
            "username": "netadmin",
            "password": "Pw-R0tated",
            "enablePassword": "En-R0tated",
        }
    }
    assert done["result"]["credential_id"] == CREDS[0]["id"]
    assert done["result"]["task_id"] == "tu"


async def test_update_snmpv2_rename_and_community(api: respx.MockRouter) -> None:
    mock_creds(api)
    put = api.put(V2).respond(200, json={"response": {"taskId": "tu"}})
    task_ok(api, "tu")
    args = {"credential": "lab-rw", "community": "N3w-comm", "description": "lab-rw-2026"}
    preview, _ = await preview_then_apply("catc_update_global_credential", args)
    assert preview["preview"]["changes"] == {"description": {"from": "lab-rw", "to": "lab-rw-2026"}}
    assert "rename to lab-rw-2026" in preview["action"]
    assert json.loads(put.calls.last.request.content) == {
        "snmpV2cWrite": {"id": CREDS[2]["id"], "description": "lab-rw-2026", "writeCommunity": "N3w-comm"}
    }


async def test_update_snmpv3_keeps_current_protocols(api: respx.MockRouter) -> None:
    mock_creds(api, [*CREDS, SNMPV3])
    put = api.put(V2).respond(200, json={"response": {"taskId": "tu"}})
    task_ok(api, "tu")
    args = {"credential": "lab-v3", "snmpv3_auth_password": "Auth-S3c", "snmpv3_privacy_password": "Priv-S3c"}
    preview, done = await preview_then_apply("catc_update_global_credential", args)
    assert "S3c" not in json.dumps(preview) + json.dumps(done)
    assert json.loads(put.calls.last.request.content) == {
        "snmpV3": {
            "id": SNMPV3["id"],
            "description": "lab-v3",
            "username": "v3user",
            "snmpMode": "AUTHPRIV",
            "authType": "SHA",
            "privacyType": "AES128",
            "authPassword": "Auth-S3c",
            "privacyPassword": "Priv-S3c",
        }
    }


async def test_update_credential_blockers(api: respx.MockRouter) -> None:
    mock_creds(api)
    put = api.put(V2).respond(200, json={"response": {"taskId": "tu"}})
    preview, _ = await preview_then_apply("catc_update_global_credential", {"credential": "lab"})
    assert preview["status"] == "blocked" and any("password" in b for b in preview["blockers"])
    preview, _ = await preview_then_apply(
        "catc_update_global_credential", {"credential": "nc", "description": "nc2"}
    )
    assert preview["status"] == "blocked" and any("NETCONF" in b for b in preview["blockers"])
    preview, _ = await preview_then_apply(
        "catc_update_global_credential",
        {"credential": "lab-ro", "community": "x", "description": "LAB-RW", "username": "u"},
    )
    # Renaming onto another type's description is fine; a username on SNMPv2c isn't.
    assert preview["status"] == "blocked" and preview["blockers"] == [
        "SNMPV2_READ_COMMUNITY credentials have no username."
    ]
    mock_creds(api, [*CREDS, {**CREDS[0], "id": "aaaaaaaa-1111-0000-0000-000000000009", "description": "b"}])
    preview, _ = await preview_then_apply(
        "catc_update_global_credential", {"credential": "lab", "password": "p", "description": "B"}
    )
    assert preview["status"] == "blocked" and "already described" in preview["blockers"][0]
    assert put.call_count == 0


async def test_update_token_refuses_a_changed_secret(api: respx.MockRouter) -> None:
    mock_creds(api)
    put = api.put(V2).respond(200, json={"response": {"taskId": "tu"}})
    task_ok(api, "tu")
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_update_global_credential", {"credential": "lab", "password": "one"})
        with pytest.raises(Exception, match="(?i)token|argument|changed"):
            await run(
                c,
                "catc_update_global_credential",
                {"credential": "lab", "password": "two", "confirm": preview["confirm"]},
            )
    assert put.call_count == 0


# --- catc_apply_site_credentials --------------------------------------------------------------


@pytest.fixture
def fast_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "STATUS_INTERVAL", 0.0)


async def test_apply_site_credentials_flow(api: respx.MockRouter, fast_status: None) -> None:
    mock_sites(api, [GLOBAL, AREA])
    mock_creds(api)
    creds = site_creds(
        api,
        AREA["id"],
        {
            "cliCredentialsId": {"credentialsId": CREDS[0]["id"]},
            "snmpv2cReadCredentialsId": {"credentialsId": CREDS[1]["id"]},
            "snmpv2cWriteCredentialsId": None,
            "snmpv3CredentialsId": None,
            "httpReadCredentialsId": None,
            "httpWriteCredentialsId": None,
        },
    )
    site_status(
        api,
        AREA["id"],
        status("Not Synced"),  # preview
        status("Not Synced"),  # confirm re-check
        status("In Progress"),
        status("Synced", snmp="Partially Synced"),
    )
    post = api.post(APPLY)
    post.side_effect = [
        httpx.Response(202, json={"response": {"taskId": "ta1"}, "version": "1.0"}),
        httpx.Response(202, json={"response": {"taskId": "ta2"}, "version": "1.0"}),
    ]
    task_ok(api, "ta1")
    task_ok(api, "ta2")
    preview, done = await flow("catc_apply_site_credentials", {"site": "Global/AU"})
    assert preview["status"] == "preview" and post.call_count == 2
    assert creds.calls.last.request.url.params["_inherited"] == "true"
    p = preview["preview"]
    assert [a["credential"] for a in p["apply"]] == ["CLI:lab", "SNMPV2_READ_COMMUNITY:lab-ro"]
    assert p["status_now"] == [
        {"type": "CLI", "status": "Not Synced", "devices": 3},
        {"type": "SNMPV2_READ_COMMUNITY", "status": "Not Synced", "devices": 3},
    ]
    assert preview["blast_radius"] == 3
    assert [json.loads(c.request.content) for c in post.calls] == [
        {"deviceCredentialId": CREDS[0]["id"], "siteId": AREA["id"]},
        {"deviceCredentialId": CREDS[1]["id"], "siteId": AREA["id"]},
    ]
    r = done["result"]
    assert [a["ok"] for a in r["applied"]] == [True, True]
    assert r["status"] == [
        {"type": "CLI", "status": "Synced", "devices": 3},
        {"type": "SNMPV2_READ_COMMUNITY", "status": "Partially Synced", "devices": 3},
    ]
    assert r["ok"] is False  # partially synced isn't done


async def test_apply_only_chosen_types_and_task_failure(api: respx.MockRouter, fast_status: None) -> None:
    mock_sites(api, [GLOBAL, AREA])
    mock_creds(api)
    site_creds(
        api,
        AREA["id"],
        {
            "cliCredentialsId": {"credentialsId": CREDS[0]["id"]},
            "snmpv2cReadCredentialsId": {"credentialsId": CREDS[1]["id"]},
        },
    )
    site_status(api, AREA["id"], status("Not Synced"), status("Not Synced"), status("Failed"))
    post = api.post(APPLY).respond(202, json={"response": {"taskId": "tf"}})
    api.get("/dna/intent/api/v1/task/tf").respond(
        json={"response": {"isError": True, "failureReason": "device unreachable", "endTime": 1}}
    )
    preview, done = await flow(
        "catc_apply_site_credentials", {"site": "Global/AU", "credential_types": ["CLI"]}
    )
    assert [a["type"] for a in preview["preview"]["apply"]] == ["CLI"]
    assert post.call_count == 1
    assert done["result"]["applied"][0]["ok"] is False
    assert "unreachable" in done["result"]["applied"][0]["error"]
    assert done["result"]["status"] == [{"type": "CLI", "status": "Failed", "devices": 3}]
    assert done["result"]["ok"] is False


async def test_apply_blockers(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_creds(api)
    post = api.post(APPLY).respond(202, json={"response": {"taskId": "t"}})
    # Inherited from the area: apply there.
    site_creds(
        api,
        BLDG["id"],
        {
            "cliCredentialsId": {
                "credentialsId": CREDS[0]["id"],
                "inheritedSiteId": AREA["id"],
                "inheritedSiteName": "AU",
            }
        },
    )
    site_status(api, BLDG["id"], status("Not Synced"))
    preview, _ = await flow("catc_apply_site_credentials", {"site": BLDG["nameHierarchy"]})
    assert preview["status"] == "blocked" and "inherits its CLI credential from AU" in preview["blockers"][0]
    # Nothing assigned.
    site_creds(api, AREA["id"], {"cliCredentialsId": None})
    site_status(api, AREA["id"], status("Not Synced"), status("Not Synced"))
    preview, _ = await flow("catc_apply_site_credentials", {"site": "Global/AU"})
    assert preview["status"] == "blocked" and "catc_assign_site_credentials" in preview["blockers"][0]
    preview, _ = await flow(
        "catc_apply_site_credentials", {"site": "Global/AU", "credential_types": ["SNMPV3"]}
    )
    assert preview["blockers"] == ["Global/AU has no SNMPV3 credential."]
    # Assigned, but no devices use it.
    site_creds(api, AREA["id"], {"cliCredentialsId": {"credentialsId": CREDS[0]["id"]}})
    site_status(api, AREA["id"], {"cli": [], "snmpV2Read": [], "snmpV2Write": [], "snmpV3": []})
    preview, _ = await flow("catc_apply_site_credentials", {"site": "Global/AU"})
    assert preview["status"] == "blocked" and "No devices" in preview["blockers"][0]
    assert post.call_count == 0


async def test_apply_is_dangerous_tier_update_is_write() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_update_global_credential" in names
    assert "catc_apply_site_credentials" not in names


def test_status_rows_skips_empty_types() -> None:
    assert credentials.status_rows({"cli": [{"status": "Synced", "deviceCount": 2}], "snmpV3": None}) == [
        {"type": "CLI", "status": "Synced", "devices": 2}
    ]
