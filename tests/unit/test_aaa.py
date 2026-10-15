"""D8: policy servers, ISE integration and site AAA settings (respx-mocked). Secrets never leak."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, GLOBAL
from .test_write_tools import mock_sites, run, task_ok

SERVER_ID = "4f058cb5-c43c-441a-b97e-06020d56a953"
ISE_SERVER = {
    "ipAddress": "198.18.134.35",
    "sharedSecret": "",
    "protocol": "RADIUS_TACACS",
    "role": "primary",
    "port": 49,
    "authenticationPort": 1812,
    "accountingPort": 1813,
    "retries": 3,
    "timeoutSeconds": 4,
    "isIseEnabled": True,
    "instanceUuid": SERVER_ID,
    "state": "ACTIVE",
    "encryptionKey": "",
    "messageKey": "",
    "pxgridEnabled": True,
    "ciscoIseDtos": [
        {
            "subscriberName": "pxgrid_client_1",
            "password": "",
            "userName": "admin",
            "fqdn": "ise.lab",
            "ipAddress": "198.18.134.35",
            "trustState": "TRUSTED",
            "role": "PRIMARY",
            "sshkey": None,
        }
    ],
}
CERT = {
    "certificateChain": [
        {"subjectDn": "CN=ise.lab", "issuerDn": "CN=ise.lab", "fingerPrints": {"SHA-256": "16DE15"}}
    ]
}
WAITING = {
    "aaaServerSettingId": SERVER_ID,
    "overallStatus": "WAITING_USER_INPUT",
    "overallErrorMessage": "not yet trusted",
    "steps": [
        {
            "stepOrder": 1,
            "stepName": "Initiating connection...",
            "stepStatus": "WAITING_USER_INPUT",
            "certAcceptedByUser": False,
            "certificate": json.dumps(CERT),
        },
        {"stepOrder": 2, "stepName": "Establishing trust...", "stepStatus": "NOT_STARTED"},
    ],
}
COMPLETE = {
    "aaaServerSettingId": SERVER_ID,
    "overallStatus": "COMPLETE",
    "steps": [{"stepOrder": 1, "stepName": "Initiating connection...", "stepStatus": "COMPLETE"}],
}
SECRET, PASSWORD = "radius-s3cret", "ise-pa55"
AREA_P = {**AREA, "parentId": GLOBAL["id"]}


def rw() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def test_get_policy_servers_masks_and_reports_integration(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    api.get("/dna/intent/api/v1/ise-integration-status").respond(json=WAITING)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_get_policy_servers", {})
    srv = out["servers"][0]
    assert srv["id"] == SERVER_ID and srv["ise_nodes"][0]["trustState"] == "TRUSTED"
    assert "sharedSecret" not in json.dumps(out) and "password" not in json.dumps(srv)
    integ = out["ise_integration"]
    assert integ["status"] == "WAITING_USER_INPUT"
    assert integ["certificate_to_accept"][0]["fingerPrints"]["SHA-256"] == "16DE15"
    assert "certificate" not in integ["steps"][0]


async def test_add_ise_server_masks_secrets_and_waits_for_certificate(api: respx.MockRouter) -> None:
    servers: list[dict[str, Any]] = []
    api.get("/dna/intent/api/v1/authentication-policy-servers").mock(
        side_effect=lambda r: httpx.Response(200, json={"response": servers})
    )
    post = api.post("/dna/intent/api/v1/authentication-policy-servers").respond(
        json={"response": {"taskId": "t1"}}
    )
    task_ok(api, "t1", progress="Operation Successful")
    api.get("/dna/intent/api/v1/ise-integration-status").respond(json=WAITING)
    args = {
        "ip": "198.18.134.35",
        "fqdn": "ise.lab",
        "username": "admin",
        "password": PASSWORD,
        "shared_secret": SECRET,
        "protocol": "RADIUS_TACACS",
    }
    async with Client(rw()) as c:
        preview = await run(c, "catc_add_ise_server", args)
        text = json.dumps(preview)
        assert preview["status"] == "preview" and SECRET not in text and PASSWORD not in text
        assert preview["preview"]["body"]["port"] == 49
        done = await run(c, "catc_add_ise_server", {**args, "confirm": preview["confirm"]})
        # a changed secret invalidates the token
        servers.clear()
    sent = json.loads(post.calls.last.request.content)
    assert sent["sharedSecret"] == SECRET and sent["ciscoIseDtos"][0]["password"] == PASSWORD
    assert sent["ipAddress"] == "198.18.134.35" and sent["authenticationPort"] == 1812
    assert SECRET not in json.dumps(done) and PASSWORD not in json.dumps(done)
    assert done["result"]["integration"]["status"] == "WAITING_USER_INPUT"


async def test_add_ise_server_blocked_when_ise_exists(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    async with Client(rw()) as c:
        out = await run(
            c,
            "catc_add_ise_server",
            {"ip": "10.0.0.5", "fqdn": "ise2", "username": "a", "password": "p", "shared_secret": "s"},
        )
    assert out["status"] == "blocked" and "already integrated" in json.dumps(out["blockers"])


async def test_accept_certificate_shows_fingerprint_and_puts(api: respx.MockRouter) -> None:
    states = [WAITING]
    api.get("/dna/intent/api/v1/ise-integration-status").mock(
        side_effect=lambda r: httpx.Response(200, json=states[-1])
    )

    def accept(request: httpx.Request) -> httpx.Response:
        states.append(COMPLETE)
        return httpx.Response(200, json={})

    put = api.put(f"/dna/intent/api/v1/integrate-ise/{SERVER_ID}").mock(side_effect=accept)
    async with Client(rw()) as c:
        preview = await run(c, "catc_accept_ise_certificate", {})
        assert preview["preview"]["certificate"][0]["subjectDn"] == "CN=ise.lab"
        done = await run(c, "catc_accept_ise_certificate", {"confirm": preview["confirm"]})
    assert json.loads(put.calls.last.request.content) == {"isCertAcceptedByUser": True}
    assert done["result"]["integration"]["status"] == "COMPLETE"


async def test_accept_certificate_blocked_without_waiting_step(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/ise-integration-status").respond(json=COMPLETE)
    async with Client(rw()) as c:
        out = await run(c, "catc_accept_ise_certificate", {})
    assert out["status"] == "blocked"


async def test_delete_policy_server(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    delete = api.delete(f"/dna/intent/api/v1/authentication-policy-servers/{SERVER_ID}").respond(
        json={"response": {"taskId": "t2"}}
    )
    task_ok(api, "t2")
    async with Client(rw()) as c:
        preview = await run(c, "catc_delete_policy_server", {"server": "198.18.134.35"})
        assert preview["action"] == "Remove ISE server 198.18.134.35" and delete.call_count == 0
        await run(c, "catc_delete_policy_server", {"server": "198.18.134.35", "confirm": preview["confirm"]})
    assert delete.call_count == 1


def mock_aaa(api: respx.MockRouter, effective: dict[str, Any], local: dict[str, Any]) -> respx.Route:
    path = f"/dna/intent/api/v1/sites/{AREA['id']}/aaaSettings"
    api.get(path).mock(
        side_effect=lambda r: httpx.Response(
            200, json={"response": effective if r.url.params.get("_inherited") == "true" else local}
        )
    )
    route = api.put(path).respond(json={"response": {"taskId": "t3"}})
    task_ok(api, "t3")
    return route


async def test_update_site_aaa_ise_body_and_secret(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    put = mock_aaa(api, {}, {})
    ise = {"server_type": "ISE", "protocol": "RADIUS", "primary": "198.18.134.35"}
    args = {"site": "Global/AU", "network": ise, "client": ise, "client_shared_secret": SECRET}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_site_aaa_settings", args)
        assert preview["status"] == "preview" and SECRET not in json.dumps(preview)
        done = await run(c, "catc_update_site_aaa_settings", {**args, "confirm": preview["confirm"]})
    sent = json.loads(put.calls.last.request.content)
    assert sent["aaaNetwork"] == {
        "serverType": "ISE",
        "protocol": "RADIUS",
        "primaryServerIp": "198.18.134.35",
        "pan": "198.18.134.35",
    }
    assert sent["aaaClient"]["sharedSecret"] == SECRET and SECRET not in json.dumps(done)


async def test_update_site_aaa_blocks_unknown_server_and_tacacs_client(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    mock_aaa(api, {}, {})
    async with Client(rw()) as c:
        out = await run(
            c,
            "catc_update_site_aaa_settings",
            {"site": "Global/AU", "network": {"server_type": "ISE", "primary": "10.9.9.9"}},
        )
        assert out["status"] == "blocked" and "10.9.9.9" in json.dumps(out["blockers"])
        res = await c.call_tool(
            "catc_update_site_aaa_settings",
            {
                "site": "Global/AU",
                "client": {"server_type": "AAA", "protocol": "TACACS", "primary": "198.18.134.35"},
            },
            raise_on_error=False,
        )
        assert res.is_error and "RADIUS" in res.content[0].text  # type: ignore[union-attr]


async def test_update_site_aaa_inherit_keeps_other_role(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    local = {
        "aaaNetwork": {"serverType": "ISE", "protocol": "RADIUS", "primaryServerIp": "198.18.134.35"},
        "aaaClient": {"serverType": "ISE", "protocol": "RADIUS", "primaryServerIp": "198.18.134.35"},
    }
    put = mock_aaa(api, local, local)
    mock_sites(api, [GLOBAL, AREA_P])
    api.get(f"/dna/intent/api/v1/sites/{GLOBAL['id']}/aaaSettings").respond(json={"response": local})
    args = {"site": "Global/AU", "inherit": ["client"]}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_site_aaa_settings", args)
        await run(c, "catc_update_site_aaa_settings", {**args, "confirm": preview["confirm"]})
    sent = json.loads(put.calls.last.request.content)
    assert "aaaClient" not in sent and sent["aaaNetwork"]["primaryServerIp"] == "198.18.134.35"


async def test_update_site_aaa_nothing_to_change(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    cur = {
        "serverType": "ISE",
        "protocol": "RADIUS",
        "primaryServerIp": "198.18.134.35",
        "pan": "198.18.134.35",
        "inheritedSiteName": "Global",
    }
    mock_aaa(api, {"aaaNetwork": cur}, {})
    async with Client(rw()) as c:
        out = await run(
            c,
            "catc_update_site_aaa_settings",
            {"site": "Global/AU", "network": {"server_type": "ISE", "primary": "198.18.134.35"}},
        )
    assert out["status"] == "blocked" and "Nothing to change" in json.dumps(out["blockers"])


async def test_update_site_aaa_inherit_blocked_without_parent_value(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    local = {"aaaClient": {"serverType": "ISE", "protocol": "RADIUS", "primaryServerIp": "198.18.134.35"}}
    mock_aaa(api, local, local)
    mock_sites(api, [GLOBAL, AREA_P])
    api.get(f"/dna/intent/api/v1/sites/{GLOBAL['id']}/aaaSettings").respond(json={"response": {}})
    async with Client(rw()) as c:
        out = await run(c, "catc_update_site_aaa_settings", {"site": "Global/AU", "inherit": ["client"]})
    assert out["status"] == "blocked" and "no parent site sets client AAA" in json.dumps(out["blockers"])


async def test_read_back_secret_never_previewed_or_resent(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    net = {
        "serverType": "ISE",
        "protocol": "RADIUS",
        "primaryServerIp": "198.18.134.35",
        "pan": "198.18.134.35",
        "sharedSecret": "read-back-secret",
    }
    put = mock_aaa(api, {"aaaNetwork": net}, {"aaaNetwork": net})
    args = {"site": "Global/AU", "client": {"server_type": "ISE", "primary": "198.18.134.35"}}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_site_aaa_settings", args)
        assert "read-back-secret" not in json.dumps(preview)
        await run(c, "catc_update_site_aaa_settings", {**args, "confirm": preview["confirm"]})
    sent = json.loads(put.calls.last.request.content)
    assert (
        "sharedSecret" not in sent["aaaNetwork"] and sent["aaaClient"]["primaryServerIp"] == "198.18.134.35"
    )


async def test_changed_secret_invalidates_confirm_token(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(json={"response": [ISE_SERVER]})
    put = mock_aaa(api, {}, {})
    ise = {"server_type": "ISE", "primary": "198.18.134.35"}
    args = {"site": "Global/AU", "client": ise, "client_shared_secret": SECRET}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_site_aaa_settings", args)
        res = await c.call_tool(
            "catc_update_site_aaa_settings",
            {**args, "client_shared_secret": "other", "confirm": preview["confirm"]},
            raise_on_error=False,
        )
    assert put.call_count == 0
    assert res.is_error or (res.structured_content or {}).get("status") != "applied"


async def test_secret_without_role_is_rejected(api: respx.MockRouter) -> None:
    async with Client(rw()) as c:
        res = await c.call_tool(
            "catc_update_site_aaa_settings",
            {"site": "Global/AU", "inherit": ["client"], "client_shared_secret": SECRET},
            raise_on_error=False,
        )
    assert res.is_error and SECRET not in str(res.content)
