"""D88: external authentication (admin login through ISE) and catc_test_login, on payloads recorded from the
3.2.2 lab (tests/fixtures/external_auth_322.json). Secrets, passwords and tokens never leak."""

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import run

FIX = json.loads((Path(__file__).parent.parent / "fixtures" / "external_auth_322.json").read_text())
FLAG = "/dna/system/api/v1/users/external-authentication"
SERVERS = "/dna/system/api/v1/users/external-servers"
ATTR = "/dna/system/api/v1/users/external-servers/aaa-attribute"
LOGIN = "/dna/system/api/v1/auth/token"
PASSWORD = "Ad-user-pa55-d88"


def rw() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


def mock_state(api: respx.MockRouter, enabled: bool = False, servers: Any = None) -> dict[str, Any]:
    state = {"enabled": enabled, "attr": ""}
    api.get(FLAG).mock(
        side_effect=lambda r: httpx.Response(
            200, json={"response": {"external-authentication-flag": [{"enabled": state["enabled"]}]}}
        )
    )
    api.get(SERVERS).respond(json=FIX["servers"] if servers is None else servers)
    api.get(ATTR).mock(
        side_effect=lambda r: httpx.Response(
            200, json={"response": {"aaa-attributes": [{"attributeName": state["attr"]}]}}
        )
    )
    return state


def jwt(claims: dict[str, Any]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.c2lnbmF0dXJl"


async def test_get_external_authentication_recorded(api: respx.MockRouter) -> None:
    mock_state(api)
    api.get("/dna/system/api/v1/roles").respond(json=FIX["roles"])
    users = api.get("/dna/system/api/v1/user").respond(json=FIX["external_users_none"])
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_get_external_authentication", {})
    assert out["enabled"] is False and out["aaa_attribute"] == "(default: Cisco-AVPair)"
    assert out["servers"] == [
        {
            "serverIp": "198.18.134.35",
            "serverId": "6ad83e8813f2e5004f400f5c",
            "protocol": "RADIUS",
            "role": "primary",
            "authenticationPort": 1812,
            "accountingPort": 1813,
            "retries": 3,
            "socketTimeout": 4,
        }
    ]
    assert {r["name"] for r in out["roles"]} == {"SUPER-ADMIN-ROLE", "OBSERVER-ROLE", "NETWORK-ADMIN-ROLE"}
    assert out["external_users"] == [] and "sharedSecret" not in json.dumps(out)
    assert "Role=OBSERVER-ROLE" in out["server_reply"]
    assert users.calls.last.request.url.params["authSource"] == "external"


async def test_enable_previews_risk_then_posts(api: respx.MockRouter) -> None:
    state = mock_state(api)

    def flip(request: httpx.Request) -> httpx.Response:
        state["enabled"] = json.loads(request.content)["enable"]
        return httpx.Response(200, json={"response": {"message": "ok"}})

    post = api.post(FLAG).mock(side_effect=flip)
    attr = api.post(ATTR)
    async with Client(rw()) as c:
        preview = await run(c, "catc_set_external_authentication", {"enable": True})
        p = preview["preview"]
        assert preview["status"] == "preview" and post.call_count == 0
        assert p["steps"] == [{"method": "POST", "path": FLAG, "body": {"enable": True}}]
        assert "198.18.134.35 (RADIUS, primary)" in p["effects"][0] and "Lockout risk" in p["effects"][1]
        done = await run(
            c, "catc_set_external_authentication", {"enable": True, "confirm": preview["confirm"]}
        )
    assert json.loads(post.calls.last.request.content) == {"enable": True} and attr.call_count == 0
    assert done["result"]["enabled"] is True and "catc_test_login" in done["result"]["next"]


async def test_enable_blocked_without_servers_and_when_already_on(api: respx.MockRouter) -> None:
    mock_state(api, servers={"response": {"aaa-servers": []}})
    async with Client(rw()) as c:
        out = await run(c, "catc_set_external_authentication", {"enable": True})
    assert out["status"] == "blocked" and "No RADIUS/TACACS server" in json.dumps(out["blockers"])


async def test_disable_when_on_and_noop_blocked(api: respx.MockRouter) -> None:
    state = mock_state(api, enabled=True)
    post = api.post(FLAG).respond(json={"response": {"message": "ok"}})
    async with Client(rw()) as c:
        preview = await run(c, "catc_set_external_authentication", {"enable": False})
        assert preview["preview"]["steps"][0]["body"] == {"enable": False}
        state["enabled"] = False
        again = await run(c, "catc_set_external_authentication", {"enable": False})
    assert again["status"] == "blocked" and "already off" in json.dumps(again["blockers"])
    assert post.call_count == 0


async def test_custom_attribute_set_first(api: respx.MockRouter) -> None:
    mock_state(api)
    calls: list[str] = []
    api.post(ATTR).mock(side_effect=lambda r: calls.append("attr") or httpx.Response(200, json={}))
    api.post(FLAG).mock(side_effect=lambda r: calls.append("flag") or httpx.Response(200, json={}))
    args = {"enable": True, "aaa_attribute": "My-Role-Attr"}
    async with Client(rw()) as c:
        preview = await run(c, "catc_set_external_authentication", args)
        assert [s["path"] for s in preview["preview"]["steps"]] == [ATTR, FLAG]
        await run(c, "catc_set_external_authentication", {**args, "confirm": preview["confirm"]})
        bad = await c.call_tool(
            "catc_set_external_authentication",
            {"enable": True, "aaa_attribute": "a b;c"},
            raise_on_error=False,
        )
    assert calls == ["attr", "flag"] and bad.is_error


async def test_test_login_passes_reports_roles_never_the_secrets(api: respx.MockRouter) -> None:
    token = jwt({"username": "mcp-ad-observer", "authSource": "external", "roles": ["OBSERVER"], "x": 1})

    def login(request: httpx.Request) -> httpx.Response:
        expected = base64.b64encode(f"mcp-ad-observer:{PASSWORD}".encode()).decode()
        if request.headers["Authorization"] == f"Basic {expected}":
            return httpx.Response(200, json={"Token": token})
        return httpx.Response(200, json={"Token": "tok-123"})  # the server's own account

    api.post(LOGIN).mock(side_effect=login)
    api.get("/dna/system/api/v1/user").respond(
        json={
            "response": {
                "users": [
                    {"username": "admin", "roleList": ["SUPER-ADMIN-ROLE"], "authSource": "internal"},
                    {"username": "mcp-ad-observer", "roleList": ["OBSERVER-ROLE"], "authSource": "external"},
                ]
            }
        }
    )
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_test_login", {"username": "mcp-ad-observer", "password": PASSWORD})
    text = json.dumps(out)
    assert out["login"] == "passed" and out["roles"] == ["OBSERVER-ROLE"]
    assert out["token_claims"] == {
        "username": "mcp-ad-observer",
        "authSource": "external",
        "roles": ["OBSERVER"],
    }
    assert out["user"]["authSource"] == "external"
    assert PASSWORD not in text and token not in text and token.split(".")[1] not in text


async def test_test_login_failure_reason(api: respx.MockRouter) -> None:
    def login(request: httpx.Request) -> httpx.Response:
        if "admin:pw" in base64.b64decode(request.headers["Authorization"].split()[1]).decode():
            return httpx.Response(200, json={"Token": "tok-123"})
        return httpx.Response(
            401, json={"error": "Authentication has failed. Please provide valid credentials."}
        )

    api.post(LOGIN).mock(side_effect=login)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_test_login", {"username": "nobody", "password": PASSWORD})
    assert out["login"] == "failed" and out["http_status"] == 401 and "valid credentials" in out["reason"]
    assert PASSWORD not in json.dumps(out)


async def test_test_login_reports_catc_text_reason(api: respx.MockRouter) -> None:
    """3.2.2 live: an ISE reply with a custom role -> 400 with a plain-text reason."""

    def login(request: httpx.Request) -> httpx.Response:
        if "admin:pw" in base64.b64decode(request.headers["Authorization"].split()[1]).decode():
            return httpx.Response(200, json={"Token": "tok-123"})
        return httpx.Response(
            400, text="Invalid user profile. Please check your Radius/TACACS+ configuration."
        )

    api.post(LOGIN).mock(side_effect=login)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_test_login", {"username": "mcp-catc-ro", "password": PASSWORD})
    assert out["login"] == "failed" and out["http_status"] == 400
    assert out["reason"].startswith("Invalid user profile")
