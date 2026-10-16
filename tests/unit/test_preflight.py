"""D32: `catc-mcp-server check` against a mocked Catalyst Center, one test per failure mode."""

import json
from typing import Any

import httpx
import pytest
import respx

from catc_mcp import main
from catc_mcp._core.preflight import run_preflight
from catc_mcp.preflight import preflight
from tests.unit.conftest import BASE, make_settings

LOGIN = "/dna/system/api/v1/auth/token"
USERS = "/dna/system/api/v1/user"
POLICY = "/dna/intent/api/v1/authentication-policy-servers"
ISE_ACTIVE = [
    {
        "ipAddress": "198.51.100.10",
        "isIseEnabled": True,
        "state": "ACTIVE",
        "ciscoIseDtos": [{"role": "PRIMARY", "fqdn": "ise.example.com", "trustState": "TRUSTED"}],
    }
]
RO_PERMISSIONS = [
    {"id": "Assurance.Monitoring", "privilege": "Read"},
    {"id": "Network Management.Inventory", "privilege": "Read"},
]
RW_PERMISSIONS = [
    {"id": "Assurance.Monitoring", "privilege": "Write"},
    {"id": "Network Management.Inventory", "privilege": "Write"},
]


def _mock(
    router: respx.MockRouter,
    *,
    version: str = "3.2.2-75131",
    roles: list[str] | None = None,
    users: httpx.Response | None = None,
    policy: list[dict[str, Any]] | httpx.Response | None = None,
) -> None:
    router.post(LOGIN).respond(json={"Token": "tok-123"})
    router.get("/dna/intent/api/v1/dnac-release").respond(json={"response": {"installedVersion": version}})
    if users is not None:
        router.get(USERS).mock(return_value=users)
    else:
        user = {"username": "admin", "roleList": roles if roles is not None else ["mcp-catc-ro"]}
        router.get(USERS).respond(json={"response": {"users": [user]}})
    router.get("/dna/system/api/v2/roles/mcp-catc-ro").respond(
        json={"response": {"name": "mcp-catc-ro", "permissions": RO_PERMISSIONS}}
    )
    router.get("/dna/system/api/v2/roles/mcp-catc-rw").respond(
        json={"response": {"name": "mcp-catc-rw", "permissions": RW_PERMISSIONS}}
    )
    router.get("/dna/system/api/v2/roles/mystery").respond(403)
    if isinstance(policy, httpx.Response):
        router.get(POLICY).mock(return_value=policy)
    else:
        router.get(POLICY).respond(json={"response": ISE_ACTIVE if policy is None else policy})


async def _run(**kw: Any) -> dict[str, Any]:
    return await run_preflight(
        make_settings(**kw),
        preflight,
        server="catc-mcp-server",
        product="Catalyst Center",
        env_prefix="CATC_",
    )


def _rows(report: dict[str, Any], check: str, inst: int = 0) -> list[dict[str, Any]]:
    return [c for c in report["instances"][inst]["checks"] if c["check"] == check]


def _one(report: dict[str, Any], check: str) -> dict[str, Any]:
    (row,) = _rows(report, check)
    return row


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as r:
        yield r


async def test_healthy_read_only(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run()
    assert report["ok"]
    reach = _rows(report, "reachability")
    assert [r["surface"] for r in reach] == ["login", "intent"]
    assert all(r["outcome"] == "ok" for r in reach) and "3.2.2-75131" in reach[1]["detail"]
    assert _one(report, "tls")["outcome"] == "ok"
    auth = _one(report, "auth")
    assert auth["outcome"] == "ok" and "renewed" in auth["detail"]
    role = _one(report, "role")
    assert role["outcome"] == "ok" and "mcp-catc-ro (ro)" in role["detail"]
    version = _one(report, "version")
    assert version["outcome"] == "ok" and "3.2.2" in version["detail"]
    ise = _one(report, "ise")
    assert ise["outcome"] == "ok" and "ACTIVE" in ise["detail"]
    assert "pw" not in json.dumps(report).replace("pwd", "")
    assert "tok-123" not in json.dumps(report)


async def test_unreachable(router: respx.MockRouter) -> None:
    router.route().mock(side_effect=httpx.ConnectError("no route to host"))
    report = await _run()
    (reach,) = _rows(report, "reachability")
    assert reach["outcome"] == "fail" and reach["surface"] == "login" and "CATC_URL" in reach["hint"]
    assert _one(report, "role")["outcome"] == "skip"
    assert not _rows(report, "ise")


async def test_tls_not_trusted(router: respx.MockRouter) -> None:
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed")
    router.route().mock(side_effect=err)
    report = await _run()
    tls = _one(report, "tls")
    assert tls["outcome"] == "fail" and "CATC_CA_BUNDLE" in tls["hint"]
    assert _one(report, "version")["outcome"] == "skip"


async def test_wrong_password(router: respx.MockRouter) -> None:
    router.post(LOGIN).respond(401, json={"error": "Authentication has failed"})
    report = await _run()
    auth = _one(report, "auth")
    assert auth["outcome"] == "fail" and "CATC_PASSWORD" in auth["hint"]
    assert _one(report, "role")["outcome"] == "skip"
    assert not report["ok"]


async def test_static_token_warns(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run(username=None, password=None, token="tok-static-9f3")
    assert [r["surface"] for r in _rows(report, "reachability")] == ["intent"]
    auth = _one(report, "auth")
    assert auth["outcome"] == "warn" and "CATC_USERNAME" in auth["hint"]
    assert _one(report, "role")["outcome"] == "ok"  # read-only: nothing more to know
    assert "tok-static-9f3" not in json.dumps(report)


async def test_read_only_role_with_writes_on_fails(router: respx.MockRouter) -> None:
    _mock(router, roles=["OBSERVER-ROLE"])
    report = await _run(mcp_enable_writes=True)
    role = _one(report, "role")
    assert role["outcome"] == "fail" and "write" in role["detail"]
    assert "MCP_ENABLE_WRITES=false" in role["hint"]
    assert not report["ok"]


async def test_rw_role_missing_dangerous_tier(router: respx.MockRouter) -> None:
    _mock(router, roles=["mcp-catc-rw"])
    assert _one(await _run(mcp_enable_writes=True), "role")["outcome"] == "ok"
    report = await _run(mcp_enable_writes=True, mcp_enable_dangerous=True)
    role = _one(report, "role")
    assert role["outcome"] == "fail" and "dangerous" in role["detail"]


async def test_super_admin_on_read_only_server_warns(router: respx.MockRouter) -> None:
    _mock(router, roles=["SUPER-ADMIN-ROLE"])
    report = await _run()
    role = _one(report, "role")
    assert role["outcome"] == "warn" and "read-only account" in role["hint"]
    assert report["ok"]


async def test_super_admin_with_every_tier_still_warns(router: respx.MockRouter) -> None:
    _mock(router, roles=["SUPER-ADMIN-ROLE"])
    role = _one(await _run(mcp_enable_writes=True, mcp_enable_dangerous=True), "role")
    assert role["outcome"] == "warn" and "mcp-catc-dangerous" in role["hint"]


async def test_unknown_role(router: respx.MockRouter) -> None:
    _mock(router, roles=["mystery"])  # the custom role can't be read (403)
    assert _one(await _run(), "role")["outcome"] == "ok"  # reads work; nothing more is enabled
    role = _one(await _run(mcp_enable_writes=True), "role")
    assert role["outcome"] == "warn" and "could not tell" in role["detail"]


async def test_roles_unreadable_or_external_account(router: respx.MockRouter) -> None:
    _mock(router, users=httpx.Response(403))
    role = _one(await _run(mcp_enable_writes=True), "role")
    assert role["outcome"] == "warn" and "System Administration Read" in role["detail"]
    router.get(USERS).respond(json={"response": {"users": [{"username": "someone-else", "roleList": []}]}})
    role = _one(await _run(mcp_enable_writes=True), "role")
    assert role["outcome"] == "warn" and "not a local user" in role["detail"]


@pytest.mark.parametrize(
    ("version", "outcome"),
    [("3.2.2-75131", "ok"), ("3.1.3.0", "warn"), ("2.3.7.6", "warn"), ("2.3.5.5", "fail")],
)
async def test_version_matrix(router: respx.MockRouter, version: str, outcome: str) -> None:
    _mock(router, version=version)
    row = _one(await _run(), "version")
    assert row["outcome"] == outcome and "bundled API spec 3.2.2-75131" in row["detail"]


@pytest.mark.parametrize(
    ("policy", "outcome", "text"),
    [
        (None, "ok", "ACTIVE"),
        ([], "warn", "no Cisco ISE integrated"),
        ([{"ipAddress": "198.51.100.20", "isIseEnabled": False, "state": "ACTIVE"}], "warn", "1 plain AAA"),
        ([{**ISE_ACTIVE[0], "state": "FAILED"}], "warn", "integration FAILED: ERS unreachable"),
        (httpx.Response(403), "warn", "could not read"),
    ],
)
async def test_ise_integration(router: respx.MockRouter, policy: Any, outcome: str, text: str) -> None:
    _mock(router, policy=policy)
    router.get("/dna/intent/api/v1/ise-integration-status").respond(
        json={"overallStatus": "FAILED", "overallErrorMessage": "ERS unreachable", "steps": []}
    )
    report = await _run()
    ise = _one(report, "ise")
    assert ise["outcome"] == outcome and text in ise["detail"]
    assert report["ok"]  # informational: never fails the check


async def test_two_instances(router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATC_LAB_URL", "https://catc-lab.test")
    monkeypatch.setenv("CATC_LAB_USERNAME", "ro")
    monkeypatch.setenv("CATC_LAB_PASSWORD", "x")
    _mock(router)
    respx.route(host="catc-lab.test").mock(side_effect=httpx.ConnectError("no route to host"))
    report = await _run(instances="lab")
    assert [i["instance"] for i in report["instances"]] == ["default", "lab"]
    assert report["instances"][0]["ok"] and not report["instances"][1]["ok"]
    assert not report["ok"]


def test_cli_check_json(
    router: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    for k, v in {
        "CATC_URL": BASE,
        "CATC_USERNAME": "admin",
        "CATC_PASSWORD": "s3cret",
        "CATC_RETRIES": "0",
    }.items():
        monkeypatch.setenv(k, v)
    _mock(router)
    monkeypatch.setattr("sys.argv", ["catc-mcp-server", "check", "--json"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["ok"] is True and report["server"] == "catc-mcp-server"
    assert "s3cret" not in out and "tok-123" not in out
