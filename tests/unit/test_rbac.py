"""D17: least-privilege role definitions and the account check in catc_status."""

from typing import Any

import respx
from fastmcp import Client

from catc_mcp import rbac
from catc_mcp.server import create_server
from tests.unit.conftest import make_settings


def test_roles_are_nested() -> None:
    for perm, priv in rbac.READ.items():
        assert priv in ("Read", "Write"), perm
        assert rbac.WRITE[perm] in ("Read", "Write")
    assert set(rbac.READ) <= set(rbac.WRITE) <= set(rbac.DANGEROUS)
    order = {"Read": 1, "Write": 2}
    for perm in rbac.READ:
        assert order[rbac.READ[perm]] <= order[rbac.WRITE[perm]] <= order[rbac.DANGEROUS[perm]]
    assert all(v == "Read" for v in rbac.READ.values()), "the read-only role grants no Write"
    assert rbac.WRITE["Network Provision.Device Provision"] == "Read"
    assert rbac.DANGEROUS["Network Provision.Device Provision"] == "Write"


def perms(d: dict[str, str]) -> list[dict[str, str]]:
    return [{"id": k, "privilege": v} for k, v in d.items()]


def test_permissions_tier() -> None:
    assert rbac.permissions_tier(perms(rbac.READ)) == "ro"
    assert rbac.permissions_tier(perms(rbac.WRITE)) == "rw"
    assert rbac.permissions_tier(perms(rbac.DANGEROUS)) == "dangerous"
    assert rbac.permissions_tier([{"id": "Policy.Application Policy", "privilege": "Write"}]) == "admin"
    assert rbac.permissions_tier([{"id": "Network Operations.PnP", "privilege": "Write"}]) == "dangerous"
    assert rbac.permissions_tier([]) == "ro"


def test_account_check_warns_and_notes() -> None:
    out = rbac.account_check({"SUPER-ADMIN-ROLE": "admin"}, "rw")
    assert out["role_tier"] == "admin" and "least-privilege" in out["warning"]
    out = rbac.account_check({"mcp-catc-rw": "rw"}, "rw")
    assert "warning" not in out and "note" not in out
    out = rbac.account_check({"mcp-catc-ro": "ro"}, "dangerous")
    assert "refuse" in out["note"]
    assert rbac.account_check({}, "ro")["role_tier"] == "unknown"
    assert rbac.enabled_tier(True, True) == "dangerous" and rbac.enabled_tier(False, True) == "ro"


async def status(settings: Any) -> dict[str, Any]:
    async with Client(create_server(settings)) as c:
        res = await c.call_tool("catc_status", {})
        return res.structured_content["catc"]  # type: ignore[index]


async def test_status_reports_super_admin(api: respx.MockRouter) -> None:
    out = await status(make_settings())
    assert out["account"]["roles"] == ["SUPER-ADMIN-ROLE"]
    assert out["account"]["enabled_tier"] == "ro" and "warning" in out["account"]


async def test_status_custom_role(api: respx.MockRouter) -> None:
    api.get("/dna/system/api/v1/user").respond(
        json={"response": {"users": [{"username": "mcp-catc-rw", "roleList": ["mcp-catc-rw"]}]}}
    )
    api.get("/dna/system/api/v2/roles/mcp-catc-rw").respond(
        json={"id": "mcp-catc-rw", "permissions": perms(rbac.WRITE)}
    )
    out = await status(make_settings(username="mcp-catc-rw", mcp_enable_writes=True))
    assert out["account"] == {"roles": ["mcp-catc-rw"], "role_tier": "rw", "enabled_tier": "rw"}


async def test_status_account_unavailable(api: respx.MockRouter) -> None:
    api.get("/dna/system/api/v1/user").respond(403, json={"response": {"message": "denied"}})
    out = await status(make_settings())
    assert "unavailable" in out["account"] and out["devices"] == 0


async def test_status_unknown_role(api: respx.MockRouter) -> None:
    api.get("/dna/system/api/v1/user").respond(
        json={"response": {"users": [{"username": "x", "roleList": ["gone"]}]}}
    )
    api.get("/dna/system/api/v2/roles/gone").respond(404, json={"response": {"message": "no"}})
    out = await status(make_settings(username="x"))
    assert out["account"]["role_tier"] == "unknown" and "warning" not in out["account"]
