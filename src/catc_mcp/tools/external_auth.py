"""Catalyst Center admin login through ISE (D88): external authentication (System > Users & Roles >
External Authentication). Catalyst Center sends GUI/API logins it can't match to a local user (and, on some
releases, every login) to its AAA servers over RADIUS or TACACS+; the server's answer carries the role in an
AVPair (`Role=SUPER-ADMIN-ROLE` etc. in the configured AAA attribute, Cisco-AVPair by default).
Passwords and shared secrets are never returned; catc_test_login never stores or logs its credentials."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import base64
import binascii
import json
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field, SecretStr

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from catc_mcp._core.http import basic_header
from catc_mcp._core.secrets import register_secret
from catc_mcp.client import LOGIN_PATH, CatcApp
from catc_mcp.common import ensure_list, gather_sections, pick

FLAG_PATH = "/dna/system/api/v1/users/external-authentication"
SERVERS_PATH = "/dna/system/api/v1/users/external-servers"
ATTRIBUTE_PATH = "/dna/system/api/v1/users/external-servers/aaa-attribute"
ROLES_PATH = "/dna/system/api/v1/roles"
USERS_PATH = "/dna/system/api/v1/user"
DEFAULT_ATTRIBUTE = {"RADIUS": "Cisco-AVPair", "TACACS": "cisco-av-pair"}
BUILTIN_ROLES = ("SUPER-ADMIN-ROLE", "NETWORK-ADMIN-ROLE", "OBSERVER-ROLE")
SERVER_FIELDS = [
    "serverIp",
    "serverId",
    "protocol",
    "role",
    "authenticationPort",
    "accountingPort",
    "retries",
    "socketTimeout",
    "aaaAttribute",
]
# Token claims worth reporting (never the token itself).
CLAIMS = ["username", "authSource", "roles", "tenantName", "exp", "iat"]


def enabled_of(body: Any) -> bool | None:
    flags = ensure_list((body or {}).get("external-authentication-flag")) if isinstance(body, dict) else []
    for f in flags:
        if isinstance(f, dict) and isinstance(f.get("enabled"), bool):
            return bool(f["enabled"])
    return None


def attribute_of(body: Any) -> str | None:
    rows = ensure_list((body or {}).get("aaa-attributes")) if isinstance(body, dict) else []
    names = [str(r.get("attributeName") or "").strip() for r in rows if isinstance(r, dict)]
    return next((n for n in names if n), None)


def servers_of(body: Any) -> list[dict[str, Any]]:
    rows = ensure_list((body or {}).get("aaa-servers")) if isinstance(body, dict) else []
    return [pick(r, SERVER_FIELDS) for r in rows if isinstance(r, dict)]  # sharedSecret is not picked


def roles_of(body: Any) -> list[dict[str, Any]]:
    rows = ensure_list((body or {}).get("roles")) if isinstance(body, dict) else []
    return [pick(r, ["name", "type", "description"]) for r in rows if isinstance(r, dict)]


def users_of(body: Any) -> list[dict[str, Any]]:
    rows = ensure_list((body or {}).get("users")) if isinstance(body, dict) else []
    return [pick(u, ["username", "authSource", "roleList"]) for u in rows if isinstance(u, dict)]


def token_claims(token: str) -> dict[str, Any]:
    """The informative claims of a Catalyst Center token (a JWT; not verified: CatC just issued it)."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    pad = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(pad))
    except (binascii.Error, ValueError):
        return {}
    return pick(claims, CLAIMS) if isinstance(claims, dict) else {}


async def read_state(app: CatcApp) -> tuple[dict[str, Any], dict[str, str]]:
    ok, errors = await gather_sections(
        {
            "flag": app.get_response(FLAG_PATH),
            "servers": app.get_response(SERVERS_PATH, {"invokeSource": "external"}),
            "attribute": app.get_response(ATTRIBUTE_PATH),
        }
    )
    state: dict[str, Any] = {
        "enabled": enabled_of(ok.get("flag")),
        "aaa_attribute": attribute_of(ok.get("attribute")),
        "servers": servers_of(ok.get("servers")),
    }
    return state, errors


def default_attribute(servers: list[dict[str, Any]]) -> str:
    protos = {str(s.get("protocol") or "").upper() for s in servers}
    return DEFAULT_ATTRIBUTE["TACACS"] if protos == {"TACACS"} else DEFAULT_ATTRIBUTE["RADIUS"]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="External authentication (admin login through AAA)")
    async def catc_get_external_authentication(ctx: Context) -> dict[str, Any]:
        """How Catalyst Center admins log in: whether external authentication (System > Users & Roles >
        External Authentication) is on, the AAA attribute it reads the role from (empty = the default,
        Cisco-AVPair for RADIUS / cisco-av-pair for TACACS+), the AAA servers it asks (from the
        authentication and policy servers, e.g. the integrated ISE), the roles an external user can be
        given (the value the AAA server must return: 'Role=<name>'), and the external users that have
        logged in so far. Shared secrets are never returned. Change it with
        catc_set_external_authentication; prove a login with catc_test_login."""
        app: CatcApp = get_client(ctx)
        state, errors = await read_state(app)
        extra, more = await gather_sections(
            {
                "roles": app.get_response(ROLES_PATH),
                "users": app.get_response(USERS_PATH, {"authSource": "external"}),
            }
        )
        errors |= more
        attr = state["aaa_attribute"]
        out: dict[str, Any] = {
            "enabled": state["enabled"],
            "aaa_attribute": attr or f"(default: {default_attribute(state['servers'])})",
            "servers": state["servers"],
            "roles": roles_of(extra.get("roles")),
            "external_users": users_of(extra.get("users")),
            "server_reply": f"{attr or default_attribute(state['servers'])}=Role=<role name>, e.g. "
            "Role=OBSERVER-ROLE (an ISE authorization profile's advanced attribute "
            "cisco-av-pair = Role=OBSERVER-ROLE)",
        }
        if not state["servers"]:
            out["note"] = (
                "No AAA server for external users: add one under Authentication and Policy Servers "
                "(catc_add_ise_server) first."
            )
        if errors:
            out["unavailable"] = errors
        return out

    @reg.dangerous(title="Turn external authentication on or off")
    async def catc_set_external_authentication(
        ctx: Context,
        enable: Annotated[
            bool, Field(description="true: admin logins go to the AAA servers; false: local only")
        ],
        aaa_attribute: Annotated[
            str | None,
            Field(
                min_length=1,
                max_length=64,
                description="AAA attribute carrying 'Role=<role>' (default Cisco-AVPair for RADIUS); "
                "only set it when your AAA server uses another one",
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn Catalyst Center's external authentication on or off (System > Users & Roles > External
        Authentication), optionally setting the AAA attribute first. With it on, a GUI or API login is
        sent to the AAA servers listed in the preview (RADIUS or TACACS+); the server must answer with
        '<attribute>=Role=<SUPER-ADMIN-ROLE|NETWORK-ADMIN-ROLE|OBSERVER-ROLE|custom role>' or the user
        gets no access. LOCKOUT RISK: some releases ask the AAA server first and fall back to the local
        user list only when it is unreachable, so a local account (including the one this server uses)
        may stop working while ISE answers 'reject'. Before enabling: hold a working local session,
        mirror the local accounts in ISE, and re-test a local login (catc_test_login) right after.
        Dangerous tier; preview-first. Needs a SUPER-ADMIN account."""
        app: CatcApp = get_client(ctx)
        state, errors = await read_state(app)
        if "flag" in errors:
            raise UpstreamError(f"Can't read the external authentication setting: {errors['flag']}")
        servers = state["servers"]
        current_attr = state["aaa_attribute"]
        want_attr = aaa_attribute.strip() if aaa_attribute else None
        if want_attr is not None and not want_attr.replace("-", "").replace("_", "").isalnum():
            raise InvalidRequest(f"aaa_attribute {want_attr!r}: letters, digits, '-' and '_' only.")
        blockers: list[str] = []
        set_attr = want_attr is not None and want_attr != (current_attr or default_attribute(servers))
        if enable and not servers:
            blockers.append(
                "No RADIUS/TACACS server is available for external users (users/external-servers is "
                "empty): integrate ISE or add an AAA server first."
            )
        if state["enabled"] is enable and not set_attr:
            blockers.append(f"External authentication is already {'on' if enable else 'off'}.")
        attr = want_attr or current_attr or default_attribute(servers)
        steps: list[dict[str, Any]] = []
        if set_attr:
            steps.append({"method": "POST", "path": ATTRIBUTE_PATH, "body": {"attributeName": want_attr}})
        if state["enabled"] is not enable:
            steps.append({"method": "POST", "path": FLAG_PATH, "body": {"enable": enable}})
        effects = (
            [
                "Admin logins (GUI and API) are sent to "
                + ", ".join(f"{s.get('serverIp')} ({s.get('protocol')}, {s.get('role')})" for s in servers)
                + f"; a user gets the role in the reply's {attr} 'Role=<role>' value (no role: no access).",
                "Lockout risk: a local account may stop working while the AAA server answers (some releases "
                "use the local user list only when the server is unreachable). Keep a session open, have the "
                "local accounts mirrored on the AAA server, and test a local login right after "
                "(catc_test_login); undo with catc_set_external_authentication(enable=false).",
                "Catalyst Center must be a network device (NAD) on ISE with the shared secret of its "
                "authentication and policy server entry, and an ISE authorization rule must return the role.",
            ]
            if enable
            else [
                "Only local users can log in again; external users already logged in keep their session "
                "until it expires."
            ]
        )
        plan = Plan(
            ("Enable" if enable else "Disable")
            + " external authentication"
            + (f" (AAA attribute {want_attr})" if set_attr else ""),
            details={
                "current": {"enabled": state["enabled"], "aaa_attribute": current_attr or "(default)"},
                "steps": steps,
                "servers": servers,
                "effects": effects,
            },
            fingerprint={"state": state},
            blockers=blockers,
        )

        async def apply() -> Any:
            for step in steps:
                await app.api.request(step["method"], step["path"], json=step["body"])
            now, errs = await read_state(app)
            out: dict[str, Any] = {
                "enabled": now["enabled"],
                "aaa_attribute": now["aaa_attribute"] or "(default)",
            }
            if errs:
                out["unavailable"] = errs
            if enable:
                out["next"] = (
                    "Test a local login now (catc_test_login with a local admin); if it fails, disable "
                    "with catc_set_external_authentication(enable=false) from a session that still works."
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_set_external_authentication",
            args={"enable": enable, "aaa_attribute": want_attr},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="Test a Catalyst Center login")
    async def catc_test_login(
        ctx: Context,
        username: Annotated[str, Field(min_length=1, max_length=128, description="User to log in as")],
        password: Annotated[
            SecretStr, Field(description="That user's password (never stored, logged or returned)")
        ],
    ) -> dict[str, Any]:
        """Prove that a user can log in to Catalyst Center (a local account, or an external one through
        ISE when external authentication is on): one token request with these credentials, nothing
        else. Reports pass/fail, Catalyst Center's reason on failure, and on success the roles and auth
        source Catalyst Center granted (from the token and the user list). The password and the token
        are never stored, logged or returned; the token simply expires. Each failed try counts towards
        Catalyst Center's lockout of that account."""
        app: CatcApp = get_client(ctx)
        user = username.strip()
        if not user or any(not ch.isprintable() for ch in user):
            raise InvalidRequest("username must be printable text.")
        secret = password.get_secret_value()
        register_secret(secret)
        resp = await app.api.send_raw(
            "POST", LOGIN_PATH, headers={"Authorization": basic_header(user, secret)}
        )
        out: dict[str, Any] = {"username": user, "http_status": resp.status_code}
        if resp.status_code != 200:
            out["login"] = "failed"
            try:
                detail = resp.json()
            except ValueError:
                detail = resp.text[:200]
            reason = detail.get("error") or detail.get("message") if isinstance(detail, dict) else detail
            out["reason"] = str(reason or f"HTTP {resp.status_code}")[:300]
            return out
        try:
            token = str(resp.json()["Token"])
        except (ValueError, KeyError, TypeError):
            out |= {"login": "failed", "reason": "no Token in the login response"}
            return out
        register_secret(token)
        out["login"] = "passed"
        claims = token_claims(token)
        if claims:
            out["token_claims"] = claims
        # What Catalyst Center recorded for the user (the server's own account reads the user list).
        try:
            users = users_of(await app.get_response(USERS_PATH))
            me = next((u for u in users if u.get("username") == user), None)
            if me:
                out["user"] = me
        except UpstreamError as e:
            out["user_lookup"] = f"unavailable: {str(e)[:150]}"
        roles = (out.get("user") or {}).get("roleList") or claims.get("roles")
        if roles:
            out["roles"] = roles
        return out
