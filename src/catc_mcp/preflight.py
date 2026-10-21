"""`catc-mcp-server check` (D32): what an operator needs to know before connecting a client.

Rows: the token login (POST /dna/system/api/v1/auth/token) and the Intent API, TLS trust, credentials, the API
account's roles vs the enabled tiers (docs/least-privilege.md, rbac.py), the Catalyst Center release vs the
bundled spec, and the ISE integration (informational: it never fails the check).
"""

from __future__ import annotations

from typing import Any

from catc_mcp._core import UpstreamError
from catc_mcp._core.http import LoginTokenAuth
from catc_mcp._core.preflight import Outcome, Preflight
from catc_mcp.client import LOGIN_PATH, TOKEN_LIFETIME, CatcApp
from catc_mcp.common import ensure_list
from catc_mcp.config import Settings
from catc_mcp.rbac import TIER_ORDER
from catc_mcp.server import SPEC_VERSION
from catc_mcp.tools.aaa import POLICY_PATH, integration_status

TESTED = (SPEC_VERSION.split("-")[0],)  # the bundled spec's release (3.2.2), live-tested
MINIMUM = "2.3.7"  # README: the long-standing Intent API endpoints should work from 2.3.7.x

# Server tier of a role (rbac.BUILTIN_TIERS / permissions_tier) -> (write allowed, dangerous allowed).
_ALLOWS: dict[str, tuple[bool, bool]] = {
    "ro": (False, False),
    "rw": (True, False),
    "dangerous": (True, True),
    "admin": (True, True),
}


def _access_of(tiers: dict[str, str]) -> tuple[str, bool | None, bool | None]:
    """The highest tier among the roles and what it allows; a role that couldn't be read turns every "no"
    into "can't tell" (it might grant more)."""
    tier = max(tiers.values(), key=lambda t: TIER_ORDER.get(t, -1)) if tiers else "unknown"
    if tier not in _ALLOWS:
        return tier, None, None
    write, dangerous = _ALLOWS[tier]
    if "unknown" in tiers.values():
        return tier, write or None, dangerous or None
    return tier, write, dangerous


async def _role(app: CatcApp, pf: Preflight) -> None:
    if not app.settings.username:
        pf.access(write=None, detail="a static CATC_TOKEN does not say which account it belongs to")
        return
    try:
        tiers = await app.role_tiers()
    except UpstreamError as e:
        pf.access(
            write=None,
            detail=f"Catalyst Center did not list the account's roles ({str(e)[:160]}); reading users needs "
            "System Administration Read",
        )
        return
    if tiers is None:
        pf.access(write=None, detail=f"{app.settings.username!r} is not a local user (external/AAA login?)")
        return
    tier, write, dangerous = _access_of(tiers)
    role = ", ".join(f"{name} ({t})" for name, t in sorted(tiers.items())) or "none"
    row = pf.access(write=write, dangerous=dangerous, role=role)
    if tier == "admin" and row.outcome is Outcome.OK:
        row.outcome = Outcome.WARN
        row.detail = f"{row.detail}, but it is an administrator role (more than any tier needs)"
        row.hint = (
            "Use the custom role mcp-catc-dangerous (or mcp-catc-rw / mcp-catc-ro) instead of "
            f"SUPER-ADMIN-ROLE ({pf.least_privilege_doc})."
        )


def _ise_row(server: dict[str, Any]) -> dict[str, Any]:
    nodes = [n for n in ensure_list(server.get("ciscoIseDtos")) if isinstance(n, dict)]
    return {
        "ip": server.get("ipAddress"),
        "state": server.get("state"),
        "nodes": [{k: n.get(k) for k in ("role", "fqdn", "trustState") if n.get(k)} for n in nodes],
    }


async def _ise(app: CatcApp, pf: Preflight) -> None:
    """ISE integration state, as catc_get_system_health / catc_get_policy_servers report it. Informational:
    ok when an integrated ISE is ACTIVE, otherwise a warning (never a failure)."""
    try:
        servers = [s for s in ensure_list(await app.get_response(POLICY_PATH)) if isinstance(s, dict)]
    except UpstreamError as e:
        pf.warn(
            "ise",
            f"could not read the authentication and policy servers ({str(e)[:160]})",
            hint="Reading them needs System Settings Read (docs/least-privilege.md); only "
            "catc_get_policy_servers and the AAA site settings depend on it.",
        )
        return
    ise = [s for s in servers if s.get("isIseEnabled") or s.get("iseEnabled")]
    if not ise:
        others = f" ({len(servers)} plain AAA server(s))" if servers else ""
        pf.warn(
            "ise",
            f"no Cisco ISE integrated{others}",
            hint="Only needed for ISE-based site AAA and SD-Access: System > Settings > Authentication and "
            "Policy Servers, or catc_add_ise_server (dangerous tier).",
        )
        return
    rows = [_ise_row(s) for s in ise]
    states = ", ".join(f"{r['ip']} {r['state'] or 'unknown'}" for r in rows)
    if all(str(r["state"] or "").upper() == "ACTIVE" for r in rows):
        pf.ok("ise", f"Cisco ISE integrated: {states}", servers=rows)
        return
    detail = f"Cisco ISE integration is not ACTIVE: {states}"
    try:
        status = await integration_status(app)
    except UpstreamError:
        status = None
    if status and status.get("status"):
        detail += f" (integration {status['status']}"
        detail += f": {status['message']})" if status.get("message") else ")"
    pf.warn(
        "ise",
        detail,
        hint="catc_get_policy_servers shows each step and next_action: catc_update_policy_server for an "
        "entry that FAILED (e.g. an FQDN that doesn't match ISE's certificate), catc_accept_ise_certificate "
        "for a certificate waiting to be accepted.",
        servers=rows,
    )


async def preflight(settings: Settings, pf: Preflight) -> None:
    app = CatcApp(settings)
    try:
        auth = app.api.auth
        if isinstance(auth, LoginTokenAuth):
            token = await pf.reach(
                "login",
                auth.headers(app.api),
                detail=f"POST {LOGIN_PATH} issued an X-Auth-Token",
                seconds=settings.timeout * 2,
            )
            if token is None:
                return
        found = await pf.reach(
            "intent",
            app.version(),
            detail=lambda v: f"Intent API answered (release {v})",
            seconds=settings.timeout * 2,
        )
        if found is None:
            return
        if isinstance(auth, LoginTokenAuth):
            pf.ok(
                "auth",
                f"credentials accepted; the token lasts 60 min and is renewed after {TOKEN_LIFETIME // 60} "
                "min, shared by every caller of this server",
            )
        else:
            pf.warn(
                "auth",
                "CATC_TOKEN accepted, but a pre-issued token expires about an hour after login and is never "
                "renewed",
                hint="Set CATC_USERNAME and CATC_PASSWORD (or CATC_PASSWORD_FILE) so the server logs in and "
                "renews the token itself.",
            )
        await _role(app, pf)
        pf.version(
            None if found == "unknown" else found,
            tested=TESTED,
            minimum=MINIMUM,
            detail=f"bundled API spec {SPEC_VERSION}",
        )
        await _ise(app, pf)
    finally:
        await app.aclose()
