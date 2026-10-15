"""AAA and ISE (D8): authentication and policy servers (System > Settings > Authentication and Policy
Servers), the Catalyst Center <-> ISE integration (certificate trust, pxGrid) and per-site AAA network
settings. Appliance-to-appliance only: this server never subscribes to pxGrid (ADR-003). Shared
secrets and passwords are write-only: never echoed, masked in previews."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import hashlib
import ipaddress
import json
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field, SecretStr
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    poll_until,
    preview_or_apply,
)
from stutters_mcp_core.formatting import MASK

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, pick, resolve_site

POLICY_PATH = "/dna/intent/api/v1/authentication-policy-servers"
STATUS_PATH = "/dna/intent/api/v1/ise-integration-status"
ACCEPT_PATH = "/dna/intent/api/v1/integrate-ise/{id}"
AAA_PATH = "/dna/intent/api/v1/sites/{id}/aaaSettings"

SERVER_FIELDS = [
    "ipAddress",
    "protocol",
    "role",
    "state",
    "isIseEnabled",
    "pxgridEnabled",
    "authenticationPort",
    "accountingPort",
    "port",
    "retries",
    "timeoutSeconds",
    "encryptionScheme",
    "instanceUuid",
]
ISE_FIELDS = ["role", "ipAddress", "fqdn", "trustState", "subscriberName", "userName", "failureReason"]
STEP_FIELDS = ["stepOrder", "stepName", "stepStatus", "errorMessage", "certAcceptedByUser"]


async def policy_servers(app: CatcApp) -> list[dict[str, Any]]:
    return [r for r in ensure_list(await app.get_response(POLICY_PATH)) if isinstance(r, dict)]


def server_row(r: dict[str, Any]) -> dict[str, Any]:
    """A policy server without any secret (sharedSecret, encryption/message keys, ISE password/SSH key)."""
    row = pick(r, SERVER_FIELDS)
    row["id"] = r.get("instanceUuid") or r.get("id")
    row.pop("instanceUuid", None)
    ise = [pick(d, ISE_FIELDS) for d in ensure_list(r.get("ciscoIseDtos")) if isinstance(d, dict)]
    if ise:
        row["ise_nodes"] = ise
    return row


def certificate_of(step: dict[str, Any]) -> list[dict[str, Any]]:
    """The ISE certificate chain a WAITING_USER_INPUT step carries (subject, issuer, validity,
    fingerprints)."""
    raw = step.get("certificate")
    try:
        chain = json.loads(raw).get("certificateChain", []) if isinstance(raw, str) else []
    except ValueError:
        return []
    keep = ["subjectDn", "issuerDn", "serialNumber", "issueDate", "expiryDate", "fingerPrints"]
    return [pick(c, keep) for c in chain if isinstance(c, dict)]


def integration_summary(st: Any) -> dict[str, Any] | None:
    if not isinstance(st, dict) or not st.get("overallStatus"):
        return None
    steps = sorted(
        (s for s in ensure_list(st.get("steps")) if isinstance(s, dict)), key=lambda s: s.get("stepOrder", 0)
    )
    out: dict[str, Any] = {
        "server_id": st.get("aaaServerSettingId"),
        "status": st.get("overallStatus"),
        "steps": [{k: v for k, v in pick(s, STEP_FIELDS).items() if v not in ("", None)} for s in steps],
    }
    if st.get("overallErrorMessage"):
        out["message"] = st["overallErrorMessage"]
    for s in steps:
        if s.get("stepStatus") == "WAITING_USER_INPUT" and (cert := certificate_of(s)):
            out["certificate_to_accept"] = cert
            out["next"] = "Check the fingerprints with the ISE admin, then catc_accept_ise_certificate."
    return out


async def integration_status(app: CatcApp) -> dict[str, Any] | None:
    try:
        st = await app.api.get(STATUS_PATH)
    except NotFound:
        return None
    return integration_summary(st)


def _ip(name: str, v: str | None) -> str | None:
    if v is None or not v.strip():
        return None
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError as e:
        raise InvalidRequest(f"{name}: {v!r} is not an IP address.") from e


def _no_secrets(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _no_secrets(x) for k, x in v.items() if k not in ("sharedSecret", "password")}
    return v


def _digest(secrets: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(secrets, sort_keys=True).encode()).hexdigest()


def _settled(st: dict[str, Any] | None) -> bool:
    return bool(st) and st is not None and st.get("status") in ("COMPLETE", "FAILED")


def _settled_or_waiting(st: dict[str, Any] | None) -> bool:
    """Finished, or waiting for a certificate decision (once the certificate is actually shown)."""
    if not st:
        return False
    if st.get("status") == "WAITING_USER_INPUT":
        return bool(st.get("certificate_to_accept"))
    return _settled(st)


class AaaServer(BaseModel):
    """One AAA role of a site: who devices (network) or endpoints (client) authenticate against."""

    server_type: Annotated[
        Literal["ISE", "AAA"],
        Field(
            description="ISE (an integrated ISE: CatC also creates the NAD in ISE) or AAA "
            "(plain RADIUS/TACACS)"
        ),
    ]
    protocol: Annotated[
        Literal["RADIUS", "TACACS"], Field(description="RADIUS (client AAA must be RADIUS) or TACACS")
    ] = "RADIUS"
    primary: Annotated[str, Field(description="Primary server IP (an ISE PSN for server_type ISE)")]
    secondary: Annotated[str | None, Field(description="Secondary server IP (optional)")] = None
    pan: Annotated[
        str | None,
        Field(description="ISE primary admin node IP (server_type ISE; default: the primary)"),
    ] = None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List authentication and policy servers")
    async def catc_get_policy_servers(ctx: Context) -> dict[str, Any]:
        """Authentication and policy servers known to Catalyst Center (System > Settings >
        Authentication and Policy Servers): plain RADIUS/TACACS servers and integrated Cisco ISE, with
        protocol, ports, state, pxGrid, and per ISE node its role (PRIMARY/SECONDARY/PXGRID), FQDN and
        certificate trust state; plus the ISE integration status (each step, and the certificate
        waiting to be accepted, if any). Shared secrets and passwords are never returned. Site AAA
        settings point at these servers (catc_update_site_aaa_settings)."""
        app: CatcApp = get_client(ctx)
        servers = [server_row(r) for r in await policy_servers(app)]
        out: dict[str, Any] = {"servers": servers, "count": len(servers)}
        if any(s.get("isIseEnabled") for s in servers):
            out["ise_integration"] = await integration_status(app)
        return out

    @reg.dangerous(title="Add Cisco ISE to Catalyst Center")
    async def catc_add_ise_server(
        ctx: Context,
        ip: Annotated[str, Field(description="ISE primary admin node (PAN) IP address")],
        fqdn: Annotated[str, Field(min_length=3, description="ISE FQDN, e.g. ise.example.com")],
        username: Annotated[str, Field(min_length=1, description="ISE super-admin user (ERS enabled)")],
        password: Annotated[SecretStr, Field(description="That user's password (never echoed back)")],
        shared_secret: Annotated[
            SecretStr,
            Field(description="RADIUS/TACACS shared secret for the devices CatC provisions (never echoed)"),
        ],
        protocol: Annotated[
            Literal["RADIUS", "TACACS", "RADIUS_TACACS"],
            Field(description="Which protocols ISE serves (RADIUS_TACACS needs ISE's Device Admin service)"),
        ] = "RADIUS",
        description: Annotated[str, Field(max_length=200, description="Description shown in CatC")] = "",
        pxgrid: Annotated[bool, Field(description="Integrate pxGrid (ISE needs the pxGrid persona)")] = True,
        timeout_seconds: Annotated[int, Field(ge=2, le=20, description="Device AAA timeout")] = 4,
        retries: Annotated[int, Field(ge=1, le=3, description="Device AAA retries")] = 3,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Integrate Cisco ISE with Catalyst Center as the AAA and policy server: CatC connects to ISE
        (ERS over 443, pxGrid 8910), discovers its nodes and, after you accept ISE's certificate,
        trusts it. From then on provisioning a device at a site whose AAA points at ISE also creates
        the device as a network device (NAD) in ISE. Hard to undo (certificate trust, pxGrid client,
        NADs), so dangerous tier. Preview-first; secrets are masked and never returned. The
        integration usually stops at 'WAITING_USER_INPUT' for the certificate: the result shows its
        fingerprints; accept it with catc_accept_ise_certificate. Only one ISE can be integrated."""
        app: CatcApp = get_client(ctx)
        addr = _ip("ip", ip)
        existing = await policy_servers(app)
        blockers = []
        if any(r.get("isIseEnabled") or r.get("iseEnabled") for r in existing):
            blockers.append("An ISE is already integrated (catc_get_policy_servers); remove it first.")
        if any(r.get("ipAddress") == addr for r in existing):
            blockers.append(f"{addr} is already an authentication and policy server.")
        body: dict[str, Any] = {
            "ipAddress": addr,
            "isIseEnabled": True,
            "protocol": protocol,
            "role": "primary",
            "retries": str(retries),
            "timeoutSeconds": str(timeout_seconds),
            "pxgridEnabled": pxgrid,
            "useDnacCertForPxgrid": False,
            "ciscoIseDtos": [
                {
                    "ipAddress": addr,
                    "fqdn": fqdn.strip(),
                    "userName": username,
                    "subscriberName": "catalyst-center",
                    "description": description,
                }
            ],
        }
        if protocol in ("RADIUS", "RADIUS_TACACS"):
            body |= {"authenticationPort": 1812, "accountingPort": 1813}
        if protocol in ("TACACS", "RADIUS_TACACS"):
            body["port"] = 49
        secrets = {"sharedSecret": shared_secret.get_secret_value(), "password": password.get_secret_value()}
        shown = json.loads(json.dumps(body))
        shown["sharedSecret"] = MASK
        shown["ciscoIseDtos"][0]["password"] = MASK
        plan = Plan(
            f"Integrate Cisco ISE {fqdn} ({addr}) with Catalyst Center ({protocol}"
            f"{', pxGrid' if pxgrid else ''})",
            details={
                "method": "POST",
                "path": POLICY_PATH,
                "body": shown,
                "effects": [
                    "CatC logs in to ISE (ERS) and discovers its nodes; ISE's certificate must then be "
                    "accepted (catc_accept_ise_certificate).",
                    "With pxGrid, CatC registers a pxGrid client in ISE (auto-approved for certificate "
                    "clients when ISE allows it).",
                    "Devices provisioned at sites whose AAA uses this ISE get AAA/RADIUS config and a NAD "
                    "in ISE with this shared secret.",
                ],
            },
            fingerprint={"servers": [server_row(r) for r in existing]},
            blockers=blockers,
        )
        args = {
            "ip": ip,
            "fqdn": fqdn,
            "username": username,
            "protocol": protocol,
            "description": description,
            "pxgrid": pxgrid,
            "timeout_seconds": timeout_seconds,
            "retries": retries,
            "secrets": _digest(secrets),
        }

        async def apply() -> Any:
            sent = json.loads(json.dumps(body))
            sent["sharedSecret"] = secrets["sharedSecret"]
            sent["ciscoIseDtos"][0]["password"] = secrets["password"]
            job = await app.run_job("POST", POLICY_PATH, sent, ctx=ctx, what="add ISE")
            st = await poll_until(
                lambda: integration_status(app),
                done=_settled_or_waiting,
                describe=lambda s: str((s or {}).get("status")),
                timeout=app.settings.mcp_task_timeout,
                ctx=ctx,
                what="ISE integration",
                interval=3.0,
            )
            return {"task": job.get("status"), "integration": st}

        return await preview_or_apply(
            ctx, tool="catc_add_ise_server", args=args, confirm=confirm, plan=plan, apply=apply
        )

    @reg.dangerous(title="Accept the ISE certificate")
    async def catc_accept_ise_certificate(
        ctx: Context,
        accept: Annotated[
            bool, Field(description="true trusts the certificate shown; false rejects it and stops")
        ] = True,
        retry: Annotated[
            bool, Field(description="Retry a FAILED integration instead (no certificate decision)")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Answer Catalyst Center's 'trust this ISE certificate?' step of the ISE integration (or retry a
        failed integration). The preview shows the certificate chain (subject, issuer, validity,
        SHA-1/SHA-256 fingerprints): compare them with the ISE admin certificate before confirming.
        Waits until the integration is COMPLETE or FAILED and returns every step."""
        app: CatcApp = get_client(ctx)
        st = await integration_status(app)
        blockers = []
        if st is None:
            raise NotFound("No ISE integration in progress; add one with catc_add_ise_server.")
        if retry and st.get("status") != "FAILED":
            blockers.append(f"The integration is {st.get('status')}, not FAILED; nothing to retry.")
        if retry and not accept:
            raise InvalidRequest("retry=true retries the integration; leave accept at true.")
        if not retry and not st.get("certificate_to_accept"):
            blockers.append(f"No certificate is waiting to be accepted (status {st.get('status')}).")
        if not st.get("server_id"):
            raise NotFound("The integration status names no server id; see catc_get_policy_servers.")
        sid = safe_id(str(st["server_id"]), "server id")
        payload: dict[str, Any] = {} if retry else {"isCertAcceptedByUser": accept}
        action = "Retry the ISE integration" if retry else ("Trust" if accept else "Reject")
        plan = Plan(
            f"{action} the ISE certificate for integration {sid}" if not retry else action,
            details={
                "method": "PUT",
                "path": ACCEPT_PATH.format(id=sid),
                "body": payload,
                "certificate": st.get("certificate_to_accept"),
            },
            fingerprint=st,
            blockers=blockers,
        )

        async def apply() -> Any:
            await app.api.request("PUT", ACCEPT_PATH.format(id=sid), json=payload)
            if not retry and not accept:
                return {"accepted": False, "integration": await integration_status(app)}
            done = await poll_until(
                lambda: integration_status(app),
                done=_settled,
                describe=lambda s: str((s or {}).get("status")),
                timeout=app.settings.mcp_task_timeout,
                ctx=ctx,
                what="ISE integration",
                interval=5.0,
            )
            return {"accepted": accept, "integration": done}

        return await preview_or_apply(
            ctx,
            tool="catc_accept_ise_certificate",
            args={"accept": accept, "retry": retry},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Remove an authentication and policy server")
    async def catc_delete_policy_server(
        ctx: Context,
        server: Annotated[str, Field(description="Server IP address or id (catc_get_policy_servers)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove an authentication and policy server (plain AAA or the integrated ISE) from Catalyst
        Center. For ISE this ends the integration (pxGrid, trust); NADs and AAA config already pushed
        to devices stay as they are. Sites whose AAA settings use it must be changed first
        (catc_update_site_aaa_settings), or Catalyst Center refuses. Preview-first."""
        app: CatcApp = get_client(ctx)
        ref = server.strip()
        rows = await policy_servers(app)
        match = [r for r in rows if ref in (r.get("ipAddress"), r.get("instanceUuid"), r.get("id"))]
        if not match:
            raise NotFound(f"No authentication and policy server {ref!r}; see catc_get_policy_servers.")
        if len(match) > 1:
            raise InvalidRequest(f"{ref!r} matches {len(match)} servers; give the id.")
        row = server_row(match[0])
        sid = safe_id(str(row["id"]), "server id")
        plan = Plan(
            f"Remove {'ISE' if row.get('isIseEnabled') else 'AAA'} server {row.get('ipAddress')}",
            details={"method": "DELETE", "path": f"{POLICY_PATH}/{sid}", "server": row},
            fingerprint=row,
        )

        async def apply() -> Any:
            job = await app.run_job("DELETE", f"{POLICY_PATH}/{sid}", ctx=ctx, what="remove policy server")
            return {"removed": row.get("ipAddress"), "task": job.get("status")}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_policy_server",
            args={"server": ref},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Update site AAA settings", destructive=False)
    async def catc_update_site_aaa_settings(
        ctx: Context,
        site: Annotated[str, Field(description="Site (id or name hierarchy); child sites inherit it")],
        network: Annotated[
            AaaServer | None,
            Field(description="Device administration AAA (login/enable on the devices): RADIUS or TACACS"),
        ] = None,
        client: Annotated[
            AaaServer | None, Field(description="Client/endpoint AAA (802.1X/MAB): RADIUS")
        ] = None,
        network_shared_secret: Annotated[
            SecretStr | None, Field(description="Shared secret for network AAA (server_type ISE; optional)")
        ] = None,
        client_shared_secret: Annotated[
            SecretStr | None, Field(description="Shared secret for client AAA (server_type ISE; optional)")
        ] = None,
        inherit: Annotated[
            list[Literal["network", "client"]] | None,
            Field(description="Drop this site's own value so it inherits from the parent again"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set a site's AAA network settings (Design > Network Settings > AAA): which server devices
        use for administrator login (network) and for 802.1X/MAB endpoints (client), as ISE or plain
        AAA, RADIUS or TACACS. With server_type ISE the servers must be integrated ISE nodes
        (catc_get_policy_servers); provisioning then pushes aaa/radius config to the devices and
        creates them as NADs in ISE. Only what you pass changes; inherited values stay inherited.
        Preview-first: shows effective (inherited) and new values; secrets are masked and never
        returned. Devices only get it when (re)provisioned (catc_provision_devices). Read it with
        catc_get_site_settings(categories=['aaa'])."""
        app: CatcApp = get_client(ctx)
        if network is None and client is None and not inherit:
            raise InvalidRequest("Give network, client or inherit.")
        both = {"network", "client"} & set(inherit or [])
        if (network and "network" in both) or (client and "client" in both):
            raise InvalidRequest("A role can't be both set and inherited.")
        if client is not None and client.protocol != "RADIUS":
            raise InvalidRequest("Client (endpoint) AAA must use RADIUS.")
        if (network_shared_secret is not None and network is None) or (
            client_shared_secret is not None and client is None
        ):
            raise InvalidRequest("A shared secret needs the matching network/client server settings.")
        s = await resolve_site(app, site)
        sid = safe_id(str(s["id"]), "site id")
        path = AAA_PATH.format(id=sid)
        try:
            effective = await app.get_response(path, {"_inherited": "true"})
            local = await app.get_response(path, {"_inherited": "false"})
        except UpstreamError as e:
            raise UpstreamError(f"Can't read the AAA settings of {s.get('nameHierarchy')}: {e}") from e
        # Secrets are write-only: never carry one read back (or its mask) into a preview or a PUT.
        effective = _no_secrets(effective) if isinstance(effective, dict) else {}
        local = _no_secrets(local) if isinstance(local, dict) else {}

        servers = await policy_servers(app)
        ise_ips = {
            str(d.get("ipAddress"))
            for r in servers
            for d in ensure_list(r.get("ciscoIseDtos"))
            if isinstance(d, dict)
        } | {str(r.get("ipAddress")) for r in servers if r.get("isIseEnabled")}
        aaa_ips = {str(r.get("ipAddress")) for r in servers if not r.get("isIseEnabled")}
        blockers: list[str] = []
        secrets: dict[str, str] = {}

        def build(role: str, spec: AaaServer, secret: SecretStr | None) -> dict[str, Any]:
            primary = _ip(f"{role}.primary", spec.primary)
            secondary = _ip(f"{role}.secondary", spec.secondary)
            known = ise_ips if spec.server_type == "ISE" else aaa_ips | ise_ips
            for ip in (primary, secondary):
                if ip and ip not in known:
                    blockers.append(
                        f"{role}: {ip} is not an "
                        f"{'integrated ISE node' if spec.server_type == 'ISE' else 'AAA server'} "
                        "in Catalyst Center (catc_get_policy_servers / catc_add_ise_server)."
                    )
            out: dict[str, Any] = {
                "serverType": spec.server_type,
                "protocol": spec.protocol,
                "primaryServerIp": primary,
            }
            if secondary:
                out["secondaryServerIp"] = secondary
            if spec.server_type == "ISE":
                out["pan"] = _ip(f"{role}.pan", spec.pan) or primary
                if secret is not None:
                    secrets[role] = secret.get_secret_value()
            elif secret is not None:
                raise InvalidRequest(f"{role}_shared_secret only applies to server_type ISE.")
            return out

        def clean(v: Any) -> Any:
            if isinstance(v, dict):
                return {k: x for k, x in v.items() if k not in ("inheritedSiteId", "inheritedSiteName")}
            return v

        body: dict[str, Any] = {k: clean(local.get(k)) for k in ("aaaNetwork", "aaaClient") if local.get(k)}
        want: dict[str, Any] = {}
        if network is not None:
            want["aaaNetwork"] = build("network", network, network_shared_secret)
        if client is not None:
            want["aaaClient"] = build("client", client, client_shared_secret)
        parent: dict[str, Any] = {}
        if inherit and s.get("parentId"):
            got = await app.get_response(
                AAA_PATH.format(id=safe_id(str(s["parentId"]), "site id")), {"_inherited": "true"}
            )
            parent = got if isinstance(got, dict) else {}
        for role in inherit or []:
            key = "aaaNetwork" if role == "network" else "aaaClient"
            if not local.get(key):
                blockers.append(f"{role}: {s.get('nameHierarchy')} already inherits it.")
            elif not clean(parent.get(key)):
                # NCND00070: Catalyst Center refuses to drop a value no parent sets.
                blockers.append(
                    f"{role}: no parent site sets {role} AAA, and Catalyst Center can't clear it at "
                    f"{s.get('nameHierarchy')}; set it at a parent first, or delete the site."
                )
            body.pop(key, None)
        body.update(want)

        def visible(v: Any) -> Any:
            """A role as previewed: no inheritance markers and never a read-back shared secret."""
            v = clean(v)
            return {k: x for k, x in v.items() if k != "sharedSecret"} if isinstance(v, dict) else v

        # The body carries both local roles; a role given here is a whole new object (replace=True), and a
        # dropped role is listed as "(inherit)" below.
        changes = {
            k: field_changes(visible(effective.get(k)) or {}, v, replace=True) for k, v in want.items()
        } | {
            f"{r} (inherit)": {"from": visible(local.get("aaaNetwork" if r == "network" else "aaaClient"))}
            for r in inherit or []
        }
        if want and not any(changes.get(k) for k in want) and not inherit and not secrets:
            blockers.append("Nothing to change: the site already has these AAA settings.")
        shown = json.loads(json.dumps(body))
        for name in secrets:
            shown["aaaNetwork" if name == "network" else "aaaClient"]["sharedSecret"] = MASK
        plan = Plan(
            f"Update AAA settings of {s.get('nameHierarchy')}",
            details={
                "method": "PUT",
                "path": path,
                "body": shown,
                "changes": changes,
                "effective_now": {k: visible(effective.get(k)) for k in ("aaaNetwork", "aaaClient")},
                "note": "Devices get it when (re)provisioned; with ISE, provisioning also creates the NAD "
                "in ISE.",
            },
            fingerprint={"effective": effective, "local": local},
            blockers=blockers,
        )

        async def apply() -> Any:
            sent = json.loads(json.dumps(body))
            for name, value in secrets.items():
                sent["aaaNetwork" if name == "network" else "aaaClient"]["sharedSecret"] = value
            job = await app.run_job("PUT", path, sent, ctx=ctx, what="AAA settings")
            return {"site": s.get("nameHierarchy"), "status": job.get("status") or "ok", "aaa": shown}

        return await preview_or_apply(
            ctx,
            tool="catc_update_site_aaa_settings",
            args={
                "site": site,
                "network": network.model_dump() if network else None,
                "client": client.model_dump() if client else None,
                "inherit": inherit,
                "secrets": _digest(secrets),
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
