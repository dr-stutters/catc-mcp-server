"""AAA and ISE (D8): authentication and policy servers (System > Settings > Authentication and Policy
Servers), the Catalyst Center <-> ISE integration (certificate trust, pxGrid) and per-site AAA network
settings. Appliance-to-appliance only: this server never subscribes to pxGrid (ADR-003). Shared
secrets and passwords are write-only: never echoed, masked in previews."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import ipaddress
import json
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field, SecretStr

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    field_changes,
    get_client,
    poll_until,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, pick, resolve_site
from catc_mcp.tools.sites import all_sites

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


async def raw_integration_status(app: CatcApp) -> Any:
    try:
        return await app.api.get(STATUS_PATH)
    except NotFound:
        return None


async def integration_status(app: CatcApp) -> dict[str, Any] | None:
    return integration_summary(await raw_integration_status(app))


def last_step_time(st: Any) -> int:
    """The newest stepTime (epoch ms) of a raw integration status: it moves when the integration re-runs,
    which tells a fresh result from the one left over from before an edit."""
    if not isinstance(st, dict):
        return 0
    times = [s.get("stepTime") for s in ensure_list(st.get("steps")) if isinstance(s, dict)]
    return max((t for t in times if isinstance(t, int) and not isinstance(t, bool)), default=0)


# What Catalyst Center's failure message names, checked in this order (resolution before the FQDN check:
# a name the appliance can't resolve is also "the FQDN").
FAILURE_FIELDS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"resolv|unknown ?host|name or service not known|no such host|nxdomain", re.I),
        "fqdn",
        "Catalyst Center can't resolve the ISE FQDN: correct the name, or give the appliance a DNS "
        "server that resolves it (appliance setting, not an API).",
    ),
    (
        re.compile(r"\bFQDN\b|common name|subject alternative|host ?name", re.I),
        "fqdn",
        "Set fqdn to the name in ISE's admin certificate (CN or SAN; ise_list_certificates or "
        "ise_pxgrid_status show it).",
    ),
    (
        re.compile(
            r"password|credential|user ?name|unauthori[sz]ed|authenticat\w* fail|\b401\b|\bERS\b", re.I
        ),
        "ise_password",
        "Re-enter the ISE super-admin user and password (ERS must be enabled on ISE).",
    ),
    (re.compile(r"\bport\b", re.I), "ports", "Check the ports CatC uses to reach ISE (443, 8910)."),
]
TERMINAL = ("COMPLETE", "FAILED")


def failure_field(message: str | None) -> tuple[str | None, str | None]:
    for rx, fld, hint in FAILURE_FIELDS:
        if message and rx.search(message):
            return fld, hint
    return None, None


def next_action(server: dict[str, Any], integ: dict[str, Any] | None) -> dict[str, Any]:
    """What to do next for one policy server (a server_row), from its state and the ISE integration
    status: update_entry (with the field Catalyst Center's message names), accept_certificate,
    approve_pxgrid_on_ise, wait (still running) or none."""
    if not server.get("isIseEnabled"):
        if server.get("state") == "FAILED":
            return {"action": "update_entry", "field": None, "tool": "catc_update_policy_server"}
        return {"action": "none"}
    st = integ if integ and integ.get("server_id") in (None, server.get("id")) else None
    nodes = ensure_list(server.get("ise_nodes"))
    reason = next((n.get("failureReason") for n in nodes if n.get("failureReason")), None)
    status = (st or {}).get("status") or ("FAILED" if server.get("state") == "FAILED" else None)
    steps = ensure_list((st or {}).get("steps"))
    message = (st or {}).get("message") or reason
    pxgrid_step = next((s for s in steps if "pxgrid" in str(s.get("stepName", "")).lower()), None)
    subscriber = next((n.get("subscriberName") for n in nodes if n.get("subscriberName")), None)
    approve = {
        "action": "approve_pxgrid_on_ise",
        "tool": "ise_list_pxgrid_clients",
        "subscriber": subscriber,
        "detail": f"On ISE: ise_list_pxgrid_clients(state='pending'), then ise_approve_pxgrid_client for "
        f"{subscriber or 'the Catalyst Center client'}; if the integration FAILED, retry it afterwards "
        "with catc_accept_ise_certificate(retry=true).",
    }
    if status == "WAITING_USER_INPUT":
        if st and st.get("certificate_to_accept"):
            return {
                "action": "accept_certificate",
                "tool": "catc_accept_ise_certificate",
                "detail": "Compare the fingerprints with ISE's certificate (ise_pxgrid_status / "
                "ise_list_certificates) before accepting.",
            }
        return {"action": "wait", "detail": "The integration waits for a certificate that isn't shown yet."}
    if status == "FAILED":
        failed = next((s for s in steps if s.get("stepStatus") == "FAILED"), None)
        if failed is not None and pxgrid_step is not None and failed is pxgrid_step:
            return approve | {"why": failed.get("errorMessage") or message}
        fld, hint = failure_field(message)
        out: dict[str, Any] = {"action": "update_entry", "field": fld, "tool": "catc_update_policy_server"}
        if hint:
            out["detail"] = hint
        if message:
            out["why"] = message
        return out
    if status == "COMPLETE":
        if any(n.get("trustState") not in (None, "TRUSTED") for n in nodes):
            untrusted = [n.get("ipAddress") for n in nodes if n.get("trustState") not in (None, "TRUSTED")]
            return {"action": "none", "detail": f"Integration COMPLETE; nodes not TRUSTED: {untrusted}."}
        return {"action": "none"}
    if pxgrid_step and pxgrid_step.get("stepStatus") not in ("COMPLETE", "NOT_STARTED", "NOT_APPLICABLE"):
        return approve | {"action": "approve_pxgrid_on_ise"}
    if status is None:
        return {"action": "none"} if server.get("state") == "ACTIVE" else {"action": "wait"}
    return {"action": "wait", "detail": f"The integration is {status}; check again shortly."}


def _server_ips(raw: dict[str, Any]) -> set[str]:
    ips = {str(raw.get("ipAddress"))} if raw.get("ipAddress") else set()
    return ips | {
        str(d.get("ipAddress"))
        for d in ensure_list(raw.get("ciscoIseDtos"))
        if isinstance(d, dict) and d.get("ipAddress")
    }


async def sites_using(app: CatcApp, servers: list[dict[str, Any]]) -> dict[str, Any]:
    """{server id: [{site, roles}]} for the sites whose own (not inherited) network or client AAA names
    one of the server's addresses (primary, secondary or PAN). Child sites inherit unless they set it."""
    sites, complete = await all_sites(app)
    sites = [s for s in sites if s.get("id")]
    sem = asyncio.Semaphore(8)

    async def local_aaa(site: dict[str, Any]) -> Any:
        async with sem:
            path = AAA_PATH.format(id=safe_id(str(site["id"]), "site id"))
            return await app.get_response(path, {"_inherited": "false"})

    results = await asyncio.gather(*(local_aaa(s) for s in sites), return_exceptions=True)
    used: dict[str, list[dict[str, Any]]] = {str(r.get("instanceUuid") or r.get("id")): [] for r in servers}
    unreadable = 0
    for s, got in zip(sites, results, strict=True):
        if isinstance(got, BaseException):
            if not isinstance(got, UpstreamError):
                raise got
            unreadable += 1
            continue
        if not isinstance(got, dict):
            continue
        for r in servers:
            ips = _server_ips(r)
            roles = [
                role
                for role, key in (("network", "aaaNetwork"), ("client", "aaaClient"))
                if isinstance(got.get(key), dict)
                and ips & {str(got[key].get(f)) for f in ("primaryServerIp", "secondaryServerIp", "pan")}
            ]
            if roles:
                used[str(r.get("instanceUuid") or r.get("id"))].append(
                    {"site": s.get("nameHierarchy") or s.get("name"), "roles": roles}
                )
    out: dict[str, Any] = {"by_server": used, "sites_checked": len(sites)}
    if unreadable:
        out["sites_unreadable"] = unreadable
    if not complete:
        out["note"] = "The site list was truncated; some sites were not checked."
    return out


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
    async def catc_get_policy_servers(
        ctx: Context,
        include_sites: Annotated[
            bool,
            Field(
                description="Also list the sites whose own network or client AAA points at each server "
                "(reads every site's AAA settings; slower on large hierarchies)"
            ),
        ] = False,
    ) -> dict[str, Any]:
        """Authentication and policy servers known to Catalyst Center (System > Settings >
        Authentication and Policy Servers): plain RADIUS/TACACS servers and integrated Cisco ISE, with
        protocol, ports, state, pxGrid, and per ISE node its role (PRIMARY/SECONDARY/PXGRID), FQDN and
        certificate trust state; plus the ISE integration status (each step, and the certificate
        waiting to be accepted, if any). Each server carries `next_action`: update_entry (with the
        field Catalyst Center's failure message names; fix it with catc_update_policy_server),
        accept_certificate (catc_accept_ise_certificate), approve_pxgrid_on_ise (the Catalyst Center
        pxGrid client waits on ISE), wait, or none. With include_sites=true each server also lists the
        sites that set it as their network or client AAA (child sites inherit). Shared secrets and
        passwords are never returned. Site AAA settings point at these servers
        (catc_update_site_aaa_settings)."""
        app: CatcApp = get_client(ctx)
        raw = await policy_servers(app)
        servers = [server_row(r) for r in raw]
        out: dict[str, Any] = {"servers": servers, "count": len(servers)}
        integ = None
        if any(s.get("isIseEnabled") for s in servers):
            integ = await integration_status(app)
            out["ise_integration"] = integ
        for srv in servers:
            srv["next_action"] = next_action(srv, integ)
        if include_sites and raw:
            used = await sites_using(app, raw)
            for srv in servers:
                srv["sites"] = used["by_server"].get(str(srv.get("id")), [])
            out["sites_checked"] = used["sites_checked"]
            for k in ("sites_unreadable", "note"):
                if k in used:
                    out[f"sites_{k}" if k == "note" else k] = used[k]
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

    @reg.dangerous(title="Update an authentication and policy server")
    async def catc_update_policy_server(
        ctx: Context,
        server: Annotated[str, Field(description="Server IP address or id (catc_get_policy_servers)")],
        fqdn: Annotated[
            str | None,
            Field(
                min_length=3,
                description="ISE FQDN; must match ISE's admin certificate and resolve from the appliance",
            ),
        ] = None,
        ise_password: Annotated[
            SecretStr | None,
            Field(
                description="The ISE user's password: required for every edit of an ISE entry (Catalyst "
                "Center never returns it); never echoed"
            ),
        ] = None,
        ise_username: Annotated[
            str | None, Field(min_length=1, description="ISE super-admin user (default: the stored one)")
        ] = None,
        protocol: Annotated[
            Literal["RADIUS", "TACACS", "RADIUS_TACACS"] | None,
            Field(description="RADIUS or TACACS can only be widened to RADIUS_TACACS"),
        ] = None,
        authentication_port: Annotated[int | None, Field(ge=1, le=65535, description="RADIUS auth")] = None,
        accounting_port: Annotated[int | None, Field(ge=1, le=65535, description="RADIUS accounting")] = None,
        tacacs_port: Annotated[int | None, Field(ge=1, le=65535, description="TACACS port")] = None,
        pxgrid: Annotated[bool | None, Field(description="Integrate pxGrid (ISE entries)")] = None,
        use_catc_cert_for_pxgrid: Annotated[
            bool | None,
            Field(
                description="Catalyst Center presents its own certificate to pxGrid (ISE must trust its CA)"
            ),
        ] = None,
        retries: Annotated[int | None, Field(ge=1, le=3, description="Device AAA retries")] = None,
        timeout_seconds: Annotated[int | None, Field(ge=2, le=20, description="Device AAA timeout")] = None,
        wait: Annotated[
            bool,
            Field(description="Wait for the re-run ISE integration to finish or to ask for the certificate"),
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Edit an authentication and policy server (System > Settings > Authentication and Policy
        Servers > Edit): the ISE FQDN and login, ports, protocol, pxGrid, retries and timeout. This is
        the fix Catalyst Center names when the ISE integration FAILED on a renamed node or a renewed
        certificate ('update this Cisco ISE server entry'). The whole ISE entry is resent, so an ISE
        edit always needs ise_password (masked, never returned); the RADIUS/TACACS shared secret and
        the IP address can't be changed here (no API field: delete and re-add the server). Only what
        you pass changes. For ISE the integration re-runs: the tool waits for it and, when it stops
        for ISE's certificate, returns the chain and next_action accept_certificate
        (catc_accept_ise_certificate after comparing fingerprints). Dangerous tier: it resets trust
        and the pxGrid client. Preview-first."""
        app: CatcApp = get_client(ctx)
        ref = server.strip()
        rows = await policy_servers(app)
        match = [r for r in rows if ref in (r.get("ipAddress"), r.get("instanceUuid"), r.get("id"))]
        if not match:
            raise NotFound(f"No authentication and policy server {ref!r}; see catc_get_policy_servers.")
        if len(match) > 1:
            raise InvalidRequest(f"{ref!r} matches {len(match)} servers; give the id.")
        cur = match[0]
        row = server_row(cur)
        sid = safe_id(str(row["id"]), "server id")
        is_ise = bool(cur.get("isIseEnabled") or cur.get("iseEnabled"))
        ise_only = {
            "fqdn": fqdn,
            "ise_password": ise_password,
            "ise_username": ise_username,
            "pxgrid": pxgrid,
            "use_catc_cert_for_pxgrid": use_catc_cert_for_pxgrid,
        }
        if not is_ise and (given := [k for k, v in ise_only.items() if v is not None]):
            raise InvalidRequest(f"{', '.join(given)} only apply to an integrated ISE entry.")

        old_proto = str(cur.get("protocol") or "RADIUS")
        proto = protocol or old_proto
        blockers: list[str] = []
        if proto != old_proto and proto != "RADIUS_TACACS":
            blockers.append(
                f"Catalyst Center only widens a {old_proto} server to RADIUS_TACACS; to use {proto} "
                "alone, delete and re-add the server."
            )

        def num(v: Any, default: int) -> int:
            try:
                return int(v)
            except (TypeError, ValueError):
                return default

        body: dict[str, Any] = {
            "protocol": proto,
            "retries": str(retries if retries is not None else num(cur.get("retries"), 3)),
            "timeoutSeconds": str(
                timeout_seconds if timeout_seconds is not None else num(cur.get("timeoutSeconds"), 4)
            ),
        }
        if "RADIUS" in proto:
            body["authenticationPort"] = authentication_port or num(cur.get("authenticationPort"), 1812)
            body["accountingPort"] = accounting_port or num(cur.get("accountingPort"), 1813)
        if "TACACS" in proto:
            body["port"] = tacacs_port or num(cur.get("port"), 49)
        node: dict[str, Any] = {}
        if is_ise:
            nodes = [d for d in ensure_list(cur.get("ciscoIseDtos")) if isinstance(d, dict)]
            node = next(
                (d for d in nodes if str(d.get("role", "")).upper() == "PRIMARY"), nodes[0] if nodes else {}
            )
            body["pxgridEnabled"] = bool(cur.get("pxgridEnabled")) if pxgrid is None else pxgrid
            body["useDnacCertForPxgrid"] = (
                bool(cur.get("useDnacCertForPxgrid"))
                if use_catc_cert_for_pxgrid is None
                else use_catc_cert_for_pxgrid
            )
            user = ise_username or node.get("userName")
            if not user:
                blockers.append("The entry has no stored ISE user; give ise_username.")
            body["ciscoIseDtos"] = [{"fqdn": (fqdn or str(node.get("fqdn") or "")).strip(), "userName": user}]
            if ext := [d for d in ensure_list(cur.get("externalCiscoIseIpAddrDtos")) if d]:
                body["externalCiscoIseIpAddrDtos"] = ext
            if ise_password is None:
                blockers.append(
                    "An ISE entry is resent whole with its password: give ise_password (Catalyst Center "
                    "never returns it)."
                )

        def view(src: dict[str, Any], dto: dict[str, Any]) -> dict[str, Any]:
            v = {k: src.get(k) for k in ("protocol", "authenticationPort", "accountingPort", "port")}
            v |= {"retries": num(src.get("retries"), 0), "timeoutSeconds": num(src.get("timeoutSeconds"), 0)}
            if is_ise:
                v |= {
                    "pxgridEnabled": bool(src.get("pxgridEnabled")),
                    "useDnacCertForPxgrid": bool(src.get("useDnacCertForPxgrid")),
                    "fqdn": dto.get("fqdn"),
                    "userName": dto.get("userName"),
                }
            return {k: x for k, x in v.items() if x is not None}

        new_view = view(body, (body.get("ciscoIseDtos") or [{}])[0])
        changes = field_changes(view(cur, node), new_view)
        if not changes and ise_password is None:
            blockers.append("Nothing to change: the server already has these settings.")

        effects: list[str] = []
        if is_ise:
            integ = await integration_status(app)
            if integ and integ.get("status") not in (*TERMINAL, "WAITING_USER_INPUT", None):
                blockers.append(
                    f"The ISE integration is running ({integ.get('status')}); wait until it finishes."
                )
            effects.append(
                "Catalyst Center re-runs the ISE integration (connect, trust, discover nodes, pxGrid); "
                "ISE-dependent provisioning waits until it is COMPLETE."
            )
            if "fqdn" in changes or row.get("state") == "FAILED":
                effects.append(
                    f"It connects to ISE as {body['ciscoIseDtos'][0]['fqdn']}: the name must resolve from "
                    "the appliance and match ISE's admin certificate (CN or SAN). Trust in ISE's "
                    "certificate is established again, so the integration stops for the certificate: "
                    "compare its fingerprints (ise_pxgrid_status / ise_list_certificates), then "
                    "catc_accept_ise_certificate."
                )
            if body["pxgridEnabled"]:
                effects.append(
                    f"pxGrid: Catalyst Center (re)registers its pxGrid client on ISE "
                    f"({node.get('subscriberName') or 'catalyst-center...'}); if ISE doesn't auto-approve "
                    "it, approve it with ise_approve_pxgrid_client."
                )
            elif "pxgridEnabled" in changes:
                effects.append(
                    "pxGrid off: Catalyst Center drops its pxGrid subscription; group-based policy and "
                    "endpoint context from ISE stop updating."
                )
            if changes.get("useDnacCertForPxgrid", {}).get("to"):
                effects.append(
                    "Catalyst Center presents its own certificate to pxGrid: ISE must trust its issuing CA."
                )
            if not changes:
                effects.append(
                    "No field changes: this re-enters the ISE password and re-runs the integration."
                )
        if {"authenticationPort", "accountingPort", "port", "retries", "timeoutSeconds", "protocol"} & set(
            changes
        ):
            effects.append("Devices get new ports, retries or timeout when they are re-provisioned.")
        effects.append(
            "The RADIUS/TACACS shared secret and the server IP stay as they are; AAA config already on "
            "devices is not touched."
        )

        shown = json.loads(json.dumps(body))
        if is_ise:
            shown["ciscoIseDtos"][0]["password"] = MASK
        plan = Plan(
            f"Update {'ISE' if is_ise else 'AAA'} server {row.get('ipAddress')}"
            + (f" ({', '.join(changes)})" if changes else ""),
            details={
                "method": "PUT",
                "path": f"{POLICY_PATH}/{sid}",
                "body": shown,
                "changes": changes,
                "current": row,
                "effects": effects,
            },
            fingerprint={"server": row},
            blockers=blockers,
        )
        secret = {"password": ise_password.get_secret_value()} if ise_password is not None else {}
        args = {
            "server": ref,
            "fqdn": fqdn,
            "ise_username": ise_username,
            "protocol": protocol,
            "ports": [authentication_port, accounting_port, tacacs_port],
            "pxgrid": pxgrid,
            "use_catc_cert_for_pxgrid": use_catc_cert_for_pxgrid,
            "retries": retries,
            "timeout_seconds": timeout_seconds,
            "wait": wait,
            "secrets": _digest(secret),
        }

        async def apply() -> Any:
            before = last_step_time(await raw_integration_status(app)) if is_ise else 0
            sent = json.loads(json.dumps(body))
            if is_ise:
                sent["ciscoIseDtos"][0]["password"] = secret["password"]
            job = await app.run_job("PUT", f"{POLICY_PATH}/{sid}", sent, ctx=ctx, what="update policy server")
            out: dict[str, Any] = {
                "server": row.get("ipAddress"),
                "task": job.get("status"),
                "changed": changes,
            }
            st: dict[str, Any] | None = None
            if is_ise and wait:
                seen: dict[str, Any] = {}

                async def fresh() -> dict[str, Any] | None:
                    raw = await raw_integration_status(app)
                    seen["new"] = last_step_time(raw) > before
                    summary = integration_summary(raw)
                    seen["st"] = summary
                    return summary

                try:
                    st = await poll_until(
                        fresh,
                        done=lambda s: bool(seen.get("new")) and _settled_or_waiting(s),
                        describe=lambda s: str((s or {}).get("status")),
                        timeout=app.settings.mcp_task_timeout,
                        ctx=ctx,
                        what="ISE integration",
                        interval=3.0,
                    )
                except UpstreamTimeout:
                    st = seen.get("st")
                    out["note"] = "The integration is still running; check catc_get_policy_servers."
                out["integration"] = st
            elif is_ise:
                st = await integration_status(app)
            after = [server_row(r) for r in await policy_servers(app)]
            now = next((r for r in after if r.get("id") == row["id"]), None)
            if now is not None:
                out["now"] = now
                out["next_action"] = next_action(now, st)
            return out

        return await preview_or_apply(
            ctx, tool="catc_update_policy_server", args=args, confirm=confirm, plan=plan, apply=apply
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
