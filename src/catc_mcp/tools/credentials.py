"""Device credentials: global credentials (Design > Network Settings > Device Credentials) and
which ones a site uses. Secrets are write-only: Catalyst Center never returns them and these tools
never echo them."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import json
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field, SecretStr

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    TaskFailed,
    ToolRegistrar,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp._core.http import fetch_all, page_of
from catc_mcp.client import CatcApp
from catc_mcp.common import is_uuid, pick, resolve_site

CRED_PATH = "/dna/intent/api/v1/globalCredentials"

CredType = Literal[
    "CLI",
    "SNMPV2_READ_COMMUNITY",
    "SNMPV2_WRITE_COMMUNITY",
    "SNMPV3",
    "NETCONF",
    "HTTP_READ",
    "HTTP_WRITE",
]

CRED_TYPES = {
    "CLI",
    "SNMPV2_READ_COMMUNITY",
    "SNMPV2_WRITE_COMMUNITY",
    "SNMPV3",
    "NETCONF",
    "HTTP_READ",
    "HTTP_WRITE",
}

# Site credential slots (PUT /sites/{id}/deviceCredentials) by credential type. NETCONF has no slot.
SITE_SLOTS = {
    "CLI": "cliCredentialsId",
    "SNMPV2_READ_COMMUNITY": "snmpv2cReadCredentialsId",
    "SNMPV2_WRITE_COMMUNITY": "snmpv2cWriteCredentialsId",
    "SNMPV3": "snmpv3CredentialsId",
    "HTTP_READ": "httpReadCredentialsId",
    "HTTP_WRITE": "httpWriteCredentialsId",
}

# PUT /dna/intent/api/v2/global-credential: one object per credential type (NETCONF has none).
V2_CRED_PATH = "/dna/intent/api/v2/global-credential"
V2_KEYS = {
    "CLI": "cliCredential",
    "SNMPV2_READ_COMMUNITY": "snmpV2cRead",
    "SNMPV2_WRITE_COMMUNITY": "snmpV2cWrite",
    "SNMPV3": "snmpV3",
    "HTTP_READ": "httpsRead",
    "HTTP_WRITE": "httpsWrite",
}

# Credential sync (POST sites/deviceCredentials/apply) takes CLI and SNMP credentials only. Per type:
# the site slot it reads, and the key of GET sites/{id}/deviceCredentials/status.
APPLY_TYPES = {
    "CLI": ("cliCredentialsId", "cli"),
    "SNMPV2_READ_COMMUNITY": ("snmpv2cReadCredentialsId", "snmpV2Read"),
    "SNMPV2_WRITE_COMMUNITY": ("snmpv2cWriteCredentialsId", "snmpV2Write"),
    "SNMPV3": ("snmpv3CredentialsId", "snmpV3"),
}
ApplyType = Literal["CLI", "SNMPV2_READ_COMMUNITY", "SNMPV2_WRITE_COMMUNITY", "SNMPV3"]
APPLY_PATH = "/dna/intent/api/v1/sites/deviceCredentials/apply"
# Status re-reads after the apply tasks end, while a type still says 'In Progress'.
STATUS_POLLS = 6
STATUS_INTERVAL = 5.0

CRED_FIELDS = ["description", "type", "username", "port", "protocol", "mode", "authType", "privacyType", "id"]


async def all_credentials(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, CRED_PATH, cap=5000)
    return [c for c in page.items if isinstance(c, dict)]


async def resolve_credential(
    app: CatcApp, ref: str, *, creds: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """A global credential from its id, its description, or 'TYPE:description' when the same
    description is used for several types (e.g. 'CLI:lab')."""
    ref = ref.strip()
    creds = creds if creds is not None else await all_credentials(app)
    if is_uuid(ref):
        for c in creds:
            if c.get("id") == ref:
                return c
        raise NotFound(f"No global credential with id {ref}. Use catc_list_global_credentials.")
    exact = [c for c in creds if str(c.get("description", "")).lower() == ref.lower()]
    ctype, _, desc = ref.rpartition(":")
    if exact or ctype.upper() not in CRED_TYPES:
        ctype, desc = "", ref
    found = exact or [
        c
        for c in creds
        if str(c.get("description", "")).lower() == desc.lower()
        and (not ctype or str(c.get("type", "")).upper() == ctype.upper())
    ]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        kinds = ", ".join(f"{c.get('type')}:{c.get('description')}" for c in found)
        raise InvalidRequest(
            f"Credential {ref!r} is ambiguous ({kinds}); prefix the type, e.g. 'CLI:{desc}'."
        )
    raise NotFound(f"No global credential described {ref!r}. Use catc_list_global_credentials.")


def status_rows(status: Any, types: list[str] | None = None) -> list[dict[str, Any]]:
    """GET sites/{id}/deviceCredentials/status as rows: credential type, sync status, device count."""
    status = status if isinstance(status, dict) else {}
    rows: list[dict[str, Any]] = []
    for ctype, (_, key) in APPLY_TYPES.items():
        if types is not None and ctype not in types:
            continue
        for r in status.get(key) or []:
            if isinstance(r, dict):
                rows.append({"type": ctype, "status": r.get("status"), "devices": r.get("deviceCount")})
    return rows


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List global credentials")
    async def catc_list_global_credentials(
        ctx: Context,
        credential_type: Annotated[CredType | None, Field(description="Only this credential type")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Global device credentials (CLI, SNMPv2c read/write, SNMPv3, NETCONF port, HTTP(S)) that
        discovery and sites use: description, type, username/port and id. Secrets are never returned.
        Use the description or id with catc_create_discovery, catc_assign_site_credentials and
        catc_delete_global_credential."""
        app: CatcApp = get_client(ctx)
        rows = [pick(c, CRED_FIELDS) for c in await all_credentials(app)]
        if credential_type:
            rows = [r for r in rows if r.get("type") == credential_type]
        rows.sort(key=lambda r: (str(r.get("type")), str(r.get("description")).lower()))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Create global credential")
    async def catc_create_global_credential(
        ctx: Context,
        credential_type: Annotated[CredType, Field(description="What kind of credential")],
        description: Annotated[
            str, Field(min_length=1, max_length=128, description="Unique name shown in Catalyst Center")
        ],
        username: Annotated[
            str | None, Field(description="CLI / SNMPv3 / HTTP username (required for those types)")
        ] = None,
        password: Annotated[
            SecretStr | None,
            Field(description="CLI or HTTP password (never echoed back)"),
        ] = None,
        enable_password: Annotated[SecretStr | None, Field(description="CLI enable password")] = None,
        community: Annotated[
            SecretStr | None, Field(description="SNMPv2c read or write community (never echoed back)")
        ] = None,
        port: Annotated[
            int | None, Field(ge=1, le=65535, description="NETCONF port (default 830) or HTTP(S) port")
        ] = None,
        snmpv3_mode: Annotated[
            Literal["AUTHPRIV", "AUTHNOPRIV", "NOAUTHNOPRIV"] | None,
            Field(description="SNMPv3 security level"),
        ] = None,
        snmpv3_auth_type: Annotated[Literal["SHA", "MD5"] | None, Field(description="SNMPv3 auth")] = None,
        snmpv3_auth_password: Annotated[SecretStr | None, Field(description="SNMPv3 auth password")] = None,
        snmpv3_privacy_type: Annotated[
            Literal["AES128", "AES192", "AES256", "CISCOAES192", "CISCOAES256"] | None,
            Field(description="SNMPv3 privacy (encryption)"),
        ] = None,
        snmpv3_privacy_password: Annotated[
            SecretStr | None, Field(description="SNMPv3 privacy password")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a global device credential that discovery and site assignment can use. Preview-first;
        secrets are masked in the preview and never returned. Refuses a description already used by
        a credential of the same type. Returns the new credential id."""
        app: CatcApp = get_client(ctx)
        body: dict[str, Any] = {"type": credential_type, "description": description}
        secrets: dict[str, str] = {}
        blockers: list[str] = []

        def need(cond: Any, msg: str) -> None:
            if not cond:
                blockers.append(msg)

        if credential_type == "CLI":
            need(username and password, "CLI credentials need username and password.")
            body["username"] = username
            if password:
                secrets["password"] = password.get_secret_value()
            if enable_password:
                secrets["enablePassword"] = enable_password.get_secret_value()
        elif credential_type in ("SNMPV2_READ_COMMUNITY", "SNMPV2_WRITE_COMMUNITY"):
            need(community, "SNMPv2c credentials need `community`.")
            key = "readCommunity" if credential_type == "SNMPV2_READ_COMMUNITY" else "writeCommunity"
            if community:
                secrets[key] = community.get_secret_value()
        elif credential_type == "SNMPV3":
            mode = snmpv3_mode or "AUTHPRIV"
            need(username, "SNMPv3 credentials need `username`.")
            body.update({"username": username, "mode": mode})
            if mode != "NOAUTHNOPRIV":
                need(snmpv3_auth_type and snmpv3_auth_password, f"{mode} needs auth type and password.")
                body["authType"] = snmpv3_auth_type
                if snmpv3_auth_password:
                    secrets["authPassword"] = snmpv3_auth_password.get_secret_value()
            if mode == "AUTHPRIV":
                need(
                    snmpv3_privacy_type and snmpv3_privacy_password,
                    "AUTHPRIV needs privacy type and password.",
                )
                body["privacyType"] = snmpv3_privacy_type
                if snmpv3_privacy_password:
                    secrets["privacyPassword"] = snmpv3_privacy_password.get_secret_value()
        elif credential_type == "NETCONF":
            body["port"] = port or 830
        else:  # HTTP_READ / HTTP_WRITE
            need(username and password, "HTTP credentials need username and password.")
            body.update({"username": username, "port": port or 443, "protocol": "HTTPS"})
            if password:
                secrets["password"] = password.get_secret_value()
        existing = await all_credentials(app)
        if any(
            c.get("type") == credential_type and str(c.get("description", "")).lower() == description.lower()
            for c in existing
        ):
            blockers.append(f"A {credential_type} credential described {description!r} already exists.")
        plan = Plan(
            f"Create {credential_type} credential {description}",
            details={"method": "POST", "path": CRED_PATH, "body": {**body, **dict.fromkeys(secrets, MASK)}},
            blockers=blockers,
        )
        args = {
            "credential_type": credential_type,
            "description": description,
            "username": username,
            "port": port,
            "snmpv3_mode": snmpv3_mode,
            "snmpv3_auth_type": snmpv3_auth_type,
            "snmpv3_privacy_type": snmpv3_privacy_type,
            # Secrets aren't stored; a digest makes the token refuse changed values.
            "secrets": hashlib.sha256(json.dumps(secrets, sort_keys=True).encode()).hexdigest(),
        }

        async def apply() -> Any:
            job = await app.run_job("POST", CRED_PATH, {**body, **secrets}, ctx=ctx, what="create credential")
            # The task reports the new credential's id in `progress`.
            new_id = job.get("data") or job.get("progress")
            return {"credential_id": new_id, "type": credential_type, "description": description}

        return await preview_or_apply(
            ctx, tool="catc_create_global_credential", args=args, confirm=confirm, plan=plan, apply=apply
        )

    @reg.write(title="Delete global credential", destructive=True)
    async def catc_delete_global_credential(
        ctx: Context,
        credential: Annotated[
            str, Field(description="Credential id, description, or 'TYPE:description' (e.g. 'CLI:lab')")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a global device credential. Devices already discovered keep working with the
        credentials they were discovered with, but sites that use this credential lose it.
        Preview-first."""
        app: CatcApp = get_client(ctx)
        c = await resolve_credential(app, credential)
        path = f"{CRED_PATH}/{c['id']}"
        plan = Plan(
            f"Delete {c.get('type')} credential {c.get('description')}",
            details={"method": "DELETE", "path": path, "credential": pick(c, CRED_FIELDS)},
            fingerprint=pick(c, CRED_FIELDS),
        )

        async def apply() -> Any:
            return await app.run_job("DELETE", path, ctx=ctx, what="delete credential")

        return await preview_or_apply(
            ctx,
            tool="catc_delete_global_credential",
            args={"credential": credential},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Assign credentials to site", destructive=False)
    async def catc_assign_site_credentials(
        ctx: Context,
        site: Annotated[str, Field(description="Site (id or name hierarchy); children inherit it")],
        credentials: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=6,
                description="Global credentials (id, description or 'TYPE:description'), one per type",
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set which global credentials (CLI, SNMPv2c read/write, SNMPv3, HTTP read/write) a site uses
        (Design > Network Settings > Device Credentials). Devices assigned to the site are managed with
        them, and Catalyst Center checks them when devices are assigned or provisioned there. Types not
        given keep their current value. Preview-first: shows the current and new credential per slot.
        Nothing is pushed to devices."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        creds = await all_credentials(app)
        chosen = [await resolve_credential(app, r, creds=creds) for r in credentials]
        by_id = {str(c.get("id")): c for c in creds}
        blockers: list[str] = []
        body: dict[str, Any] = {}
        for c in chosen:
            slot = SITE_SLOTS.get(str(c.get("type")))
            if slot is None:
                blockers.append(f"{c.get('type')} credentials can't be assigned to a site.")
            elif slot in body:
                blockers.append(f"Two {c.get('type')} credentials given; a site uses one per type.")
            else:
                body[slot] = {"credentialsId": c["id"]}
        current = await app.get_response(f"/dna/intent/api/v1/sites/{s['id']}/deviceCredentials")
        current = current if isinstance(current, dict) else {}

        def label(v: Any) -> Any:
            cid = v.get("credentialsId") if isinstance(v, dict) else None
            if not cid:
                return None
            c = by_id.get(str(cid))
            return f"{c.get('type')}:{c.get('description')}" if c else cid

        changes = {
            slot: {"from": label(current.get(slot)), "to": label(v)}
            for slot, v in body.items()
            if label(current.get(slot)) != label(v)
        }
        if not blockers and not changes:
            blockers.append("Nothing to change: the site already uses these credentials.")
        path = f"/dna/intent/api/v1/sites/{s['id']}/deviceCredentials"
        plan = Plan(
            f"Set device credentials of {s.get('nameHierarchy')}",
            details={"changes": changes, "method": "PUT", "path": path},
            fingerprint={
                "current": {k: label(v) for k, v in current.items() if k.endswith("CredentialsId")},
                "new": body,
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job("PUT", path, body, ctx=ctx, what="site credentials")

        return await preview_or_apply(
            ctx,
            tool="catc_assign_site_credentials",
            args={"site": site, "credentials": credentials},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Update global credential", destructive=True)
    async def catc_update_global_credential(
        ctx: Context,
        credential: Annotated[
            str, Field(description="Credential id, description, or 'TYPE:description' (e.g. 'CLI:lab')")
        ],
        description: Annotated[
            str | None, Field(min_length=1, max_length=128, description="New description (rename)")
        ] = None,
        username: Annotated[str | None, Field(description="New CLI / SNMPv3 / HTTP username")] = None,
        password: Annotated[
            SecretStr | None, Field(description="New CLI or HTTP password (never echoed back)")
        ] = None,
        enable_password: Annotated[SecretStr | None, Field(description="New CLI enable password")] = None,
        community: Annotated[
            SecretStr | None, Field(description="New SNMPv2c read or write community (never echoed back)")
        ] = None,
        port: Annotated[int | None, Field(ge=1, le=65535, description="New HTTP(S) port")] = None,
        snmpv3_mode: Annotated[
            Literal["AUTHPRIV", "AUTHNOPRIV", "NOAUTHNOPRIV"] | None,
            Field(description="SNMPv3 security level (default: the current one)"),
        ] = None,
        snmpv3_auth_type: Annotated[
            Literal["SHA", "MD5"] | None, Field(description="SNMPv3 auth (default: the current one)")
        ] = None,
        snmpv3_auth_password: Annotated[SecretStr | None, Field(description="SNMPv3 auth password")] = None,
        snmpv3_privacy_type: Annotated[
            Literal["AES128", "AES192", "AES256"] | None,
            Field(description="SNMPv3 privacy (default: the current one)"),
        ] = None,
        snmpv3_privacy_password: Annotated[
            SecretStr | None, Field(description="SNMPv3 privacy password")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Rotate a global device credential in place (CLI, SNMPv2c read/write, SNMPv3, HTTP(S)): new
        secret(s), and optionally a new username or description. The credential keeps its id, so the
        sites and discoveries that use it pick up the new values. Rotation always sends the new secret
        (CLI or HTTP password, SNMPv2c community, the SNMPv3 passwords its mode needs): Catalyst Center
        never returns the old one. Preview-first; secrets are masked in the preview and never returned.
        Only Catalyst Center's copy changes: push it to the devices with catc_apply_site_credentials."""
        app: CatcApp = get_client(ctx)
        creds = await all_credentials(app)
        c = await resolve_credential(app, credential, creds=creds)
        ctype = str(c.get("type", "")).upper()
        blockers: list[str] = []
        secrets: dict[str, str] = {}

        def need(cond: Any, msg: str) -> None:
            if not cond:
                blockers.append(msg)

        def secret(key: str, value: SecretStr | None) -> None:
            if value is not None:
                secrets[key] = value.get_secret_value()

        key = V2_KEYS.get(ctype)
        new_desc = description or str(c.get("description") or "")
        obj: dict[str, Any] = {"id": c["id"], "description": new_desc}
        if key is None:
            blockers.append(
                f"{ctype or 'This'} credentials can't be updated with the v2 credential API (NETCONF only "
                "holds a port): create a new one with catc_create_global_credential."
            )
        elif ctype == "CLI":
            obj["username"] = username or c.get("username")
            need(password, "Rotating a CLI credential needs the new `password`.")
            secret("password", password)
            secret("enablePassword", enable_password)
        elif ctype in ("SNMPV2_READ_COMMUNITY", "SNMPV2_WRITE_COMMUNITY"):
            need(community, "Rotating an SNMPv2c credential needs the new `community`.")
            secret("readCommunity" if ctype == "SNMPV2_READ_COMMUNITY" else "writeCommunity", community)
        elif ctype == "SNMPV3":
            mode = snmpv3_mode or c.get("snmpMode") or c.get("mode") or "AUTHPRIV"
            obj.update({"username": username or c.get("username"), "snmpMode": mode})
            if mode != "NOAUTHNOPRIV":
                obj["authType"] = snmpv3_auth_type or c.get("authType")
                need(obj["authType"], f"{mode} needs `snmpv3_auth_type`.")
                need(snmpv3_auth_password, f"Rotating a {mode} credential needs `snmpv3_auth_password`.")
                secret("authPassword", snmpv3_auth_password)
            if mode == "AUTHPRIV":
                obj["privacyType"] = snmpv3_privacy_type or c.get("privacyType")
                need(obj["privacyType"], "AUTHPRIV needs `snmpv3_privacy_type`.")
                need(
                    snmpv3_privacy_password,
                    "Rotating an AUTHPRIV credential needs `snmpv3_privacy_password`.",
                )
                secret("privacyPassword", snmpv3_privacy_password)
        else:  # HTTP_READ / HTTP_WRITE
            obj.update({"username": username or c.get("username"), "port": port or c.get("port") or 443})
            need(password, "Rotating an HTTP(S) credential needs the new `password`.")
            secret("password", password)
        need(
            ctype in ("CLI", "SNMPV3", "HTTP_READ", "HTTP_WRITE") or username is None,
            f"{ctype} credentials have no username.",
        )
        need(ctype.startswith("HTTP") or port is None, "`port` applies to HTTP(S) credentials only.")
        if description and any(
            x.get("id") != c["id"]
            and str(x.get("type", "")).upper() == ctype
            and str(x.get("description", "")).lower() == description.lower()
            for x in creds
        ):
            blockers.append(f"Another {ctype} credential is already described {description!r}.")
        changes = {
            f: {"from": c.get(src), "to": obj.get(f)}
            for f, src in (("description", "description"), ("username", "username"), ("port", "port"))
            if f in obj and obj.get(f) != c.get(src)
        }
        body = {key: {**obj, **dict.fromkeys(secrets, MASK)}} if key else {}
        plan = Plan(
            f"Update {ctype} credential {c.get('description')}"
            + (f" (rename to {new_desc})" if new_desc != c.get("description") else ""),
            details={
                "credential": pick(c, CRED_FIELDS),
                "changes": changes,
                "secrets_rotated": sorted(secrets),
                "method": "PUT",
                "path": V2_CRED_PATH,
                "body": body,
            },
            side_effects=[
                "Catalyst Center manages every device that uses this credential with the new values "
                "from now on (inventory sync, discovery, provisioning). Devices still have the old ones "
                "until catc_apply_site_credentials pushes the new credential to a site's devices.",
            ],
            fingerprint=pick(c, CRED_FIELDS),
            blockers=blockers,
            undo="not reversible: the old secret can't be read back; run this again with the old values",
        )
        args = {
            "credential": credential,
            "description": description,
            "username": username,
            "port": port,
            "snmpv3_mode": snmpv3_mode,
            "snmpv3_auth_type": snmpv3_auth_type,
            "snmpv3_privacy_type": snmpv3_privacy_type,
            # Secrets aren't stored; a digest makes the token refuse changed values.
            "secrets": hashlib.sha256(json.dumps(secrets, sort_keys=True).encode()).hexdigest(),
        }

        async def apply() -> Any:
            job = await app.run_job(
                "PUT", V2_CRED_PATH, {key: {**obj, **secrets}}, ctx=ctx, what="update credential"
            )
            return {
                "credential_id": c["id"],
                "type": ctype,
                "description": new_desc,
                "secrets_rotated": sorted(secrets),
                "task_id": job.get("task_id"),
                "next": "catc_apply_site_credentials(site) pushes it to the devices of a site that uses it",
            }

        return await preview_or_apply(
            ctx, tool="catc_update_global_credential", args=args, confirm=confirm, plan=plan, apply=apply
        )

    @reg.dangerous(title="Apply site credentials to devices", task=True)
    async def catc_apply_site_credentials(
        ctx: Context,
        site: Annotated[
            str, Field(description="Site (id or name hierarchy) the credentials are assigned to")
        ],
        credential_types: Annotated[
            list[ApplyType] | None,
            Field(description="Only these credential types (default: every CLI/SNMP one the site has)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push a site's current CLI and SNMP credentials to its devices (Catalyst Center's credential
        sync): every device at the site and at the sites below it that inherit them gets the credential
        configured, then is managed with it. Use it after catc_update_global_credential or
        catc_assign_site_credentials. A CLI credential isn't configured on devices that log in through
        AAA (they are only managed with it). The preview shows each credential and the current sync
        status per type (device counts); the result has each sync task and the status afterwards
        (Synced / Failed / Not Synced / In Progress / Partially Synced, with device counts).
        Credentials a site inherits are applied at the site they are assigned to. Preview-first."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        sid = str(s["id"])
        creds = await all_credentials(app)
        by_id = {str(c.get("id")): c for c in creds}
        assigned = await app.get_response(
            f"/dna/intent/api/v1/sites/{sid}/deviceCredentials", {"_inherited": True}
        )
        assigned = assigned if isinstance(assigned, dict) else {}
        status_path = f"/dna/intent/api/v1/sites/{sid}/deviceCredentials/status"
        before = await app.get_response(status_path)
        wanted = list(dict.fromkeys(credential_types or APPLY_TYPES))
        blockers: list[str] = []
        apply_list: list[dict[str, Any]] = []
        for ctype in wanted:
            raw = assigned.get(APPLY_TYPES[ctype][0])
            slot: dict[str, Any] = raw if isinstance(raw, dict) else {}
            cid = slot.get("credentialsId")
            if not cid:
                if credential_types:
                    blockers.append(f"{s.get('nameHierarchy')} has no {ctype} credential.")
                continue
            inherited = slot.get("inheritedSiteId")
            if inherited and str(inherited) != sid:
                blockers.append(
                    f"{s.get('nameHierarchy')} inherits its {ctype} credential from "
                    f"{slot.get('inheritedSiteName') or inherited}: apply it at that site."
                )
                continue
            c = by_id.get(str(cid), {})
            apply_list.append(
                {
                    "type": ctype,
                    "credential": f"{ctype}:{c.get('description')}" if c else cid,
                    "credential_id": cid,
                }
            )
        if not apply_list and not blockers:
            blockers.append(
                f"{s.get('nameHierarchy')} has no CLI or SNMP credentials of its own: assign them with "
                "catc_assign_site_credentials."
            )
        rows = status_rows(before, [a["type"] for a in apply_list])
        # A type can have several rows (one per sync status): its devices are their sum.
        per_type: dict[str, int] = {}
        for r in rows:
            per_type[r["type"]] = per_type.get(r["type"], 0) + int(r.get("devices") or 0)
        devices = max(per_type.values(), default=0)
        if apply_list and not devices:
            blockers.append(
                "No devices at the site or below use these credentials (the sync status lists none)."
            )
        from catc_mcp.safety import device_limit_blockers  # noqa: PLC0415 - safety imports sites -> here

        blockers += device_limit_blockers(app, devices)
        plan = Plan(
            f"Apply {len(apply_list)} credential(s) to the devices of {s.get('nameHierarchy')}",
            details={
                "site": {"nameHierarchy": s.get("nameHierarchy"), "id": sid},
                "apply": apply_list,
                "status_now": rows,
                "requests": [f"POST {APPLY_PATH}" for _ in apply_list],
            },
            side_effects=[
                "Configures the credentials on every device at the site and the sites below it that "
                "inherit them, then manages the devices with them: a wrong CLI or SNMP credential leaves "
                "devices unmanageable from Catalyst Center until it is fixed.",
                "A CLI credential isn't configured on devices that log in through AAA; they are only "
                "managed with it.",
            ],
            fingerprint={"assigned": [(a["type"], a["credential_id"]) for a in apply_list], "status": rows},
            blockers=blockers,
            blast_radius=devices,
            undo="not reversible as such: assign and apply the previous credentials again",
        )

        async def apply() -> Any:
            results: list[dict[str, Any]] = []
            for a in apply_list:
                body = {"deviceCredentialId": a["credential_id"], "siteId": sid}
                row: dict[str, Any] = {"type": a["type"], "credential": a["credential"]}
                try:
                    job = await app.run_job("POST", APPLY_PATH, body, ctx=ctx, what=f"apply {a['type']}")
                    row.update({"ok": True, "task_id": job.get("task_id")})
                except TaskFailed as err:
                    row.update({"ok": False, "error": str(err)})
                results.append(row)
            types = [a["type"] for a in apply_list]
            after = status_rows(await app.get_response(status_path), types)
            for _ in range(STATUS_POLLS):
                if not any(r.get("status") == "In Progress" for r in after):
                    break
                await asyncio.sleep(STATUS_INTERVAL)
                after = status_rows(await app.get_response(status_path), types)
            return {
                "site": s.get("nameHierarchy"),
                "applied": results,
                "status": after,
                "ok": all(r["ok"] for r in results)
                and all(r.get("status") in ("Synced", "Not Applicable") for r in after),
            }

        return await preview_or_apply(
            ctx,
            tool="catc_apply_site_credentials",
            args={"site": site, "credential_types": credential_types},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
