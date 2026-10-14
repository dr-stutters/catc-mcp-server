"""Device credentials: global credentials (Design > Network Settings > Device Credentials) and
which ones a site uses. Secrets are write-only: Catalyst Center never returns them and these tools
never echo them."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import hashlib
import json
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field, SecretStr
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    preview_or_apply,
)
from stutters_mcp_core.formatting import MASK
from stutters_mcp_core.http import fetch_all, page_of

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

# Site credential slots (PUT /sites/{id}/deviceCredentials) by credential type. NETCONF has no slot.
SITE_SLOTS = {
    "CLI": "cliCredentialsId",
    "SNMPV2_READ_COMMUNITY": "snmpv2cReadCredentialsId",
    "SNMPV2_WRITE_COMMUNITY": "snmpv2cWriteCredentialsId",
    "SNMPV3": "snmpv3CredentialsId",
    "HTTP_READ": "httpReadCredentialsId",
    "HTTP_WRITE": "httpWriteCredentialsId",
}

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
    ctype, _, desc = ref.rpartition(":")
    found = [
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
            fingerprint={k: label(v) for k, v in current.items() if k.endswith("CredentialsId")},
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
