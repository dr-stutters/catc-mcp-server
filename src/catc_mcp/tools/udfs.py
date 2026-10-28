"""User-defined fields (UDFs, roadmap D123): global field definitions and per-device values.

Catalyst Center keeps UDFs as global definitions (GET/POST /network-device/user-defined-field,
PUT/DELETE /network-device/user-defined-field/{id}); a device carries a value for a defined field
(PUT /network-device/{deviceId}/user-defined-field with [{name, value}], which adds or updates, and
DELETE ...?name= to clear). Device values are read with GET /networkDevices?views=USER_DEFINED_FIELDS,
which returns `userDefinedFields` as a {name: value} map per device.

Writes are preview-first. Deleting a field that devices still carry clears it from all of them, so that
case needs MCP_ENABLE_DANGEROUS on top of writes.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.http import fetch_all, page_of
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device
from catc_mcp.safety import device_limit_blockers

UDF_PATH = "/dna/intent/api/v1/network-device/user-defined-field"
DEVICES_UDF_VIEW = "/dna/intent/api/v1/networkDevices"
SCAN_CAP = 5000


async def all_udfs(app: CatcApp) -> list[dict[str, Any]]:
    """Every global UDF definition ({id, name, description})."""
    return [u for u in ensure_list(await app.get_response(UDF_PATH)) if isinstance(u, dict)]


def find_udf(udfs: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    """A UDF by id or by name (exact first, then case-insensitive)."""
    ref = ref.strip()
    for u in udfs:
        if str(u.get("id")) == ref or str(u.get("name")) == ref:
            return u
    low = ref.lower()
    hits = [u for u in udfs if str(u.get("name", "")).lower() == low]
    return hits[0] if len(hits) == 1 else None


async def device_udfs(app: CatcApp, device_id: str) -> dict[str, str]:
    """The {name: value} map of UDFs one device carries."""
    rec = ensure_list(
        await app.get_response(
            f"{DEVICES_UDF_VIEW}/{safe_id(device_id, 'device id')}", {"views": "USER_DEFINED_FIELDS"}
        )
    )
    row = rec[0] if rec and isinstance(rec[0], dict) else {}
    udfs = row.get("userDefinedFields") if isinstance(row, dict) else None
    return (
        {str(k): "" if v is None else str(v) for k, v in (udfs or {}).items()}
        if isinstance(udfs, dict)
        else {}
    )


async def devices_with_udfs(app: CatcApp) -> tuple[list[dict[str, Any]], bool]:
    """Every device with its UDF map ({id, hostname, managementAddress, userDefinedFields}), and whether
    the scan saw the whole inventory."""
    page = await fetch_all(
        app.pager, app.api, DEVICES_UDF_VIEW, {"views": "USER_DEFINED_FIELDS"}, cap=SCAN_CAP
    )
    rows = [d for d in page.items if isinstance(d, dict)]
    return rows, page.complete


def carriers(devices: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """Devices that carry the UDF `name`, with the value each holds."""
    out = []
    for d in devices:
        udfs = d.get("userDefinedFields")
        if isinstance(udfs, dict) and name in udfs:
            out.append(
                {
                    "device": d.get("hostname") or d.get("managementAddress"),
                    "id": d.get("id"),
                    "value": udfs.get(name),
                }
            )
    out.sort(key=lambda r: str(r.get("device") or ""))
    return out


class UdfRow(BaseModel):
    device: str = Field(description="Device hostname, management IP, serial or id")
    name: str = Field(min_length=1, description="UDF name (must already exist globally: catc_set_udf)")
    value: str | None = Field(
        default=None, description="Value to set; null or omitted clears the field from the device"
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List user-defined fields")
    async def catc_list_udfs(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Only this UDF (name or id); with devices=true, who carries it")
        ] = None,
        devices: Annotated[
            bool,
            Field(
                description="Also scan the inventory: per UDF the number of devices carrying it and (with "
                "`name`) each device and its value"
            ),
        ] = False,
        value: Annotated[
            str | None, Field(description="With name + devices: only devices whose value equals this")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """User-defined fields (UDFs): the global field definitions Catalyst Center devices can carry
        (asset tag, owner, contract, CMDB id...) with name, description and id. devices=true adds how many
        devices carry each; with a name it lists those devices and their values (value= filters them).
        Values for one device: catc_get_device. Create or change fields with catc_set_udf, values with
        catc_set_device_udfs."""
        app: CatcApp = get_client(ctx)
        if value is not None and not (name and devices):
            raise InvalidRequest("`value` filters the devices of one UDF: give name and devices=true too.")
        udfs = await all_udfs(app)
        if name:
            u = find_udf(udfs, name)
            if u is None:
                raise NotFound(
                    f"No user-defined field {name!r}. Defined: "
                    + (", ".join(sorted(str(x.get("name")) for x in udfs)) or "none")
                    + ". Create it with catc_set_udf."
                )
            udfs = [u]
        rows = [{k: u.get(k) for k in ("name", "description", "id")} for u in udfs]
        rows.sort(key=lambda r: str(r.get("name") or "").lower())
        if not devices:
            return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
        inv, complete = await devices_with_udfs(app)
        extra: dict[str, Any] = {"devices_scanned": len(inv)}
        if not complete:
            extra["note"] = f"Only the first {SCAN_CAP} devices were scanned: counts may be low."
        if name:
            held = carriers(inv, str(rows[0]["name"]))
            if value is not None:
                held = [h for h in held if str(h.get("value")) == value]
            extra["udf"] = rows[0]
            return list_result(page_of(held, limit=limit, offset=offset), fmt=response_format, extra=extra)
        for r in rows:
            r["device_count"] = len(carriers(inv, str(r["name"])))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.write(title="Create, update or delete a user-defined field")
    async def catc_set_udf(
        ctx: Context,
        name: Annotated[
            str,
            Field(min_length=1, max_length=128, description="UDF name (or id, to update/delete one)"),
        ],
        description: Annotated[str | None, Field(description="Field description")] = None,
        new_name: Annotated[
            str | None, Field(min_length=1, max_length=128, description="Rename an existing field")
        ] = None,
        delete: Annotated[
            bool,
            Field(
                description="Delete the global field. When devices carry it, Catalyst Center drops it from "
                "all of them: that needs MCP_ENABLE_DANGEROUS."
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a global user-defined field (asset tag, owner, CMDB id...) that devices can then carry,
        change its description or name, or delete it. Preview-first: shows the field before and after,
        and for a delete how many devices carry it and their values (deleting a field in use clears it
        from those devices and needs the dangerous tier). Set values with catc_set_device_udfs."""
        app: CatcApp = get_client(ctx)
        udfs = await all_udfs(app)
        current = find_udf(udfs, name)
        blockers: list[str] = []
        side_effects: list[str] = []
        details: dict[str, Any] = {}
        blast: int | None = None
        noop = False
        noop_reason: str | None = None
        fingerprint: Any = current
        if delete:
            if new_name or description is not None:
                raise InvalidRequest("delete=true takes no new_name or description.")
            if current is None:
                raise NotFound(f"No user-defined field {name!r} to delete. List them with catc_list_udfs.")
            inv, complete = await devices_with_udfs(app)
            held = carriers(inv, str(current.get("name")))
            if not complete:
                blockers.append(
                    f"The inventory is larger than {SCAN_CAP} devices, so the devices carrying this field "
                    "can't all be counted. Clear it from devices first with catc_set_device_udfs."
                )
            if held and not app.settings.mcp_enable_dangerous:
                blockers.append(
                    f"{len(held)} device(s) carry {current.get('name')!r}; deleting it clears it from all "
                    "of them, which needs MCP_ENABLE_DANGEROUS. Or clear the values first with "
                    "catc_set_device_udfs."
                )
            if held:
                side_effects.append(f"Clears the field from {len(held)} device(s).")
            path = f"{UDF_PATH}/{safe_id(str(current['id']), 'UDF id')}"
            summary = f"Delete user-defined field {current.get('name')}" + (
                f" (carried by {len(held)} device(s))" if held else ""
            )
            details = {"method": "DELETE", "path": path, "before": current, "devices_carrying": held[:50]}
            blast = len(held) or None
            fingerprint = {"udf": current, "carriers": held}
            method, body = "DELETE", None
        elif current is None:
            if new_name:
                raise NotFound(f"No user-defined field {name!r} to rename. List them with catc_list_udfs.")
            body = {"name": name, "description": description or ""}
            path, method = UDF_PATH, "POST"
            summary = f"Create user-defined field {name}"
            details = {"method": "POST", "path": path, "body": body, "before": None, "after": body}
        else:
            target = new_name or str(current.get("name"))
            desc = str(current.get("description") or "") if description is None else description
            if new_name and new_name != current.get("name") and find_udf(udfs, new_name):
                blockers.append(f"A user-defined field named {new_name!r} already exists.")
            body = {"name": target, "description": desc}
            path = f"{UDF_PATH}/{safe_id(str(current['id']), 'UDF id')}"
            method = "PUT"
            before = {"name": current.get("name"), "description": current.get("description") or ""}
            summary = f"Update user-defined field {current.get('name')}" + (
                f" -> {target}" if target != current.get("name") else ""
            )
            details = {"method": "PUT", "path": path, "body": body, "before": before, "after": body}
            if before == body:
                noop, noop_reason = True, f"{target!r} already has that name and description."
            elif target != current.get("name"):
                side_effects.append("Devices carrying the field keep their values under the new name.")
        plan = Plan(
            summary,
            details=details,
            fingerprint=fingerprint,
            blockers=blockers,
            side_effects=side_effects,
            blast_radius=blast,
            noop=noop and not blockers,
            noop_reason=noop_reason if noop and not blockers else None,
        )

        async def apply() -> Any:
            job = await app.run_job(method, path, body, ctx=ctx, what="user-defined field")
            out: dict[str, Any] = {"task": job.get("task_id"), "status": job.get("status")}
            if body is not None:
                out["udf"] = find_udf(await all_udfs(app), body["name"])
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_set_udf",
            args={"name": name, "description": description, "new_name": new_name, "delete": delete},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set user-defined field values on devices", destructive=False)
    async def catc_set_device_udfs(
        ctx: Context,
        rows: Annotated[
            list[UdfRow],
            Field(
                min_length=1,
                max_length=500,
                description="One row per device and field: {device, name, value}; value null clears it",
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set or clear user-defined field values on network devices (e.g. asset tag, owner, CMDB id from
        the source of truth). Each field must already exist globally (catc_set_udf). Preview-first: the
        before and after values per device, rows already in that state, and the device count against
        CATC_MAX_DEVICES_PER_CHANGE. Only Catalyst Center's inventory record changes, not the device."""
        app: CatcApp = get_client(ctx)
        defined = {str(u.get("name")) for u in await all_udfs(app)}
        blockers: list[str] = []
        missing = sorted({r.name for r in rows if r.name not in defined})
        if missing:
            blockers.append(
                "Not defined globally: " + ", ".join(missing) + ". Create them first with catc_set_udf."
            )
        devs: dict[str, dict[str, Any]] = {}
        wanted: dict[str, dict[str, str | None]] = {}
        for r in rows:
            d = await resolve_device(app, r.device)
            did = str(d["id"])
            devs[did] = d
            if r.name in wanted.setdefault(did, {}) and wanted[did][r.name] != r.value:
                raise InvalidRequest(f"Two rows set {r.name!r} on {d.get('hostname')} to different values.")
            wanted[did][r.name] = r.value
        changes: list[dict[str, Any]] = []
        unchanged: list[dict[str, Any]] = []
        befores: dict[str, dict[str, str]] = {}
        for did, want in wanted.items():
            before = await device_udfs(app, did)
            befores[did] = before
            after = dict(before)
            for k, v in want.items():
                if v is None:
                    after.pop(k, None)
                else:
                    after[k] = v
            label = devs[did].get("hostname") or devs[did].get("managementIpAddress")
            if after == before:
                unchanged.append({"device": label, "fields": want})
                continue
            changes.append(
                {
                    "device": label,
                    "id": did,
                    "set": {k: v for k, v in want.items() if v is not None and before.get(k) != v},
                    "clear": sorted(k for k, v in want.items() if v is None and k in before),
                    "before": before,
                    "after": after,
                }
            )
        blockers += device_limit_blockers(app, len(changes))
        nothing = not changes and not blockers
        plan = Plan(
            f"Set user-defined fields on {len(changes)} device(s)",
            details={"changes": changes, "already_in_state": unchanged},
            fingerprint=befores,
            blockers=blockers,
            blast_radius=len(changes),
            noop=nothing,
            noop_reason="Every device already has those values." if nothing else None,
        )

        async def apply() -> Any:
            done: list[dict[str, Any]] = []
            for c in changes:
                did = safe_id(str(c["id"]), "device id")
                try:
                    if c["set"]:
                        body = [{"name": k, "value": v} for k, v in c["set"].items()]
                        await app.run_job(
                            "PUT",
                            f"/dna/intent/api/v1/network-device/{did}/user-defined-field",
                            body,
                            ctx=ctx,
                            what="set device UDFs",
                        )
                    for k in c["clear"]:
                        await app.run_job(
                            "DELETE",
                            f"/dna/intent/api/v1/network-device/{did}/user-defined-field",
                            params={"name": k},
                            ctx=ctx,
                            what="clear device UDF",
                        )
                except UpstreamError as e:
                    return {"done": done, "failed": {"device": c["device"], "error": str(e)[:300]}}
                done.append({"device": c["device"], "after": await device_udfs(app, str(c["id"]))})
            return {"done": done}

        return await preview_or_apply(
            ctx,
            tool="catc_set_device_udfs",
            args={"rows": [r.model_dump() for r in rows]},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
