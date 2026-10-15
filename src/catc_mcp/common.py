"""Shared helpers for tools: id/name resolution, time windows, field projection."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Awaitable
from typing import Any
from urllib.parse import quote

from stutters_mcp_core import InvalidRequest, NotFound, UpstreamError

from catc_mcp.client import CatcApp, safe_id

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")

# Per-endpoint page-size caps (`fetch_page(max_page=...)`), found on 3.2.2: the API rejects or
# silently truncates larger pages, and the spec doesn't say.
PAGE_ISSUES = 25  # /dna/data/api/v1/assuranceIssues (app.data_pager)
PAGE_EVENTS = 20  # /dna/data/api/v1/assuranceEvents (app.data_pager)
PAGE_AUDIT = 25  # /dna/data/api/v1/event/event-series/audit-logs (app.audit_pager, 0-based)
PAGE_NOTIFICATIONS = 500  # /dna/intent/api/v1/event/event-series (app.audit_pager, 0-based; 1000 accepted)
PAGE_DEVICE_HEALTH = 500  # /dna/intent/api/v1/device-health (app.data_pager, totalCount)

DEVICE_FIELDS = [
    "hostname",
    "managementIpAddress",
    "platformId",
    "softwareVersion",
    "role",
    "reachabilityStatus",
    "collectionStatus",
    "serialNumber",
    "family",
    "upTime",
    "id",
]


def is_uuid(value: str) -> bool:
    return bool(UUID_RE.match(value.strip()))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def norm_mac(mac: str) -> str:
    """aa:bb:cc:dd:ee:ff from any of the usual notations."""
    raw = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(raw) != 12 or not MAC_RE.match(mac.strip()):
        raise InvalidRequest(f"{mac!r} is not a MAC address (use aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff).")
    raw = raw.lower()
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def seg(value: str) -> str:
    """Quote a free-text value for use as one URL path segment."""
    value = value.strip()
    if value in ("", ".", ".."):
        raise InvalidRequest(f"Invalid value {value!r}.")
    return quote(value, safe="")


def window(hours: float) -> dict[str, int]:
    """startTime/endTime (epoch ms) covering the last `hours`."""
    end = int(time.time() * 1000)
    return {"startTime": end - int(hours * 3600 * 1000), "endTime": end}


def pick(obj: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {f: obj[f] for f in fields if obj.get(f) not in (None, "")}


def ensure_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def ago(ms: Any, now_ms: float | None = None) -> str | None:
    """'2h49m ago' for an epoch-ms time (None if it isn't one)."""
    if not isinstance(ms, int | float) or ms <= 0:
        return None
    secs = max(0, int(((now_ms if now_ms is not None else time.time() * 1000) - ms) / 1000))
    if secs < 60:
        return f"{secs}s ago"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m ago"
    hours, mins = divmod(mins, 60)
    if hours < 48:
        return f"{hours}h{mins:02d}m ago"
    return f"{hours // 24}d{hours % 24}h ago"


async def inventory_names(app: CatcApp, ids: Any) -> dict[str, str] | None:
    """{device id: hostname} for the ids that are still in the inventory, or None when the lookup
    failed (then nothing can be said about missing devices). Assurance keeps health records and
    issues for devices deleted from the inventory; this tells them apart."""
    wanted = sorted({str(i) for i in ids if i and is_uuid(str(i))})
    out: dict[str, str] = {}
    try:
        for n in range(0, len(wanted), 50):
            found = await app.get_response(
                "/dna/intent/api/v1/network-device", {"id": ",".join(wanted[n : n + 50])}
            )
            for d in ensure_list(found):
                if isinstance(d, dict) and d.get("id"):
                    out[str(d["id"])] = str(d.get("hostname") or d.get("managementIpAddress") or d["id"])
    except UpstreamError:
        return None
    return out


# --- resolution ----------------------------------------------------------------------------


async def resolve_device(app: CatcApp, ref: str) -> dict[str, Any]:
    """A network device record from its id, management IP, serial number or hostname (exact, then
    'hostname.*' so a short name matches an FQDN)."""
    ref = ref.strip()
    if not ref:
        raise InvalidRequest("Give a device hostname, management IP, serial number or id.")
    if is_uuid(ref):
        dev = await app.get_response(f"/dna/intent/api/v1/network-device/{ref}")
        if isinstance(dev, dict) and dev.get("id"):
            return dev
        raise NotFound(f"No network device with id {ref}. Use catc_list_devices to find it.")
    low = ref.lower()
    # (query, client-side check): the API treats values as patterns, so re-check matches exactly.
    queries: list[tuple[dict[str, str], Any]]
    if is_ip(ref):
        queries = [({"managementIpAddress": ref}, lambda d: d.get("managementIpAddress") == ref)]
    else:
        queries = [
            ({"hostname": ref}, lambda d: str(d.get("hostname", "")).lower() == low),
            ({"serialNumber": ref}, lambda d: low in str(d.get("serialNumber", "")).lower().split(", ")),
            ({"hostname": ref + ".*"}, lambda d: str(d.get("hostname", "")).lower().startswith(low + ".")),
        ]
    for q, ok in queries:
        found = ensure_list(await app.get_response("/dna/intent/api/v1/network-device", q))
        found = [d for d in found if isinstance(d, dict) and ok(d)]
        if len(found) == 1:
            return dict(found[0])
        if len(found) > 1:
            names = ", ".join(f"{d.get('hostname')} ({d.get('managementIpAddress')})" for d in found[:10])
            raise InvalidRequest(f"{ref!r} matches {len(found)} devices: {names}. Use the IP or id.")
    raise NotFound(
        f"No network device matches {ref!r} (tried IP/hostname/serial). Use catc_list_devices to search."
    )


async def resolve_site(app: CatcApp, ref: str) -> dict[str, Any]:
    """A site from its id, full name hierarchy ('Global/US/SJC-1/Floor 1') or unique short name."""
    ref = ref.strip().strip("/")
    if not ref:
        raise InvalidRequest("Give a site id or name hierarchy such as 'Global/Area/Building'.")
    if is_uuid(ref):
        one = await app.get_response(f"/dna/intent/api/v1/sites/{ref}")
        if isinstance(one, dict) and one.get("id"):
            return one
        raise NotFound(f"No site with id {ref}. Use catc_get_site_hierarchy to list sites.")
    if "/" in ref or ref.lower() == "global":
        if ref.lower() != "global" and not ref.lower().startswith("global/"):
            ref = "Global/" + ref
        found = ensure_list(await app.get_response("/dna/intent/api/v1/sites", {"nameHierarchy": ref}))
        found = [s for s in found if str(s.get("nameHierarchy", "")).lower() == ref.lower()]
    else:
        found = ensure_list(await app.get_response("/dna/intent/api/v1/sites", {"name": ref}))
        found = [s for s in found if str(s.get("name", "")).lower() == ref.lower()]
    if len(found) == 1:
        site: dict[str, Any] = found[0]
        return site
    if len(found) > 1:
        paths = ", ".join(str(s.get("nameHierarchy")) for s in found[:10])
        raise InvalidRequest(f"Site name {ref!r} is ambiguous: {paths}. Use the full hierarchy.")
    raise NotFound(f"No site {ref!r}. Use catc_get_site_hierarchy to list sites.")


async def resolve_template(app: CatcApp, ref: str) -> dict[str, Any]:
    """A template (summary record with templateId/projectName) from its id, 'Project/Name' or a
    unique template name."""
    ref = ref.strip()
    if is_uuid(ref):
        # The list carries versionsInfo (commit history), the single GET doesn't.
        for t in await list_all_templates(app):
            if t.get("templateId") == ref:
                return t
        tpl = await app.get_response(f"/dna/intent/api/v1/template-programmer/template/{ref}")
        if isinstance(tpl, dict) and tpl.get("id"):
            return {"templateId": tpl["id"], **tpl}
        raise NotFound(f"No template with id {ref}.")
    project, _, name = ref.rpartition("/")
    found = [
        t
        for t in await list_all_templates(app)
        if str(t.get("name") or "").lower() == name.lower()
        and (not project or str(t.get("projectName", "")).lower() == project.lower())
    ]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        where = ", ".join(f"{t.get('projectName')}/{t.get('name')}" for t in found)
        raise InvalidRequest(f"Template {ref!r} is ambiguous: {where}. Use 'Project/Name' or the id.")
    raise NotFound(f"No template {ref!r}. Use catc_list_templates to find it.")


async def list_all_templates(app: CatcApp, **params: Any) -> list[dict[str, Any]]:
    """Every template, committed or not (the v1 list hides never-committed templates unless
    unCommitted=true, which returns both)."""
    data = await app.api.get(
        "/dna/intent/api/v1/template-programmer/template", {"unCommitted": "true", **params}
    )
    return [t for t in ensure_list(data) if isinstance(t, dict)]


async def resolve_project(app: CatcApp, ref: str) -> dict[str, Any]:
    """A template project ({"id", "name", ...}) from its id or name."""
    ref = ref.strip()
    if is_uuid(ref):
        proj = await app.api.get(f"/dna/intent/api/v1/template-programmer/project/{safe_id(ref)}")
        if isinstance(proj, dict) and proj.get("id"):
            return dict(proj)
        raise NotFound(f"No template project with id {ref}.")
    found = ensure_list(await app.api.get("/dna/intent/api/v1/template-programmer/project", {"name": ref}))
    found = [p for p in found if isinstance(p, dict) and str(p.get("name", "")).lower() == ref.lower()]
    if len(found) == 1:
        return dict(found[0])
    raise NotFound(f"No template project named {ref!r}. Use catc_list_template_projects.")


async def resolve_tag(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    if is_uuid(ref):
        tag = await app.get_response(f"/dna/intent/api/v1/tag/{ref}")
        if isinstance(tag, dict) and tag.get("id"):
            return dict(tag)
        raise NotFound(f"No tag with id {ref}.")
    found = ensure_list(await app.get_response("/dna/intent/api/v1/tag", {"name": ref}))
    found = [t for t in found if isinstance(t, dict) and str(t.get("name", "")).lower() == ref.lower()]
    if len(found) == 1:
        return dict(found[0])
    raise NotFound(f"No tag named {ref!r}. Use catc_list_tags.")


async def gather_sections(sections: dict[str, Awaitable[Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Await named sections concurrently: ({name: value}, {name: error}) where upstream errors are
    collected per section instead of failing the whole tool; anything else is raised."""
    results = await asyncio.gather(*sections.values(), return_exceptions=True)
    ok: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key, val in zip(sections, results, strict=True):
        if isinstance(val, UpstreamError):
            errors[key] = str(val)[:200]
        elif isinstance(val, BaseException):
            raise val
        else:
            ok[key] = val
    return ok, errors
