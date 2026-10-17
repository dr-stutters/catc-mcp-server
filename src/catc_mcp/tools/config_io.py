"""Config export and diff (roadmap D39): Catalyst Center design intent as reviewable YAML.

`catc_export_config` writes the site hierarchy, per-site network settings, credentials (names only),
template projects and templates, network profiles and their sites, IP pools and reservations, SSIDs,
wireless profiles, tags and compliance policies, by name and in a stable order (docs/config-export.md).
`catc_diff_config` compares two exports, or an export with live Catalyst Center. D40 (config import)
plans from the same document.

Two layers:
- fetch (`collect`): reads Catalyst Center into a raw dict of API records, keyed by section;
- pure (`build_export`, `dump_export`, `load_export`, `diff_exports`): raw dict -> export document ->
  YAML text -> document -> changes. No I/O, so tests run them on recorded fixtures.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from functools import partial
from typing import Annotated, Any, Literal

import yaml
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client, text_result
from catc_mcp._core.formatting import mask_secrets, max_chars
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, list_all_templates, resolve_site
from catc_mcp.tools.compliance_policies import CP, list_policies, root_ids
from catc_mcp.tools.credentials import all_credentials
from catc_mcp.tools.inventory import redact_config
from catc_mcp.tools.ipam import GLOBAL as GLOBAL_POOLS
from catc_mcp.tools.ipam import RESERVED as RESERVED_POOLS
from catc_mcp.tools.ipam import _all as all_pools
from catc_mcp.tools.profiles import list_profiles, profile_site_ids, profile_template_ids
from catc_mcp.tools.sites import SETTINGS, all_sites
from catc_mcp.tools.templates import param_summary
from catc_mcp.tools.wireless import site_ssids, wireless_profiles

FORMAT = "catc-config-export"
VERSION = 1

# Section order in the document (also the default set).
SECTIONS = (
    "sites",
    "settings",
    "credentials",
    "template_projects",
    "templates",
    "network_profiles",
    "ip_pools",
    "ip_reservations",
    "ssids",
    "wireless_profiles",
    "tags",
    "compliance_policies",
)
Section = Literal[
    "sites",
    "settings",
    "credentials",
    "template_projects",
    "templates",
    "network_profiles",
    "ip_pools",
    "ip_reservations",
    "ssids",
    "wireless_profiles",
    "tags",
    "compliance_policies",
]

# Keys shown first in every mapping (in this order); the rest follow alphabetically.
KEY_FIRST = ("path", "site", "project", "name", "ssid", "type", "description")

# Dropped from every record: ids, tenant and hierarchy ids, timestamps, links.
DROP_KEYS = {
    "id",
    "instanceTenantId",
    "siteHierarchyId",
    "parentId",
    "links",
    "createTime",
    "lastUpdateTime",
    "latestVersionTime",
    "createdTime",
    "lastUpdatedTime",
    "inheritedSiteId",
    "inheritedSiteName",
    "inheritedSiteUUID",
}
DROP_SUFFIXES = ("Id", "Ids", "UUID", "Uuid")

SITE_FIELDS = {
    "area": [],
    "building": ["address", "latitude", "longitude", "country"],
    "floor": ["floorNumber", "rfModel", "width", "length", "height", "unitsOfMeasure"],
}
CRED_EXPORT_FIELDS = ["type", "description", "username", "port", "protocol", "secure", "comments"]
CRED_EXPORT_FIELDS += ["snmpMode", "authType", "privacyType"]
POOL_SPACE_FIELDS = [
    "subnet",
    "prefixLength",
    "gatewayIpAddress",
    "dhcpServers",
    "dnsServers",
    "slaacSupport",
]
TEMPLATE_FIELDS = ["description", "language", "softwareType", "composite", "failurePolicy"]

# Bounded concurrency for the per-site reads (settings, SSIDs).
PARALLEL = 8


# --- pure layer: raw API records -> export document --------------------------------------------


def clean(v: Any) -> Any:
    """Drop ids/timestamps, None and empty mappings (recursively); keep empty lists (they clear)."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k in DROP_KEYS or k.endswith(DROP_SUFFIXES):
                continue
            x = clean(x)
            if x is None or x == {}:
                continue
            out[k] = x
        return out
    if isinstance(v, list):
        return [clean(x) for x in v if x is not None]
    return v


def segs(path: str) -> list[str]:
    return [p.lower() for p in str(path).split("/")]


def in_scope(path: str, root: str) -> bool:
    return path.lower() == root.lower() or path.lower().startswith(root.lower() + "/")


def _site_entries(raw_sites: list[dict[str, Any]], root: str) -> list[dict[str, Any]]:
    """Sites in scope plus the ancestors of the scope root (so an import can create the chain)."""
    out = []
    for s in raw_sites:
        path = str(s.get("nameHierarchy") or "")
        kind = str(s.get("type") or "")
        if kind == "global" or not path:
            continue
        if not (in_scope(path, root) or in_scope(root, path)):
            continue
        entry: dict[str, Any] = {"path": path, "type": kind}
        entry.update({f: s[f] for f in SITE_FIELDS.get(kind, []) if s.get(f) not in (None, "")})
        out.append(entry)
    return out


def _settings(
    raw: dict[str, Any], paths: dict[str, str], root: str, cred_names: dict[str, str]
) -> dict[str, Any]:
    """{site path: {category: body}} with only the values set at that site (not inherited)."""
    out: dict[str, Any] = {}
    for sid, cats in raw.items():
        site: dict[str, Any] = {}
        for cat, body in (cats or {}).items():
            if not isinstance(body, dict):
                continue
            if cat == "credentials":
                # cliCredentialsId: <id> -> cliCredentials: CLI:<description>
                ids = {k: v.get("credentialsId") if isinstance(v, dict) else v for k, v in body.items()}
                body = {k.removesuffix("Id"): cred_names.get(str(v), str(v)) for k, v in ids.items() if v}
            else:
                body = mask_secrets(clean(body))
            if body:
                site[cat] = body
        if site and sid in paths and in_scope(paths[sid], root):
            out[paths[sid]] = site
    return out


def _credentials(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        mask_secrets({f: c[f] for f in CRED_EXPORT_FIELDS if c.get(f) not in (None, "")})
        for c in raw
        if isinstance(c, dict)
    ]


def cred_label(c: dict[str, Any]) -> str:
    return f"{c.get('type')}:{c.get('description')}"


def _templates(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(template_projects, templates) from the project listing and the full template records.

    TODO(D36): switch to templates.serialize_templates(...) once D36 lands; keep this signature so
    the export format only changes in one place."""
    system = {
        str(t.get("id"))
        for p in raw.get("projects") or []
        for t in p.get("templates") or []
        if t.get("templateSource") == "SYSTEM_DEFINED"
    }
    names = {
        str(t.get("id")): f"{t.get('projectName')}/{t.get('name')}"
        for t in raw.get("templates") or []
        if isinstance(t, dict)
    }
    templates = []
    used_projects = set()
    for t in raw.get("templates") or []:
        if not isinstance(t, dict) or str(t.get("id")) in system:
            continue
        entry: dict[str, Any] = {"project": t.get("projectName"), "name": t.get("name")}
        entry.update({f: t[f] for f in TEMPLATE_FIELDS if t.get(f) not in (None, "")})
        families = [
            clean({k: d.get(k) for k in ("productFamily", "productSeries", "productType")})
            for d in t.get("deviceTypes") or []
            if isinstance(d, dict)
        ]
        if families:
            entry["deviceTypes"] = sorted(families, key=lambda d: sorted(d.items()))
        if isinstance(t.get("templateContent"), str):
            entry["content"] = redact_config(t["templateContent"])
        params = [param_summary(p) for p in t.get("templateParams") or [] if isinstance(p, dict)]
        if not t.get("customParamsOrder"):
            # The API returns variables in no fixed order unless the template sets one.
            params.sort(key=lambda p: str(p.get("parameterName")))
        if params:
            entry["params"] = params
        members = [
            names.get(str(c.get("id")), f"{c.get('projectName')}/{c.get('name')}")
            for c in t.get("containingTemplates") or []
            if isinstance(c, dict)
        ]
        if members:
            entry["containingTemplates"] = members
        tags = sorted(str(x.get("name")) for x in t.get("tags") or [] if isinstance(x, dict))
        if tags:
            entry["tags"] = tags
        templates.append(entry)
        used_projects.add(str(t.get("projectName")))
    projects = [
        clean({"name": p.get("name"), "description": p.get("description")})
        for p in raw.get("projects") or []
        if isinstance(p, dict) and (p.get("isDeletable") or str(p.get("name")) in used_projects)
    ]
    return projects, templates


def _profiles(
    raw: list[dict[str, Any]], paths: dict[str, str], root: str, template_names: dict[str, str]
) -> list[dict[str, Any]]:
    out = []
    for p in raw:
        prof = p.get("profile") or {}
        entry: dict[str, Any] = {"name": prof.get("name"), "type": prof.get("type")}
        tpls = sorted(template_names.get(i, n) for i, n in (p.get("templates") or {}).items())
        if tpls:
            entry["templates"] = tpls
        entry["sites"] = _root_paths(p.get("site_ids") or [], paths, root)
        out.append(entry)
    return out


def _root_paths(ids: list[str], paths: dict[str, str], root: str) -> list[str]:
    """The assigned sites in scope, without those implied by an assigned parent."""
    ids = [i for i in ids if i in paths and in_scope(paths[i], root)]
    return sorted((paths[i] for i in root_ids(ids, paths)), key=segs)


def _space(space: Any, pool_names: dict[str, str]) -> dict[str, Any]:
    if not isinstance(space, dict) or not space.get("subnet"):
        return {}
    out = {f: space[f] for f in POOL_SPACE_FIELDS if space.get(f) is not None}
    if space.get("globalPoolId"):
        out["globalPool"] = pool_names.get(str(space["globalPoolId"]), str(space["globalPoolId"]))
    return out


def _pools(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for p in raw:
        entry: dict[str, Any] = {"name": p.get("name"), "type": p.get("poolType")}
        for key in ("addressSpace", "ipV4AddressSpace", "ipV6AddressSpace"):
            space = _space(p.get(key), {})
            if space:
                entry["ipv6" if "V6" in key else "ipv4"] = space
        out.append(entry)
    return out


def _reservations(
    raw: list[dict[str, Any]], paths: dict[str, str], root: str, pool_names: dict[str, str]
) -> list[dict[str, Any]]:
    out = []
    for p in raw:
        path = paths.get(str(p.get("siteId")), str(p.get("siteName") or ""))
        if not in_scope(path, root):
            continue
        entry: dict[str, Any] = {"site": path, "name": p.get("name"), "type": p.get("poolType")}
        for key, label in (("ipV4AddressSpace", "ipv4"), ("ipV6AddressSpace", "ipv6")):
            space = _space(p.get(key), pool_names)
            if space:
                entry[label] = space
        out.append(entry)
    return out


def _ssids(raw: dict[str, list[dict[str, Any]]], paths: dict[str, str], root: str) -> list[dict[str, Any]]:
    """SSIDs defined at each site in scope (inherited copies are skipped)."""
    out = []
    for sid, items in raw.items():
        if sid not in paths or not in_scope(paths[sid], root):
            continue
        for s in items or []:
            if not isinstance(s, dict) or s.get("inheritedSiteUUID") not in (None, "", sid):
                continue
            out.append(mask_secrets({"site": paths[sid], **clean(s)}))
    return out


def _wireless_profiles(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for p in raw:
        entry = clean({k: v for k, v in p.items() if k not in ("wirelessProfileName", "featureTemplates")})
        out.append({"name": p.get("wirelessProfileName"), **entry})
    return out


def _tags(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        clean(
            {
                "name": t.get("name"),
                "description": t.get("description"),
                "dynamicRules": t.get("dynamicRules"),
            }
        )
        for t in raw
        if isinstance(t, dict) and not t.get("systemTag")
    ]


def _policies(raw: list[dict[str, Any]], paths: dict[str, str], root: str) -> list[dict[str, Any]]:
    out = []
    for p in raw:
        pol = p.get("policy") or {}
        rules = []
        for r in p.get("rules") or []:
            rule = r.get("rule") or {}
            entry = clean({k: v for k, v in rule.items() if k not in ("deviceTypes",)})
            fams = [d.get("deviceFamily") for d in rule.get("deviceTypes") or [] if isinstance(d, dict)]
            if fams:
                entry["deviceFamilies"] = sorted(str(f) for f in fams)
            conds = [clean(c) for c in r.get("conditions") or [] if isinstance(c, dict)]
            entry["conditions"] = sorted(conds, key=lambda c: int(c.get("sequenceNumber") or 0))
            rules.append(entry)
        out.append(
            {
                **clean({k: pol.get(k) for k in ("name", "description")}),
                "rules": sorted(rules, key=lambda r: str(r.get("name"))),
                "sites": _root_paths(p.get("site_ids") or [], paths, root),
            }
        )
    return out


def build_export(raw: dict[str, Any]) -> dict[str, Any]:
    """The export document from the raw records `collect` gathered (pure; see the module doc)."""
    meta = dict(raw.get("meta") or {})
    root = str(meta.get("scope") or "Global")
    sites = [s for s in raw.get("sites") or [] if isinstance(s, dict)]
    paths = {str(s.get("id")): str(s.get("nameHierarchy")) for s in sites}
    creds = [c for c in raw.get("credentials_raw") or [] if isinstance(c, dict)]
    cred_names = {str(c.get("id")): cred_label(c) for c in creds}
    pool_names = {str(p.get("id")): str(p.get("name")) for p in raw.get("ip_pools") or []}
    tpl = raw.get("templates") or {}
    template_names = {
        str(t.get("id")): f"{t.get('projectName')}/{t.get('name')}"
        for t in tpl.get("templates") or []
        if isinstance(t, dict)
    }
    wanted = list(meta.get("sections") or SECTIONS)
    doc: dict[str, Any] = {"format": FORMAT, "version": VERSION, "meta": meta}
    builders: dict[str, Callable[[], Any]] = {
        "sites": lambda: _site_entries(sites, root),
        "settings": lambda: _settings(raw.get("settings") or {}, paths, root, cred_names),
        "credentials": lambda: _credentials(creds),
        "template_projects": lambda: _templates(tpl)[0],
        "templates": lambda: _templates(tpl)[1],
        "network_profiles": lambda: _profiles(raw.get("network_profiles") or [], paths, root, template_names),
        "ip_pools": lambda: _pools(raw.get("ip_pools") or []),
        "ip_reservations": lambda: _reservations(raw.get("ip_reservations") or [], paths, root, pool_names),
        "ssids": lambda: _ssids(raw.get("ssids") or {}, paths, root),
        "wireless_profiles": lambda: _wireless_profiles(raw.get("wireless_profiles") or []),
        "tags": lambda: _tags(raw.get("tags") or []),
        "compliance_policies": lambda: _policies(raw.get("compliance_policies") or [], paths, root),
    }
    errors = meta.get("errors") or {}
    for section in SECTIONS:
        if section in wanted and section not in errors:
            doc[section] = builders[section]()
    return canonical(doc)


# --- pure layer: stable ordering, YAML, diff -----------------------------------------------------


def item_key(section: str, item: dict[str, Any]) -> str:
    """The identity of an item in a list section (what an import matches by)."""
    if section == "sites":
        return str(item.get("path"))
    if section == "credentials":
        return cred_label(item)
    if section == "templates":
        return f"{item.get('project')}/{item.get('name')}"
    if section == "ip_reservations":
        return f"{item.get('site')}:{item.get('name')}"
    if section == "ssids":
        return f"{item.get('site')}:{item.get('ssid')}"
    return str(item.get("name"))


def _sort_key(section: str, item: dict[str, Any]) -> tuple[Any, ...]:
    if section == "sites":
        return (segs(str(item.get("path"))),)
    if section in ("ip_reservations", "ssids"):
        return (segs(str(item.get("site"))), item_key(section, item).lower())
    return (item_key(section, item).lower(), item_key(section, item))


def _ordered(v: Any) -> Any:
    """Mappings with KEY_FIRST keys first, then the rest alphabetically; list order kept."""
    if isinstance(v, dict):
        first = [k for k in KEY_FIRST if k in v]
        rest = sorted(k for k in v if k not in KEY_FIRST)
        return {k: _ordered(v[k]) for k in [*first, *rest]}
    if isinstance(v, list):
        return [_ordered(x) for x in v]
    return v


def canonical(doc: dict[str, Any]) -> dict[str, Any]:
    """The document in its stable order: header, then sections in SECTIONS order, list items by
    identity, settings by site path, mapping keys per `_ordered`. Idempotent."""
    out: dict[str, Any] = {"format": doc.get("format"), "version": doc.get("version")}
    if "meta" in doc:
        out["meta"] = _ordered(doc["meta"])
    for section in SECTIONS:
        if section not in doc:
            continue
        val = doc[section]
        if section == "settings" and isinstance(val, dict):
            val = {k: val[k] for k in sorted(val, key=segs)}
        elif isinstance(val, list):
            val = sorted((x for x in val if isinstance(x, dict)), key=partial(_sort_key, section))
        out[section] = _ordered(val)
    return out


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def _str(dumper: yaml.SafeDumper, s: str) -> yaml.ScalarNode:
    style = "|" if "\n" in s else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)


_Dumper.add_representer(str, _str)


def dump_export(doc: dict[str, Any]) -> str:
    """Stable YAML for an export document (dump(load(dump(d))) == dump(d))."""
    return yaml.dump(
        canonical(doc),
        Dumper=_Dumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=4096,
        indent=2,
    )


def load_export(text: str) -> dict[str, Any]:
    """Parse and check an export (format name and a version this server understands)."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InvalidRequest(f"Not valid YAML: {str(e)[:300]}") from e
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise InvalidRequest(f"Not a Catalyst Center config export (expected 'format: {FORMAT}').")
    version = doc.get("version")
    if not isinstance(version, int) or not 1 <= version <= VERSION:
        raise InvalidRequest(f"Export version {version!r} is not supported (this server reads 1..{VERSION}).")
    return doc


def _as_items(section: str, val: Any) -> dict[str, Any]:
    if isinstance(val, dict):
        return val
    return {item_key(section, x): x for x in ensure_list(val) if isinstance(x, dict)}


def _walk(before: Any, after: Any, path: list[str], out: list[tuple[list[str], Any, Any]]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for k in [*before, *(k for k in after if k not in before)]:
            _walk(before.get(k), after.get(k), [*path, str(k)], out)
    elif before != after:
        out.append((path, before, after))


def diff_exports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Changes between two export documents, by section and item identity (list order and the
    header/meta are ignored). Sections missing from either side are listed as not compared."""
    changes: list[dict[str, Any]] = []
    summary: dict[str, dict[str, int]] = {}
    skipped = [s for s in SECTIONS if (s in before) != (s in after)]
    for section in SECTIONS:
        if section not in before or section not in after:
            continue
        a, b = _as_items(section, before[section]), _as_items(section, after[section])
        counts = {"added": 0, "removed": 0, "changed": 0}
        for key in sorted(set(a) | set(b), key=lambda k: (segs(k), k)):
            if key not in b:
                counts["removed"] += 1
                changes.append({"section": section, "item": key, "change": "removed", "before": a[key]})
            elif key not in a:
                counts["added"] += 1
                changes.append({"section": section, "item": key, "change": "added", "after": b[key]})
            elif a[key] != b[key]:
                counts["changed"] += 1
                diffs: list[tuple[list[str], Any, Any]] = []
                _walk(a[key], b[key], [], diffs)
                for path, old, new in diffs:
                    row: dict[str, Any] = {"section": section, "item": key, "change": "changed"}
                    row["field"] = ".".join(path)
                    row |= {"before": old, "after": new}
                    changes.append(row)
        if any(counts.values()):
            summary[section] = counts
    return {"identical": not changes, "summary": summary, "changes": changes, "not_compared": skipped}


# --- fetch layer -------------------------------------------------------------------------------


async def _bounded(calls: dict[str, Callable[[], Awaitable[Any]]]) -> dict[str, Any]:
    """Run the calls with at most PARALLEL in flight; {key: result or the UpstreamError}."""
    sem = asyncio.Semaphore(PARALLEL)

    async def one(fn: Callable[[], Awaitable[Any]]) -> Any:
        async with sem:
            try:
                return await fn()
            except UpstreamError as e:
                return e

    results = await asyncio.gather(*(one(fn) for fn in calls.values()))
    return dict(zip(calls, results, strict=True))


async def _site_settings(app: CatcApp, site_ids: list[str]) -> dict[str, Any]:
    calls: dict[str, Callable[[], Awaitable[Any]]] = {}
    for sid in site_ids:
        for cat, suffix in SETTINGS.items():
            path = f"/dna/intent/api/v1/sites/{safe_id(sid, 'site id')}/{suffix}"
            calls[f"{sid}|{cat}"] = partial(app.get_response, path, {"_inherited": "false"})
    out: dict[str, dict[str, Any]] = {}
    for key, val in (await _bounded(calls)).items():
        sid, cat = key.split("|", 1)
        if isinstance(val, UpstreamError):
            raise val
        out.setdefault(sid, {})[cat] = val
    return out


async def _ssids_raw(app: CatcApp, site_ids: list[str]) -> dict[str, Any]:
    results = await _bounded({sid: partial(site_ssids, app, sid) for sid in site_ids})
    for val in results.values():
        if isinstance(val, UpstreamError):
            raise val
    return results


async def _templates_raw(app: CatcApp) -> dict[str, Any]:
    """Project listing + full records of the non-system templates.

    TODO(D36): switch to D36's template serializer once it lands (see `_templates`)."""
    projects = ensure_list(await app.api.get("/dna/intent/api/v1/template-programmer/project"))
    projects = [p for p in projects if isinstance(p, dict)]
    system = {
        str(t.get("id"))
        for p in projects
        for t in p.get("templates") or []
        if t.get("templateSource") == "SYSTEM_DEFINED"
    }
    ids = sorted(
        {
            str(t.get("templateId") or t.get("id"))
            for t in await list_all_templates(app)
            if str(t.get("templateId") or t.get("id")) not in system
        }
    )
    tp = "/dna/intent/api/v1/template-programmer/template"
    full = await _bounded({i: partial(app.api.get, f"{tp}/{safe_id(i, 'template id')}") for i in ids})
    templates = []
    for val in full.values():
        if isinstance(val, UpstreamError):
            raise val
        if isinstance(val, dict):
            templates.append(val)
    return {"projects": projects, "templates": templates}


async def _profiles_raw(app: CatcApp) -> list[dict[str, Any]]:
    out = []
    for p in await list_profiles(app):
        pid = str(p["id"])
        tpls, sites = await asyncio.gather(profile_template_ids(app, pid), profile_site_ids(app, pid))
        out.append({"profile": p, "templates": tpls, "site_ids": sites})
    return out


async def _policies_raw(app: CatcApp) -> list[dict[str, Any]]:
    out = []
    for p in await list_policies(app):
        pid = safe_id(str(p["id"]), "policy id")
        rules = [r for r in ensure_list(await app.get_response(f"{CP}/{pid}/rules")) if isinstance(r, dict)]
        conds = await asyncio.gather(
            *(
                app.get_response(f"{CP}/{pid}/rules/{safe_id(str(r['id']), 'rule id')}/conditions")
                for r in rules
            )
        )
        assigned = await app.get_response(f"{CP}/{pid}/siteAssignments")
        site_ids = assigned.get("siteIds") if isinstance(assigned, dict) else assigned
        out.append(
            {
                "policy": p,
                "rules": [
                    {"rule": r, "conditions": ensure_list(c)} for r, c in zip(rules, conds, strict=True)
                ],
                "site_ids": [str(i) for i in ensure_list(site_ids)],
            }
        )
    return out


async def _tags_raw(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/tag", cap=5000)
    return [t for t in page.items if isinstance(t, dict)]


async def collect(app: CatcApp, scope: str, sections: list[str]) -> dict[str, Any]:
    """Read everything the sections need into the raw dict `build_export` takes. A section whose
    reads fail is left out and named in meta.errors."""
    root_site = await resolve_site(app, scope)
    root = str(root_site.get("nameHierarchy"))
    sites, complete = await all_sites(app)
    scoped = [str(s["id"]) for s in sites if in_scope(str(s.get("nameHierarchy", "")), root)]
    needs_creds = "credentials" in sections or "settings" in sections
    needs_pools = "ip_pools" in sections or "ip_reservations" in sections
    needs_templates = any(s in sections for s in ("templates", "template_projects", "network_profiles"))
    reads: dict[str, Callable[[], Awaitable[Any]]] = {}
    if "settings" in sections:
        reads["settings"] = lambda: _site_settings(app, scoped)
    if needs_creds:
        reads["credentials_raw"] = lambda: all_credentials(app)
    if needs_templates:
        reads["templates"] = lambda: _templates_raw(app)
    if "network_profiles" in sections:
        reads["network_profiles"] = lambda: _profiles_raw(app)
    if needs_pools:
        reads["ip_pools"] = lambda: all_pools(app, GLOBAL_POOLS)
    if "ip_reservations" in sections:
        reads["ip_reservations"] = lambda: all_pools(app, RESERVED_POOLS)
    if "ssids" in sections:
        reads["ssids"] = lambda: _ssids_raw(app, scoped)
    if "wireless_profiles" in sections:
        reads["wireless_profiles"] = lambda: wireless_profiles(app)
    if "tags" in sections:
        reads["tags"] = lambda: _tags_raw(app)
    if "compliance_policies" in sections:
        reads["compliance_policies"] = lambda: _policies_raw(app)
    results = await asyncio.gather(*(fn() for fn in reads.values()), return_exceptions=True)
    raw: dict[str, Any] = {"sites": sites}
    errors: dict[str, str] = {}
    for key, val in zip(reads, results, strict=True):
        if isinstance(val, UpstreamError):
            errors[key] = str(val)[:200]
        elif isinstance(val, BaseException):
            raise val
        else:
            raw[key] = val
    # A failed shared read takes the sections built from it with it.
    depends = {
        "credentials_raw": ["credentials", "settings"],
        "templates": ["templates", "template_projects", "network_profiles"],
        "ip_pools": ["ip_pools", "ip_reservations"],
    }
    section_errors = {}
    for key, msg in errors.items():
        for section in depends.get(key, [key]):
            if section in sections:
                section_errors[section] = msg
    try:
        release = await app.version()
    except UpstreamError:
        release = None
    meta: dict[str, Any] = {
        "exported_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "catalyst_center": release,
        "scope": root,
        "sections": [s for s in SECTIONS if s in sections],
    }
    if not complete:
        section_errors["sites"] = "partial: more than 20000 sites"
    if section_errors:
        meta["errors"] = dict(sorted(section_errors.items()))
    raw["meta"] = {k: v for k, v in meta.items() if v is not None}
    return raw


# --- tools -------------------------------------------------------------------------------------


Sections = Annotated[
    list[Section] | None,
    Field(description="Sections to export (default all): " + ", ".join(SECTIONS)),
]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export configuration", task=True)
    async def catc_export_config(
        ctx: Context,
        scope: Annotated[
            str,
            Field(
                description="Site (name hierarchy or id) whose subtree to export; site-bound sections "
                "(sites, settings, reservations, SSIDs, profile/policy site assignments) are limited to it"
            ),
        ] = "Global",
        sections: Sections = None,
    ) -> ToolResult:
        """Export Catalyst Center design intent as YAML, by name and in a stable order: the site
        hierarchy, network settings set at each site (not inherited), credentials (type, description
        and username only: secrets are never exported), template projects and templates (secrets in
        template bodies masked), network profiles with their templates and sites, global IP pools
        and site reservations, SSIDs (passphrases masked), wireless profiles, tags with their dynamic
        rules, and compliance policies with their rules and sites. No ids, timestamps or counters, so
        two exports of an unchanged Catalyst Center are identical apart from meta.exported_at. Keep
        the YAML as a baseline and compare later with catc_diff_config. Format:
        docs/config-export.md."""
        app: CatcApp = get_client(ctx)
        wanted: list[str] = list(sections) if sections else list(SECTIONS)
        doc = build_export(await collect(app, scope, wanted))
        text = dump_export(doc)
        if len(text) > max_chars():
            sizes = {
                s: len(dump_export({"format": FORMAT, "version": VERSION, s: doc[s]}))
                for s in SECTIONS
                if s in doc
            }
            raise InvalidRequest(
                f"The export is {len(text)} characters, over the response limit ({max_chars()}, "
                f"MCP_MAX_RESPONSE_CHARS). Export fewer sections or a smaller scope. Sizes by section: "
                + ", ".join(f"{k} {v}" for k, v in sizes.items())
            )
        return text_result(text)

    @reg.read(title="Diff configuration exports", task=True)
    async def catc_diff_config(
        ctx: Context,
        before: Annotated[str, Field(description="An export (YAML from catc_export_config)")],
        after: Annotated[
            str | None,
            Field(
                description="A later export to compare with; omit to compare with live Catalyst Center "
                "(exported now with the same scope and sections as `before`)"
            ),
        ] = None,
        section: Annotated[Section | None, Field(description="Only report changes in this section")] = None,
        limit: Annotated[int, Field(ge=1, le=2000, description="Most changes to list")] = 200,
    ) -> dict[str, Any]:
        """Compare two config exports, or an export with live Catalyst Center: items added or removed
        and, for changed items, each field that differs (before and after values). Items are matched by
        name (sites by path, settings by site path, credentials by type:description, templates by
        project/name), so reordering is not a change. Use it for "what changed since the baseline" next
        to catc_list_audit_logs (who changed it)."""
        app: CatcApp = get_client(ctx)
        a = load_export(before)
        meta = a.get("meta") or {}
        if after is None:
            wanted = [s for s in ensure_list(meta.get("sections")) if s in SECTIONS] or list(SECTIONS)
            wanted = [s for s in wanted if s in a]
            b = build_export(await collect(app, str(meta.get("scope") or "Global"), wanted))
            b_label = "live"
        else:
            b = load_export(after)
            b_label = str((b.get("meta") or {}).get("exported_at") or "after")
        result = diff_exports(canonical(a), canonical(b))
        if section:
            result["changes"] = [c for c in result["changes"] if c["section"] == section]
            result["summary"] = {k: v for k, v in result["summary"].items() if k == section}
            result["identical"] = not result["changes"]
        total = len(result["changes"])
        result["changes"] = result["changes"][:limit]
        if total > limit:
            result["truncated"] = f"{total} changes; showing {limit} (raise limit or pass section)"
        result["before"] = str(meta.get("exported_at") or "before")
        result["after"] = b_label
        result["scope"] = meta.get("scope")
        if (b.get("meta") or {}).get("errors"):
            result["after_errors"] = b["meta"]["errors"]
        return result
