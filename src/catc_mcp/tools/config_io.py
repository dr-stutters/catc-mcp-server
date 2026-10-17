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
import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from functools import partial
from typing import Annotated, Any, Literal

import yaml
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client, text_result
from catc_mcp._core.formatting import _is_flag as is_flag
from catc_mcp._core.formatting import mask_all, max_chars
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, list_all_templates, resolve_site
from catc_mcp.tools.compliance_policies import CP, list_policies, root_ids
from catc_mcp.tools.credentials import all_credentials
from catc_mcp.tools.ipam import GLOBAL as GLOBAL_POOLS
from catc_mcp.tools.ipam import RESERVED as RESERVED_POOLS
from catc_mcp.tools.ipam import _all as all_pools
from catc_mcp.tools.profiles import list_profiles, profile_site_ids, profile_template_ids
from catc_mcp.tools.sites import SETTINGS, all_sites

# Secret masking is the templates module's (D36), so a template is masked the same in both exports.
from catc_mcp.tools.templates import param_view, redact_template, secret_name
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

# Most Catalyst Center reads in flight at once, across the whole export.
PARALLEL = 8
# Request budget for the per-site reads (sites x 9 settings categories; sites for SSIDs). Over it,
# the first sites by path are read and a warning says to export a smaller scope for the rest.
MAX_SITE_REQUESTS = 1800

# Lists inside records that are sets (order means nothing): sorted by this field (None: the whole
# value), ties broken by the item's canonical JSON. Lists not named here keep the API's order, which
# carries meaning (server priority, composite template sequence, choice order).
SET_LISTS: dict[str, str | None] = {
    "additionalInterfaces": None,
    "apZones": "apZoneName",
    "ssidDetails": "ssidName",
    "ssids": None,
    "dynamicRules": None,
    "nasOptions": None,
    "deviceTypes": None,
    "deviceFamilies": None,
    "tags": None,
    "templates": None,
    "sites": None,
    "rules": "name",
    "conditions": "sequenceNumber",
    "multiPSKSettings": "priority",
}


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


def mask_doc(v: Any) -> Any:
    """Mask the value of every secret-named key (flags such as isAuthKeyPSK stay readable)."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if secret_name(str(k)) and not is_flag(x) and x not in (None, "", [], {}):
                out[k] = mask_all(x)
            else:
                out[k] = mask_doc(x)
        return out
    if isinstance(v, list):
        return [mask_doc(x) for x in v]
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
                body = clean(body)
            if body:
                site[cat] = body
        if site and sid in paths and in_scope(paths[sid], root):
            out[paths[sid]] = site
    return out


def _credentials(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {f: c[f] for f in CRED_EXPORT_FIELDS if c.get(f) not in (None, "")}
        for c in raw
        if isinstance(c, dict)
    ]


def cred_label(c: dict[str, Any]) -> str:
    return f"{c.get('type')}:{c.get('description')}"


def _templates(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(template_projects, templates) from the project listing and the full template records.

    Content and variables are masked by the templates module (D36). The entry shape stays this
    module's: moving to templates.serialize_templates (with version history) would change the export
    format and is left to D40."""
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
            entry["content"] = redact_template(t["templateContent"])
        params = [param_view(p) for p in t.get("templateParams") or [] if isinstance(p, dict)]
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
            out.append({"site": paths[sid], **clean(s)})
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
            # Final pass over everything built: no section relies on its builder to mask.
            doc[section] = mask_doc(builders[section]())
    doc = canonical(doc)
    dups = duplicates(doc)
    if dups:
        warnings = list(doc["meta"].get("warnings") or [])
        warnings += [
            f"{s}: {n} items share the name {k!r} (diff tells them apart as #2, #3...)" for s, k, n in dups
        ]
        doc["meta"] = _ordered({**doc["meta"], "warnings": warnings})
    return doc


def duplicates(doc: dict[str, Any]) -> list[tuple[str, str, int]]:
    """(section, identity, count) for identities used by more than one item."""
    out = []
    for section in SECTIONS:
        if isinstance(doc.get(section), list):
            keys = [item_key(section, x) for x in doc[section] if isinstance(x, dict)]
            out += [(section, k, keys.count(k)) for k in sorted(set(keys)) if keys.count(k) > 1]
    return out


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


def canon_json(v: Any) -> str:
    return json.dumps(v, sort_keys=True, default=str, ensure_ascii=False)


def _sort_key(section: str, item: dict[str, Any]) -> tuple[Any, ...]:
    """Identity first; the item's canonical JSON breaks ties (duplicates never fall back to API order)."""
    key = item_key(section, item)
    if section == "sites":
        head: tuple[Any, ...] = (segs(str(item.get("path"))),)
    elif section in ("ip_reservations", "ssids"):
        head = (segs(str(item.get("site"))), key.lower())
    else:
        head = (key.lower(), key)
    return (*head, canon_json(item))


def _set_key(field: str | None, x: Any) -> tuple[Any, ...]:
    if field and isinstance(x, dict):
        v = x.get(field)
        if isinstance(v, int | float) and not isinstance(v, bool):
            return (0, v, "", canon_json(x))
        return (1, 0, str(v).lower(), canon_json(x))
    if field == "sites" or (field is None and isinstance(x, str) and x.startswith("Global")):
        return (1, 0, "/".join(segs(str(x))), canon_json(x))
    return (1, 0, str(x).lower() if isinstance(x, str) else "", canon_json(x))


def _ordered(v: Any, key: str | None = None) -> Any:
    """Mappings with KEY_FIRST keys first, then the rest alphabetically. Lists named in SET_LISTS
    are sorted; other lists keep their order."""
    if isinstance(v, dict):
        first = [k for k in KEY_FIRST if k in v]
        rest = sorted(k for k in v if k not in KEY_FIRST)
        return {k: _ordered(v[k], k) for k in [*first, *rest]}
    if isinstance(v, list):
        items = [_ordered(x) for x in v]
        if key in SET_LISTS:
            items.sort(key=partial(_set_key, SET_LISTS[key]))
        return items
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
            val = [_ordered(x) for x in val if isinstance(x, dict)]
            val = sorted(val, key=partial(_sort_key, section))
        out[section] = (
            {k: _ordered(x) for k, x in val.items()} if isinstance(val, dict) else [_ordered(x) for x in val]
        )
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


def _groups(section: str, val: Any) -> dict[str, list[Any]]:
    """{identity: [items]} in canonical order (settings: one item per site path)."""
    if isinstance(val, dict):
        return {k: [v] for k, v in val.items()}
    out: dict[str, list[Any]] = {}
    items = sorted((x for x in ensure_list(val) if isinstance(x, dict)), key=partial(_sort_key, section))
    for x in items:
        out.setdefault(item_key(section, x), []).append(x)
    return out


def _pairs(key: str, a: list[Any], b: list[Any]) -> list[tuple[str, Any, Any]]:
    """Match the items that share an identity: identical ones first, the rest in order; a repeated
    identity is labelled '#2', '#3'... so no item is lost."""
    a, b = list(a), list(b)
    matched: list[tuple[Any, Any]] = []
    for x in list(a):
        if x in b:
            a.remove(x)
            b.remove(x)
            matched.append((x, x))
    rest = max(len(a), len(b))
    matched += [(a[n] if n < len(a) else None, b[n] if n < len(b) else None) for n in range(rest)]
    if len(matched) == 1:
        return [(key, *matched[0])]
    return [(key if n == 0 else f"{key} #{n + 1}", x, y) for n, (x, y) in enumerate(matched)]


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
        ga, gb = _groups(section, before[section]), _groups(section, after[section])
        counts = {"added": 0, "removed": 0, "changed": 0}
        rows = []
        for key in sorted(set(ga) | set(gb), key=lambda k: (segs(k), k)):
            rows += _pairs(key, ga.get(key, []), gb.get(key, []))
        for key, old, new in rows:
            if new is None:
                counts["removed"] += 1
                changes.append({"section": section, "item": key, "change": "removed", "before": old})
            elif old is None:
                counts["added"] += 1
                changes.append({"section": section, "item": key, "change": "added", "after": new})
            elif old != new:
                counts["changed"] += 1
                diffs: list[tuple[list[str], Any, Any]] = []
                _walk(old, new, [], diffs)
                for path, was, now in diffs:
                    row: dict[str, Any] = {"section": section, "item": key, "change": "changed"}
                    row["field"] = ".".join(path)
                    row |= {"before": was, "after": now}
                    changes.append(row)
        if any(counts.values()):
            summary[section] = counts
    return {"identical": not changes, "summary": summary, "changes": changes, "not_compared": skipped}


DIFF_VALUE_CHARS = 400  # longest before/after value shown in a diff row (a template body, a whole item)


def short(v: Any) -> Any:
    """A diff value cut to DIFF_VALUE_CHARS, saying how long it was."""
    if isinstance(v, str) and len(v) > DIFF_VALUE_CHARS:
        return v[:DIFF_VALUE_CHARS] + f"... [{len(v)} characters; compare the exports for the rest]"
    if isinstance(v, dict | list):
        text = canon_json(v)
        if len(text) > DIFF_VALUE_CHARS:
            return f"{text[:DIFF_VALUE_CHARS]}... [{len(text)} characters; compare the exports for the rest]"
    return v


def cap_changes(
    changes: list[dict[str, Any]], limit: int, budget: int
) -> tuple[list[dict[str, Any]], str | None]:
    """At most `limit` rows with long values shortened, and no more than `budget` characters of them."""
    out: list[dict[str, Any]] = []
    used = 0
    for c in changes[:limit]:
        row = {k: short(v) if k in ("before", "after") else v for k, v in c.items()}
        used += len(canon_json(row))
        if out and used > budget:
            break
        out.append(row)
    if len(out) < len(changes):
        why = "limit" if len(out) == min(limit, len(changes)) and len(changes) > limit else "response size"
        return out, f"{len(changes)} changes; showing {len(out)} ({why}: pass section or raise limit)"
    return out, None


# --- fetch layer -------------------------------------------------------------------------------


class Reader:
    """Reads for one export: at most PARALLEL calls in flight across every section, and per-item
    failures (one site's settings, one template) recorded as warnings instead of failing a section.
    429s are retried by the API client (Retry-After) and it paces itself, so nothing is added here."""

    def __init__(self, app: CatcApp) -> None:
        self.app = app
        self.sem = asyncio.Semaphore(PARALLEL)
        self.warnings: list[str] = []

    async def run(self, fn: Callable[[], Awaitable[Any]]) -> Any:
        """One Catalyst Center call under the limit. `fn` must not call run/get itself: the
        semaphore isn't reentrant, so nesting can hold every slot and wait forever."""
        async with self.sem:
            return await fn()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.run(partial(self.app.get_response, path, params))

    async def each(self, calls: Mapping[str, Callable[[], Awaitable[Any]]], what: str) -> dict[str, Any]:
        """{key: result} for the calls that worked; each failure becomes a warning '<what> <key>: ...'.
        Takes no slot itself: each call acquires one through run/get, once per request."""

        async def one(fn: Callable[[], Awaitable[Any]]) -> Any:
            try:
                return await fn()
            except UpstreamError as e:
                return e

        results = await asyncio.gather(*(one(fn) for fn in calls.values()))
        out = {}
        for key, val in zip(calls, results, strict=True):
            if isinstance(val, UpstreamError):
                self.warnings.append(f"{what} {key}: {str(val)[:160]}")
            else:
                out[key] = val
        return out


def within_budget(
    r: Reader, site_ids: list[str], paths: dict[str, str], per_site: int, what: str
) -> list[str]:
    """The sites (by path) whose reads fit MAX_SITE_REQUESTS; a warning when some don't."""
    ordered = sorted(site_ids, key=lambda i: segs(paths.get(i) or i))
    room = max(1, MAX_SITE_REQUESTS // per_site)
    if len(ordered) > room:
        r.warnings.append(
            f"{what}: {len(ordered)} sites in scope, read the first {room} by path "
            f"({MAX_SITE_REQUESTS}-request budget); export a smaller scope for the rest "
            f"(first skipped: {paths.get(ordered[room], ordered[room])})"
        )
    return ordered[:room]


async def _site_settings(r: Reader, site_ids: list[str], paths: dict[str, str]) -> dict[str, Any]:
    site_ids = within_budget(r, site_ids, paths, len(SETTINGS), "settings")
    calls: dict[str, Callable[[], Awaitable[Any]]] = {}
    for sid in site_ids:
        for cat, suffix in SETTINGS.items():
            path = f"/dna/intent/api/v1/sites/{safe_id(sid, 'site id')}/{suffix}"
            calls[f"{paths.get(sid, sid)} {cat}"] = partial(r.get, path, {"_inherited": "false"})
    keys = {f"{paths.get(sid, sid)} {cat}": (sid, cat) for sid in site_ids for cat in SETTINGS}
    out: dict[str, dict[str, Any]] = {}
    for key, val in (await r.each(calls, "settings")).items():
        sid, cat = keys[key]
        out.setdefault(sid, {})[cat] = val
    return out


async def _ssids_raw(r: Reader, site_ids: list[str], paths: dict[str, str]) -> dict[str, Any]:
    site_ids = within_budget(r, site_ids, paths, 1, "ssids")
    calls = {paths.get(sid, sid): partial(r.run, partial(site_ssids, r.app, sid)) for sid in site_ids}
    by_path = {paths.get(sid, sid): sid for sid in site_ids}
    return {by_path[k]: v for k, v in (await r.each(calls, "ssids")).items()}


async def _templates_raw(r: Reader) -> dict[str, Any]:
    """Project listing + full records of the non-system templates.

    Masking is the templates module's (D36); see `_templates` for the entry shape."""
    projects = ensure_list(
        await r.run(partial(r.app.api.get, "/dna/intent/api/v1/template-programmer/project"))
    )
    projects = [p for p in projects if isinstance(p, dict)]
    system = {
        str(t.get("id"))
        for p in projects
        for t in p.get("templates") or []
        if t.get("templateSource") == "SYSTEM_DEFINED"
    }
    names = {}
    for t in await r.run(partial(list_all_templates, r.app)):
        tid = str(t.get("templateId") or t.get("id"))
        if tid not in system:
            names[tid] = f"{t.get('projectName')}/{t.get('name')}"
    tp = "/dna/intent/api/v1/template-programmer/template"
    calls = {
        names[i]: partial(r.run, partial(r.app.api.get, f"{tp}/{safe_id(i, 'template id')}"))
        for i in sorted(names)
    }
    full = await r.each(calls, "template")
    return {"projects": projects, "templates": [v for v in full.values() if isinstance(v, dict)]}


async def _profiles_raw(r: Reader) -> list[dict[str, Any]]:
    profiles = await r.run(partial(list_profiles, r.app))

    async def one(p: dict[str, Any]) -> dict[str, Any]:
        pid = str(p["id"])
        tpls, sites = await asyncio.gather(
            r.run(partial(profile_template_ids, r.app, pid)), r.run(partial(profile_site_ids, r.app, pid))
        )
        return {"profile": p, "templates": tpls, "site_ids": sites}

    got = await r.each({str(p.get("name")): partial(one, p) for p in profiles}, "network profile")
    return list(got.values())


async def _policies_raw(r: Reader) -> list[dict[str, Any]]:
    """User compliance policies (SYSTEM ones are built in and the same everywhere)."""
    policies = [p for p in await r.run(partial(list_policies, r.app)) if p.get("source") != "SYSTEM"]

    async def one(p: dict[str, Any]) -> dict[str, Any]:
        pid = safe_id(str(p["id"]), "policy id")
        rules = [x for x in ensure_list(await r.get(f"{CP}/{pid}/rules")) if isinstance(x, dict)]
        conds = await asyncio.gather(
            *(r.get(f"{CP}/{pid}/rules/{safe_id(str(x['id']), 'rule id')}/conditions") for x in rules)
        )
        assigned = await r.get(f"{CP}/{pid}/siteAssignments")
        site_ids = assigned.get("siteIds") if isinstance(assigned, dict) else assigned
        return {
            "policy": p,
            "rules": [{"rule": x, "conditions": ensure_list(c)} for x, c in zip(rules, conds, strict=True)],
            "site_ids": [str(i) for i in ensure_list(site_ids)],
        }

    got = await r.each({str(p.get("name")): partial(one, p) for p in policies}, "compliance policy")
    return list(got.values())


async def _tags_raw(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/tag", cap=5000)
    return [t for t in page.items if isinstance(t, dict)]


async def collect(app: CatcApp, scope: str, sections: list[str]) -> dict[str, Any]:
    """Read everything the sections need into the raw dict `build_export` takes. A section whose
    reads fail is left out and named in meta.errors; a failed item inside a section (one site, one
    template) is skipped and named in meta.warnings."""
    r = Reader(app)
    root_site = await resolve_site(app, scope)
    root = str(root_site.get("nameHierarchy"))
    sites, complete = await all_sites(app)
    paths = {str(s.get("id")): str(s.get("nameHierarchy")) for s in sites}
    scoped = [str(s["id"]) for s in sites if in_scope(str(s.get("nameHierarchy", "")), root)]
    needs_creds = "credentials" in sections or "settings" in sections
    needs_pools = "ip_pools" in sections or "ip_reservations" in sections
    needs_templates = any(s in sections for s in ("templates", "template_projects", "network_profiles"))
    reads: dict[str, Callable[[], Awaitable[Any]]] = {}
    if "settings" in sections:
        reads["settings"] = partial(_site_settings, r, scoped, paths)
    if needs_creds:
        reads["credentials_raw"] = partial(r.run, partial(all_credentials, app))
    if needs_templates:
        reads["templates"] = partial(_templates_raw, r)
    if "network_profiles" in sections:
        reads["network_profiles"] = partial(_profiles_raw, r)
    if needs_pools:
        reads["ip_pools"] = partial(r.run, partial(all_pools, app, GLOBAL_POOLS))
    if "ip_reservations" in sections:
        reads["ip_reservations"] = partial(r.run, partial(all_pools, app, RESERVED_POOLS))
    if "ssids" in sections:
        reads["ssids"] = partial(_ssids_raw, r, scoped, paths)
    if "wireless_profiles" in sections:
        reads["wireless_profiles"] = partial(r.run, partial(wireless_profiles, app))
    if "tags" in sections:
        reads["tags"] = partial(r.run, partial(_tags_raw, app))
    if "compliance_policies" in sections:
        reads["compliance_policies"] = partial(_policies_raw, r)
    results = await asyncio.gather(*(fn() for fn in reads.values()), return_exceptions=True)
    raw: dict[str, Any] = {"sites": sites}
    errors: dict[str, str] = {}
    for key, val in zip(reads, results, strict=True):
        if isinstance(val, UpstreamError):
            errors[key] = str(val)[:200]
        elif isinstance(val, Exception):
            # Not an API error (an unexpected record shape): still leave the section out, not the export.
            errors[key] = f"{type(val).__name__}: {str(val)[:180]}"
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
    if r.warnings:
        meta["warnings"] = sorted(r.warnings)
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
        result["changes"], note = cap_changes(result["changes"], limit, max_chars() // 2)
        if note:
            result["truncated"] = note
        result["before"] = str(meta.get("exported_at") or "before")
        result["after"] = b_label
        result["scope"] = meta.get("scope")
        for key in ("errors", "warnings"):
            if (b.get("meta") or {}).get(key):
                result[f"after_{key}"] = b["meta"][key]
        return result
