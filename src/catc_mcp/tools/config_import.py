"""Config import (roadmap D40): build Catalyst Center design intent from a catc_export_config document.

`catc_import_config` matches every item of an export (docs/config-export.md) by name against a live
export of the same scope and plans, in dependency order, what to create, update, attach or assign:

    sites -> credentials -> settings -> IP pools -> reservations -> template projects -> templates
    -> network profiles (create, attach templates, assign sites) -> tags

It never deletes or unassigns anything, and it never overwrites an existing credential, pool,
template or tag: those are reported as "differs" and left alone. Credential secrets are not in an
export, so they come in through `secrets`; a value still masked in the export (an AAA shared secret, a
template line) blocks its item, so the mask is never written as a real value. Applying is dangerous
tier, runs the plan step by step and stops at the first failure, saying what was applied and what
wasn't. Provisioning stays a separate step (catc_provision_devices).

Two layers, as in config_io: `plan_import` is pure (export + live export -> steps and blockers, tested
on documents), `Applier` runs the steps against Catalyst Center.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field, SecretStr

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp._core.secrets import scrub_text
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, resolve_site, resolve_template
from catc_mcp.tools.config_io import (
    SITE_FIELDS,
    Section,
    build_export,
    canon_json,
    canonical,
    collect,
    cred_label,
    in_scope,
    item_key,
    load_export,
    short,
)
from catc_mcp.tools.credentials import CRED_PATH, all_credentials
from catc_mcp.tools.ipam import GLOBAL as GLOBAL_POOLS
from catc_mcp.tools.ipam import RESERVED as RESERVED_POOLS
from catc_mcp.tools.ipam import _all as all_pools
from catc_mcp.tools.profiles import NP, TPL, create_switching_profile, list_profiles
from catc_mcp.tools.site_writes import CREATE_PATHS, EDITABLE, site_detail
from catc_mcp.tools.sites import SETTINGS, SITE_DETAIL_PATHS
from catc_mcp.tools.template_writes import TP, create_imported_template, import_blockers, project_by_name

# The order steps run in: what an item refers to is created before it.
IMPORT_ORDER = (
    "sites",
    "credentials",
    "settings",
    "ip_pools",
    "ip_reservations",
    "template_projects",
    "templates",
    "network_profiles",
    "tags",
)
# In the export but not imported (yet); the preview counts them so nothing is skipped silently.
NOT_IMPORTED = {
    "ssids": "SSIDs carry passphrases and per-site wireless settings; create them with catc_create_ssid.",
    "wireless_profiles": "wireless profiles depend on SSIDs; create them with catc_create_wireless_profile.",
    "compliance_policies": "create compliance policies with catc_create_compliance_policy.",
}
# Secret fields a new credential needs, by type (SNMPv3 by security level). NETCONF has none.
CRED_SECRETS: dict[str, tuple[str, ...]] = {
    "CLI": ("password",),
    "SNMPV2_READ_COMMUNITY": ("readCommunity",),
    "SNMPV2_WRITE_COMMUNITY": ("writeCommunity",),
    "SNMPV3:AUTHPRIV": ("authPassword", "privacyPassword"),
    "SNMPV3:AUTHNOPRIV": ("authPassword",),
    "SNMPV3:NOAUTHNOPRIV": (),
    "NETCONF": (),
    "HTTP_READ": ("password",),
    "HTTP_WRITE": ("password",),
}
CRED_OPTIONAL_SECRETS = {"CLI": ("enablePassword",)}
# Non-secret credential fields sent on create (export name -> API name).
CRED_BODY_FIELDS = {
    "username": "username",
    "port": "port",
    "protocol": "protocol",
    "secure": "secure",
    "comments": "comments",
    "snmpMode": "mode",
    "authType": "authType",
    "privacyType": "privacyType",
}
TAG_PATH = "/dna/intent/api/v1/tag"
# Live-export warnings (config_io Reader / budget) that make a section's comparison unreliable.
WARNING_PREFIXES = {
    "settings": ("settings",),
    "templates": ("template",),
    "network_profiles": ("network profile", "template"),
}
# Secret fields `secrets` may give, by lower-case name (accepted in any case, sent as spelled here).
SECRET_FIELDS = {
    f.lower(): f
    for f in (
        "password",
        "enablePassword",
        "readCommunity",
        "writeCommunity",
        "authPassword",
        "privacyPassword",
    )
}
ACTIONS = ("create", "update", "attach", "assign")
IMPORT_COMMENT = "imported by catc_import_config"


def required_secrets(cred: dict[str, Any]) -> tuple[str, ...]:
    ctype = str(cred.get("type"))
    if ctype == "SNMPV3":
        return CRED_SECRETS.get(f"SNMPV3:{cred.get('snmpMode') or 'AUTHPRIV'}", ("authPassword",))
    return CRED_SECRETS.get(ctype, ())


@dataclass
class Step:
    """One planned change (or a reported skip). `payload` is what the applier needs; no secrets."""

    section: str
    action: str  # create | update | attach | assign | skip
    item: str
    payload: dict[str, Any] = field(default_factory=dict)
    note: str | None = None
    changes: list[dict[str, Any]] | None = None

    def row(self) -> dict[str, Any]:
        out: dict[str, Any] = {"section": self.section, "action": self.action, "item": self.item}
        if self.note:
            out["note"] = self.note
        if self.changes:
            out["changes"] = self.changes
        return out


@dataclass
class ImportPlan:
    steps: list[Step] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    unchanged: dict[str, int] = field(default_factory=dict)
    not_imported: dict[str, str] = field(default_factory=dict)

    @property
    def changes(self) -> list[Step]:
        return [s for s in self.steps if s.action in ACTIONS]

    def summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for s in self.steps:
            out.setdefault(s.section, {}).setdefault(s.action, 0)
            out[s.section][s.action] += 1
        return out


# --- pure layer: export + live export -> plan ------------------------------------------------------


def _index(doc: dict[str, Any], section: str) -> dict[str, dict[str, Any]]:
    """{identity (lower-case): item}; Catalyst Center names are case-insensitive."""
    return {item_key(section, x).lower(): x for x in ensure_list(doc.get(section)) if isinstance(x, dict)}


def _field_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    keys = sorted(set(before) | set(after))
    return [
        {"field": k, "before": short(before.get(k)), "after": short(after.get(k))}
        for k in keys
        if canon_json(before.get(k)) != canon_json(after.get(k))
    ]


def _masked_at(v: Any, path: str = "") -> str | None:
    """Where the mask token sits in a payload (first hit), or None."""
    if isinstance(v, dict):
        for k, x in v.items():
            hit = _masked_at(x, f"{path}.{k}" if path else str(k))
            if hit:
                return hit
    elif isinstance(v, list):
        for i, x in enumerate(v):
            hit = _masked_at(x, f"{path}[{i}]")
            if hit:
                return hit
    elif isinstance(v, str) and MASK in v:
        return path or "value"
    return None


def merged_settings(have: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """The category body to PUT: the export's values over what is set at the site now (one level deep,
    as a category holds sub-objects such as dns.dns or telemetry.syslogs). An import never removes a
    setting the export doesn't mention; an explicit [] in the export still clears a list."""
    out = dict(have)
    for k, v in body.items():
        out[k] = {**have[k], **v} if isinstance(v, dict) and isinstance(have.get(k), dict) else v
    return out


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0]


def _covered(site: str, assigned: list[str]) -> bool:
    """A site is covered when it, or one of its ancestors, is assigned."""
    return any(in_scope(site, a) for a in assigned)


def plan_import(
    doc: dict[str, Any],
    live: dict[str, Any],
    *,
    secrets: dict[str, set[str]],
    sections: list[str] | None = None,
    commit_templates: bool = True,
) -> ImportPlan:
    """What importing `doc` onto the Catalyst Center that `live` was exported from would do.

    `secrets` maps a credential label ('CLI:lab') to the secret field names supplied for it (values
    stay with the caller). `live` must cover the same sections (and the credentials, templates and
    pools that settings, profiles and reservations refer to)."""
    plan = ImportPlan()
    wanted = [s for s in IMPORT_ORDER if s in doc and (not sections or s in sections)]
    for s, why in NOT_IMPORTED.items():
        if ensure_list(doc.get(s)) and (not sections or s in sections):
            plan.not_imported[s] = f"{len(ensure_list(doc.get(s)))} item(s) not imported: {why}"
    errors = (live.get("meta") or {}).get("errors") or {}
    for s in wanted:
        if s in errors:
            plan.blockers.append(f"Can't read the live {s} to compare with: {errors[s]}")
    # A per-item read failure (one site's settings, one template) or the request budget would look
    # like "missing here" and plan a wrong write: block instead.
    for w in (live.get("meta") or {}).get("warnings") or []:
        if any(
            str(w).startswith(prefix)
            for s, prefixes in WARNING_PREFIXES.items()
            if s in wanted
            for prefix in prefixes
        ):
            plan.blockers.append(f"The live read was incomplete, so the plan could be wrong: {w}")
    if plan.blockers:
        return plan

    def unchanged(section: str) -> None:
        plan.unchanged[section] = plan.unchanged.get(section, 0) + 1

    def step(section: str, action: str, item: str, payload: dict[str, Any] | None = None, **kw: Any) -> Step:
        st = Step(section, action, item, payload or {}, **kw)
        plan.steps.append(st)
        # Templates are checked by import_blockers (content lines and variables), credentials below.
        if action in ACTIONS and section not in ("templates", "credentials"):
            where = _masked_at(st.payload)
            if where:
                plan.blockers.append(
                    f"{section} {item}: {where} still holds the mask {MASK} where the export hid a "
                    "secret; importing it would write the mask as the real value. Put the real value "
                    "in the export (or drop that field) and import again."
                )
        return st

    # Sites (parents before children: the export is sorted by path).
    live_sites = _index(live, "sites")
    new_sites: set[str] = set()

    def site_known(path: str) -> bool:
        p = path.lower()
        return p == "global" or p in live_sites or p in new_sites

    if "sites" in wanted:
        for s in ensure_list(doc.get("sites")):
            path, kind = str(s.get("path")), str(s.get("type"))
            have = live_sites.get(path.lower())
            fields = {k: s[k] for k in SITE_FIELDS.get(kind, []) if k in s}
            if have:
                if have.get("type") != kind:
                    plan.blockers.append(f"Site {path} is a {have.get('type')} here, a {kind} in the export.")
                    continue
                current = {k: have[k] for k in SITE_FIELDS.get(kind, []) if k in have}
                diff = _field_changes(current, {**current, **fields})
                if diff:
                    step(
                        "sites", "update", path, {"path": path, "type": kind, "fields": fields}, changes=diff
                    )
                else:
                    unchanged("sites")
                continue
            if kind not in CREATE_PATHS:
                plan.blockers.append(f"Site {path}: unknown type {kind!r}.")
                continue
            if not site_known(_parent(path)):
                plan.blockers.append(
                    f"Site {path}: its parent {_parent(path)} is neither here nor in the export."
                )
            if kind == "building" and (
                not s.get("country")
                or (not s.get("address") and (s.get("latitude") is None or s.get("longitude") is None))
            ):
                plan.blockers.append(f"Building {path} needs a country and an address or latitude/longitude.")
            new_sites.add(path.lower())
            step("sites", "create", path, {"path": path, "type": kind, "fields": fields})

    # Credentials: created with the supplied secrets; existing ones are never overwritten.
    live_creds = _index(live, "credentials")
    new_creds: set[str] = set()
    if "credentials" in wanted:
        seen: set[str] = set()
        for c in ensure_list(doc.get("credentials")):
            label = cred_label(c)
            if label.lower() in seen:
                plan.blockers.append(f"Credential {label} appears more than once in the export.")
                continue
            seen.add(label.lower())
            have = live_creds.get(label.lower())
            if have:
                diff = _field_changes(have, c)
                if diff:
                    step(
                        "credentials",
                        "skip",
                        label,
                        note="exists; import doesn't change credentials",
                        changes=diff,
                    )
                else:
                    unchanged("credentials")
                continue
            given = {k.lower() for k in secrets.get(label, set())}
            missing = [f for f in required_secrets(c) if f.lower() not in given]
            if missing:
                plan.blockers.append(
                    f"Credential {label} is new and needs {', '.join(missing)} in `secrets` "
                    f"(e.g. secrets={{'{label}': {{'{missing[0]}': '...'}}}})."
                )
            if (
                c.get("type") == "SNMPV3"
                and c.get("snmpMode") not in (None, "NOAUTHNOPRIV")
                and not c.get("authType")
            ):
                plan.blockers.append(
                    f"Credential {label}: SNMPv3 with authentication needs authType in the export."
                )
            new_creds.add(label.lower())
            st = step("credentials", "create", label, {k: v for k, v in c.items()})
            where = _masked_at(st.payload)
            if where:
                plan.blockers.append(f"credentials {label}: {where} still holds the mask {MASK}.")
        unknown = sorted(k for k in secrets if k.lower() not in new_creds)
        if unknown:
            plan.blockers.append(
                "`secrets` names credentials that this import doesn't create: "
                + ", ".join(unknown)
                + " (only new credentials take secrets)."
            )

    def cred_known(label: str) -> bool:
        return label.lower() in live_creds or label.lower() in new_creds

    # Settings: a category that differs is PUT with the export's values merged over the site's own.
    if "settings" in wanted:
        live_settings = {str(k).lower(): v for k, v in (live.get("settings") or {}).items()}
        for path, cats in (doc.get("settings") or {}).items():
            if not site_known(str(path)):
                plan.blockers.append(f"Settings for {path}: the site is neither here nor in the export.")
                continue
            have_cats = live_settings.get(str(path).lower()) or {}
            for cat, body in (cats or {}).items():
                if cat not in SETTINGS:
                    plan.blockers.append(f"Settings for {path}: unknown category {cat!r}.")
                    continue
                have = have_cats.get(cat) or {}
                # Merge into what is set there now, so a value the export doesn't carry stays.
                body = merged_settings(have, body or {})
                if canon_json(have) == canon_json(body):
                    unchanged("settings")
                    continue
                if cat == "credentials":
                    for slot, label in (body or {}).items():
                        if not cred_known(str(label)):
                            plan.blockers.append(
                                f"Settings for {path}: {slot} names credential {label}, which is neither "
                                "here nor in the export"
                                + (
                                    " (add 'credentials' to `sections`)"
                                    if "credentials" not in wanted
                                    else "."
                                )
                            )
                step(
                    "settings",
                    "update",
                    f"{path} {cat}",
                    {"site": str(path), "category": cat, "body": body},
                    changes=_field_changes(have, body),
                )

    # Global pools, then site reservations (which carve out of a global pool).
    live_pools = _index(live, "ip_pools")
    new_pools: set[str] = set()
    if "ip_pools" in wanted:
        for p in ensure_list(doc.get("ip_pools")):
            name = str(p.get("name"))
            have = live_pools.get(name.lower())
            if have:
                diff = _field_changes(have, p)
                if diff:
                    step(
                        "ip_pools",
                        "skip",
                        name,
                        note="differs; import doesn't change existing pools",
                        changes=diff,
                    )
                else:
                    unchanged("ip_pools")
                continue
            if not (p.get("ipv4") or p.get("ipv6")):
                plan.blockers.append(f"IP pool {name} has no address space in the export.")
            if p.get("ipv4") and p.get("ipv6"):
                plan.blockers.append(
                    f"IP pool {name} is dual-stack; a global pool holds one family here. Split it into an "
                    "IPv4 and an IPv6 pool in the export."
                )
            new_pools.add(name.lower())
            step("ip_pools", "create", name, dict(p))
    if "ip_reservations" in wanted:
        live_res = _index(live, "ip_reservations")
        for p in ensure_list(doc.get("ip_reservations")):
            key = item_key("ip_reservations", p)
            have = live_res.get(key.lower())
            if have:
                diff = _field_changes(have, p)
                if diff:
                    step(
                        "ip_reservations",
                        "skip",
                        key,
                        note="differs; import doesn't change reservations",
                        changes=diff,
                    )
                else:
                    unchanged("ip_reservations")
                continue
            if not site_known(str(p.get("site"))):
                plan.blockers.append(f"Reservation {key}: the site is neither here nor in the export.")
            for fam in ("ipv4", "ipv6"):
                gp = (p.get(fam) or {}).get("globalPool")
                if gp and str(gp).lower() not in live_pools and str(gp).lower() not in new_pools:
                    plan.blockers.append(
                        f"Reservation {key}: global pool {gp} is neither here nor in the export."
                    )
            step("ip_reservations", "create", key, dict(p))

    # Template projects and templates: created when missing, never overwritten.
    live_projects = _index(live, "template_projects")
    new_projects: set[str] = set()
    if "template_projects" in wanted:
        for p in ensure_list(doc.get("template_projects")):
            name = str(p.get("name"))
            if name.lower() in live_projects:
                unchanged("template_projects")
                continue
            new_projects.add(name.lower())
            step("template_projects", "create", name, dict(p))
    live_templates = _index(live, "templates")
    new_templates: set[str] = set()
    if "templates" in wanted:
        for t in ensure_list(doc.get("templates")):
            label = item_key("templates", t)
            have = live_templates.get(label.lower())
            if have:
                diff = _field_changes(have, t)
                if diff:
                    step(
                        "templates",
                        "skip",
                        label,
                        note="differs; import doesn't overwrite templates "
                        "(catc_import_templates imports a copy)",
                        changes=diff,
                    )
                else:
                    unchanged("templates")
                continue
            project = str(t.get("project"))
            if project.lower() not in live_projects and project.lower() not in new_projects:
                # A project the export names only through its templates: create it first.
                new_projects.add(project.lower())
                step("template_projects", "create", project, {"name": project})
            content = str(t.get("content") or "")
            versions = (
                [{"version": 1, "content": content, "comment": IMPORT_COMMENT}] if commit_templates else []
            )
            plan.blockers += import_blockers(t, label, versions)
            new_templates.add(label.lower())
            step(
                "templates",
                "create",
                label,
                dict(t),
                note="committed as version 1" if commit_templates else None,
            )

    # Network profiles: create switching profiles, attach missing templates, assign missing sites.
    if "network_profiles" in wanted:
        live_profiles = _index(live, "network_profiles")
        for p in ensure_list(doc.get("network_profiles")):
            name = str(p.get("name"))
            have = live_profiles.get(name.lower())
            existed = have is not None
            if not have:
                if str(p.get("type") or "").lower() != "switching":
                    step(
                        "network_profiles",
                        "skip",
                        name,
                        note=f"{p.get('type')} profiles can't be created through the API; create it in "
                        "the UI "
                        "(Design > Network Profiles) and import again to attach templates and assign sites",
                    )
                    continue
                step("network_profiles", "create", name, {"name": name})
                have = {"templates": [], "sites": []}
            attached = {str(x).lower() for x in ensure_list(have.get("templates"))}
            to_attach = [str(x) for x in ensure_list(p.get("templates")) if str(x).lower() not in attached]
            for tpl in to_attach:
                if tpl.lower() not in live_templates and tpl.lower() not in new_templates:
                    plan.blockers.append(f"Profile {name}: template {tpl} is neither here nor in the export.")
            if to_attach:
                step(
                    "network_profiles",
                    "attach",
                    name,
                    {"profile": name, "templates": to_attach},
                    note=", ".join(to_attach),
                )
            assigned = [str(x) for x in ensure_list(have.get("sites"))]
            to_assign = [str(x) for x in ensure_list(p.get("sites")) if not _covered(str(x), assigned)]
            for site in to_assign:
                if not site_known(site):
                    plan.blockers.append(f"Profile {name}: site {site} is neither here nor in the export.")
            if to_assign:
                step(
                    "network_profiles",
                    "assign",
                    name,
                    {"profile": name, "sites": to_assign},
                    note=", ".join(to_assign),
                )
            if existed and not to_attach and not to_assign:
                unchanged("network_profiles")

    # Tags: created when missing.
    if "tags" in wanted:
        live_tags = _index(live, "tags")
        for t in ensure_list(doc.get("tags")):
            name = str(t.get("name"))
            have = live_tags.get(name.lower())
            if have:
                diff = _field_changes(have, t)
                if diff:
                    step(
                        "tags",
                        "skip",
                        name,
                        note="differs; import doesn't change existing tags",
                        changes=diff,
                    )
                else:
                    unchanged("tags")
                continue
            step("tags", "create", name, dict(t))
    return plan


# --- fetch layer: the live side ----------------------------------------------------------------------


def live_sections(wanted: list[str]) -> list[str]:
    """What to export live to plan `wanted`: plus what those sections refer to by name."""
    out = set(wanted)
    if "settings" in out:
        out |= {"credentials", "sites"}
    if "network_profiles" in out:
        out |= {"templates", "template_projects", "sites"}
    if "templates" in out:
        out.add("template_projects")
    if "ip_reservations" in out:
        out |= {"ip_pools", "sites"}
    return sorted(out)


async def existing_scope(app: CatcApp, scope: str) -> str:
    """The scope itself, or its nearest ancestor that exists (an import may create the rest)."""
    parts = [p for p in scope.strip("/").split("/") if p] or ["Global"]
    for i in range(len(parts), 0, -1):
        candidate = "/".join(parts[:i])
        try:
            site = await resolve_site(app, candidate)
        except NotFound:
            continue
        return str(site.get("nameHierarchy") or candidate)
    return "Global"


async def live_export(app: CatcApp, scope: str, wanted: list[str]) -> dict[str, Any]:
    root = await existing_scope(app, scope)
    doc = canonical(build_export(await collect(app, root, live_sections(wanted))))
    if root.lower() != scope.lower():
        doc.setdefault("meta", {})["note"] = f"{scope} doesn't exist yet; compared with {root}"
    return doc


# --- apply layer -------------------------------------------------------------------------------------


class Applier:
    """Runs plan steps against Catalyst Center, one at a time. Ids are looked up by name when a step
    needs them (an earlier step may have just created the object) and cached."""

    def __init__(self, app: CatcApp, ctx: Context | None, secrets: dict[str, dict[str, str]]) -> None:
        self.app = app
        self.ctx = ctx
        self.secrets = {k.lower(): v for k, v in secrets.items()}
        self.ids: dict[tuple[str, str], str] = {}
        self.partial: dict[str, str | None] = {"template_id": None}

    def scrub(self, text: str) -> str:
        """An error message without any secret value this import was given."""
        for fields in self.secrets.values():
            for v in fields.values():
                if v:
                    text = text.replace(v, MASK)
        return scrub_text(text)

    async def job(self, method: str, path: str, body: Any, what: str) -> dict[str, Any]:
        result: dict[str, Any] = await self.app.run_job(method, path, body, ctx=self.ctx, what=what)
        return result

    async def site_id(self, path: str) -> str:
        key = ("site", path.lower())
        if key not in self.ids:
            self.ids[key] = str((await resolve_site(self.app, path))["id"])
        return self.ids[key]

    async def cred_id(self, label: str) -> str:
        key = ("cred", label.lower())
        if key not in self.ids:
            for c in await all_credentials(self.app):
                self.ids[("cred", cred_label(c).lower())] = str(c.get("id"))
        if key not in self.ids:
            raise NotFound(f"No credential {label}.")
        return self.ids[key]

    async def pool_id(self, name: str) -> str:
        key = ("pool", name.lower())
        if key not in self.ids:
            for p in await all_pools(self.app, GLOBAL_POOLS):
                self.ids[("pool", str(p.get("name")).lower())] = str(p.get("id"))
        if key not in self.ids:
            raise NotFound(f"No global pool {name}.")
        return self.ids[key]

    async def project_id(self, name: str) -> str:
        key = ("project", name.lower())
        if key not in self.ids:
            proj = await project_by_name(self.app, name)
            if proj is None:
                raise NotFound(f"No template project {name}.")
            self.ids[key] = str(proj["id"])
        return self.ids[key]

    async def profile_id(self, name: str) -> str:
        key = ("profile", name.lower())
        if key not in self.ids:
            for p in await list_profiles(self.app):
                self.ids[("profile", str(p.get("name")).lower())] = str(p.get("id"))
        if key not in self.ids:
            raise NotFound(f"No network profile {name}.")
        return self.ids[key]

    # One method per (section, action).

    async def sites_create(self, p: dict[str, Any]) -> Any:
        path, kind, f = p["path"], p["type"], p["fields"]
        body: dict[str, Any] = {"name": path.rsplit("/", 1)[1], "parentId": await self.site_id(_parent(path))}
        if kind == "building":
            body.update(
                {k: f[k] for k in ("country", "address", "latitude", "longitude") if f.get(k) is not None}
            )
        elif kind == "floor":
            body.update(
                {
                    "floorNumber": f.get("floorNumber", 1),
                    "rfModel": f.get("rfModel") or "Cubes And Walled Offices",
                    "width": f.get("width") or 100.0,
                    "length": f.get("length") or 100.0,
                    "height": f.get("height") or 10.0,
                    "unitsOfMeasure": f.get("unitsOfMeasure") or "feet",
                }
            )
        job = await self.job("POST", CREATE_PATHS[kind], body, f"create {kind}")
        if job.get("data"):
            self.ids[("site", path.lower())] = str(job["data"])
        return {"site_id": job.get("data")}

    async def sites_update(self, p: dict[str, Any]) -> Any:
        site = await resolve_site(self.app, p["path"])
        current = await site_detail(self.app, site)
        body = {k: current.get(k) for k in EDITABLE[p["type"]] if current.get(k) is not None}
        body.update(p["fields"])
        await self.job("PUT", SITE_DETAIL_PATHS[p["type"]].format(id=site["id"]), body, f"update {p['type']}")
        return {"site_id": site["id"]}

    async def credentials_create(self, p: dict[str, Any]) -> Any:
        label = cred_label(p)
        body: dict[str, Any] = {"type": p["type"], "description": p["description"]}
        body.update({api: p[k] for k, api in CRED_BODY_FIELDS.items() if p.get(k) is not None})
        if p["type"] == "NETCONF":
            body.setdefault("port", 830)
        elif p["type"] in ("HTTP_READ", "HTTP_WRITE"):
            body.setdefault("port", 443)
            body.setdefault("protocol", "HTTPS")
        allowed = set(required_secrets(p)) | set(CRED_OPTIONAL_SECRETS.get(str(p["type"]), ()))
        given = self.secrets.get(label.lower(), {})
        body.update({k: v for k, v in given.items() if k in allowed})
        job = await self.job("POST", CRED_PATH, body, "create credential")
        new_id = job.get("data") or job.get("progress")
        if new_id:
            self.ids[("cred", label.lower())] = str(new_id)
        return {"credential_id": new_id}

    async def settings_update(self, p: dict[str, Any]) -> Any:
        sid = await self.site_id(p["site"])
        body = p["body"]
        if p["category"] == "credentials":
            body = {
                f"{slot}Id": {"credentialsId": await self.cred_id(str(label))} for slot, label in body.items()
            }
        await self.job(
            "PUT",
            f"/dna/intent/api/v1/sites/{sid}/{SETTINGS[p['category']]}",
            body,
            f"{p['category']} settings",
        )
        return {"site_id": sid}

    @staticmethod
    def _space(space: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in space.items() if k != "globalPool"}

    async def ip_pools_create(self, p: dict[str, Any]) -> Any:
        space = p.get("ipv4") or p.get("ipv6") or {}
        body = {"name": p["name"], "poolType": p.get("type") or "Generic", "addressSpace": self._space(space)}
        job = await self.job("POST", GLOBAL_POOLS, body, "create pool")
        return {"pool_id": job.get("data") or job.get("progress")}

    async def ip_reservations_create(self, p: dict[str, Any]) -> Any:
        body: dict[str, Any] = {
            "name": p["name"],
            "poolType": p.get("type") or "Generic",
            "siteId": await self.site_id(p["site"]),
        }
        for fam, key in (("ipv4", "ipV4AddressSpace"), ("ipv6", "ipV6AddressSpace")):
            if p.get(fam):
                space = self._space(p[fam])
                if p[fam].get("globalPool"):
                    space["globalPoolId"] = await self.pool_id(str(p[fam]["globalPool"]))
                body[key] = space
        job = await self.job("POST", RESERVED_POOLS, body, "reserve pool")
        return {"reservation_id": job.get("data") or job.get("progress")}

    async def template_projects_create(self, p: dict[str, Any]) -> Any:
        body = {"name": p["name"], "description": p.get("description") or p["name"]}
        job = await self.job("POST", f"{TP}/project", body, "create project")
        if job.get("data"):
            self.ids[("project", str(p["name"]).lower())] = str(job["data"])
        return {"project_id": job.get("data")}

    async def templates_create(self, p: dict[str, Any], commit: bool) -> Any:
        content = str(p.get("content") or "")
        versions = [{"version": 1, "content": content, "comment": IMPORT_COMMENT}] if commit else []
        self.partial["template_id"] = None
        return await create_imported_template(
            self.app,
            self.ctx,
            project_id=await self.project_id(str(p["project"])),
            project=str(p["project"]),
            name=str(p["name"]),
            t=p,
            versions=versions,
            draft=content,
            created=self.partial,
        )

    async def network_profiles_create(self, p: dict[str, Any]) -> Any:
        out = await create_switching_profile(self.app, self.ctx, p["name"])
        if out.get("profile_id"):
            self.ids[("profile", str(p["name"]).lower())] = str(out["profile_id"])
        return {"profile_id": out.get("profile_id"), "via": out.get("via")}

    async def network_profiles_attach(self, p: dict[str, Any]) -> Any:
        pid = await self.profile_id(p["profile"])
        for tpl in p["templates"]:
            t = await resolve_template(self.app, tpl)
            tid = str(t.get("templateId") or t.get("id"))
            body = {"items": [{"profileId": pid}]}
            await self.job("POST", f"{TPL}/{tid}/networkProfilesForSites/bulk", body, "attach template")
        return {"attached": p["templates"]}

    async def network_profiles_assign(self, p: dict[str, Any]) -> Any:
        pid = await self.profile_id(p["profile"])
        body = {"items": [{"id": await self.site_id(s)} for s in p["sites"]]}
        await self.job("POST", f"{NP}/{pid}/siteAssignments/bulk", body, "assign profile")
        return {"assigned": p["sites"]}

    async def tags_create(self, p: dict[str, Any]) -> Any:
        body = {k: p[k] for k in ("name", "description", "dynamicRules") if p.get(k) not in (None, "", [])}
        job = await self.job("POST", TAG_PATH, body, "create tag")
        return {"tag_id": job.get("data") or job.get("progress")}

    async def run(self, steps: list[Step], commit_templates: bool) -> dict[str, Any]:
        todo = [s for s in steps if s.action in ACTIONS]
        done: list[dict[str, Any]] = []
        for i, s in enumerate(todo):
            handler: Callable[..., Awaitable[Any]] = getattr(self, f"{s.section}_{s.action}")
            try:
                if s.section == "templates":
                    result = await handler(s.payload, commit_templates)
                else:
                    result = await handler(s.payload)
            except Exception as e:  # noqa: BLE001 - every failure stops the import and is reported
                failed = s.row()
                failed["error"] = self.scrub(str(e))[:400]
                if s.section == "templates" and self.partial.get("template_id"):
                    failed["left_behind"] = (
                        f"template {self.partial['template_id']} was created and is incomplete; delete it "
                        "(catc_delete_template) before importing again"
                    )
                return {
                    "status": "stopped",
                    "applied": done,
                    "failed": failed,
                    "not_applied": [x.row() for x in todo[i + 1 :]],
                    "note": "Nothing after the failed step was attempted. Fix the cause and run the import "
                    "again: the new plan skips what now exists.",
                }
            row = s.row()
            row.pop("changes", None)
            if isinstance(result, dict):
                row.update({k: v for k, v in result.items() if v is not None})
            done.append(row)
        return {"status": "applied", "applied": done}


# --- tool --------------------------------------------------------------------------------------------


Secrets = Annotated[
    dict[str, dict[str, SecretStr]] | None,
    Field(
        description="Secrets for the credentials this import creates, by 'TYPE:description': CLI and "
        "HTTP {'password', CLI also 'enablePassword'}, SNMPv2c {'readCommunity'} or {'writeCommunity'}, "
        "SNMPv3 {'authPassword', 'privacyPassword'}. Never echoed back."
    ),
]


def _secret_values(secrets: dict[str, dict[str, SecretStr]] | None) -> dict[str, dict[str, str]]:
    """Plain values with field names in their API spelling; an unknown field name is refused."""
    out: dict[str, dict[str, str]] = {}
    for label, fields in (secrets or {}).items():
        for k, v in fields.items():
            canon = SECRET_FIELDS.get(k.lower())
            if canon is None:
                raise InvalidRequest(
                    f"secrets[{label!r}]: unknown field {k!r}; use " + ", ".join(SECRET_FIELDS.values()) + "."
                )
            out.setdefault(label, {})[canon] = v.get_secret_value()
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Import configuration", task=True)
    async def catc_import_config(
        ctx: Context,
        export: Annotated[str, Field(description="A config export (the YAML catc_export_config returned)")],
        sections: Annotated[
            list[Section] | None,
            Field(description="Only import these sections (default: every section in the export)"),
        ] = None,
        secrets: Secrets = None,
        commit_templates: Annotated[
            bool, Field(description="Commit each new template as version 1 so it can be deployed (default)")
        ] = True,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Most plan steps listed in the preview")
        ] = 200,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build Catalyst Center design intent from a catc_export_config document: a PoC's design
        on a production Catalyst Center, or a rebuilt lab. Items are matched by name against the live
        configuration of the export's scope, and the plan runs in dependency order: sites, credentials
        (with `secrets`), network settings per site, global IP pools, reservations, template projects,
        templates, switching network profiles (create, attach templates, assign sites), tags. It
        creates what is missing and updates sites and site settings that differ; it never deletes,
        unassigns or overwrites existing credentials, pools, templates or tags (they show as 'skip' with
        what differs). SSIDs, wireless profiles and compliance policies are counted, not imported.
        Preview-first: the preview lists every step and refuses values the export masked. Applying
        stops at the first failure and says what was applied and what wasn't. Devices get the new
        settings only when provisioned (catc_provision_devices)."""
        app: CatcApp = get_client(ctx)
        doc = canonical(load_export(export))
        scope = str((doc.get("meta") or {}).get("scope") or "Global")
        values = _secret_values(secrets)
        for label, fields in values.items():
            if any(MASK in v or not v for v in fields.values()):
                raise InvalidRequest(
                    f"secrets[{label!r}]: every value must be the real secret (not empty or the mask)."
                )
        wanted = [s for s in IMPORT_ORDER if s in doc and (not sections or s in sections)]
        if not wanted and not any(s in doc for s in NOT_IMPORTED):
            raise InvalidRequest("The export has none of the sections to import.")
        live = await live_export(app, scope, wanted) if wanted else {}
        plan = plan_import(
            doc,
            live,
            secrets={label: set(fields) for label, fields in values.items()},
            sections=list(sections) if sections else None,
            commit_templates=commit_templates,
        )
        changes = plan.changes
        blockers = list(plan.blockers)
        if not changes and not blockers:
            blockers.append(
                "Nothing to import: Catalyst Center already has everything the export would create or update."
            )
        rows = [s.row() for s in plan.steps]
        details: dict[str, Any] = {
            "scope": scope,
            "summary": plan.summary(),
            "steps": rows[:limit],
        }
        if len(rows) > limit:
            details["truncated"] = f"{len(rows) - limit} more step(s) not listed; raise `limit` to see them"
        if plan.unchanged:
            details["unchanged"] = plan.unchanged
        if plan.not_imported:
            details["not_imported"] = plan.not_imported
        if (live.get("meta") or {}).get("note"):
            details["live"] = live["meta"]["note"]
        if (live.get("meta") or {}).get("warnings"):
            details["live_warnings"] = live["meta"]["warnings"]
        counts = {a: sum(1 for s in changes if s.action == a) for a in ACTIONS}
        what = ", ".join(f"{n} {a}" for a, n in counts.items() if n) or "nothing to change"
        plan_obj = Plan(
            f"Import config into {scope}: {what}",
            details=details,
            blockers=blockers,
            # What the plan would write: a live change that alters it refuses the token, unrelated ones don't.
            fingerprint=hashlib.sha256(
                canon_json([[st.section, st.action, st.item, st.payload] for st in plan.steps]).encode()
            ).hexdigest(),
            blast_radius=len(changes),
            side_effects=[
                "Creates and updates design objects only; nothing reaches devices until they are "
                "provisioned.",
                "Stops at the first failed step; steps before it stay applied.",
            ],
        )
        digest = hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

        async def apply() -> Any:
            return await Applier(app, ctx, values).run(plan.steps, commit_templates)

        return await preview_or_apply(
            ctx,
            tool="catc_import_config",
            args={
                "export": export,
                "sections": sections,
                # Secrets aren't stored; a digest makes the token refuse changed values.
                "secrets": digest,
                "commit_templates": commit_templates,
                "limit": limit,
            },
            confirm=confirm,
            plan=plan_obj,
            apply=apply,
        )
