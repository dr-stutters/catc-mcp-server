"""Lifecycle and security signals (roadmap D56, Wave 6 amendment G20): EoX, Cisco security advisories
(PSIRT), field notices, network bugs and insecure configurations, per device or for every device under a
site, plus the write that triggers the cloud scans.

Catalyst Center computes EoX, advisories, field notices and bugs by matching the inventory against Cisco's
cloud data. Without the Cisco account (CCO) connection and Consent to Connect every device stays
NOT_SCANNED with zero counts (live 2026-10-28: eox-status/device comment MLCN10323, networkBugs scanMode
NOT_AVAILABLE): that is "no data", never "no exposure", and every tool here says so. Insecure
configurations are computed on the appliance from the running config, but only IOS-XE 26.1.1 and later
restrict (and so report) those commands.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from collections import Counter
from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    AuthError,
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    get_client,
    preview_or_apply,
)
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, inventory_names, resolve_device, resolve_site
from catc_mcp.safety import site_devices

API = "/dna/intent/api/v1"
EOX_SUMMARY = f"{API}/eox-status/summary"
EOX_DEVICES = f"{API}/eox-status/device"
PSIRT = f"{API}/securityAdvisories"
NOTICES = f"{API}/fieldNotices"
BUGS = f"{API}/networkBugs"
INSECURE = API + "/networkDevices/{id}/insecureConfigurations"
ROW_CAP = 5000
DETAIL_CAP = 25  # per-device detail calls for a site or the whole network
DEVICE_ROWS = 100
SCANNED = ("SUCCESS", "FALL_BACK")

NO_CCO = (
    "Not scanned: Catalyst Center gets EoX, security advisories, field notices and bugs by matching the "
    "inventory against Cisco's cloud data, which needs the Cisco account (CCO) connection and Consent to "
    "Connect accepted in System > Settings. NOT_SCANNED with zero counts means no data, not no exposure."
)
PSIRT_DENIED = (
    "Catalyst Center refused the security advisory API (403): the account's role needs "
    "Security.Security Advisory Read (docs/least-privilege.md)."
)
INSECURE_NOTE = (
    "Insecure configurations are reported from IOS-XE 26.1.1 on (the release that restricts these commands); "
    "older releases and other platforms return none."
)
Impact = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
SCANS = {
    "field_notices": (NOTICES, "field notices"),
    "bugs": (BUGS, "network bugs"),
    "security_advisories": (PSIRT, "security advisories"),
}
Scan = Literal["field_notices", "bugs", "security_advisories"]

DeviceArg = Annotated[str | None, Field(description="One device (hostname, IP, serial or id)")]
SiteArg = Annotated[
    str | None,
    Field(description="Every device at this site and below (name hierarchy or id); neither = whole network"),
]


# --- helpers -------------------------------------------------------------------------------------


def utc(ms: Any) -> str | None:
    if isinstance(ms, bool) or not isinstance(ms, int | float) or ms <= 0:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M")


def count(v: Any) -> int:
    return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0


def comment(v: Any) -> str | None:
    """The first comment line (EoX sends a list, the other APIs a string)."""
    items = [str(c) for c in ensure_list(v) if c]
    return items[0][:300] if items else None


def past(day: Any) -> bool | None:
    """True when an EoX date ('2025-10-31', or with a time) is before today."""
    try:
        return date.fromisoformat(str(day)[:10]) < datetime.now(tz=UTC).date()
    except ValueError:
        return None


class Scope:
    """Which devices a call covers: one device, every device under a site, or the whole network (None)."""

    def __init__(self, label: str, devices: list[dict[str, Any]] | None) -> None:
        self.label = label
        self.devices = devices
        self.names: dict[str, str] = {
            str(d["id"]): str(d.get("hostname") or d.get("managementIpAddress") or d["id"])
            for d in devices or []
            if d.get("id")
        }

    @property
    def ids(self) -> set[str] | None:
        return None if self.devices is None else set(self.names)

    @property
    def one(self) -> dict[str, Any] | None:
        return self.devices[0] if self.devices is not None and len(self.devices) == 1 else None

    def keep(self, rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        ids = self.ids
        return rows if ids is None else [r for r in rows if str(r.get(key)) in ids]

    async def name_all(self, app: CatcApp, ids: list[str]) -> None:
        missing = [i for i in ids if i not in self.names]
        if missing:
            self.names |= await inventory_names(app, missing) or {}

    def name(self, did: Any) -> str:
        return self.names.get(str(did), str(did))


async def resolve_scope(app: CatcApp, device: str | None, site: str | None) -> Scope:
    if device and site:
        raise InvalidRequest("Give a device or a site, not both.")
    if device:
        d = await resolve_device(app, device)
        return Scope(str(d.get("hostname") or d["id"]), [d])
    if site:
        s = await resolve_site(app, site)
        if s.get("type") == "global":
            return Scope("Global (whole network)", None)
        return Scope(str(s.get("nameHierarchy")), await site_devices(app, s))
    return Scope("Global (whole network)", None)


async def rows(
    app: CatcApp, path: str, params: dict[str, Any] | None = None
) -> tuple[list[dict[str, Any]], bool]:
    page = await fetch_all(app.pager, app.api, path, params or {}, cap=ROW_CAP, max_page=500)
    return [r for r in page.items if isinstance(r, dict)], page.complete


async def scan_rows(app: CatcApp, base: str, scope: Scope) -> tuple[list[dict[str, Any]], bool]:
    """The per-device scan records of fieldNotices / networkBugs / securityAdvisories for the scope."""
    one = scope.one
    params = {"networkDeviceId": str(one["id"])} if one else {}
    found, complete = await rows(app, f"{base}/results/networkDevices", params)
    return scope.keep(found, "networkDeviceId"), complete


def scan_summary(label: str, recs: list[dict[str, Any]], key: str, noun: str) -> dict[str, Any]:
    """Scan status counts and one verdict line for one signal over the scope's records."""
    statuses = Counter(str(r.get("scanStatus") or "UNKNOWN") for r in recs)
    scanned = [r for r in recs if r.get("scanStatus") in SCANNED]
    affected = [r for r in scanned if count(r.get(key))]
    total = sum(count(r.get(key)) for r in scanned)
    out: dict[str, Any] = {
        "devices": len(recs),
        "scan_status": dict(sorted(statuses.items())),
        "scanned": len(scanned),
        "affected_devices": len(affected),
        f"total_{noun}": total,
    }
    modes = Counter(str(r["scanMode"]) for r in recs if r.get("scanMode"))
    if modes:
        out["scan_mode"] = dict(sorted(modes.items()))
    last = max((count(r.get("lastScanTime")) for r in recs), default=0)
    if last:
        out["last_scan"] = utc(last)
    if not recs:
        out["verdict"] = f"{label}: no scan records for these devices."
    elif not scanned:
        hint = next((comment(r.get("comments")) for r in recs if r.get("comments")), None)
        out["verdict"] = (
            f"{label}: no data, none of the {len(recs)} device(s) has been scanned "
            f"({', '.join(f'{k} {v}' for k, v in sorted(statuses.items()))})."
        )
        out["note"] = NO_CCO + (f" Catalyst Center says: {hint}" if hint else "")
    else:
        line = f"{label}: {len(affected)} of {len(scanned)} scanned device(s) affected ({total} {noun})"
        if len(scanned) < len(recs):
            line += f"; {len(recs) - len(scanned)} not scanned"
        out["verdict"] = line + "."
    return out


def eox_types(r: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(s.get("eoxType"))
            for s in ensure_list(r.get("summary"))
            if isinstance(s, dict) and s.get("eoxType")
        }
        - {"NONE"}
    )


def eox_bulletin(b: dict[str, Any]) -> dict[str, Any]:
    out = {
        "type": b.get("eoxAlertType"),
        "name": b.get("name"),
        "headline": b.get("bulletinHeadline"),
        "bulletin": b.get("bulletinNumber"),
        "pid": b.get("bulletinPID"),
        "physical_type": b.get("eoXPhysicalType"),
        "end_of_sale": b.get("endOfSaleDate"),
        "end_of_sw_maintenance": b.get("endOfSoftwareMaintenanceReleasesDate"),
        "end_of_vulnerability_support": b.get("endOfSoftwareVulnerabilityOrSecuritySupportDate")
        or b.get("endOfSoftwareVulnerabilityOrSecuritySupportDateHw"),
        "last_date_of_support": b.get("lastDateOfSupport"),
        "url": b.get("bulletinURL"),
    }
    out = {k: v for k, v in out.items() if v not in (None, "")}
    gone = past(b.get("lastDateOfSupport")) if b.get("lastDateOfSupport") else None
    if gone is not None:
        out["past_last_date_of_support"] = gone
    return out


async def eox_details(app: CatcApp, did: str) -> list[dict[str, Any]]:
    try:
        rec = await app.get_response(f"{EOX_DEVICES}/{safe_id(did, 'device id')}")
    except NotFound:
        return []  # MLCN10301: "EoX details for this device could not be found" (not scanned)
    rec = rec if isinstance(rec, dict) else {}
    return [eox_bulletin(b) for b in ensure_list(rec.get("eoxDetails")) if isinstance(b, dict)]


def advisory(a: dict[str, Any]) -> dict[str, Any]:
    fixed = {
        str(f.get("vulnerableVersion")): ensure_list(f.get("fixedVersions"))
        for f in ensure_list(a.get("firstFixedVersionsList"))
        if isinstance(f, dict) and f.get("vulnerableVersion")
    }
    out = {
        "id": a.get("id"),
        "impact": a.get("securityImpactRating"),
        "cvss": a.get("cvssBaseScore"),
        "cves": ensure_list(a.get("cveIds")),
        "first_fixed": fixed or None,
        "device_count": a.get("deviceCount"),
        "url": a.get("publicationUrl"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def by_cvss(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def score(a: dict[str, Any]) -> float:
        v = a.get("cvss")
        return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0.0

    return sorted(items, key=lambda a: (-score(a), str(a.get("id"))))


def notice(n: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": n.get("id"),
        "name": n.get("name"),
        "type": n.get("type"),
        "match": n.get("matchConfidence"),
        "reason": n.get("matchReason"),
        "published": utc(n.get("firstPublishDate")),
        "updated": utc(n.get("lastUpdatedDate")),
        "url": n.get("publicationUrl"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def bug(b: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": b.get("id"),
        "severity": b.get("severity"),
        "headline": b.get("headline"),
        "has_workaround": b.get("hasWorkaround"),
        "workaround": b.get("workaround"),
        "affected_versions": ensure_list(b.get("affectedVersions")) or None,
        "fixed_in": ensure_list(b.get("integratedReleases")) or None,
        "url": b.get("publicationUrl"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def insecure(c: dict[str, Any]) -> dict[str, Any]:
    out = {
        "module": c.get("module"),
        "severity": c.get("severity"),
        "cli": c.get("cliCommand"),
        "parent": c.get("parentCommand"),
        "mode": c.get("configMode"),
        "reason": c.get("reason"),
        "remediation": c.get("remediation"),
        "status": c.get("status"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def xe_major(dev: dict[str, Any]) -> int | None:
    try:
        return int(str(dev.get("softwareVersion") or "").split(".")[0])
    except ValueError:
        return None


async def insecure_configs(app: CatcApp, did: str, modules: list[str] | None = None) -> list[dict[str, Any]]:
    # `module` is an exploded array (module=TELNET&module=SNMP); a comma-joined value matches nothing.
    params: dict[str, Any] = {"module": list(modules)} if modules else {}
    found, _ = await rows(app, INSECURE.format(id=safe_id(did, "device id")), params)
    return [insecure(c) for c in found]


async def eox_section(app: CatcApp, scope: Scope, details: bool) -> dict[str, Any]:
    found, complete = await rows(app, EOX_DEVICES)
    recs = scope.keep(found, "deviceId")
    await scope.name_all(app, [str(r.get("deviceId")) for r in recs if r.get("deviceId")])
    out = scan_summary("EoX", recs, "alertCount", "alerts")
    types = Counter(t for r in recs for t in eox_types(r))
    if types:
        out["by_type"] = dict(sorted(types.items()))
    if scope.devices is None:
        try:
            summ = await app.get_response(EOX_SUMMARY)
            if isinstance(summ, dict):
                out["network_summary"] = {
                    k: summ[k]
                    for k in ("totalCount", "hardwareCount", "softwareCount", "moduleCount")
                    if k in summ
                }
        except UpstreamError as e:
            out["network_summary_unavailable"] = str(e)[:200]
    devices: list[dict[str, Any]] = [
        {
            "device": scope.name(r.get("deviceId")),
            "device_id": r.get("deviceId"),
            "scan_status": r.get("scanStatus"),
            "alerts": count(r.get("alertCount")),
            **({"types": eox_types(r)} if eox_types(r) else {}),
            **({"last_scan": utc(r.get("lastScanTime"))} if utc(r.get("lastScanTime")) else {}),
            **({"comment": comment(r.get("comments"))} if r.get("comments") else {}),
        }
        for r in recs
    ]
    devices.sort(key=lambda d: (-d["alerts"], d["device"]))
    out["device_rows"] = devices
    if details:
        wanted = [d for d in devices if d["alerts"]] if scope.one is None else devices
        detail: dict[str, Any] = {}
        for d in wanted[:DETAIL_CAP]:
            bulletins = await eox_details(app, str(d["device_id"]))
            if bulletins:
                detail[d["device"]] = bulletins
        if detail:
            out["bulletins"] = detail
        if len(wanted) > DETAIL_CAP:
            out["bulletins_truncated"] = f"Bulletins for the first {DETAIL_CAP} affected devices only."
    if not complete:
        out["truncated"] = f"First {ROW_CAP} EoX records only."
    return out


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="EoX report")
    async def catc_eox_report(
        ctx: Context,
        site: SiteArg = None,
        device: DeviceArg = None,
        details: Annotated[
            bool, Field(description="Add the EoX bulletins (dates, PIDs, links) of each affected device")
        ] = True,
    ) -> dict[str, Any]:
        """End-of-life (EoX) report from Catalyst Center: the network summary (hardware, software and module
        alerts), each device's scan status, alert count and alert types, and the bulletins behind them
        (end of sale, end of software maintenance and vulnerability support, last date of support, flagged
        when already past, with the Cisco link). One device, every device under a site, or the whole
        network. Devices show NOT_SCANNED without the Cisco account (CCO) connection: the report then
        says 'no data', which is not the same as 'no EoX'."""
        app: CatcApp = get_client(ctx)
        scope = await resolve_scope(app, device, site)
        res = await eox_section(app, scope, details)
        rows_ = res.pop("device_rows")
        out: dict[str, Any] = {"scope": scope.label, "verdict": res.pop("verdict"), **res}
        out["devices"] = rows_[:DEVICE_ROWS]
        if len(rows_) > DEVICE_ROWS:
            out["devices_total"] = len(rows_)
        return out

    @reg.read(title="Security advisories (PSIRT)")
    async def catc_security_advisories(
        ctx: Context,
        device: DeviceArg = None,
        site: SiteArg = None,
        impact: Annotated[
            list[Impact] | None, Field(description="Only advisories with these security impact ratings")
        ] = None,
        min_cvss: Annotated[
            float | None, Field(ge=0, le=10, description="Only CVSS base score >= this")
        ] = None,
    ) -> dict[str, Any]:
        """Cisco security advisories (PSIRTs) Catalyst Center matched against the devices: per device the
        scan status, scan mode and advisory count, and the advisories themselves (id, impact rating, CVSS,
        CVEs, first fixed releases per vulnerable version, Cisco link, affected devices), highest CVSS
        first. One device, every device under a site, or the whole network. Without the Cisco account
        (CCO) connection devices stay NOT_SCANNED and the tool says 'no data'; a 403 means the account's
        role lacks Security.Security Advisory."""
        app: CatcApp = get_client(ctx)
        scope = await resolve_scope(app, device, site)
        out: dict[str, Any] = {"scope": scope.label}
        try:
            recs, complete = await scan_rows(app, PSIRT, scope)
        except AuthError:
            return {
                **out,
                "verdict": "Security advisories: not readable with this account.",
                "unavailable": PSIRT_DENIED,
            }
        await scope.name_all(app, [str(r.get("networkDeviceId")) for r in recs if r.get("networkDeviceId")])
        summ = scan_summary("Security advisories", recs, "advisoryCount", "advisories")
        out["verdict"] = summ.pop("verdict")
        out |= summ
        # securityImpactRating is a single-value filter on 3.2.2 (CRITICAL or HIGH only), so the impact
        # and CVSS filters are applied here instead.
        params: dict[str, Any] = {}
        advisories: dict[str, dict[str, Any]] = {}
        if scope.devices is None:
            for a in (await rows(app, f"{PSIRT}/results/advisories", params))[0]:
                advisories[str(a.get("id"))] = advisory(a)
        else:
            affected = [r for r in recs if count(r.get("advisoryCount"))]
            for r in affected[:DETAIL_CAP]:
                did = str(r.get("networkDeviceId"))
                path = f"{PSIRT}/results/networkDevices/{safe_id(did, 'device id')}/advisories"
                for a in (await rows(app, path, params))[0]:
                    entry = advisories.setdefault(str(a.get("id")), {**advisory(a), "devices": []})
                    entry["devices"].append(scope.name(did))
            if len(affected) > DETAIL_CAP:
                out["advisories_truncated"] = f"Advisories of the first {DETAIL_CAP} affected devices only."
        items = [
            a
            for a in advisories.values()
            if (min_cvss is None or (a.get("cvss") or 0) >= min_cvss)
            and (not impact or a.get("impact") in impact)
        ]
        out["advisories"] = by_cvss(items)
        out["by_impact"] = dict(sorted(Counter(str(a.get("impact")) for a in items).items()))
        device_rows: list[dict[str, Any]] = [
            {
                "device": scope.name(r.get("networkDeviceId")),
                "scan_status": r.get("scanStatus"),
                "scan_mode": r.get("scanMode"),
                "advisories": count(r.get("advisoryCount")),
                **({"comment": comment(r.get("comments"))} if r.get("comments") else {}),
            }
            for r in recs
        ]
        out["devices"] = sorted(device_rows, key=lambda d: (-d["advisories"], d["device"]))[:DEVICE_ROWS]
        if not complete:
            out["truncated"] = f"First {ROW_CAP} device records only."
        return out

    @reg.read(title="Lifecycle and security signals")
    async def catc_lifecycle_signals(
        ctx: Context,
        device: DeviceArg = None,
        site: SiteArg = None,
        insecure_modules: Annotated[
            list[str] | None,
            Field(
                max_length=10,
                description="Insecure configurations: only these modules (SNMP, TELNET, HTTP, ...)",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Every lifecycle and security signal Catalyst Center has for one device or the devices under a
        site, in one read: EoX alerts, Cisco security advisories (PSIRT), field notices, network bugs and
        insecure configurations (deprecated or weak CLI such as telnet, SNMPv1/v2c communities, HTTP),
        with one verdict line per signal and a row per device. For one device it also lists each notice,
        bug, advisory and insecure command with its remediation. The cloud-matched signals need the Cisco
        account (CCO) connection (NOT_SCANNED = no data, said so); insecure configurations are reported from
        IOS-XE 26.1.1 on. Start a scan with catc_trigger_lifecycle_scan."""
        app: CatcApp = get_client(ctx)
        scope = await resolve_scope(app, device, site)
        out: dict[str, Any] = {"scope": scope.label}
        signals: dict[str, Any] = {}
        unavailable: dict[str, str] = {}
        per_device: dict[str, dict[str, Any]] = {}

        def row(did: Any) -> dict[str, Any]:
            return per_device.setdefault(str(did), {"device": scope.name(did)})

        try:
            eox = await eox_section(app, scope, details=scope.one is not None)
            for r in eox.pop("device_rows"):
                row(r["device_id"])["eox"] = r["alerts"] if r["scan_status"] in SCANNED else r["scan_status"]
            signals["eox"] = eox
        except UpstreamError as e:
            unavailable["eox"] = str(e)[:200]
        for key, base, field, noun in (
            ("security_advisories", PSIRT, "advisoryCount", "advisories"),
            ("field_notices", NOTICES, "noticeCount", "notices"),
            ("bugs", BUGS, "bugCount", "bugs"),
        ):
            try:
                recs, complete = await scan_rows(app, base, scope)
            except AuthError:
                unavailable[key] = PSIRT_DENIED if base == PSIRT else "Catalyst Center refused the API (403)."
                continue
            except UpstreamError as e:
                unavailable[key] = str(e)[:200]
                continue
            await scope.name_all(
                app, [str(r.get("networkDeviceId")) for r in recs if r.get("networkDeviceId")]
            )
            summ = scan_summary(key.replace("_", " ").capitalize(), recs, field, noun)
            if not complete:
                summ["truncated"] = f"First {ROW_CAP} device records only."
            signals[key] = summ
            for r in recs:
                status = r.get("scanStatus")
                row(r.get("networkDeviceId"))[key] = count(r.get(field)) if status in SCANNED else status
        # Insecure configurations: per device, so for a site only the first DETAIL_CAP devices.
        if scope.devices is None:
            signals["insecure_configurations"] = {
                "verdict": "Insecure configurations: per device; give a site or a device to check them.",
            }
        else:
            checked: list[str] = []
            modules: Counter[str] = Counter()
            errors: list[str] = []
            older = 0
            details: list[dict[str, Any]] = []
            for d in scope.devices[:DETAIL_CAP]:
                did = str(d["id"])
                try:
                    found = await insecure_configs(app, did, insecure_modules)
                except UpstreamError as e:
                    errors.append(f"{scope.name(did)}: {str(e)[:120]}")
                    continue
                checked.append(did)
                row(did)["insecure_configurations"] = len(found)
                modules.update(str(c.get("module")) for c in found)
                major = xe_major(d)
                if major is not None and major < 26:
                    older += 1
                if scope.one is not None:
                    details = found
            with_findings = sum(1 for did in checked if per_device[did]["insecure_configurations"])
            total = sum(modules.values())
            line = (
                f"Insecure configurations: {total} on {with_findings} of {len(checked)} device(s) checked"
                + (f" ({', '.join(f'{m} {n}' for m, n in modules.most_common())})" if total else "")
                + "."
            )
            sec: dict[str, Any] = {
                "devices_checked": len(checked),
                "affected_devices": with_findings,
                "verdict": line,
            }
            if modules:
                sec["by_module"] = dict(modules.most_common())
            if older and not total:
                sec["note"] = f"{older} of the devices run a release before 26.1: " + INSECURE_NOTE
            if len(scope.devices) > DETAIL_CAP:
                sec["truncated"] = f"First {DETAIL_CAP} of {len(scope.devices)} devices only."
            if errors:
                sec["errors"] = errors[:10]
            signals["insecure_configurations"] = sec
            if details:
                out["insecure_configurations"] = details
        # One device: the findings themselves.
        one = scope.one
        if one is not None:
            did = safe_id(str(one["id"]), "device id")
            for key, path, fn in (
                ("security_advisories", f"{PSIRT}/results/networkDevices/{did}/advisories", advisory),
                ("field_notices", f"{NOTICES}/results/networkDevices/{did}/notices", notice),
                ("bugs", f"{BUGS}/results/networkDevices/{did}/bugs", bug),
            ):
                if key in unavailable or not signals.get(key, {}).get("scanned"):
                    continue
                try:
                    out[key] = [fn(x) for x in (await rows(app, path))[0]]
                except UpstreamError as e:
                    unavailable[key] = str(e)[:200]
            if signals.get("eox", {}).get("bulletins"):
                out["eox_bulletins"] = signals["eox"].pop("bulletins").get(scope.name(did), [])
        out["verdict"] = [s["verdict"] for s in signals.values() if s.get("verdict")]
        if any(s.get("note", "").startswith("Not scanned") for s in signals.values()):
            out["note"] = NO_CCO
            for s in signals.values():
                if str(s.get("note", "")).startswith("Not scanned"):
                    s.pop("note")
        out["signals"] = signals
        if unavailable:
            out["unavailable"] = unavailable
        rows_ = sorted(
            per_device.values(),
            key=lambda r: (-sum(v for v in r.values() if isinstance(v, int)), r["device"]),
        )
        out["devices"] = rows_[:DEVICE_ROWS]
        if len(rows_) > DEVICE_ROWS:
            out["devices_total"] = len(rows_)
        return out

    @reg.write(title="Trigger lifecycle scan", destructive=False, idempotent=True)
    async def catc_trigger_lifecycle_scan(
        ctx: Context,
        scans: Annotated[
            list[Scan] | None,
            Field(description="field_notices, bugs, security_advisories (default: all three)"),
        ] = None,
        failed_only: Annotated[
            bool, Field(description="Rescan only the devices whose last scan failed")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Start Catalyst Center's field notice, network bug and/or security advisory scans now instead of
        waiting for the scheduled run (EoX has no on-demand scan). The scans cover every supported device
        (switches, routers, wireless controllers; bugs: switches and routers) and change nothing on them.
        They need the Cisco account (CCO) connection and Consent to Connect: without it the task fails or the
        devices stay NOT_SCANNED. Preview-first. Read the results with catc_lifecycle_signals."""
        app: CatcApp = get_client(ctx)
        wanted: list[str] = list(scans) if scans else list(SCANS)
        chosen = list(dict.fromkeys(wanted))
        params = {"failedDevicesOnly": str(failed_only).lower()}
        what = ", ".join(SCANS[s][1] for s in chosen)
        plan = Plan(
            f"Trigger {what} scan" + (" (failed devices only)" if failed_only else ""),
            details={
                "requests": [
                    {"method": "POST", "path": f"{SCANS[s][0]}/triggerScan", "params": params} for s in chosen
                ],
            },
            side_effects=[
                "Changes no device: Catalyst Center matches the inventory against Cisco's cloud data.",
                "Needs the Cisco account (CCO) connection and Consent to Connect; without it the scan fails.",
                "Catalyst Center allows 10 trigger requests a minute per scan type.",
            ],
            fingerprint={"scans": chosen, "failed_only": failed_only},
        )

        async def apply() -> Any:
            results: dict[str, Any] = {}
            for s in chosen:
                try:
                    resp = await app.api.request("POST", f"{SCANS[s][0]}/triggerScan", params=params)
                    timeout = min(float(app.settings.mcp_task_timeout), 60.0)
                    results[s] = await app.wait_job(resp, ctx=ctx, timeout=timeout, what=f"{s} scan")
                except UpstreamTimeout as e:
                    results[s] = {"status": "RUNNING", "note": str(e)[:300]}
                except UpstreamError as e:
                    results[s] = {"status": "FAILED", "error": str(e)[:300]}
            return {
                "scans": results,
                "next": "Scans take minutes; read the results with catc_lifecycle_signals.",
            }

        return await preview_or_apply(
            ctx,
            tool="catc_trigger_lifecycle_scan",
            args={"scans": scans, "failed_only": failed_only},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
