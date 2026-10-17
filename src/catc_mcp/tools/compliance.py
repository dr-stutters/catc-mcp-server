"""Compliance reads: fleet summary, per-device detail, the compliance report (by site, category
and severity, with the trend between runs, D37) and config drift against a golden device or a
template (D37)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import contextlib
import functools
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Awaitable, Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    InvalidRequest,
    NotFound,
    ToolRegistrar,
    UpstreamError,
    get_client,
    get_settings,
    object_result,
)
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import (
    ago,
    ensure_list,
    inventory_names,
    pick,
    resolve_device,
    resolve_site,
    resolve_template,
)
from catc_mcp.tools.archive import archive_files, file_text
from catc_mcp.tools.compliance_policies import site_map, violation_rows
from catc_mcp.tools.inventory import redact_config

STATUSES = ["COMPLIANT", "NON_COMPLIANT", "IN_PROGRESS", "NOT_AVAILABLE", "NOT_APPLICABLE", "ERROR"]
CATEGORIES = Literal["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT", "DESIGN_OOD", "EOX", "NETWORK_SETTINGS"]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Compliance summary")
    async def catc_get_compliance_summary(
        ctx: Context,
        max_devices: Annotated[
            int, Field(ge=0, le=500, description="How many non-compliant devices to list (default 50)")
        ] = 50,
    ) -> ToolResult:
        """Fleet compliance at a glance: how many devices are compliant, non-compliant, in progress,
        not available or in error, and which devices are non-compliant (with hostname). Drill into one
        with catc_get_compliance_detail."""
        app: CatcApp = get_client(ctx)
        counts = await asyncio.gather(
            *(
                app.get_response("/dna/intent/api/v1/compliance/count", {"complianceStatus": s})
                for s in STATUSES
            )
        )
        out: dict[str, Any] = {"counts": dict(zip(STATUSES, counts, strict=True))}
        if max_devices:
            bad = ensure_list(
                await app.get_response(
                    "/dna/intent/api/v1/compliance",
                    {"complianceStatus": "NON_COMPLIANT,ERROR", "limit": max_devices, "offset": 1},
                )
            )
            names: dict[str, str] = {}
            ids = [str(b.get("deviceUuid")) for b in bad if isinstance(b, dict) and b.get("deviceUuid")]
            if ids:
                devs = ensure_list(
                    await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids[:100])})
                )
                names = {d["id"]: d.get("hostname", "") for d in devs if isinstance(d, dict) and d.get("id")}
            out["non_compliant"] = [
                {
                    "device": names.get(str(b.get("deviceUuid")), b.get("deviceUuid")),
                    "status": b.get("complianceStatus"),
                    "lastUpdateTime": b.get("lastUpdateTime"),
                    "deviceUuid": b.get("deviceUuid"),
                }
                for b in bad
                if isinstance(b, dict)
            ]
        return object_result(out)

    @reg.read(title="Device compliance detail")
    async def catc_get_compliance_detail(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial number or id")],
        category: Annotated[CATEGORIES | None, Field(description="Only this compliance category")] = None,
        include_diff: Annotated[
            bool, Field(description="Include the config/intent difference list for non-compliant items")
        ] = False,
    ) -> ToolResult:
        """Compliance report for one device per category (startup vs running config, image, PSIRT,
        EoX, network settings, network profile, fabric): status, message, last check time, whether
        Catalyst Center can remediate it and, with include_diff, what differs. Non-compliant items come
        first. For RUNNING_CONFIG (unsaved changes) see the actual lines with
        catc_compare_device_configs(compare='startup'). Re-check with catc_run_compliance."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        params: dict[str, Any] = {}
        if category:
            params["category"] = category
        if include_diff:
            params["diffList"] = "true"
        detail = await app.get_response(f"/dna/intent/api/v1/compliance/{dev['id']}/detail", params)
        rows = []
        for d in ensure_list(detail):
            if not isinstance(d, dict):
                continue
            row = pick(
                d, ["complianceType", "status", "state", "message", "severity", "remediationSupported"]
            )
            if isinstance(d.get("lastUpdateTime"), int | float):
                row["checked"] = datetime.fromtimestamp(d["lastUpdateTime"] / 1000, tz=UTC).strftime(
                    "%Y-%m-%d %H:%M UTC"
                )
            if d.get("sourceInfoList"):
                row["differences"] = d["sourceInfoList"]
            rows.append(row)
        rows.sort(key=lambda r: (r.get("status") == "COMPLIANT", str(r.get("complianceType"))))
        return object_result({"device": dev.get("hostname"), "deviceUuid": dev["id"], "compliance": rows})

    register_report(reg)
    register_drift(reg)


# --- compliance report (D37) ----------------------------------------------------------------

BAD = ("NON_COMPLIANT", "ERROR")
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MAJOR", "MEDIUM", "MINOR", "LOW", "WARNING", "INFO"]
HISTORY_FILE = "compliance-history.json"
HISTORY_KEEP = 20
# A status that changed within this long of the category's last run changed *in* that run.
SAME_RUN_MS = 120_000


def when(ms: Any) -> str | None:
    if not isinstance(ms, int | float) or ms <= 0:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


def sev_rank(sev: Any) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


async def bounded(n: int, jobs: list[Callable[[], Awaitable[Any]]]) -> list[Any]:
    """Run the jobs at most n at a time; exceptions are returned, not raised."""
    sem = asyncio.Semaphore(n)

    async def one(job: Callable[[], Awaitable[Any]]) -> Any:
        async with sem:
            return await job()

    return await asyncio.gather(*(one(j) for j in jobs), return_exceptions=True)


async def device_site_name(app: CatcApp, device_id: str) -> str:
    try:
        a = await app.get_response(f"/dna/intent/api/v1/networkDevices/{safe_id(device_id)}/assignedToSite")
    except NotFound:
        return "(unassigned)"
    return (
        str(a.get("siteNameHierarchy"))
        if isinstance(a, dict) and a.get("siteNameHierarchy")
        else "(unassigned)"
    )


async def site_members(app: CatcApp, root: str, device_ids: list[str] | None = None) -> dict[str, str]:
    """{device id: site hierarchy} for the devices assigned at `root` or below. Lists each site's
    direct members (one paged call per site in the subtree), unless the caller gives fewer device
    ids than there are sites: then it asks once per device instead, whichever is fewer calls."""
    names = await site_map(app)
    subtree = {i: n for i, n in names.items() if root == "Global" or n == root or n.startswith(root + "/")}
    if device_ids is not None and len(device_ids) < len(subtree):
        found = await bounded(4, [functools.partial(device_site_name, app, i) for i in device_ids])
        return {i: (w if isinstance(w, str) else "(unknown)") for i, w in zip(device_ids, found, strict=True)}

    async def members(site_id: str) -> list[str]:
        page = await fetch_all(
            app.pager,
            app.api,
            "/dna/intent/api/v1/networkDevices/assignedToSite",
            {"siteId": site_id},
            cap=5000,
        )
        return [str(a["deviceId"]) for a in page.items if isinstance(a, dict) and a.get("deviceId")]

    ids = sorted(subtree, key=lambda i: subtree[i].count("/"))  # deepest last: its assignment wins
    found = await bounded(4, [functools.partial(members, i) for i in ids])
    out: dict[str, str] = {}
    for sid, devs in zip(ids, found, strict=True):
        if isinstance(devs, BaseException):
            raise devs
        for d in devs:
            out[d] = subtree[sid]
    return out


async def rule_violations(app: CatcApp, device_id: str) -> list[dict[str, Any]]:
    """The user-policy (NETWORK_RULES) violations of one device: policy, rule, severity, message."""
    did = safe_id(device_id, "device id")
    base = f"/dna/intent/api/v1/compliance/networkDevices/{did}/detail/policys"
    out: list[dict[str, Any]] = []
    for p in ensure_list(await app.get_response(base)):
        if not isinstance(p, dict) or not (p.get("id") or p.get("policyId")):
            continue
        pid = safe_id(str(p.get("id") or p.get("policyId")), "policy id")
        page = await fetch_all(app.pager, app.api, f"{base}/{pid}/violations", cap=500)
        name = p.get("name") or p.get("policyName")
        for v in page.items:
            if isinstance(v, dict):
                out += [{"policy": name, **r} for r in violation_rows(v)]
    return out


def history_path(ctx: Context) -> Path | None:
    try:
        settings = get_settings(ctx)
        base = settings.cache_dir_for("catc-mcp-server")
    except Exception:  # noqa: BLE001 - no settings (tests, odd hosts): the trend is then stateless only
        return None
    return Path(base) / HISTORY_FILE if base else None


def history_key(ctx: Context, site_id: str, categories: list[str] | None) -> str:
    try:
        url = str(get_settings(ctx).url)
    except Exception:  # noqa: BLE001
        url = ""
    raw = json.dumps([url, site_id, sorted(categories or [])])
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def load_history(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


HISTORY_LOCK = asyncio.Lock()


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """An exclusive lock on <path>.lock across processes (best effort where fcntl is missing)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_suffix(".lock"), "a") as fh:
        try:
            import fcntl

            fcntl.flock(fh, fcntl.LOCK_EX)
        except ImportError:  # Windows: in-process lock only
            pass
        yield


def save_history(path: Path, data: dict[str, list[dict[str, Any]]]) -> bool:
    """Write atomically: a unique temp file in the same directory, then rename over the old one."""
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError, UnboundLocalError):
            os.unlink(tmp)
        return False
    return True


def record_snapshot(
    path: Path | None, key: str, snapshot: dict[str, Any]
) -> tuple[dict[str, Any] | None, bool]:
    """Store this report's snapshot; return the latest earlier-run snapshot (or None) and whether
    the store worked. Read-modify-write runs under an in-process and a file lock."""
    if path is None:
        return None, True
    try:
        with file_lock(path):
            history = load_history(path)
            snaps = [x for x in history.get(key, []) if isinstance(x, dict)]
            earlier = [x for x in snaps if x.get("run_ms") != snapshot["run_ms"]]
            history[key] = (earlier + [snapshot])[-HISTORY_KEEP:]
            ok = save_history(path, history)
    except OSError:
        return None, False
    return (earlier[-1] if earlier else None), ok


def compare_snapshots(prev: dict[str, Any], cur: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    """What became non-compliant and what was fixed between two report snapshots."""

    def label(key: str) -> dict[str, str]:
        dev, _, rest = key.partition("|")
        return {"device": names.get(dev, dev), "item": rest}

    before, after = set(prev.get("bad") or []), set(cur.get("bad") or [])
    return {
        "previous_report": prev.get("taken"),
        "previous_run": prev.get("run"),
        "non_compliant_items_before": len(before),
        "non_compliant_items_now": len(after),
        "new": [label(k) for k in sorted(after - before)],
        "resolved": [label(k) for k in sorted(before - after)],
    }


def register_report(reg: ToolRegistrar) -> None:
    @reg.read(title="Compliance report")
    async def catc_compliance_report(
        ctx: Context,
        site: Annotated[
            str | None, Field(description="Site hierarchy or id; devices at it and below (default Global)")
        ] = None,
        categories: Annotated[
            list[str] | None,
            Field(
                description="Only these compliance types, e.g. ['NETWORK_RULES', 'RUNNING_CONFIG'] "
                "(NETWORK_RULES = your compliance policies); default all"
            ),
        ] = None,
        include_rule_violations: Annotated[
            bool, Field(description="List the policy rule violations of non-compliant devices")
        ] = True,
        max_devices: Annotated[
            int,
            Field(
                ge=0,
                le=500,
                description="How many non-compliant devices to detail (default 25; each with policy "
                "violations costs 2+ API calls)",
            ),
        ] = 25,
    ) -> ToolResult:
        """Which devices are out of standard: compliance at a site (and below) from the last
        compliance runs, counted by site, category (startup vs running config, image, PSIRT, EoX,
        network settings, your compliance policies as NETWORK_RULES...) and severity, with the
        non-compliant devices and their failing categories and policy rule violations (worst first).
        Trend between runs: `trend.in_last_run` marks non-compliance that appeared in each device's
        latest run versus non-compliance that persists; `trend.since_previous_report` lists what is
        new and what was fixed since the previous report for the same site taken at an earlier run
        (kept in the server's cache directory). Run catc_run_compliance first for fresh results."""
        app: CatcApp = get_client(ctx)
        st = await resolve_site(app, site or "Global")
        sid = safe_id(str(st["id"]), "site id")
        params: dict[str, Any] = {}
        if categories:
            params["complianceTypes"] = ",".join(c.strip().upper() for c in categories)
        page = await fetch_all(
            app.pager, app.api, f"/dna/intent/api/v1/compliance/sites/{sid}/networkDevices", params, cap=5000
        )
        recs = [r for r in page.items if isinstance(r, dict) and r.get("networkDeviceId")]
        ids = [str(r["networkDeviceId"]) for r in recs]
        names = await inventory_names(app, ids) or {}
        members = await site_members(app, str(st.get("nameHierarchy") or "Global"), ids)
        site_of = {i: members.get(i, "(unassigned)") for i in ids}

        by_status: Counter[str] = Counter()
        by_category: dict[str, Counter[str]] = {}
        by_severity: Counter[str] = Counter()
        by_site: dict[str, dict[str, Any]] = {}
        bad_devices: list[dict[str, Any]] = []
        # Category-level keys for every device, so the snapshot doesn't depend on max_devices or
        # include_rule_violations (rule detail is only fetched for the detailed devices).
        bad_keys: list[str] = []
        new_items: list[dict[str, Any]] = []
        persisting = 0
        latest_run = 0
        for r in recs:
            did = str(r["networkDeviceId"])
            dname = names.get(did, did)
            status = str(r.get("status") or "UNKNOWN")
            by_status[status] += 1
            latest_run = max(latest_run, int(r.get("lastComplianceExecutionTime") or 0))
            srow = by_site.setdefault(site_of[did], {"site": site_of[did], "devices": 0, "non_compliant": 0})
            srow["devices"] += 1
            items = []
            for d in r.get("details") or []:
                if not isinstance(d, dict):
                    continue
                ctype, cstat = str(d.get("complianceType")), str(d.get("status"))
                by_category.setdefault(ctype, Counter())[cstat] += 1
                if cstat not in BAD:
                    continue
                sev = str(d.get("severity") or "UNKNOWN")
                by_severity[sev] += 1
                ran, changed = d.get("lastComplianceRun") or 0, d.get("lastStatusChangeTime") or 0
                fresh = bool(ran and changed and changed >= ran - SAME_RUN_MS)
                item = {
                    "category": ctype,
                    "status": cstat,
                    "severity": sev,
                    "since": when(changed),
                    "last_run": when(ran),
                    "new_in_last_run": fresh,
                }
                if d.get("statusDescription"):
                    item["description"] = str(d["statusDescription"])[:200]
                items.append(item)
                bad_keys.append(f"{did}|{ctype}")
                if fresh:
                    new_items.append({"device": dname, "category": ctype, "severity": sev})
                else:
                    persisting += 1
            if items:
                srow["non_compliant"] += 1
                items.sort(key=lambda x: (sev_rank(x["severity"]), x["category"]))
                bad_devices.append(
                    {
                        "device": dname,
                        "site": site_of[did],
                        "status": status,
                        "worst_severity": items[0]["severity"],
                        "last_run": when(r.get("lastComplianceExecutionTime")),
                        "categories": items,
                        "deviceUuid": did,
                    }
                )
        bad_devices.sort(key=lambda b: (sev_rank(b["worst_severity"]), b["device"]))

        rule_counts: Counter[tuple[str, str, str]] = Counter()
        errors: list[str] = []
        detailed = bad_devices[:max_devices]
        if include_rule_violations:
            targets = [b for b in detailed if any(c["category"] == "NETWORK_RULES" for c in b["categories"])]
            found = await bounded(
                4, [functools.partial(rule_violations, app, str(b["deviceUuid"])) for b in targets]
            )
            for b, rows in zip(targets, found, strict=True):
                if isinstance(rows, BaseException):
                    errors.append(f"{b['device']}: rule violations unavailable ({rows})"[:300])
                    continue
                b["rule_violations"] = rows
                for v in rows:
                    rule_counts[(str(v.get("policy")), str(v.get("rule")), str(v.get("severity")))] += 1

        trend: dict[str, Any] = {
            "in_last_run": {"new_non_compliant": new_items, "persisting_non_compliant": persisting}
        }
        snapshot = {
            "taken": datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "run": when(latest_run),
            "run_ms": latest_run,
            "bad": sorted(set(bad_keys)),
        }
        path = history_path(ctx)
        async with HISTORY_LOCK:
            previous, saved = await asyncio.to_thread(
                record_snapshot, path, history_key(ctx, sid, categories), snapshot
            )
        if previous is not None:
            trend["since_previous_report"] = compare_snapshots(previous, snapshot, names)
        elif path is not None:
            trend["since_previous_report"] = (
                "No earlier report for this site at an earlier compliance run yet; the next report "
                "after a new compliance run will compare against this one."
            )
        if not saved:
            errors.append(f"Couldn't save the report history to {path}.")

        out: dict[str, Any] = {
            "site": st.get("nameHierarchy"),
            "devices": len(recs),
            "latest_run": when(latest_run),
            "by_status": dict(by_status),
            "by_category": {k: dict(v) for k, v in sorted(by_category.items())},
            "by_severity": dict(sorted(by_severity.items(), key=lambda kv: sev_rank(kv[0]))),
            "by_site": sorted(by_site.values(), key=lambda x: (-x["non_compliant"], x["site"])),
            "non_compliant_devices": len(bad_devices),
            "non_compliant": detailed,
            "trend": trend,
        }
        if rule_counts:
            out["by_rule"] = [
                {"policy": p, "rule": r, "severity": s, "devices": n}
                for (p, r, s), n in sorted(rule_counts.items(), key=lambda kv: (sev_rank(kv[0][2]), -kv[1]))
            ]
        if len(bad_devices) > len(detailed):
            out["truncated"] = (
                f"{len(bad_devices) - len(detailed)} more non-compliant devices; raise max_devices"
            )
        if errors:
            out["errors"] = errors
        return object_result(out)


# --- config drift (D37) ---------------------------------------------------------------------

# Lines that always differ between devices or carry no configuration (their child lines go too).
DEFAULT_IGNORE = [
    r"^Building configuration",
    r"^Current configuration",
    r"^version\s",
    r"^hostname\s",
    r"^ntp clock-period",
    r"^crypto pki certificate\s",
    r"^crypto pki trustpoint\s",
    r"^license udi",
    r"^quit$",
    r"^end$",
]


def config_paths(
    text: str, ignore: list[re.Pattern[str]], only: list[re.Pattern[str]] | None = None
) -> list[str]:
    """IOS-style config as unique 'parent > child' paths (indentation gives the nesting), skipping
    comments, ignored lines (with their children) and, with `only`, every top-level section that
    matches none of those patterns."""
    out: dict[str, None] = {}
    stack: list[tuple[int, str, bool]] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        body = line.strip()
        if not body or body.startswith("!"):
            continue
        indent = len(line) - len(line.lstrip())
        while stack and stack[-1][0] >= indent:
            stack.pop()
        skip = bool(stack and stack[-1][2])
        if not skip:
            skip = any(p.search(body) for p in ignore)
        if not skip and not stack and only is not None:
            skip = not any(p.search(body) for p in only)
        stack.append((indent, body, skip))
        if not skip:
            out[" > ".join(re.sub(r"\s+", " ", s[1]) for s in stack)] = None
    return list(out)


def template_missing(expected: list[str], have: set[str]) -> list[str]:
    """Template lines not in the running config. A 'no X' line is satisfied when the running config
    has it verbatim or has no 'X' line at that place."""
    missing = []
    for path in expected:
        if path in have:
            continue
        parent, sep, last = path.rpartition(" > ")
        if last.startswith("no "):
            positive = f"{parent}{sep}{last[3:]}"
            if positive not in have and not any(h.startswith(positive + " ") for h in have):
                continue
        missing.append(path)
    return missing


def compile_patterns(pats: list[str] | None, what: str) -> list[re.Pattern[str]]:
    out = []
    for p in pats or []:
        try:
            out.append(re.compile(p))
        except re.error as err:
            raise InvalidRequest(f"Bad {what} regex {p!r}: {err}") from err
    return out


async def latest_running(app: CatcApp, device_id: str) -> tuple[str, dict[str, Any]]:
    files = await archive_files(app, device_id, "RUNNINGCONFIG")
    if not files:
        raise NotFound("no archived running config yet (catc_resync_devices, then wait a few minutes)")
    return await file_text(app, str(files[0]["id"])), files[0]


async def scope_devices(
    app: CatcApp, devices: list[str] | None, site: str | None, family: str | None
) -> list[dict[str, Any]]:
    if devices:
        out: dict[str, dict[str, Any]] = {}
        for ref in devices:
            d = await resolve_device(app, ref)
            out[str(d["id"])] = d
        return list(out.values())
    st = await resolve_site(app, site) if site else None
    if st is None or st.get("type") == "global":
        params: dict[str, Any] = {"family": family} if family else {}
        page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/network-device", params, cap=2000)
        return [d for d in page.items if isinstance(d, dict) and d.get("id")]
    ids = sorted(await site_members(app, str(st.get("nameHierarchy"))))
    devs: list[dict[str, Any]] = []
    for n in range(0, len(ids), 100):
        found = await app.get_response(
            "/dna/intent/api/v1/network-device", {"id": ",".join(ids[n : n + 100])}
        )
        devs += [d for d in ensure_list(found) if isinstance(d, dict) and d.get("id")]
    return [d for d in devs if not family or d.get("family") == family]


def register_drift(reg: ToolRegistrar) -> None:
    @reg.read(title="Config drift")
    async def catc_config_drift(
        ctx: Context,
        against: Annotated[
            Literal["golden", "template"],
            Field(
                description="'golden': compare each device's running config with a golden device's; "
                "'template': check that each device's running config contains a template's rendered lines"
            ),
        ],
        golden_device: Annotated[
            str | None, Field(description="With against='golden': the reference device (name, IP or id)")
        ] = None,
        template: Annotated[
            str | None, Field(description="With against='template': template 'Project/Name', name or id")
        ] = None,
        params: Annotated[
            dict[str, Any] | None,
            Field(
                description="With against='template': template variable values (device-bound ones resolve)"
            ),
        ] = None,
        devices: Annotated[
            list[str] | None, Field(max_length=200, description="Devices to check (name, IP or id)")
        ] = None,
        site: Annotated[
            str | None,
            Field(description="Instead of devices: every device at this site and below (hierarchy or id)"),
        ] = None,
        only: Annotated[
            list[str] | None,
            Field(
                description="Compare only top-level sections matching these regexes, e.g. "
                "['^service ', '^ip http', '^logging', '^line vty']"
            ),
        ] = None,
        ignore: Annotated[
            list[str] | None,
            Field(description="More regexes of lines to ignore (with their children), e.g. ['^ip address']"),
        ] = None,
        max_lines: Annotated[
            int, Field(ge=1, le=500, description="Differing lines listed per device (default 30)")
        ] = 30,
        max_devices: Annotated[
            int,
            Field(
                ge=1,
                le=200,
                description="Check at most this many devices (default 50; each costs 2-3 API calls)",
            ),
        ] = 50,
    ) -> ToolResult:
        """Config drift across sites: which devices' running configuration differs from a golden
        device (lines missing compared with it, and extra lines) or no longer contains what a
        template renders to (lines missing; a 'no X' template line counts as present when X is
        absent). Uses the latest archived running configs (secrets masked; hostname, version,
        certificates and similar always-different lines ignored). Without devices or site, golden
        mode checks every device of the golden device's family. Lines are shown as 'parent > child'.
        The archive lags a config change by a few minutes; catc_resync_devices refreshes it.
        Inspect one device with catc_compare_device_configs."""
        app: CatcApp = get_client(ctx)
        ign = compile_patterns(DEFAULT_IGNORE, "ignore") + compile_patterns(ignore, "ignore")
        onl = compile_patterns(only, "only") if only else None
        notes: list[str] = []
        out: dict[str, Any] = {"against": against}
        golden: dict[str, Any] | None = None
        golden_paths: list[str] = []
        tmpl: dict[str, Any] | None = None
        if against == "golden":
            if not golden_device:
                raise InvalidRequest("against='golden' needs golden_device.")
            golden = await resolve_device(app, golden_device)
            text, gfile = await latest_running(app, str(golden["id"]))
            golden_paths = config_paths(text, ign, onl)
            out["golden"] = {
                "device": golden.get("hostname"),
                "config_age": ago(gfile.get("createdTime")),
                "lines_compared": len(golden_paths),
            }
            family = None if devices or site else str(golden.get("family") or "") or None
        else:
            if not template:
                raise InvalidRequest("against='template' needs template.")
            if not devices and not site:
                raise InvalidRequest("against='template' needs devices or site.")
            tmpl = await resolve_template(app, template)
            out["template"] = f"{tmpl.get('projectName', '')}/{tmpl.get('name', '')}".strip("/")
            family = None
        devs = await scope_devices(app, devices, site, family)
        if golden is not None:
            devs = [d for d in devs if str(d["id"]) != str(golden["id"])]
        if not devs:
            raise NotFound("No devices to check (none given, or none at the site / in the family).")

        async def check(dev: dict[str, Any]) -> dict[str, Any]:
            row: dict[str, Any] = {"device": dev.get("hostname"), "deviceUuid": dev["id"]}
            try:
                text, f = await latest_running(app, str(dev["id"]))
            except (NotFound, UpstreamError) as err:
                return {**row, "error": str(err)[:300]}
            row["config_age"] = ago(f.get("createdTime"))
            have_list = config_paths(text, ign, onl)
            have = set(have_list)
            if tmpl is not None:
                body = {"templateId": tmpl.get("templateId") or tmpl.get("id"), "params": params or {}}
                body["deviceId"] = dev["id"]
                try:
                    res = await app.api.put("/dna/intent/api/v1/template-programmer/template/preview", body)
                except UpstreamError as err:
                    return {**row, "error": f"template render failed: {err}"[:300]}
                if isinstance(res, dict) and res.get("validationErrors"):
                    return {**row, "error": f"template render errors: {res['validationErrors']}"[:300]}
                cli = redact_config(str(res.get("cliPreview") or "") if isinstance(res, dict) else "")
                expected = config_paths(cli, ign, onl)
                missing = template_missing(expected, have)
                extra: list[str] = []
                row["template_lines"] = len(expected)
            else:
                missing = [p for p in golden_paths if p not in have]
                gset = set(golden_paths)
                extra = [p for p in have_list if p not in gset]
            row["drifted"] = bool(missing or extra)
            row["missing_count"] = len(missing)
            row["missing"] = missing[:max_lines]
            if against == "golden":
                row["extra_count"] = len(extra)
                row["extra"] = extra[:max_lines]
            return row

        if len(devs) > max_devices:
            notes.append(
                f"Checked {max_devices} of {len(devs)} devices (by hostname); raise max_devices or narrow "
                "devices/site for the rest."
            )
            devs = sorted(devs, key=lambda d: str(d.get("hostname")))[:max_devices]
        rows = await bounded(4, [functools.partial(check, d) for d in devs])
        results = [
            r if isinstance(r, dict) else {"device": d.get("hostname"), "error": str(r)[:300]}
            for d, r in zip(devs, rows, strict=True)
        ]
        results.sort(key=lambda r: (not r.get("drifted"), "error" not in r, str(r.get("device"))))
        out["checked"] = len(results)
        out["drifted"] = [r["device"] for r in results if r.get("drifted")]
        out["in_line"] = [r["device"] for r in results if r.get("drifted") is False]
        out["results"] = results
        if any("error" in r for r in results):
            notes.append("Devices with 'error' were not compared.")
        if against == "golden" and not only:
            notes.append(
                "Golden mode compares every section, so addressing and per-device values show as drift; "
                "narrow it with only=[...] or ignore=[...]."
            )
        if notes:
            out["notes"] = notes
        return object_result(out)
