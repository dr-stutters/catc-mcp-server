"""Assurance health score definitions (roadmap D121): the per-device-family KPIs behind device and client
health scores, with the threshold where a KPI turns a device unhealthy and whether it counts towards the
overall score.

`GET /dna/intent/api/v1/healthScoreDefinitions` (one-based offset, `/count`, `/{id}`) lists one row per KPI
and device family: `name` (e.g. cpuUtilizationThreshold), `displayName`, `deviceFamily` (ROUTER,
SWITCH_AND_HUB, WIRELESS_CONTROLLER, UNIFIED_AP, WIRED_CLIENT, WIRELESS_CLIENT), `thresholdValue`,
`includeForOverallHealth`, `synchronizeToIssueThreshold` and `definitionStatus` (DEFAULT or MODIFIED). A 3.2.2
lab appliance holds 78 rows; the query filters are `deviceType` (the family) and `includeForOverallHealth`.
Writes are synchronous: `PUT /{id}` for one row and `POST /bulkUpdate` (a list of {id, ...}) for several,
each taking thresholdValue, includeForOverallHealth and synchronizeToIssueThreshold only.

The API reports no factory value next to a MODIFIED one, so `FACTORY` holds the 3.2.2 defaults recorded from
the lab appliance on 2026-10-28 (every row DEFAULT): reset_to_default uses them and refuses KPIs it doesn't
know rather than guess.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

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
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.http import Page, fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid

PATH = "/dna/intent/api/v1/healthScoreDefinitions"
Family = Literal[
    "ROUTER", "SWITCH_AND_HUB", "WIRELESS_CONTROLLER", "UNIFIED_AP", "WIRED_CLIENT", "WIRELESS_CLIENT"
]
FAMILY_TEXT = "ROUTER, SWITCH_AND_HUB, WIRELESS_CONTROLLER, UNIFIED_AP, WIRED_CLIENT or WIRELESS_CLIENT"
# Health score family -> inventory `family` (network-device?family=...); client families have no devices.
INVENTORY_FAMILY = {
    "ROUTER": "Routers",
    "SWITCH_AND_HUB": "Switches and Hubs",
    "WIRELESS_CONTROLLER": "Wireless Controller",
    "UNIFIED_AP": "Unified AP",
}
CLIENTS = {"WIRED_CLIENT": "wired client", "WIRELESS_CLIENT": "wireless client"}

_FABRIC_STATE_KPIS = (
    "bgpEvpnThreshold",
    "lispTransitConnScoreThreshold",
    "pubsubSessionThreshold",
    "pubsubTransitSessionScoreThreshold",
    "pubsubInfraVNSessionScoreThreshold",
    "fpcLinkScoreThreshold",
    "infraLinkAvailabilityThreshold",
    "defaultRouteThreshold",
    "bgpBgpSiteThreshold",
    "bgpPeerThreshold",
    "fwConnThreshold",
    "vniStatusThreshold",
    "peerThreshold",
    "bgpPubsubSiteThreshold",
    "bgpTcpThreshold",
    "bgpPeerInfraVnThreshold",
    "ctsEnvDataThreshold",
    "remoteRouteThreshold",
    "lispCpConnScoreThreshold",
    "multicastRPReachability",
    "fabricReachability",
)
_WIRED = {
    **dict.fromkeys(_FABRIC_STATE_KPIS, 0.0),
    "linkUtilizationThreshold": 90.0,
    "cpuUtilizationThreshold": 95.0,
    "memoryUtilizationThreshold": 95.0,
    "linkDiscardThreshold": 10.0,
    "linkErrorThreshold": 1.0,
}
# Factory thresholds on 3.2.2 (lab appliance, 2026-10-28; includeForOverallHealth true and
# synchronizeToIssueThreshold false on every row).
FACTORY: dict[str, dict[str, float]] = {
    "ROUTER": dict(_WIRED),
    "SWITCH_AND_HUB": {
        **{k: v for k, v in _WIRED.items() if k != "linkUtilizationThreshold"},
        "aaaServerReachability": 0.0,
    },
    "UNIFIED_AP": {
        "cpuUtilizationThreshold": 90.0,
        "memoryUtilizationThreshold": 90.0,
        "linkErrorThreshold": 1.0,
        "rf_airQuality_2_4GThreshold": 60.0,
        "rf_airQuality_5GThreshold": 75.0,
        "rf_airQuality_6GThreshold": 75.0,
        "rf_interference_2_4GThreshold": 50.0,
        "rf_interference_5GThreshold": 20.0,
        "rf_interference_6GThreshold": 20.0,
        "rf_utilization_2_4GThreshold": 70.0,
        "rf_utilization_5GThreshold": 70.0,
        "rf_utilization_6GThreshold": 70.0,
        "rf_noise_2_4GThreshold": -81.0,
        "rf_noise_5GThreshold": -83.0,
        "rf_noise_6GThreshold": -83.0,
    },
    "WIRELESS_CONTROLLER": {
        "memoryUtilizationThreshold": 95.0,
        "packetPool": 0.0,
        "WQEPool": 0.0,
        "freeMbufThreshold": 20.0,
        "freeTimerThreshold": 20.0,
        "fabricReachability": 0.0,
        "linkErrorThreshold": 1.0,
        "lispCpConnScoreThreshold": 0.0,
    },
    "WIRED_CLIENT": {"linkErrorThreshold": 1.0},
    "WIRELESS_CLIENT": {"snrThreshold": 9.0, "rssiThreshold": -72.0},
}


def factory_threshold(d: dict[str, Any]) -> float | None:
    return FACTORY.get(str(d.get("deviceFamily")), {}).get(str(d.get("name")))


def row(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": d.get("name"),
        "display_name": d.get("displayName"),
        "device_family": d.get("deviceFamily"),
        "threshold": d.get("thresholdValue"),
        "include_for_overall": d.get("includeForOverallHealth"),
        "sync_to_issue": d.get("synchronizeToIssueThreshold"),
        "status": d.get("definitionStatus"),
        "last_modified": d.get("lastModified"),
        "id": d.get("id"),
    }
    if d.get("description") and d.get("description") != d.get("displayName"):
        out["description"] = d["description"]
    factory = factory_threshold(d)
    if factory is not None and d.get("thresholdValue") is not None and d["thresholdValue"] != factory:
        out["factory_threshold"] = factory
    return {k: v for k, v in out.items() if v is not None}


def _matches(d: dict[str, Any], search: str) -> bool:
    s = search.lower()
    return any(s in str(d.get(k) or "").lower() for k in ("name", "displayName", "description"))


class DefinitionChange(BaseModel):
    """One KPI of one device family and what to change on it."""

    name: str = Field(
        min_length=1,
        description="KPI name (e.g. cpuUtilizationThreshold), display name, or the definition id",
    )
    device_family: Family | None = Field(
        None, description=f"{FAMILY_TEXT} (required with a name: one KPI exists per family)"
    )
    threshold: float | None = Field(
        None, description="New threshold, same unit as listed (e.g. 85 for CPU %; dBm for RSSI)"
    )
    include_for_overall: bool | None = Field(
        None, description="false: the KPI no longer pulls the overall health score down"
    )
    sync_to_issue: bool | None = Field(
        None, description="true: follow the matching issue definition's threshold instead of its own"
    )


async def _all(app: CatcApp, params: dict[str, Any] | None = None) -> Page:
    return await fetch_all(app.pager, app.api, PATH, params or {}, cap=2000)


async def find_definition(
    app: CatcApp, name: str, family: str | None, everything: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    key = name.strip()
    if is_uuid(key):
        data = await app.api.get(f"{PATH}/{safe_id(key, 'health score definition id')}")
        got = data.get("response") if isinstance(data, dict) else None
        if isinstance(got, list):  # the spec types the one-row answer as a list
            got = got[0] if got else None
        if isinstance(got, dict) and got.get("id"):
            return got
        raise NotFound(f"No health score definition {key}.")
    if not family:
        raise InvalidRequest(
            f"Give device_family with {key!r}: each KPI exists once per device family ({FAMILY_TEXT})."
        )
    rows = everything if everything is not None else (await _all(app)).items
    fam = [d for d in rows if isinstance(d, dict) and d.get("deviceFamily") == family]
    hit = [d for d in fam if d.get("name") == key] or [
        d for d in fam if str(d.get("displayName") or "").lower() == key.lower()
    ]
    if len(hit) == 1:
        return hit[0]
    if len(hit) > 1:
        raise InvalidRequest(f"{len(hit)} {family} definitions match {key!r}: give the name or id.")
    near = [str(d.get("name")) for d in fam if _matches(d, key)][:10]
    hint = (
        f" Close: {', '.join(near)}."
        if near
        else f" List them with catc_list_health_score_definitions(device_family='{family}')."
    )
    raise NotFound(f"No {family} health score definition named {key!r}.{hint}")


async def family_reach(app: CatcApp, family: str) -> str:
    """Blast radius of one family's change, in words, counted from inventory."""
    if family in CLIENTS:
        return f"every {CLIENTS[family]}'s health score"
    inv = INVENTORY_FAMILY.get(family)
    if not inv:
        return f"every {family} device"
    page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/network-device", {"family": inv}, cap=5000)
    n = len([d for d in page.items if isinstance(d, dict)])
    more = "+" if not page.complete else ""
    return f"{n}{more} device(s) in inventory with family '{inv}'"


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List health score definitions")
    async def catc_list_health_score_definitions(
        ctx: Context,
        device_family: Annotated[Family | None, Field(description=f"Only this family: {FAMILY_TEXT}")] = None,
        include_for_overall: Annotated[
            bool | None,
            Field(description="Only KPIs counted in (true) or left out of (false) the overall health score"),
        ] = None,
        search: Annotated[
            str | None, Field(description="Text in the KPI name or display name (e.g. 'cpu', 'rssi')")
        ] = None,
        modified_only: Annotated[bool, Field(description="Only KPIs changed from the default")] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Assurance health score settings: per device family (router, switch, WLC, AP, wired and wireless
        client) each KPI behind the health score, its threshold (e.g. router CPU 95%), whether it counts
        towards overall health, whether it follows the issue threshold, and DEFAULT or MODIFIED (with the
        factory threshold beside a changed one). Answers "why is this router 'poor' at 90% CPU?" and "what
        did we tune?". Change them with catc_update_health_score_definition."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if device_family:
            params["deviceType"] = device_family
        if include_for_overall is not None:
            params["includeForOverallHealth"] = str(include_for_overall).lower()
        everything = await _all(app, params)
        rows = [
            d
            for d in everything.items
            if isinstance(d, dict)
            and (not search or _matches(d, search))
            and (not modified_only or d.get("definitionStatus") == "MODIFIED")
            and (not device_family or d.get("deviceFamily") == device_family)
        ]
        rows.sort(key=lambda d: (str(d.get("deviceFamily")), str(d.get("name"))))
        page = Page(items=[row(d) for d in rows[offset : offset + limit]], offset=offset, total=len(rows))
        extra: dict[str, Any] = {}
        modified = sum(1 for d in rows if d.get("definitionStatus") == "MODIFIED")
        extra["modified"] = modified
        if not page.items and offset == 0:
            extra["note"] = "No health score definitions match."
        cols = ["device_family", "name", "threshold", "include_for_overall", "sync_to_issue", "status"]
        return list_result(page, fmt=response_format, columns=cols, extra=extra)

    @reg.write(title="Update health score definitions")
    async def catc_update_health_score_definition(
        ctx: Context,
        definitions: Annotated[
            list[DefinitionChange],
            Field(
                min_length=1,
                max_length=100,
                description="KPIs to change: [{name, device_family, threshold?, include_for_overall?, "
                "sync_to_issue?}]",
            ),
        ],
        reset_to_default: Annotated[
            bool,
            Field(
                description="Put the listed KPIs back to the factory values (threshold, counted in overall "
                "health, own threshold); give only name and device_family then"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Tune Assurance health scores to the customer's standard: change a KPI's threshold per device
        family (router CPU 95% -> 85%), leave a KPI out of overall health, or tie it to the issue threshold;
        reset_to_default puts KPIs back. One KPI is a PUT, several one bulk update. Preview-first: before
        and after per KPI and the blast radius (how many inventory devices of each family get re-scored).
        No device configuration changes; scores move from the next evaluation."""
        app: CatcApp = get_client(ctx)
        everything = [d for d in (await _all(app)).items if isinstance(d, dict)]
        blockers: list[str] = []
        warnings: list[str] = []
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for change in definitions:
            given = {
                k: v
                for k, v in (
                    ("threshold", change.threshold),
                    ("include_for_overall", change.include_for_overall),
                    ("sync_to_issue", change.sync_to_issue),
                )
                if v is not None
            }
            if reset_to_default and given:
                raise InvalidRequest(
                    f"{change.name}: reset_to_default takes only name and device_family "
                    f"(drop {', '.join(given)})."
                )
            if not reset_to_default and not given:
                raise InvalidRequest(
                    f"{change.name}: nothing to change; give threshold, include_for_overall or "
                    "sync_to_issue (or reset_to_default=true)."
                )
            d = await find_definition(app, change.name, change.device_family, everything)
            did = str(d.get("id"))
            label = f"{d.get('deviceFamily')} {d.get('name')}"
            if did in seen:
                raise InvalidRequest(f"{label} is listed twice.")
            seen.add(did)
            current = {
                "thresholdValue": d.get("thresholdValue"),
                "includeForOverallHealth": d.get("includeForOverallHealth"),
                "synchronizeToIssueThreshold": d.get("synchronizeToIssueThreshold"),
            }
            if reset_to_default:
                factory = factory_threshold(d)
                if factory is None:
                    blockers.append(
                        f"{label}: no recorded factory threshold for this KPI; set it with threshold= "
                        "instead."
                    )
                    factory = d.get("thresholdValue")
                new = {
                    "thresholdValue": factory,
                    "includeForOverallHealth": True,
                    "synchronizeToIssueThreshold": False,
                }
            else:
                new = {
                    "thresholdValue": current["thresholdValue"]
                    if change.threshold is None
                    else change.threshold,
                    "includeForOverallHealth": (
                        current["includeForOverallHealth"]
                        if change.include_for_overall is None
                        else change.include_for_overall
                    ),
                    "synchronizeToIssueThreshold": (
                        current["synchronizeToIssueThreshold"]
                        if change.sync_to_issue is None
                        else change.sync_to_issue
                    ),
                }
            if change.threshold is not None:
                if "Utilization" in str(d.get("name")) and not 0 <= change.threshold <= 100:
                    blockers.append(f"{label}: a utilization threshold is a percentage (0-100).")
                if factory_threshold(d) == 0.0:
                    warnings.append(
                        f"{label} is a state KPI (factory threshold 0: up/down, reachable or not); a numeric "
                        "threshold may have no effect."
                    )
            if new["synchronizeToIssueThreshold"] and change.threshold is not None:
                warnings.append(
                    f"{label}: with sync_to_issue on, the issue definition's threshold applies, "
                    f"not {change.threshold}."
                )
            body = {k: v for k, v in new.items() if v is not None}
            before, after = row(d), row({**d, **body})
            keys = ("threshold", "include_for_overall", "sync_to_issue")
            changes = {
                k: {"from": before.get(k), "to": after.get(k)} for k in keys if before.get(k) != after.get(k)
            }
            if not changes:
                blockers.append(f"{label} already has these values; nothing would change.")
            items.append(
                {"d": d, "id": did, "label": label, "body": body, "changes": changes, "before": before}
            )
        families = sorted({str(i["d"].get("deviceFamily")) for i in items})
        reach = {fam: await family_reach(app, fam) for fam in families}
        per_kpi = [
            {
                "kpi": i["label"],
                "display_name": i["d"].get("displayName"),
                "changes": i["changes"],
                "status": {
                    "from": i["d"].get("definitionStatus"),
                    "to": "DEFAULT" if reset_to_default else "MODIFIED",
                },
            }
            for i in items
        ]
        if len(items) == 1:
            only = items[0]
            method, path = "PUT", f"{PATH}/{only['id']}"
            payload: Any = only["body"]
        else:
            method, path = "POST", f"{PATH}/bulkUpdate"
            payload = [{"id": i["id"], **i["body"]} for i in items]
        side_effects = [f"{fam}: re-scores {reach[fam]}." for fam in families]
        if any(i["changes"].get("include_for_overall", {}).get("to") is False for i in items):
            side_effects.append(
                "A KPI left out of overall health no longer pulls the device's score down: a device poor "
                "only on that KPI shows healthy, and 'poor device' lists shrink."
            )
        side_effects.append(
            "Health scores and poor/fair/good counts move from the next evaluation (about 5 minutes); past "
            "scores stay. Issue definitions are separate (catc_update_issue_definition). No device "
            "configuration changes."
        )
        side_effects.extend(warnings)
        what = "Reset" if reset_to_default else "Update"
        plan = Plan(
            f"{what} {len(items)} health score definition(s): {', '.join(i['label'] for i in items[:5])}"
            + (" ..." if len(items) > 5 else ""),
            details={
                "definitions": per_kpi,
                "blast_radius": reach,
                "method": method,
                "path": path,
                "body": payload,
            },
            side_effects=side_effects,
            fingerprint={
                "current": {
                    i["id"]: {k: i["d"].get(k) for k in sorted(i["d"]) if k != "lastModified"} for i in items
                }
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            if len(items) == 1:
                data = await app.api.put(
                    f"{PATH}/{safe_id(items[0]['id'], 'health score definition id')}", json=payload
                )
                got = ensure_list(data.get("response") if isinstance(data, dict) else None)
            else:
                data = await app.api.post(f"{PATH}/bulkUpdate", json=payload)
                got = ensure_list(data.get("response") if isinstance(data, dict) else None)
            updated = [row(g) for g in got if isinstance(g, dict) and g.get("id")]
            if not updated:
                updated = [row({**i["d"], **i["body"]}) for i in items]
            return {"updated": updated}

        return await preview_or_apply(
            ctx,
            tool="catc_update_health_score_definition",
            args={
                "definitions": [c.model_dump() for c in definitions],
                "reset_to_default": reset_to_default,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
