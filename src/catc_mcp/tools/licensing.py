"""Licensing (roadmap D55), read-only: the appliance licence, the Smart Account and the device licences.

`catc_license_summary` answers renewal and audit questions in one call:
- the appliance's own licence (GET /dna/system/api/v1/license/status): registration with Cisco Smart
  Software Manager (CSSM), authorization (or the evaluation period and when it ends) and the entitlements;
- the Smart Accounts Catalyst Center knows (GET /dna/intent/api/v1/licenses/smartAccounts);
- the device licence summary (GET /dna/intent/api/v1/networkDeviceLicenses/summary: consumed Network, DNA
  and CNS Essentials/Advantage, unregistered, out-of-compliance, expired and expiring devices), plus a scan
  of the device licence records that names the devices whose licences expired or expire soon;
- licence usage from CSSM (GET /dna/intent/api/v1/licenseUsage: purchased, used, available per product
  family and licence type).

An appliance that was never registered with a Smart Account is a normal lab and PoC state, not an error: the
summary says so (and that CSSM usage counts need the registration). On the 3.2.2 lab appliance (2026-10-28)
license/status answered UNREGISTERED / IN_EVALUATION_PERIOD with an `evaluationRemainderTimestamp` in epoch
seconds (the spec says milliseconds; both are read), smartAccounts and licenseUsage answered empty lists, and
license/lastOperationStatus answered 404 "No operation data found" (not read here).

`catc_list_device_licenses` lists the device licence records through
POST /dna/intent/api/v1/networkDeviceLicenses/query (filters on hostname, family, site, registration and
authorization status, licence mode, or raw {key, operator, value} filters passed through) with the total from
POST .../query/count.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
)
from catc_mcp._core.http import Page, fetch_all
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, gather_sections, pick

STATUS = "/dna/system/api/v1/license/status"
SMART_ACCOUNTS = "/dna/intent/api/v1/licenses/smartAccounts"
DEVICE_SUMMARY = "/dna/intent/api/v1/networkDeviceLicenses/summary"
DEVICES = "/dna/intent/api/v1/networkDeviceLicenses"
QUERY = "/dna/intent/api/v1/networkDeviceLicenses/query"
USAGE = "/dna/intent/api/v1/licenseUsage"
DEVICE_SCAN = 5000  # device licence records read by the summary
MAX_LISTED = 100  # expired / expiring devices named by the summary
MAX_FILTERS = 20  # the spec: total filter criteria should not exceed 20

# Licence statuses (networkDeviceLicenses licenses[].status) and device authorization statuses that mean
# the licence has run out or is not covered.
EXPIRED_LICENCE = {"EXPIRED_IN_USE", "EXPIRED_NOT_IN_USE", "OUT_OF_COMPLIANCE"}
EXPIRED_AUTH = {"EVALUATION_EXPIRED", "AUTHORIZATION_EXPIRED", "OUT_OF_COMPLIANCE", "NOT_AUTHORIZED"}

Family = Literal["ROUTERS", "SWITCHES_AND_HUBS", "WIRELESS_CONTROLLER", "UNIFIED_AP"]
Registration = Literal[
    "REGISTERED",
    "UNREGISTERED",
    "REGISTRATION_EXPIRED",
    "RESERVATION_IN_PROGRESS",
    "REGISTERED_SLR",
    "REGISTERED_PLR",
    "REGISTERED_SATELLITE",
    "NA",
    "UNKNOWN",
]
Authorization = Literal[
    "AUTHORIZED",
    "EVALUATION_MODE",
    "OUT_OF_COMPLIANCE",
    "EVALUATION_EXPIRED",
    "AUTHORIZATION_EXPIRED",
    "NOT_AUTHORIZED",
    "AUTHORIZED_RESERVED",
    "NA",
    "UNKNOWN",
]
SortBy = Literal[
    "id",
    "hostname",
    "family",
    "series",
    "licenseMode",
    "registrationStatus",
    "authorizationStatus",
    "smartAccountId",
    "virtualAccountId",
    "authCodeStatus",
]
OPERATORS = ("eq", "contains", "in", "lt", "gt", "lte", "gte")

UNREGISTERED_NOTE = (
    "Catalyst Center is not registered with a Cisco Smart Account (CSSM): the appliance licence runs in "
    "evaluation and CSSM usage counts (purchased / available) are not available. Register it under System > "
    "Licensing > Smart Account (a lab or PoC appliance usually is not)."
)


def as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def epoch_seconds(v: Any) -> float | None:
    """Epoch seconds from a Catalyst Center timestamp in milliseconds or seconds (3.2.2 sends both)."""
    if isinstance(v, bool) or not isinstance(v, int | float) or v <= 0:
        return None
    return v / 1000 if v > 100_000_000_000 else float(v)


def iso(sec: float) -> str:
    return datetime.fromtimestamp(sec, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_left(sec: float, now: float) -> int:
    return int((sec - now) // 86400)


def appliance(lic: dict[str, Any], now: float) -> dict[str, Any]:
    """The appliance licence in plain fields: registration, authorization, evaluation end, entitlements."""
    reg = as_dict(lic.get("registrationStatus"))
    auth = as_dict(lic.get("authorizationStatus"))
    out: dict[str, Any] = {
        "registration": reg.get("status"),
        "authorization": auth.get("status"),
    }
    for key, src, field in (
        ("evaluation_ends", auth, "evaluationRemainderTimestamp"),
        ("authorization_expires", auth, "expiryTimestamp"),
        ("registration_expires", reg, "expiryTimestamp"),
    ):
        sec = epoch_seconds(src.get(field))
        if sec is not None:
            out[key] = iso(sec)
            out[f"{key.rsplit('_', 1)[0]}_days_left"] = days_left(sec, now)
    for key, src in (("registration_failure", reg), ("authorization_failure", auth)):
        if src.get("lastAttemptFailReason"):
            out[key] = src["lastAttemptFailReason"]
    out.update(
        {
            k: lic[k]
            for k in ("smartAccountId", "virtualAccountId", "exportControl")
            if lic.get(k) not in (None, "")
        }
    )
    ents = []
    for e in ensure_list(lic.get("entitlements")):
        if isinstance(e, dict):
            row = pick(e, ["description", "status", "usageCount"])
            if e.get("tag") and e.get("tag") != e.get("description"):
                row["tag"] = e["tag"]
            ents.append(row)
    out["entitlements"] = ents
    return out


def earliest_expiry(rec: dict[str, Any]) -> float | None:
    """The soonest evaluation expiry among a device record's licences (epoch seconds)."""
    times = [
        sec
        for x in ensure_list(rec.get("licenses"))
        if isinstance(x, dict) and (sec := epoch_seconds(x.get("evaluationExpiryTime"))) is not None
    ]
    return min(times) if times else None


def device_row(rec: dict[str, Any], now: float) -> dict[str, Any]:
    """One device licence record, flattened: who, where, status, licences and the soonest expiry."""
    row: dict[str, Any] = {
        "hostname": rec.get("hostname"),
        "address": rec.get("managementAddress"),
        "family": rec.get("family"),
        "site": rec.get("siteHierarchy"),
        "registration": rec.get("registrationStatus"),
        "authorization": rec.get("authorizationStatus"),
        "mode": rec.get("licenseMode"),
        "licenses": ", ".join(
            f"{x.get('type')}{'/' + str(x['name']) if x.get('name') not in (None, '', 'Unknown') else ''}"
            f" ({x.get('status')})"
            for x in ensure_list(rec.get("licenses"))
            if isinstance(x, dict)
        ),
    }
    sec = earliest_expiry(rec)
    if sec is not None:
        row["expires"] = iso(sec)
        row["days_left"] = days_left(sec, now)
    if rec.get("authCodeStatus") not in (None, "", "NA"):
        row["hsec_auth_code"] = rec["authCodeStatus"]
    row["id"] = rec.get("id")
    return {k: v for k, v in row.items() if v not in (None, "")}


def expired(rec: dict[str, Any], now: float) -> bool:
    if str(rec.get("authorizationStatus")) in EXPIRED_AUTH:
        return True
    if any(
        isinstance(x, dict) and str(x.get("status")) in EXPIRED_LICENCE
        for x in ensure_list(rec.get("licenses"))
    ):
        return True
    sec = earliest_expiry(rec)
    return sec is not None and sec <= now


def usage_rows(data: Any) -> list[dict[str, Any]]:
    """licenseUsage flattened: one row per account, product family and licence type."""
    rows = []
    for acct in ensure_list(data):
        if not isinstance(acct, dict):
            continue
        for fam in ensure_list(acct.get("licenseCountsSummary")):
            if not isinstance(fam, dict):
                continue
            for lic in ensure_list(fam.get("licenses")):
                if not isinstance(lic, dict):
                    continue
                counts = as_dict(lic.get("counts"))
                row = {
                    "smart_account": acct.get("smartAccountId"),
                    "virtual_account": acct.get("virtualAccountId"),
                    "family": fam.get("productFamily"),
                    "type": lic.get("type"),
                    "purchased": counts.get("purchased"),
                    "used": counts.get("used"),
                    "available": counts.get("available"),
                    "used_by_managed_devices": counts.get("usedByManagedNetworkDevices"),
                }
                rows.append({k: v for k, v in row.items() if v is not None})
    return rows


def query_filter(
    *,
    hostname: str | None,
    family: str | None,
    site: str | None,
    registration_status: str | None,
    authorization_status: str | None,
    license_mode: str | None,
    filters: list[dict[str, Any]] | None,
    logical_operator: str,
) -> dict[str, Any] | None:
    """The `filter` object of networkDeviceLicenses/query, or None when nothing filters."""
    items: list[dict[str, Any]] = []
    for key, op, value in (
        ("hostname", "contains", hostname),
        ("family", "eq", family),
        ("siteHierarchy", "contains", site),
        ("registrationStatus", "eq", registration_status),
        ("authorizationStatus", "eq", authorization_status),
        ("licenseMode", "eq", license_mode),
    ):
        if value:
            items.append({"key": key, "operator": op, "value": value})
    for f in filters or []:
        if not isinstance(f, dict) or not f.get("key") or "value" not in f:
            raise InvalidRequest("Each filter needs a `key`, an `operator` and a `value`.")
        op = str(f.get("operator") or "eq")
        if op not in OPERATORS:
            raise InvalidRequest(f"Unknown filter operator {op!r}: use one of {', '.join(OPERATORS)}.")
        if op == "in" and not isinstance(f["value"], list):
            raise InvalidRequest(f"The 'in' operator takes a list of values (filter on {f['key']}).")
        items.append({"key": str(f["key"]), "operator": op, "value": f["value"]})
    if not items:
        return None
    if len(items) > MAX_FILTERS:
        raise InvalidRequest(f"At most {MAX_FILTERS} filter criteria per query (got {len(items)}).")
    return {"filters": items, "logicalOperator": logical_operator}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Licensing summary")
    async def catc_license_summary(
        ctx: Context,
        expiring_days: Annotated[
            int, Field(ge=1, le=365, description="Name devices whose licences expire within this many days")
        ] = 30,
    ) -> ToolResult:
        """Licensing in one call, for renewal and audit questions: the appliance licence (Smart Account
        registration, authorization or evaluation and when it ends, entitlements), the Smart Accounts, the
        device licence summary (Network / DNA / CNS Essentials and Advantage consumed; unregistered,
        out-of-compliance, expired and expiring device counts; devices by registration and authorization
        status) with the devices whose licences expired or expire within `expiring_days`, and licence usage
        from CSSM (purchased, used, available per product family and type). An appliance never registered
        with a Smart Account is reported as such, not as an error. Read-only; catc_list_device_licenses
        lists and filters the device records."""
        app: CatcApp = get_client(ctx)
        now = time.time()
        data, errors = await gather_sections(
            {
                "license": app.get_response(STATUS),
                "smart_accounts": app.get_response(SMART_ACCOUNTS),
                "device_summary": app.get_response(DEVICE_SUMMARY),
                "devices": fetch_all(app.pager, app.api, DEVICES, cap=DEVICE_SCAN),
                "usage": app.get_response(USAGE),
            }
        )
        out: dict[str, Any] = {}
        lic = data.get("license")
        registered: bool | None = None
        if isinstance(lic, dict):
            out["appliance"] = appliance(lic, now)
            reg_status = out["appliance"].get("registration")
            registered = str(reg_status).upper() == "REGISTERED" if reg_status else None
        if "smart_accounts" in data:
            accounts = [
                pick(a, ["name", "domain", "id", "is_active_smart_account"])
                for a in ensure_list(data["smart_accounts"])
                if isinstance(a, dict)
            ]
            sa: dict[str, Any] = {
                "registered": bool(registered) if registered is not None else bool(accounts)
            }
            if accounts:
                sa["accounts"] = accounts
            if not sa["registered"]:
                sa["note"] = UNREGISTERED_NOTE
            out["smart_account"] = sa
        elif registered is False:
            out["smart_account"] = {"registered": False, "note": UNREGISTERED_NOTE}

        devices: dict[str, Any] = {}
        summary = data.get("device_summary")
        if isinstance(summary, dict):
            consumed = summary.get("networkDeviceLicenseSummary")
            if isinstance(consumed, dict):
                devices["consumed"] = {
                    name.removesuffix("LicenseSummary"): pick(v, ["essentialCount", "advantageCount"])
                    for name, v in consumed.items()
                    if isinstance(v, dict)
                }
            devices.update(
                {
                    out_key: summary[k]
                    for out_key, k in (
                        ("unregistered", "unregisteredNetworkDeviceCount"),
                        ("out_of_compliance", "outOfComplianceNetworkDeviceCount"),
                        ("expired", "expiredNetworkDeviceLicenseCount"),
                        ("expiring_30_days", "expiringNetworkDeviceLicenseCount"),
                    )
                    if summary.get(k) is not None
                }
            )
        scan = data.get("devices")
        if isinstance(scan, Page):
            recs = [r for r in scan.items if isinstance(r, dict)]
            devices["records"] = len(recs)
            devices["by_registration"] = dict(Counter(str(r.get("registrationStatus") or "?") for r in recs))
            devices["by_authorization"] = dict(
                Counter(str(r.get("authorizationStatus") or "?") for r in recs)
            )
            gone = [r for r in recs if expired(r, now)]
            gone_ids = {id(r) for r in gone}
            horizon = now + expiring_days * 86400
            soon = [
                r
                for r in recs
                if id(r) not in gone_ids and (sec := earliest_expiry(r)) is not None and sec <= horizon
            ]
            soon.sort(key=lambda r: earliest_expiry(r) or 0)
            devices["expired_devices"] = [device_row(r, now) for r in gone[:MAX_LISTED]] or "none"
            devices[f"expiring_within_{expiring_days}_days"] = [
                device_row(r, now) for r in soon[:MAX_LISTED]
            ] or "none"
            if not scan.complete:
                devices["scan"] = f"Read the first {DEVICE_SCAN} device licence records only."
        if devices:
            out["devices"] = devices

        if "usage" in data:
            rows = usage_rows(data["usage"])
            out["usage"] = rows or (
                "No licence usage from CSSM"
                + (" (the appliance is not registered with a Smart Account)." if registered is False else ".")
            )
        if errors:
            out["unavailable"] = errors
        return object_result(out)

    @reg.read(title="List device licences")
    async def catc_list_device_licenses(
        ctx: Context,
        hostname: Annotated[str | None, Field(description="Hostname contains this text")] = None,
        family: Annotated[Family | None, Field(description="Product family")] = None,
        site: Annotated[
            str | None, Field(description="Site hierarchy contains this text (e.g. 'Global/AU/SYD-1')")
        ] = None,
        registration_status: Annotated[
            Registration | None, Field(description="Smart Licensing registration status")
        ] = None,
        authorization_status: Annotated[
            Authorization | None, Field(description="Smart Licensing authorization status")
        ] = None,
        license_mode: Annotated[
            Literal["SMART_LICENSE", "RIGHT_TO_USE", "UNKNOWN"] | None, Field(description="Licence mode")
        ] = None,
        filters: Annotated[
            list[dict[str, Any]] | None,
            Field(
                description="Extra filter criteria passed through to networkDeviceLicenses/query, each "
                "{key, operator, value} (operator eq, contains, in, lt, gt, lte, gte; 'in' takes a list), "
                "e.g. [{'key': 'authCodeStatus', 'operator': 'eq', 'value': 'INSTALLED'}]"
            ),
        ] = None,
        logical_operator: Annotated[
            Literal["AND", "OR"], Field(description="Combine the filter criteria with AND (default) or OR")
        ] = "AND",
        sort_by: Annotated[SortBy, Field(description="Sort field")] = "hostname",
        order: Annotated[Literal["asc", "desc"], Field(description="Sort order")] = "asc",
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Device licence records (networkDeviceLicenses/query): per device its hostname, address, family,
        site, Smart Licensing registration and authorization status, licence mode, the licences on it
        (type, name and status) and the soonest evaluation expiry with days left. Filter by hostname, family,
        site, registration or authorization status and licence mode, or pass raw {key, operator, value}
        filters. Read-only; catc_license_summary gives the totals and the expiring devices."""
        app: CatcApp = get_client(ctx)
        flt = query_filter(
            hostname=hostname,
            family=family,
            site=site,
            registration_status=registration_status,
            authorization_status=authorization_status,
            license_mode=license_mode,
            filters=filters,
            logical_operator=logical_operator,
        )
        body: dict[str, Any] = {
            # Catalyst Center counts the page offset from 1.
            "page": {"limit": limit, "offset": offset + 1, "sortBy": {"name": sort_by, "order": order}}
        }
        count_body: dict[str, Any] = {}
        if flt:
            body["filter"] = flt
            count_body["filter"] = flt
        resp = await app.api.post(QUERY, body)
        # The total is a second query: when only it fails, the page still comes back.
        data, errors = await gather_sections({"count": app.api.post(f"{QUERY}/count", count_body)})
        now = time.time()
        recs = ensure_list(resp.get("response") if isinstance(resp, dict) else resp)
        rows = [device_row(r, now) for r in recs if isinstance(r, dict)]
        cnt = data.get("count")
        total = None
        if isinstance(cnt, dict):
            inner = cnt.get("response")
            total = inner.get("count") if isinstance(inner, dict) else inner
        page = Page(
            rows,
            offset,
            total if isinstance(total, int) else None,
            more=not isinstance(total, int) and len(rows) == limit,
        )
        extra: dict[str, Any] = {}
        if flt:
            extra["filter"] = flt
        if errors:
            extra["unavailable"] = errors
        return list_result(
            page,
            fmt=response_format,
            columns=[
                "hostname",
                "address",
                "family",
                "site",
                "registration",
                "authorization",
                "mode",
                "licenses",
                "expires",
                "days_left",
            ],
            extra=extra or None,
        )
