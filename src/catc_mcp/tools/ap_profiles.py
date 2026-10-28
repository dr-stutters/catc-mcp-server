"""AP join profiles and AP power profiles (roadmap D127): the site-based wireless design objects behind a
Catalyst 9800's `ap profile` and `ap power-profile`.

- catc_list_ap_profiles: every AP profile (management SSH/Telnet and credentials, the AP's 802.1X
  supplicant, CDP, rogue detection, country, time zone, power profile) with the wireless profile site tags
  that use it, plus the AP power profiles
- catc_set_ap_profile: create, update or delete an AP profile (write tier; passwords masked)
- catc_set_ap_power_profile: create, update or delete an AP power profile (ordered rules that turn down
  Ethernet speed, radio spatial streams or the USB port when PoE is short)

These are design objects: nothing reaches a WLC until a wireless profile's site tag names the AP profile
(`/wirelessProfiles/{id}/siteTags`, apProfileName) and the WLC is re-provisioned
(catc_provision_wireless_controller). A per-device WLC (Per-Device Configuration on) keeps its AP join
profiles in `.../intended/accessPoints/apJoinProfiles` instead (catc_get_wlc_config, catc_api_call).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import hmac
import os
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field, SecretStr

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    compact,
    get_client,
    list_result,
    object_result,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp._core.http import Page, fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list

AP_PROFILES = "/dna/intent/api/v1/wirelessSettings/apProfiles"
POWER_PROFILES = "/dna/intent/api/v1/wirelessSettings/powerProfiles"
WIRELESS_PROFILES = "/dna/intent/api/v1/wirelessProfiles"
# Per-process key: confirm tokens bind a keyed digest of each secret, never the value or a plain hash.
_DIGEST_KEY = os.urandom(32)
# The two profiles every Catalyst Center has (live 3.2.2): they cannot be deleted.
DEFAULT_PROFILES = frozenset({"Default_AP_Profile_AireOS", "default-ap-profile"})
# Write-only fields: Catalyst Center returns them empty or null, never the value.
SECRETS = ("managementPassword", "managementEnablePassword", "dot1xPassword")
# Country codes the 3.2.2 request schema accepts (its countryCode pattern).
_COUNTRY_PATTERN = (
    "AF|AE|AL|AR|AT|AO|AU|BD|BA|BB|BE|BG|BH|BM|BN|BO|BR|BT|BY|CA|CD|CH|CI|CL|CM|CN|CO|CR|CU|CY|CZ|DE|DK|"
    "DO|DZ|EC|EE|EG|EL|ES|ET|FI|FJ|FR|GB|GH|GI|GE|GR|GT|HK|HN|HR|HU|ID|IE|IL|IN|IQ|IS|IT|J2|J4|JM|JO|KE|"
    "KH|KN|KW|KZ|LA|LB|LI|LK|LT|LU|LV|LY|MA|MC|MD|ME|MK|MN|MM|MO|MT|MX|MY|NG|NI|NL|NO|NP|NZ|OM|PA|PE|PH|"
    "PK|PL|PR|PT|PY|QA|RO|RS|RU|SA|SD|SE|SG|SI|SK|SM|TH|TI|TN|TR|TW|TZ|UA|US|UY|VA|VE|VN|XK|YE|ZA|ZW|MU|"
    "ZM|BI|NA|BW|GA|UG|UZ"
)
COUNTRIES = frozenset(re.findall(r"[A-Z0-9]{2}", _COUNTRY_PATTERN))
# The read side answers upper case ("NOT CONFIGURED", live 3.2.2); the write side takes these.
TIME_ZONES = {
    "not_configured": "Not Configured",
    "controller": "Controller",
    "delta": "Delta from Controller",
}
Supplicant = Literal["NO-AUTH", "EAP-FAST", "EAP-TLS", "EAP-PEAP"]
TimeZone = Literal["not_configured", "controller", "delta"]
REACH_WLC = (
    "A design object: no WLC changes until a wireless profile's site tag names this AP profile "
    "(wirelessProfiles/{id}/siteTags, apProfileName) and the WLC is re-provisioned "
    "(catc_provision_wireless_controller). Per-device WLCs: .../intended/accessPoints/apJoinProfiles "
    "(catc_api_call)."
)
MGMT_IMPACT = (
    "Catalyst Center: changing the 802.1X supplicant or the management credentials is service impacting "
    "for PnP-onboarded APs, which may need a factory reset to pick them up."
)
NO_SECRETS_BACK = (
    "Catalyst Center never returns the AP passwords (it shows them masked): an update sends only the "
    "passwords given here."
)
# A create with only some rogue fields gets the rest as 0 and is refused (NCND00041, live 3.2.2): the
# factory default-ap-profile's values fill in the fields not given.
ROGUE_DEFAULTS = {
    "rogueDetection": True,
    "rogueDetectionMinRssi": -90,
    "rogueDetectionReportInterval": 10,
    "rogueDetectionTransientInterval": 0,
}
MGMT_ALL_THREE = (
    "Catalyst Center takes the AP management user, password and enable password together or not at all "
    "(NCND80157): give mgmt_user, mgmt_password and mgmt_enable_password"
)

InterfaceType = Literal["ETHERNET", "RADIO", "USB"]
InterfaceId = Literal[
    "GIGABITETHERNET0",
    "GIGABITETHERNET1",
    "LAN1",
    "LAN2",
    "LAN3",
    "6GHZ",
    "5GHZ",
    "SECONDARY_5GHZ",
    "2_4GHZ",
    "USB0",
]
ParameterType = Literal["SPEED", "SPATIALSTREAM", "STATE"]
ParameterValue = Literal[
    "5000MBPS",
    "2500MBPS",
    "1000MBPS",
    "100MBPS",
    "EIGHT_BY_EIGHT",
    "FOUR_BY_FOUR",
    "THREE_BY_THREE",
    "TWO_BY_TWO",
    "ONE_BY_ONE",
    "DISABLE",
]
# Which interface ids and parameters go with each interface type (the 9800's `ap power-profile` rules).
RULE_IDS = {
    "ETHERNET": {"GIGABITETHERNET0", "GIGABITETHERNET1", "LAN1", "LAN2", "LAN3"},
    "RADIO": {"6GHZ", "5GHZ", "SECONDARY_5GHZ", "2_4GHZ"},
    "USB": {"USB0"},
}
RULE_PARAMS = {
    "ETHERNET": {"SPEED": {"5000MBPS", "2500MBPS", "1000MBPS", "100MBPS"}, "STATE": {"DISABLE"}},
    "RADIO": {
        "SPATIALSTREAM": {"EIGHT_BY_EIGHT", "FOUR_BY_FOUR", "THREE_BY_THREE", "TWO_BY_TWO", "ONE_BY_ONE"},
        "STATE": {"DISABLE"},
    },
    "USB": {"STATE": {"DISABLE"}},
}


class PowerRule(BaseModel):
    """One power profile rule, applied in list order when the AP is short of PoE."""

    interface_type: InterfaceType
    interface_id: InterfaceId
    parameter_type: ParameterType
    parameter_value: ParameterValue


def digest(secret: SecretStr | None) -> str | None:
    if secret is None:
        return None
    return hmac.new(_DIGEST_KEY, secret.get_secret_value().encode(), hashlib.sha256).hexdigest()[:16]


def masked(v: Any) -> str | None:
    return MASK if v else None


def mgmt(p: dict[str, Any]) -> dict[str, Any]:
    m = p.get("managementSetting")
    return m if isinstance(m, dict) else {}


def rogue(p: dict[str, Any]) -> dict[str, Any]:
    r = p.get("rogueDetectionSetting")
    return r if isinstance(r, dict) else {}


def ap_row(p: dict[str, Any], used_by: list[str] | None = None) -> dict[str, Any]:
    """One AP profile in plain words, secrets masked (Catalyst Center returns them empty anyway)."""
    m, r = mgmt(p), rogue(p)
    tz = p.get("timeZone")
    if str(tz).upper() == "DELTA FROM CONTROLLER":
        tz = f"{tz} ({p.get('timeZoneOffsetHour', 0):+d}:{int(p.get('timeZoneOffsetMinutes') or 0):02d})"
    row: dict[str, Any] = compact(
        {
            "name": p.get("apProfileName"),
            "description": p.get("description"),
            "ssh": m.get("sshEnabled"),
            "telnet": m.get("telnetEnabled"),
            "mgmt_user": m.get("managementUserName"),
            "mgmt_password": masked(m.get("managementPassword")),
            "mgmt_enable_password": masked(m.get("managementEnablePassword")),
            "cdp": m.get("cdpState"),
            "dot1x_supplicant": m.get("authType"),
            "dot1x_user": m.get("dot1xUsername"),
            "dot1x_password": masked(m.get("dot1xPassword")),
            "rogue_detection": r.get("rogueDetection"),
            "rogue_min_rssi": r.get("rogueDetectionMinRssi"),
            "rogue_report_interval": r.get("rogueDetectionReportInterval"),
            "rogue_transient_interval": r.get("rogueDetectionTransientInterval"),
            "country": p.get("countryCode"),
            "time_zone": tz,
            "power_profile": p.get("apPowerProfileName"),
            "calendar_power_profiles": [
                c.get("apPowerProfileName")
                for c in ensure_list(p.get("calendarPowerProfiles"))
                if isinstance(c, dict)
            ],
            "client_limit": p.get("clientLimit"),
            "mesh": p.get("meshEnabled"),
            "awips": p.get("awipsEnabled"),
            "remote_worker": p.get("remoteWorkerEnabled"),
            "id": p.get("id"),
        }
    )
    if used_by:
        row["used_by"] = used_by
    return row


def power_row(p: dict[str, Any], used_by: list[str] | None = None) -> dict[str, Any]:
    rules = sorted(
        (r for r in ensure_list(p.get("rules")) if isinstance(r, dict)),
        key=lambda r: int(r.get("sequence") or 0),
    )
    row: dict[str, Any] = compact(
        {
            "name": p.get("profileName"),
            "description": p.get("description"),
            "rules": [
                f"{r.get('interfaceType')} {r.get('interfaceId') or r.get('interfaceID')} "
                f"{r.get('parameterType')} {r.get('parameterValue')}"
                for r in rules
            ],
            "id": p.get("id"),
        }
    )
    if used_by:
        row["used_by"] = used_by
    return row


async def ap_profiles(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, AP_PROFILES, cap=2000, max_page=500, on_partial="raise")
    return [p for p in page.items if isinstance(p, dict)]


async def power_profiles(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, POWER_PROFILES, cap=2000, max_page=500, on_partial="raise")
    return [p for p in page.items if isinstance(p, dict)]


async def site_tag_usage(app: CatcApp) -> dict[str, list[str]]:
    """{AP profile name: ['<wireless profile> / <site tag>', ...]} from every wireless profile's site tags:
    where an AP profile reaches a WLC. A failed read raises, so a delete check never passes on half the
    data."""
    page = await fetch_all(app.pager, app.api, WIRELESS_PROFILES, cap=2000, on_partial="raise")
    profiles = [p for p in page.items if isinstance(p, dict) and p.get("id")]

    async def tags(p: dict[str, Any]) -> list[dict[str, Any]]:
        path = f"{WIRELESS_PROFILES}/{safe_id(str(p['id']), 'wireless profile id')}/siteTags"
        got = await fetch_all(app.pager, app.api, path, cap=2000, on_partial="raise")
        return [t for t in got.items if isinstance(t, dict)]

    out: dict[str, list[str]] = {}
    for p, rows in zip(profiles, await asyncio.gather(*(tags(p) for p in profiles)), strict=True):
        for t in rows:
            if t.get("apProfileName"):
                out.setdefault(str(t["apProfileName"]), []).append(
                    f"{p.get('wirelessProfileName')} / {t.get('siteTagName')}"
                )
    return {k: sorted(v) for k, v in out.items()}


def power_usage(aps: list[dict[str, Any]]) -> dict[str, list[str]]:
    """{power profile name: [AP profiles using it, directly or in a calendar schedule]}."""
    out: dict[str, set[str]] = {}
    for p in aps:
        names = {p.get("apPowerProfileName")} | {
            c.get("apPowerProfileName")
            for c in ensure_list(p.get("calendarPowerProfiles"))
            if isinstance(c, dict)
        }
        for n in names - {None, ""}:
            out.setdefault(str(n), set()).add(str(p.get("apProfileName")))
    return {k: sorted(v) for k, v in out.items()}


def find(items: list[dict[str, Any]], name: str, key: str) -> dict[str, Any] | None:
    found = [p for p in items if name in (p.get(key), p.get("id"))]
    return found[0] if found else None


def put_base(rec: dict[str, Any]) -> dict[str, Any]:
    """The current AP profile as a PUT body: the read-only id, empty secrets and nulls out, and the values
    the read side spells differently from the write side normalised (time zone case; 'unconfigured'
    country, which the request schema refuses, left out)."""
    body = {k: v for k, v in rec.items() if k != "id" and v is not None}
    m = {k: v for k, v in mgmt(rec).items() if v not in (None, "") and k not in SECRETS}
    if m:
        body["managementSetting"] = m
    else:
        body.pop("managementSetting", None)
    r = {k: v for k, v in rogue(rec).items() if v is not None}
    if r:
        body["rogueDetectionSetting"] = r
    tz = str(rec.get("timeZone") or "")
    body["timeZone"] = next(
        (v for v in TIME_ZONES.values() if v.upper() == tz.upper()), tz or "Not Configured"
    )
    if str(body.get("countryCode", "")).upper() not in COUNTRIES:
        body.pop("countryCode", None)
    return body


def preview_body(body: dict[str, Any], secrets: dict[str, SecretStr]) -> dict[str, Any]:
    """The request body as the preview shows it: each password given stands as the mask."""
    out = dict(body)
    if secrets:
        out["managementSetting"] = {**out.get("managementSetting", {}), **dict.fromkeys(secrets, MASK)}
    return out


def with_secrets(body: dict[str, Any], secrets: dict[str, SecretStr]) -> dict[str, Any]:
    """The request body as sent: the passwords in clear (only ever in the request)."""
    out = dict(body)
    if secrets:
        out["managementSetting"] = {
            **out.get("managementSetting", {}),
            **{k: s.get_secret_value() for k, s in secrets.items()},
        }
    return out


def flat(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out |= flat(v, f"{prefix}{k}.")
        else:
            out[f"{prefix}{k}"] = v
    return out


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """{field: {from, to}} for what the PUT changes (secrets shown masked)."""
    a, b = flat(before), flat(after)
    out: dict[str, Any] = {}
    for k, v in b.items():
        if k.split(".")[-1] in SECRETS:
            out[k] = {"from": MASK if a.get(k) else "(not returned)", "to": f"{MASK} (new)"}
        elif a.get(k) != v and not (k == "timeZone" and str(a.get(k, "")).upper() == str(v).upper()):
            out[k] = {"from": a.get(k), "to": v}
    return out


def check_password(what: str, secret: SecretStr | None, *, strong: bool = False) -> None:
    if secret is None:
        return
    v = secret.get_secret_value()
    if not 8 <= len(v) <= 120:
        raise InvalidRequest(f"{what} must be 8-120 characters.")
    if strong and not (re.search(r"[A-Z]", v) and re.search(r"[a-z]", v) and re.search(r"\d", v)):
        raise InvalidRequest(f"{what} needs an upper case letter, a lower case letter and a digit.")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List AP profiles")
    async def catc_list_ap_profiles(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="One AP profile (name or id): its full record instead of the list")
        ] = None,
        usage: Annotated[
            bool,
            Field(
                description="Look up the wireless profile site tags that use each AP profile (one read each)"
            ),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> Any:
        """AP join profiles (Design > Network Settings > Wireless > AP Profiles): per profile the AP
        management access (SSH/Telnet, user; passwords masked), the AP's 802.1X supplicant
        (EAP-FAST/TLS/PEAP, user), CDP, rogue detection and minimum RSSI, country, time zone, power profile
        and client limit, with the wireless profile site tags that carry it to a WLC. Also the AP power
        profiles and their rules."""
        app: CatcApp = get_client(ctx)
        aps, powers, count = await asyncio.gather(
            ap_profiles(app), power_profiles(app), app.get_response(f"{AP_PROFILES}/count")
        )
        used: dict[str, list[str]] = await site_tag_usage(app) if usage else {}
        pused = power_usage(aps)
        if name is not None:
            hit = find(aps, name, "apProfileName")
            if hit is None:
                names = ", ".join(sorted(str(p.get("apProfileName")) for p in aps))
                raise NotFound(f"No AP profile {name} (has: {names or 'none'}).")
            pid = safe_id(str(hit["id"]), "AP profile id")
            got = await app.get_response(f"{AP_PROFILES}/{pid}")
            rec = got.get("profile", got) if isinstance(got, dict) else hit
            rec = rec if isinstance(rec, dict) and rec else hit
            pname = rec.get("apPowerProfileName")
            power = find(powers, str(pname), "profileName") if pname else None
            out: dict[str, Any] = {
                "ap_profile": ap_row(rec, used.get(str(rec.get("apProfileName")), []) if usage else None)
            }
            if power:
                out["power_profile"] = power_row(power)
            out["note"] = REACH_WLC
            return object_result(out)
        total = count.get("count") if isinstance(count, dict) else count
        rows = [ap_row(p, used.get(str(p.get("apProfileName")), []) if usage else None) for p in aps]
        page = Page(
            items=rows[offset : offset + limit],
            offset=offset,
            total=total if isinstance(total, int) and total >= len(aps) else len(aps),
        )
        return list_result(
            page,
            fmt=response_format,
            extra={
                "power_profiles": [power_row(p, pused.get(str(p.get("profileName")), [])) for p in powers],
                "note": REACH_WLC,
            },
        )

    @reg.write(title="Set AP profile")
    async def catc_set_ap_profile(
        ctx: Context,
        name: Annotated[
            str,
            Field(min_length=1, max_length=64, description="AP profile name (1-32 characters), or its id"),
        ],
        delete: Annotated[bool, Field(description="Delete the AP profile (no other settings)")] = False,
        description: Annotated[str | None, Field(max_length=241, description="Profile description")] = None,
        ssh: Annotated[bool | None, Field(description="SSH to the APs")] = None,
        telnet: Annotated[bool | None, Field(description="Telnet to the APs")] = None,
        mgmt_user: Annotated[
            str | None, Field(min_length=1, max_length=32, description="AP management user name")
        ] = None,
        mgmt_password: Annotated[
            SecretStr | None, Field(description="AP management password, 8-120 characters (never echoed)")
        ] = None,
        mgmt_enable_password: Annotated[
            SecretStr | None,
            Field(description="AP enable password, 8-120 characters with upper, lower case and a digit"),
        ] = None,
        dot1x_supplicant: Annotated[
            Supplicant | None,
            Field(description="The AP's 802.1X supplicant on its switch port (NO-AUTH turns it off)"),
        ] = None,
        dot1x_user: Annotated[
            str | None, Field(min_length=1, max_length=32, description="802.1X supplicant user name")
        ] = None,
        dot1x_password: Annotated[
            SecretStr | None, Field(description="802.1X supplicant password, 8-120 characters (never echoed)")
        ] = None,
        cdp: Annotated[bool | None, Field(description="CDP on the APs")] = None,
        rogue_detection: Annotated[bool | None, Field(description="Rogue detection")] = None,
        rogue_min_rssi: Annotated[
            int | None, Field(ge=-128, le=-70, description="Rogue detection minimum RSSI, dBm")
        ] = None,
        rogue_report_interval: Annotated[
            int | None,
            Field(ge=10, le=300, description="Seconds between the APs' rogue reports to the WLC (10-300)"),
        ] = None,
        rogue_transient_interval: Annotated[
            int | None,
            Field(
                ge=0,
                le=1800,
                description="Seconds a rogue must be heard before it is reported: 0 (off) or 120-1800",
            ),
        ] = None,
        country: Annotated[
            str | None, Field(min_length=2, max_length=2, description="AP country code, e.g. US, GB, AU")
        ] = None,
        time_zone: Annotated[
            TimeZone | None, Field(description="AP time zone: not configured, the controller's, or a delta")
        ] = None,
        time_zone_offset_hour: Annotated[
            int | None, Field(ge=-12, le=14, description="time_zone='delta': hours from the controller")
        ] = None,
        time_zone_offset_minutes: Annotated[
            int | None, Field(ge=0, le=59, description="time_zone='delta': minutes")
        ] = None,
        power_profile: Annotated[
            str | None, Field(max_length=128, description="AP power profile name (catc_set_ap_power_profile)")
        ] = None,
        client_limit: Annotated[int | None, Field(ge=0, le=1200, description="Clients per AP")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, update or delete an AP join profile: SSH/Telnet with the AP management credentials, the
        AP's 802.1X supplicant (EAP-FAST, EAP-TLS or EAP-PEAP) for closed-auth switch ports, CDP, rogue
        detection (minimum RSSI, report and transient intervals), country, time zone and power profile.
        Only the settings given change. The management user, password and enable password go together;
        Catalyst Center never returns the passwords, so an update of a profile that has them (or an
        EAP-FAST/PEAP supplicant) takes them again. A design object: it reaches a WLC through a wireless
        profile site tag and a re-provision. Preview-first; passwords are masked and never stored."""
        app: CatcApp = get_client(ctx)
        country = country.upper() if country else None
        if country and country not in COUNTRIES:
            raise InvalidRequest(f"Catalyst Center has no country code {country}.")
        for what, s, strong in (
            ("mgmt_password", mgmt_password, False),
            ("mgmt_enable_password", mgmt_enable_password, True),
            ("dot1x_password", dot1x_password, False),
        ):
            check_password(what, s, strong=strong)
        if rogue_transient_interval is not None and 0 < rogue_transient_interval < 120:
            raise InvalidRequest("rogue_transient_interval is 0 (off) or 120-1800 seconds.")
        offsets = (time_zone_offset_hour, time_zone_offset_minutes)
        if any(o is not None for o in offsets) and time_zone != "delta":
            raise InvalidRequest("time_zone_offset_* only apply with time_zone='delta'.")
        m_fields = {
            "sshEnabled": ssh,
            "telnetEnabled": telnet,
            "managementUserName": mgmt_user,
            "cdpState": cdp,
            "authType": dot1x_supplicant,
            "dot1xUsername": dot1x_user,
        }
        m_given = {k: v for k, v in m_fields.items() if v is not None}
        r_given = {
            k: v
            for k, v in {
                "rogueDetection": rogue_detection,
                "rogueDetectionMinRssi": rogue_min_rssi,
                "rogueDetectionReportInterval": rogue_report_interval,
                "rogueDetectionTransientInterval": rogue_transient_interval,
            }.items()
            if v is not None
        }
        top: dict[str, Any] = {
            k: v
            for k, v in {
                "description": description,
                "countryCode": country,
                "apPowerProfileName": power_profile,
                "clientLimit": client_limit,
            }.items()
            if v is not None
        }
        if time_zone is not None:
            top["timeZone"] = TIME_ZONES[time_zone]
            if time_zone == "delta":
                top["timeZoneOffsetHour"] = time_zone_offset_hour or 0
                top["timeZoneOffsetMinutes"] = time_zone_offset_minutes or 0
        secrets = {
            k: s
            for k, s in (
                ("managementPassword", mgmt_password),
                ("managementEnablePassword", mgmt_enable_password),
                ("dot1xPassword", dot1x_password),
            )
            if s is not None
        }
        given = bool(m_given or r_given or top or secrets)
        aps = await ap_profiles(app)
        rec = find(aps, name, "apProfileName")
        blockers: list[str] = []
        side: list[str] = []
        details: dict[str, Any] = {}
        body: dict[str, Any] | None = None
        if delete:
            if given:
                raise InvalidRequest("delete=true takes no other settings.")
            if rec is None:
                raise NotFound(f"No AP profile {name} (catc_list_ap_profiles).")
            used = (await site_tag_usage(app)).get(str(rec.get("apProfileName")), [])
            if rec.get("apProfileName") in DEFAULT_PROFILES:
                blockers.append(
                    f"{rec.get('apProfileName')} is a default AP profile: Catalyst Center keeps it."
                )
            if used:
                blockers.append(
                    f"Site tag(s) {', '.join(used)} use {rec.get('apProfileName')}: point them at another AP "
                    "profile first."
                )
            pid = safe_id(str(rec["id"]), "AP profile id")
            method, path = "DELETE", f"{AP_PROFILES}/{pid}"
            summary = f"Delete AP profile {rec.get('apProfileName')}"
            details = {"ap_profile": ap_row(rec)}
            fingerprint: Any = {"record": rec, "used": used}
        else:
            if not given:
                raise InvalidRequest("Nothing to set: give at least one setting (or delete=true).")
            powers = await power_profiles(app)
            if power_profile and not find(powers, power_profile, "profileName"):
                have = ", ".join(sorted(str(p.get("profileName")) for p in powers)) or "none"
                blockers.append(
                    f"No AP power profile {power_profile} (has: {have}); catc_set_ap_power_profile."
                )
            if rec is None:
                if len(name) > 32:
                    blockers.append("An AP profile name is 1-32 characters.")
                m_new = dict(m_given)
                body = {"apProfileName": name, **top}
                if m_new or secrets:
                    body["managementSetting"] = m_new
                if r_given:
                    body["rogueDetectionSetting"] = {**ROGUE_DEFAULTS, **r_given}
                    filled = [k for k in ROGUE_DEFAULTS if k not in r_given]
                    if filled:
                        side.append(
                            "Rogue detection: the settings not given ("
                            + ", ".join(f"{k}={ROGUE_DEFAULTS[k]}" for k in filled)
                            + ") take the factory default-ap-profile values; Catalyst Center refuses a "
                            "partial rogueDetectionSetting."
                        )
                method, path = "POST", AP_PROFILES
                summary = f"Create AP profile {name}"
                fingerprint = {"names": sorted(str(p.get("apProfileName")) for p in aps)}
                current_m: dict[str, Any] = {}
                used = []
            else:
                pid = safe_id(str(rec["id"]), "AP profile id")
                base = put_base(rec)
                body = {**base, **top}
                if m_given or "managementSetting" in base:
                    body["managementSetting"] = {**base.get("managementSetting", {}), **m_given}
                if r_given:
                    body["rogueDetectionSetting"] = {**base.get("rogueDetectionSetting", {}), **r_given}
                method, path = "PUT", f"{AP_PROFILES}/{pid}"
                summary = f"Update AP profile {rec.get('apProfileName')}"
                current_m = mgmt(rec)
                used = (await site_tag_usage(app)).get(str(rec.get("apProfileName")), [])
                fingerprint = {"record": rec, "used": used}
                side.append(NO_SECRETS_BACK)
                if used:
                    side.append(
                        f"Used by site tag(s) {', '.join(used)}: the next provision of their WLCs pushes the "
                        "change to every AP joined with this profile."
                    )
            m_after = {**current_m, **body.get("managementSetting", {})}
            auth = m_after.get("authType") or "NO-AUTH"
            if auth != "NO-AUTH" and not m_after.get("dot1xUsername"):
                blockers.append(f"The {auth} supplicant needs dot1x_user.")
            if auth in ("EAP-FAST", "EAP-PEAP") and dot1x_password is None:
                blockers.append(
                    f"The {auth} supplicant needs dot1x_password."
                    if rec is None
                    else f"The {auth} supplicant needs dot1x_password on every update: Catalyst Center "
                    "never returns it, and refuses the update without it."
                )
            mgmt_given = {
                "mgmt_user": mgmt_user,
                "mgmt_password": mgmt_password,
                "mgmt_enable_password": mgmt_enable_password,
            }
            missing = [k for k, v in mgmt_given.items() if v is None]
            if current_m.get("managementUserName"):
                need = [k for k in ("mgmt_password", "mgmt_enable_password") if k in missing]
                if need:
                    blockers.append(
                        f"AP profile {rec.get('apProfileName') if rec else name} has management user "
                        f"{current_m.get('managementUserName')}: give {' and '.join(need)} again with any "
                        "update. Catalyst Center never returns the passwords (it shows them masked) and "
                        "refuses an update without them (NCND80157)."
                    )
            elif 0 < len(missing) < 3:
                blockers.append(f"{MGMT_ALL_THREE} (missing: {', '.join(missing)}).")
            if (m_after.get("sshEnabled") or m_after.get("telnetEnabled")) and not m_after.get(
                "managementUserName"
            ):
                side.append("SSH/Telnet is on with no management user: give mgmt_user and mgmt_password.")
            if {"authType", "dot1xUsername", "managementUserName"} & set(m_given) or secrets:
                side.append(MGMT_IMPACT)
            if rec is not None:
                details["changes"] = diff(put_base(rec), preview_body(body, secrets))
                if not details["changes"]:
                    blockers.append(f"AP profile {rec.get('apProfileName')} already has these settings.")
        side.append(REACH_WLC)
        shown = preview_body(body, secrets) if body is not None else None
        plan = Plan(
            summary,
            details={"method": method, "path": path, **({"body": shown} if shown else {}), **details},
            side_effects=side,
            fingerprint=fingerprint,
            blockers=blockers,
        )

        async def apply() -> Any:
            send = with_secrets(body, secrets) if body is not None else None
            job = await app.run_job(method, path, send, ctx=ctx, what=summary[0].lower() + summary[1:])
            if method == "POST":
                made = find(await ap_profiles(app), name, "apProfileName")
                return {**job, "ap_profile_id": made.get("id") if made else None, "next": REACH_WLC}
            return job

        return await preview_or_apply(
            ctx,
            tool="catc_set_ap_profile",
            args={
                "name": name,
                "delete": delete,
                "description": description,
                "ssh": ssh,
                "telnet": telnet,
                "mgmt_user": mgmt_user,
                # bound by digest, so a different password needs a new preview; never the value itself
                "mgmt_password": digest(mgmt_password),
                "mgmt_enable_password": digest(mgmt_enable_password),
                "dot1x_supplicant": dot1x_supplicant,
                "dot1x_user": dot1x_user,
                "dot1x_password": digest(dot1x_password),
                "cdp": cdp,
                "rogue_detection": rogue_detection,
                "rogue_min_rssi": rogue_min_rssi,
                "rogue_report_interval": rogue_report_interval,
                "rogue_transient_interval": rogue_transient_interval,
                "country": country,
                "time_zone": time_zone,
                "time_zone_offset_hour": time_zone_offset_hour,
                "time_zone_offset_minutes": time_zone_offset_minutes,
                "power_profile": power_profile,
                "client_limit": client_limit,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set AP power profile")
    async def catc_set_ap_power_profile(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Power profile name (or id)")],
        rules: Annotated[
            list[PowerRule] | None,
            Field(
                max_length=16,
                description="Ordered rules, applied first to last when PoE is short, e.g. "
                "{interface_type: RADIO, interface_id: 6GHZ, parameter_type: STATE, "
                "parameter_value: DISABLE}; "
                "an update replaces the whole list",
            ),
        ] = None,
        description: Annotated[str | None, Field(max_length=128, description="Profile description")] = None,
        delete: Annotated[bool, Field(description="Delete the power profile (no other settings)")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, update or delete an AP power profile: ordered rules that turn an Ethernet port down to a
        speed, a radio down to fewer spatial streams, or a radio or the USB port off when the switch gives
        the AP too little PoE. AP profiles name it (catc_set_ap_profile power_profile). Preview-first."""
        app: CatcApp = get_client(ctx)
        for i, r in enumerate(rules or [], 1):
            if r.interface_id not in RULE_IDS[r.interface_type]:
                raise InvalidRequest(f"Rule {i}: {r.interface_id} is not a {r.interface_type} interface.")
            allowed = RULE_PARAMS[r.interface_type].get(r.parameter_type)
            if allowed is None:
                raise InvalidRequest(f"Rule {i}: {r.interface_type} takes no {r.parameter_type} rule.")
            if r.parameter_value not in allowed:
                raise InvalidRequest(
                    f"Rule {i}: {r.interface_type} {r.parameter_type} takes {', '.join(sorted(allowed))}."
                )
        powers, aps = await asyncio.gather(power_profiles(app), ap_profiles(app))
        rec = find(powers, name, "profileName")
        users = power_usage(aps).get(str(rec.get("profileName")) if rec else name, [])
        blockers: list[str] = []
        side: list[str] = []
        body: dict[str, Any] | None = None
        if delete:
            if rules is not None or description is not None:
                raise InvalidRequest("delete=true takes no other settings.")
            if rec is None:
                raise NotFound(f"No AP power profile {name} (catc_list_ap_profiles).")
            if users:
                blockers.append(f"AP profile(s) {', '.join(users)} use {rec.get('profileName')}.")
            method, path = "DELETE", f"{POWER_PROFILES}/{safe_id(str(rec['id']), 'power profile id')}"
            summary = f"Delete AP power profile {rec.get('profileName')}"
        elif rec is None:
            if not rules:
                raise InvalidRequest("A new power profile needs at least one rule.")
            body = {
                "profileName": name,
                **({"description": description} if description is not None else {}),
                "rules": [
                    {
                        "interfaceType": r.interface_type,
                        "interfaceId": r.interface_id,
                        "parameterType": r.parameter_type,
                        "parameterValue": r.parameter_value,
                    }
                    for r in rules
                ],
            }
            method, path = "POST", POWER_PROFILES
            summary = f"Create AP power profile {name} ({len(rules)} rule(s))"
        else:
            if rules is None and description is None:
                raise InvalidRequest("Nothing to set: give rules and/or description (or delete=true).")
            cur = sorted(
                (r for r in ensure_list(rec.get("rules")) if isinstance(r, dict)),
                key=lambda r: int(r.get("sequence") or 0),
            )
            new_rules: list[dict[str, Any]] = (
                [
                    {
                        "interfaceType": r.interface_type,
                        "interfaceID": r.interface_id,
                        "parameterType": r.parameter_type,
                        "parameterValue": r.parameter_value,
                    }
                    for r in rules
                ]
                if rules is not None
                else [
                    {
                        "interfaceType": r.get("interfaceType"),
                        "interfaceID": r.get("interfaceId") or r.get("interfaceID"),
                        "parameterType": r.get("parameterType"),
                        "parameterValue": r.get("parameterValue"),
                    }
                    for r in cur
                ]
            )
            body = {
                "profileName": rec.get("profileName"),
                "description": description if description is not None else rec.get("description") or "",
                "rules": new_rules,
            }
            if not new_rules:
                blockers.append("A power profile needs at least one rule.")
            before = power_row(rec)
            after = power_row({**body, "rules": [{**r, "sequence": i} for i, r in enumerate(new_rules, 1)]})
            if (
                before.get("rules") == after.get("rules")
                and (rec.get("description") or "") == body["description"]
            ):
                blockers.append(f"AP power profile {rec.get('profileName')} already has these settings.")
            method, path = "PUT", f"{POWER_PROFILES}/{safe_id(str(rec['id']), 'power profile id')}"
            summary = f"Update AP power profile {rec.get('profileName')}"
            if users:
                side.append(
                    f"AP profile(s) {', '.join(users)} use it: the next provision of their WLCs pushes the "
                    "new rules to those APs."
                )
        side.append(
            "A design object: it reaches a WLC through an AP profile (catc_set_ap_profile "
            "power_profile), that AP profile's wireless profile site tag and a re-provision."
        )
        plan = Plan(
            summary,
            details=compact(
                {
                    "method": method,
                    "path": path,
                    "body": body,
                    "current": power_row(rec) if rec else None,
                    "used_by_ap_profiles": users,
                }
            ),
            side_effects=side,
            fingerprint={"record": rec, "users": users},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job(method, path, body, ctx=ctx, what=summary[0].lower() + summary[1:])
            if method == "POST":
                made = find(await power_profiles(app), name, "profileName")
                return {**job, "power_profile_id": made.get("id") if made else None}
            return job

        return await preview_or_apply(
            ctx,
            tool="catc_set_ap_power_profile",
            args={
                "name": name,
                "rules": [r.model_dump() for r in rules] if rules is not None else None,
                "description": description,
                "delete": delete,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
