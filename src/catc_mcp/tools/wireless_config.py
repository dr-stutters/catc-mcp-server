"""Wireless feature config reads (roadmap D70): what Catalyst Center intends for a Catalyst 9800 WLC and what
it reads back as deployed, per feature model.

The models live under /dna/campus/api/v1/wirelessControllers/{id}/{intended|deployed}/<group>/<feature>:
WLAN, policy and RLAN profiles, policy and site tags, RF and radio profiles, AP join, power, mesh and calendar
profiles, flex, mDNS, Dot11be and tag mappings. Each record is flat (one object per profile or tag) with
a `deviceVersion` and a `configType`; some have sub-collections (a policy tag's WLAN-to-policy mappings, a
WLAN's MPSK keys) at <feature>/{recordId}/<child>.

Secrets (PSKs, MPSK keys, AP management and dot1x passwords, NTP trust keys, FTP passwords, URWB passphrases)
are masked, and the intended-vs-deployed diff never compares them: the WLC stores them encrypted, so the
values differ by design. Writes are D71 (feature templates and intended deploy).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import json
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import InvalidRequest, ToolRegistrar, compact, get_client, object_result
from catc_mcp._core.formatting import MASK, NOT_SECRET_KEYS, is_secret_key
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import gather_sections, resolve_device
from catc_mcp.tools.ops_writes import brief

CAMPUS = "/dna/campus/api/v1/wirelessControllers"
# Secret fields the core key pattern doesn't catch (spec format=password, or a key/token by name).
WLC_SECRET_KEYS = frozenset({"key", "wepKey", "ntpServerTrustKey", "spacesConnCfgToken"})
# Enum fields the core pattern would mask that only name a key or crypt type (ASCII/HEX, AES, TYPE_8...).
NOT_SECRET_KEYS.update(
    {
        "wlanPskKeyType",
        "wlanPskTypeCrypt",
        "localAuthUserPasswordType",
        "loginCredentialsDot1xPasswordType",
        "userMgmtPasswordCryptType",
        "userMgmtSecretType",
        "ftpPasswordCryptType",
        "mpskKeyConfigs",  # a sub-collection name; its `key` values are masked by mask_record
    }
)
# Bookkeeping on every record: hoisted (deviceVersion) or dropped (configType names the feature).
META_KEYS = ("configType", "deviceVersion")
NAMES_SHOWN = 20  # names per feature in the summary
CHILD_RECORDS = 25  # records whose sub-collections are fetched (children=True)


@dataclass(frozen=True)
class Feature:
    path: str  # under intended/ or deployed/
    name: str  # the record's name field
    children: tuple[str, ...] = ()
    ap: bool = False  # only holds data once APs join (CML has none)
    deployed_only: bool = False


FEATURES: dict[str, Feature] = {
    # SSIDs
    "wlan_profiles": Feature("ssids/wlanProfiles", "profileName", ("mpskKeyConfigs", "radioPolicyConfigs")),
    "policy_profiles": Feature(
        "ssids/policyProfiles",
        "policyProfileName",
        (
            "airTimeFairnessPolicies",
            "avcIpv4FMEgresses",
            "avcIpv4FMIngresses",
            "avcIpv6FMEgresses",
            "avcIpv6FMIngresses",
            "mobilityExportAnchors",
            "policyProfileCalendarConfigs",
        ),
    ),
    "policy_tags": Feature(
        "ssids/policyTags", "policyTagName", ("policyTagWlanPolicies", "policyTagRlanPolicies")
    ),
    "rlan_profiles": Feature("ssids/rlanProfiles", "rlanConfigProfileName"),
    "rlan_policies": Feature("ssids/rlanPolicies", "rlanPolicyProfileName"),
    "dot11be_profiles": Feature("ssids/dot11BeProfiles", "profileName"),
    # Access points
    "site_tags": Feature("accessPoints/siteTagConfigs", "siteTagName"),
    "ap_join_profiles": Feature(
        "accessPoints/apJoinProfiles",
        "apCfgProfileName",
        (
            "calendarConfigs",
            "haloBleConfigs",
            "icapClientMacAddressConfigs",
            "icapMacClientConfigs",
            "qosMapConfigs",
            "qosMapDscpToUPs",
        ),
    ),
    "ap_power_profiles": Feature("accessPoints/apPowerProfiles", "apPowerProfileName", ("apPpeConfigs",)),
    "calendar_profiles": Feature(
        "accessPoints/calendarProfiles", "calendarProfileName", ("monthlyConfigs", "weeklyConfigs")
    ),
    "mesh_profiles": Feature("accessPoints/meshProfiles", "meshProfileName"),
    "ap_trace_profiles": Feature("accessPoints/apTraceProfiles", "apTraceProfileName", deployed_only=True),
    "ap_packet_captures": Feature(
        "accessPoints/apPacketCaptures", "apPacketCaptureProfileName", deployed_only=True
    ),
    # Radio frequencies
    "rf_profiles": Feature(
        "radioFrequencies/rfProfiles",
        "rfProfileName",
        ("rfDcaAllowedChannelConfigs", "rfDcaRemovedChannelConfigs", "rfMcsConfigs"),
    ),
    "rf_tags": Feature("radioFrequencies/rfTags", "rfTagTagName", ("rfTagRadioProfileConfigs",)),
    "radio_profiles": Feature(
        "radioFrequencies/radioProfiles", "radioProfileName", ("urwbChannelListConfigs",)
    ),
    "multi_bssid_profiles": Feature("radioFrequencies/multiBssidProfiles", "multiBssidProfileName"),
    "urwb_profiles": Feature("radioFrequencies/urwbProfiles", "urwbProfileName", ("urwbEtherTypes",)),
    # FlexConnect
    "flex_profiles": Feature(
        "flexes/flexProfiles",
        "flexPolicyName",
        ("ifNameVlanIdConfigs", "localAuthUserConfigs", "policyAclConfigs", "umbrellaProfileConfigs"),
    ),
    # mDNS
    "mdns_gateways": Feature("mDNSs/mdnsGateways", "mdnsApServicePolicyName"),
    "mdns_service_definitions": Feature(
        "mDNSs/mdnsServiceDefinitions", "serviceDefinitionName", ("mdnsServiceTypes",)
    ),
    "mdns_service_policies": Feature(
        "mDNSs/mdnsServicePolicies", "servicePolicyName", ("mdnsServicePolicyIns", "mdnsServicePolicyOuts")
    ),
    "mdns_flex_profiles": Feature("mDNSs/mdnsFlexProfiles", "flexProfileName"),
    "mdns_wired_filters": Feature("mDNSs/mdnsWiredFilters", "wiredFilterName"),
    # Tag mappings (per AP or location: empty until APs join)
    "ap_tag_configs": Feature("tagMappings/apTagConfigs", "apTagApName", ap=True),
    "ap_priming_configs": Feature("tagMappings/apPrimingConfigs", "apPrimingProfileName", ap=True),
    "location_configs": Feature(
        "tagMappings/locationConfigs", "locationEntryLocationName", ("associatedApConfigs",), ap=True
    ),
}
FeatureName = Literal[
    "wlan_profiles",
    "policy_profiles",
    "policy_tags",
    "rlan_profiles",
    "rlan_policies",
    "dot11be_profiles",
    "site_tags",
    "ap_join_profiles",
    "ap_power_profiles",
    "calendar_profiles",
    "mesh_profiles",
    "ap_trace_profiles",
    "ap_packet_captures",
    "rf_profiles",
    "rf_tags",
    "radio_profiles",
    "multi_bssid_profiles",
    "urwb_profiles",
    "flex_profiles",
    "mdns_gateways",
    "mdns_service_definitions",
    "mdns_service_policies",
    "mdns_flex_profiles",
    "mdns_wired_filters",
    "ap_tag_configs",
    "ap_priming_configs",
    "location_configs",
]
State = Literal["intended", "deployed"]
AP_NOTE = "AP tag, priming and location mappings only hold data once access points join the WLC."


def is_wlc_secret(key: str) -> bool:
    return key in WLC_SECRET_KEYS or is_secret_key(key)


def mask_record(rec: dict[str, Any]) -> dict[str, Any]:
    """The record with secret values masked (empty secrets stay empty: 'not set' is worth knowing)."""
    return {
        k: (MASK if is_wlc_secret(k) and v not in (None, "") and not isinstance(v, bool) else v)
        for k, v in rec.items()
    }


def record_name(feat: Feature, rec: dict[str, Any]) -> str:
    return str(rec.get(feat.name) or rec.get("id") or "?")


def feature_path(did: str, state: str, feat: Feature) -> str:
    return f"{CAMPUS}/{did}/{state}/{feat.path}"


async def read_records(app: CatcApp, path: str) -> tuple[list[dict[str, Any]], bool]:
    page = await fetch_all(app.pager, app.api, path, cap=2000)
    return [r for r in page.items if isinstance(r, dict)], page.complete


async def read_feature(
    app: CatcApp, did: str, state: str, feat: Feature, *, children: bool, name: str | None = None
) -> dict[str, Any]:
    """{records, complete, children?} for one feature; records are masked, children keyed by record name."""
    recs, complete = await read_records(app, feature_path(did, state, feat))
    if name is not None:
        recs = [r for r in recs if name in (r.get(feat.name), r.get("id"))]
    out: dict[str, Any] = {"records": [mask_record(r) for r in recs], "complete": complete}
    if children and feat.children:
        base = feature_path(did, state, feat)
        jobs: dict[str, Any] = {}
        for r in recs[:CHILD_RECORDS]:
            if not r.get("id"):
                continue
            rid = safe_id(str(r["id"]), "record id")
            for child in feat.children:
                jobs[f"{record_name(feat, r)}\x00{child}"] = read_records(app, f"{base}/{rid}/{child}")
        sec, errors = await gather_sections(jobs)
        kids: dict[str, dict[str, Any]] = {}
        for key, (items, _) in sec.items():
            rec, child = key.split("\x00")
            rows = [{k: v for k, v in mask_record(x).items() if k not in (*META_KEYS, "id")} for x in items]
            if rows:
                kids.setdefault(rec, {})[child] = rows
        out["children"] = kids
        if errors:
            out["children_unavailable"] = {k.replace("\x00", "/"): v for k, v in errors.items()}
        if len(recs) > CHILD_RECORDS:
            out["children_note"] = f"Sub-collections fetched for the first {CHILD_RECORDS} records only."
    return out


def shown_record(rec: dict[str, Any], all_fields: bool) -> dict[str, Any]:
    """A record for display: no bookkeeping keys and, unless all_fields, no false flags."""
    out = {k: v for k, v in rec.items() if k not in META_KEYS}
    if not all_fields:
        out = {k: v for k, v in out.items() if v is not False}
    shown: dict[str, Any] = compact(out)
    return shown


def comparable(rec: dict[str, Any]) -> dict[str, Any]:
    """Fields to compare: no ids, bookkeeping or secrets, and nothing unset."""
    return {
        k: v
        for k, v in rec.items()
        if k not in (*META_KEYS, "id") and not is_wlc_secret(k) and v not in (None, "", [], {})
    }


def canon(rows: list[dict[str, Any]]) -> list[str]:
    return sorted(
        json.dumps({k: v for k, v in r.items() if not is_wlc_secret(k)}, sort_keys=True, default=str)
        for r in rows
    )


def diff_feature(feat: Feature, intended: dict[str, Any], deployed: dict[str, Any]) -> dict[str, Any]:
    """Intended vs deployed for one feature, matched by record name. A field counts only when the intent
    sets it (the WLC reports device defaults the intent leaves alone); secrets are never compared."""
    want = {record_name(feat, r): r for r in intended["records"]}
    have = {record_name(feat, r): r for r in deployed["records"]}
    changed: dict[str, Any] = {}
    for n in sorted(want.keys() & have.keys()):
        a, b = comparable(want[n]), comparable(have[n])
        fields = {k: {"intended": a[k], "deployed": b.get(k)} for k in sorted(a) if a[k] != b.get(k)}
        kids_a = intended.get("children", {}).get(n, {})
        kids_b = deployed.get("children", {}).get(n, {})
        for child in sorted(kids_a.keys() | kids_b.keys()):
            ca, cb = canon(kids_a.get(child, [])), canon(kids_b.get(child, []))
            if ca != cb:
                fields[child] = {
                    "only_intended": [json.loads(x) for x in ca if x not in cb],
                    "only_deployed": [json.loads(x) for x in cb if x not in ca],
                }
        if fields:
            changed[n] = fields
    out: dict[str, Any] = {
        "only_intended": sorted(want.keys() - have.keys()),
        "only_deployed": sorted(have.keys() - want.keys()),
        "changed": changed,
        "in_sync": sum(1 for n in want.keys() & have.keys() if n not in changed),
    }
    if not (intended["complete"] and deployed["complete"]):
        out["note"] = "A collection was larger than 2000 records; the diff is partial."
    result: dict[str, Any] = compact(out)
    return result


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="WLC feature config")
    async def catc_get_wlc_config(
        ctx: Context,
        wlc: Annotated[str, Field(description="Catalyst 9800 WLC: hostname, management IP, serial or id")],
        feature: Annotated[
            FeatureName | None,
            Field(description="One feature family in full (default: a summary of every family)"),
        ] = None,
        state: Annotated[
            State,
            Field(
                description="'intended' (what Catalyst Center pushes) or 'deployed' (read back from the WLC)"
            ),
        ] = "intended",
        diff: Annotated[
            bool, Field(description="Compare intended with deployed per feature (ignores `state`)")
        ] = False,
        name: Annotated[
            str | None, Field(description="With `feature`: only the record with this name (or id)")
        ] = None,
        children: Annotated[
            bool,
            Field(
                description="With `feature`: also read each record's sub-collections (policy tag "
                "WLAN-to-policy mappings, MPSK keys, RF DCA channels, flex VLANs...); diffed too"
            ),
        ] = False,
        all_fields: Annotated[
            bool, Field(description="With `feature`: keep false flags (omitted by default to save space)")
        ] = False,
    ) -> Any:
        """Wireless feature configuration Catalyst Center keeps for a Catalyst 9800 WLC (the /dna/campus
        feature models): WLAN, policy and RLAN profiles, policy and site tags, RF/radio profiles and RF tags,
        AP join, power, mesh and calendar profiles, flex, mDNS, Dot11be and AP tag mappings. Without
        `feature`: a count and the names per family. With `feature`: that family's records in full. Intended
        is what Catalyst Center will push; deployed is what it read back from the WLC. diff=true reports, per
        feature, the profiles only in one of them and the fields that differ. Secrets are masked and never
        compared. Families that need joined APs are empty on a WLC without APs."""
        app: CatcApp = get_client(ctx)
        if (name is not None or children or all_fields) and feature is None:
            raise InvalidRequest("`name`, `children` and `all_fields` apply to one `feature`.")
        dev = await resolve_device(app, wlc)
        if "Wireless Controller" not in str(dev.get("family")):
            raise InvalidRequest(f"{brief([dev])[0]} is a {dev.get('family')}, not a wireless controller.")
        did = safe_id(str(dev["id"]), "device id")
        out: dict[str, Any] = {"wlc": brief([dev])[0], "software": dev.get("softwareVersion")}
        feats = {feature: FEATURES[feature]} if feature else FEATURES

        if diff:
            jobs: dict[str, Any] = {}
            for key, f in feats.items():
                if f.deployed_only:
                    continue
                for st in ("intended", "deployed"):
                    jobs[f"{key}\x00{st}"] = read_feature(app, did, st, f, children=children, name=name)
            sec, errors = await gather_sections(jobs)
            result: dict[str, Any] = {}
            in_sync: list[str] = []
            for key, f in feats.items():
                a, b = sec.get(f"{key}\x00intended"), sec.get(f"{key}\x00deployed")
                if a is None or b is None:
                    continue
                if not a["records"] and not b["records"]:
                    continue
                d = diff_feature(f, a, b)
                if d.get("only_intended") or d.get("only_deployed") or d.get("changed") or d.get("note"):
                    result[key] = d
                else:
                    in_sync.append(key)
            out |= {"diff": result, "in_sync": in_sync}
            if feature and feats[feature].deployed_only:
                out["note"] = f"{feature} has no intended model (deployed only); nothing to compare."
            elif not result and not in_sync:
                out["note"] = "No intended or deployed records for " + (feature or "any feature") + "."
            if errors:
                out["unavailable"] = {k.replace("\x00", "/"): v for k, v in errors.items()}
            return object_result(out)

        out["state"] = state
        if feature:
            f = FEATURES[feature]
            if f.deployed_only and state == "intended":
                raise InvalidRequest(f"{feature} has no intended model; use state='deployed'.")
            got = await read_feature(app, did, state, f, children=children, name=name)
            recs = got["records"]
            versions = sorted({str(r.get("deviceVersion")) for r in recs if r.get("deviceVersion")})
            out |= {
                "feature": feature,
                "device_version": versions[0] if len(versions) == 1 else versions or None,
                "count": len(recs),
                "records": [shown_record(r, all_fields) for r in recs],
            }
            for k in ("children", "children_unavailable", "children_note"):
                if got.get(k):
                    out[k] = got[k]
            if not recs:
                what = f"named {name} " if name else ""
                out["note"] = f"No {state} {feature} {what}on this WLC." + (f" {AP_NOTE}" if f.ap else "")
            elif not got["complete"]:
                out["note"] = "More than 2000 records; the list is partial."
            if not all_fields and recs:
                out["omitted"] = "false flags (all_fields=true shows them)"
            return object_result(out)

        jobs = {
            key: read_records(app, feature_path(did, state, f))
            for key, f in FEATURES.items()
            if not (f.deployed_only and state == "intended")
        }
        sec, errors = await gather_sections(jobs)
        summary: dict[str, Any] = {}
        empty: list[str] = []
        for key, (recs, complete) in sec.items():
            if not recs:
                empty.append(key)
                continue
            names = sorted(record_name(FEATURES[key], r) for r in recs)
            row: dict[str, Any] = {
                "count": len(recs) if complete else f"{len(recs)}+",
                "names": names[:NAMES_SHOWN],
            }
            if len(names) > NAMES_SHOWN:
                row["more"] = len(names) - NAMES_SHOWN
            summary[key] = row
        out |= {"features": summary, "no_data": empty}
        if not summary:
            out["note"] = (
                f"No {state} wireless feature config for this WLC: is it provisioned "
                "(catc_provision_wireless_controller)?"
            )
        if any(FEATURES[k].ap for k in empty):
            out["ap_note"] = AP_NOTE
        if errors:
            out["unavailable"] = errors
        return object_result(out)
