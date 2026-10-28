"""Wired per-device intended configuration (roadmap D125): the layer-2 feature models Catalyst Center keeps
for a switch with Per Device Configuration (PDC) enabled, the wired twin of the 9800 flow (D70/D71).

The models live under /dna/intent/api/v1/wired/networkDevices/{id}/configFeatures:
- supported/layer2: the feature names this switch takes (vlanConfig, stpGlobalConfig,
  switchportInterfaceConfig...)
- intended/layer2/{feature}: what Catalyst Center will push (GET, POST to create, PUT to update, DELETE)
- deployed/layer2/{feature}: what it read back from the switch
- intended/configurationModels: build a provision model from the intent, generate its CLI (POST .../config),
  read it (GET .../config), then deploy it (POST .../deploy) or discard it (DELETE)
- intended/deviceDeployments: each config group's deployment status

Each feature body is {"<feature>": {"items": [{"configType": ..., ...}]}}; an item is identified by its VLAN
id (vlanConfig), its interface name (the *Interface* features) or, for the global features, is the one
record. Deploy is additive: configuration on the switch that the intent doesn't name is retained.

Catalyst Center 3.2.2 answers every read with 400 NCCO15475 "Per Device Configuration (PDC) must be
enabled on the device" until PDC is enabled in the device's Inventory page (GUI only; no API in 3.2.2).

The spec lists the model deploy at a doubled prefix (/dna/intent/api/v1/intent/api/v1/wired/...); the
single prefix is used, as for the activities API, where the doubled path is a 404 on 3.2.2 (and so is
GET .../intent/api/v1/wired/.../deviceDeployments, read live 2026-10-28).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import contextlib
import json
import re
import time
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    compact,
    get_client,
    object_result,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp.client import CatcApp, catc_error_detail, safe_id
from catc_mcp.common import ensure_list, gather_sections, resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.wireless_writes import DEPLOY_POLL, deployment_row, settled, status_counts

WIRED = "/dna/intent/api/v1/wired/networkDevices"
SETTINGS = "/dna/intent/api/v1/provisioningSettings"
PDC_CODE = "NCCO15475"
PDC_TEXT = "Per Device Configuration (PDC) must be enabled"
PDC_NOTE = (
    "Catalyst Center keeps the wired layer-2 feature models only for switches with Per Device Configuration "
    "(PDC) enabled, and this one doesn't have it: enable PDC in Inventory first (the switch's device details "
    "in the Catalyst Center GUI; no API in 3.2.2). Enabling pushes nothing: Catalyst Center learns the "
    "running layer-2 config into the deployed model. See docs/wired-per-device.md."
)
STAGED = (
    "Stores the change in Catalyst Center's intended model only: the switch is unchanged until "
    "catc_deploy_wired_config."
)
READ_CONCURRENCY = 6
KEYS_SHOWN = 20
UNSET = "(not set)"

# Per feature (the 3.2.2 request schema): the item configType and the fields an item takes.
FEATURES: dict[str, tuple[str, frozenset[str]]] = {
    "cdpGlobalConfig": (
        "CDP_GLOBAL",
        frozenset(
            {"holdTime", "isAdvertiseV2Enabled", "isCdpEnabled", "isLogDuplexMismatchEnabled", "timer"}
        ),
    ),
    "cdpInterfaceConfig": (
        "CDP_INTERFACE",
        frozenset({"interfaceName", "isCdpEnabled", "isLogDuplexMismatchEnabled"}),
    ),
    "dhcpSnoopingGlobalConfig": (
        "DHCP_SNOOPING_GLOBAL",
        frozenset(
            {
                "databaseAgent",
                "dhcpSnoopingVlans",
                "isDhcpSnoopingEnabled",
                "isGleaningEnabled",
                "proxyBridgeVlans",
            }
        ),
    ),
    "dhcpSnoopingInterfaceConfig": (
        "DHCP_SNOOPING_INTERFACE",
        frozenset({"interfaceName", "isTrustedInterface", "messageRateLimit"}),
    ),
    "dot1xGlobalConfig": ("DOT1X_GLOBAL", frozenset({"authenticationConfigMode", "isDot1xEnabled"})),
    "dot1xInterfaceConfig": (
        "DOT1X_INTERFACE",
        frozenset(
            {
                "interfaceName",
                "authenticationOrder",
                "authenticationMode",
                "inactivityTimer",
                "isInactivityTimerFromServerEnabled",
                "isReauthEnabled",
                "isReauthTimerFromServerEnabled",
                "maxReauthRequests",
                "priority",
                "reauthTimer",
                "txPeriod",
            }
        ),
    ),
    "igmpSnoopingGlobalConfig": (
        "IGMP_SNOOPING_GLOBAL",
        frozenset(
            {
                "igmpSnoopingVlanSettings",
                "isIgmpSnoopingEnabled",
                "isQuerierEnabled",
                "querierAddress",
                "querierQueryInterval",
                "querierVersion",
            }
        ),
    ),
    "lldpGlobalConfig": (
        "LLDP_GLOBAL",
        frozenset({"holdTime", "isLldpEnabled", "reinitializationDelay", "timer"}),
    ),
    "lldpInterfaceConfig": ("LLDP_INTERFACE", frozenset({"interfaceName", "adminStatus"})),
    "mabInterfaceConfig": ("MAB_INTERFACE", frozenset({"interfaceName", "isMabEnabled"})),
    "mldSnoopingGlobalConfig": (
        "MLD_SNOOPING_GLOBAL",
        frozenset(
            {
                "isMldSnoopingEnabled",
                "isQuerierEnabled",
                "isSuppressListenerMessagesEnabled",
                "mldSnoopingVlanSettings",
                "querierAddress",
                "querierQueryInterval",
                "querierVersion",
            }
        ),
    ),
    # The request schema says portChannelConfig, the read schema portchannelConfig: whichever name the
    # switch's supported list gives is used for the path and the body.
    "portChannelConfig": (
        "PORTCHANNEL",
        frozenset({"isAutoEnabled", "lacpSystemPriority", "loadBalancingMethod", "portchannels"}),
    ),
    "stpGlobalConfig": (
        "STP_GLOBAL",
        frozenset(
            {
                "isBackboneFastEnabled",
                "isBpduFilterEnabled",
                "isBpduGuardEnabled",
                "isEtherChannelGuardEnabled",
                "isExtendedSystemIdEnabled",
                "isLoggingEnabled",
                "isLoopGuardEnabled",
                "isUplinkFastEnabled",
                "portFastMode",
                "stpInstances",
                "stpMode",
                "transmitHoldCount",
                "uplinkFastMaxUpdateRate",
            }
        ),
    ),
    "stpInterfaceConfig": (
        "STP_INTERFACE",
        frozenset(
            {
                "interfaceName",
                "bpduFilter",
                "bpduGuard",
                "guardMode",
                "pathCost",
                "portFastMode",
                "portVlanCostSettings",
                "portVlanPrioritySettings",
                "priority",
            }
        ),
    ),
    "switchportInterfaceConfig": (
        "SWITCHPORT_INTERFACE",
        frozenset(
            {
                "interfaceName",
                "accessVlan",
                "adminStatus",
                "description",
                "mode",
                "nativeVlan",
                "trunkAllowedVlans",
                "voiceVlan",
            }
        ),
    ),
    "trunkInterfaceConfig": (
        "TRUNK_INTERFACE",
        frozenset({"interfaceName", "isDtpNegotiationEnabled", "isProtected", "pruneEligibleVlans"}),
    ),
    "vlanConfig": ("VLAN", frozenset({"vlanId", "name", "isVlanEnabled"})),
    "vtpGlobalConfig": (
        "VTP_GLOBAL",
        frozenset(
            {"configurationFileName", "domainName", "isPruningEnabled", "mode", "sourceInterface", "version"}
        ),
    ),
    "vtpInterfaceConfig": ("VTP_INTERFACE", frozenset({"interfaceName", "isVtpEnabled"})),
}
_BY_LOWER = {k.lower(): k for k in FEATURES}
State = Literal["intended", "deployed"]
Mode = Literal["merge", "replace", "remove", "delete"]
# ftp://user:password@host/file in the DHCP snooping database agent URL
_URL_PASSWORD = re.compile(r"(//[^:/@\s]+:)[^@/\s]+@")


def canonical(feature: str) -> str:
    """The schema name for a feature given in any case (portchannelConfig -> portChannelConfig)."""
    return _BY_LOWER.get(feature.lower(), feature)


def key_field(feature: str) -> str | None:
    """The field that names an item: VLAN id, interface name, or none (one global record)."""
    if canonical(feature) == "vlanConfig":
        return "vlanId"
    if "Interface" in feature:
        return "interfaceName"
    return None


def item_key(feature: str, item: dict[str, Any]) -> str:
    kf = key_field(feature)
    if kf is None:
        return "global"
    v = item.get(kf)
    return str(v) if v not in (None, "") else "?"


def mask(v: Any) -> Any:
    if isinstance(v, str):
        return _URL_PASSWORD.sub(rf"\g<1>{MASK}@", v)
    if isinstance(v, dict):
        return {k: mask(x) for k, x in v.items()}
    if isinstance(v, list):
        return [mask(x) for x in v]
    return v


def has_mask(v: Any) -> bool:
    if isinstance(v, str):
        return MASK in v
    if isinstance(v, dict):
        return any(has_mask(x) for x in v.values())
    if isinstance(v, list):
        return any(has_mask(x) for x in v)
    return False


def norm(v: Any) -> Any:
    """A value to compare: no configType bookkeeping, nested lists in a stable order."""
    if isinstance(v, dict):
        return {k: norm(x) for k, x in v.items() if k != "configType" and x not in (None, "", [], {})}
    if isinstance(v, list):
        return sorted((norm(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True, default=str))
    return v


def unwrap_items(data: Any, feature: str) -> list[dict[str, Any]]:
    """The items of one feature from the shapes 3.2.2 may answer: {"response": {...}}, {"features": {...}},
    {"<feature>": {"items": [...]}} (the spec's), {"items": [...]} or a bare list."""
    if isinstance(data, dict) and "response" in data:
        data = data["response"]
    if isinstance(data, dict) and isinstance(data.get("features"), dict):
        data = data["features"]
    if isinstance(data, dict) and "items" not in data:
        data = next((v for k, v in data.items() if k.lower() == feature.lower()), None)
    if isinstance(data, dict):
        data = data.get("items")
    return [x for x in ensure_list(data) if isinstance(x, dict)]


def body(feature: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {feature: {"items": items}}


def feature_path(did: str, state: str, feature: str) -> str:
    return f"{WIRED}/{did}/configFeatures/{state}/layer2/{feature}"


def model_path(did: str, pid: str | None = None) -> str:
    base = f"{WIRED}/{did}/configFeatures/intended/configurationModels"
    return f"{base}/{safe_id(pid, 'preview activity id')}" if pid else base


async def wired_target(app: CatcApp, device: str) -> tuple[dict[str, Any], str]:
    dev = await resolve_device(app, device)
    fam = str(dev.get("family") or "")
    if "Wireless Controller" in fam or "Unified AP" in fam:
        raise InvalidRequest(
            f"{brief([dev])[0]} is a {fam}: wired per-device configuration is for switches "
            "(a 9800 WLC: catc_get_wlc_config)."
        )
    return dev, safe_id(str(dev["id"]), "device id")


async def supported(app: CatcApp, did: str) -> tuple[list[str], str | None]:
    """(feature names the switch supports, Catalyst Center's reason when PDC is off). The 400 body is
    kept: the client's errors would drop its detail."""
    resp = await app.api.request(
        "GET", f"{WIRED}/{did}/configFeatures/supported/layer2", ok_status=(400,), expect="response"
    )
    if resp.status_code >= 400:
        try:
            detail = catc_error_detail(resp.json()) or ""
        except ValueError:
            detail = resp.text[:300]
        if PDC_CODE in detail or PDC_TEXT in detail:
            return [], detail
        raise UpstreamError(f"Catalyst Center rejected the request (400): {detail}", 400)
    try:
        data = resp.json()
    except ValueError:
        data = None
    if isinstance(data, dict) and "response" in data:
        data = data["response"]
    names = [str(x.get("name")) if isinstance(x, dict) else str(x) for x in ensure_list(data)]
    return [n for n in names if n and n != "None"], None


def pick_feature(feature: str, names: list[str]) -> str:
    """The switch's own name for `feature` (case-insensitive), refused when it doesn't support it."""
    if not names:
        return feature
    found = next((n for n in names if n.lower() == feature.lower()), None)
    if found is None:
        raise InvalidRequest(
            f"This switch doesn't support {feature}; it supports: {', '.join(sorted(names))}."
        )
    return found


async def read_items(app: CatcApp, did: str, state: str, feature: str) -> list[dict[str, Any]]:
    try:
        data = await app.api.get(feature_path(did, state, feature))
    except NotFound:
        # TODO(live): what 3.2.2 answers for a feature without intended records (wireless: 500 NCND00050).
        return []
    return [mask(x) for x in unwrap_items(data, feature)]


def shown(item: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = compact({k: v for k, v in item.items() if k != "configType"})
    return out


def diff_feature(feature: str, want: list[dict[str, Any]], have: list[dict[str, Any]]) -> dict[str, Any]:
    """Intended vs deployed for one feature, matched by item key. A field counts only when the intent
    sets it (the deployed model carries the switch's defaults)."""
    a = {item_key(feature, x): x for x in want}
    b = {item_key(feature, x): x for x in have}
    changed: dict[str, Any] = {}
    for k in sorted(a.keys() & b.keys()):
        x, y = norm(a[k]), norm(b[k])
        fields = {f: {"intended": x[f], "deployed": y.get(f, UNSET)} for f in sorted(x) if x[f] != y.get(f)}
        if fields:
            changed[k] = fields
    out: dict[str, Any] = compact(
        {
            "only_intended": sorted(a.keys() - b.keys()),
            "only_deployed": sorted(b.keys() - a.keys()),
            "changed": changed,
            "in_sync": sum(1 for k in a.keys() & b.keys() if k not in changed),
        }
    )
    return out


async def gated(jobs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    gate = asyncio.Semaphore(READ_CONCURRENCY)

    async def one(c: Any) -> Any:
        async with gate:
            return await c

    return await gather_sections({k: one(c) for k, c in jobs.items()})


async def diff_all(
    app: CatcApp, did: str, feats: list[str], item: str | None = None
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    """(diff per feature that differs, features in sync, unreadable 'feature/state'); `item` keeps only
    that VLAN id or interface."""
    jobs = {f"{f}\x00{st}": read_items(app, did, st, f) for f in feats for st in ("intended", "deployed")}
    sec, errors = await gated(jobs)
    out: dict[str, Any] = {}
    in_sync: list[str] = []
    for f in feats:
        a, b = sec.get(f"{f}\x00intended"), sec.get(f"{f}\x00deployed")
        if item is not None and a is not None and b is not None:
            a = [x for x in a if item_key(f, x) == item]
            b = [x for x in b if item_key(f, x) == item]
        if a is None or b is None or not a:
            continue  # nothing intended: the deploy changes nothing for this feature
        d = diff_feature(f, a, b)
        if d.get("only_intended") or d.get("changed"):
            out[f] = {k: v for k, v in d.items() if k != "only_deployed"}
        else:
            in_sync.append(f)
    return out, in_sync, {k.replace("\x00", "/"): v for k, v in errors.items()}


def check_items(
    feature: str, items: list[dict[str, Any]], *, keys_only: bool = False
) -> list[dict[str, Any]]:
    """Items validated against the 3.2.2 schema fields, each with its configType."""
    name = canonical(feature)
    ctype, fields = FEATURES.get(name, ("", frozenset()))
    kf = key_field(name)
    if kf is None and len(items) > 1:
        raise InvalidRequest(f"{name} is one global record: give one item.")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for it in items:
        if not isinstance(it, dict):
            raise InvalidRequest("Each item is an object of feature fields.")
        extra = sorted(set(it) - fields - {"configType"}) if fields else []
        if extra:
            raise InvalidRequest(
                f"{name} has no field(s) {', '.join(extra)}; it takes: {', '.join(sorted(fields))}."
            )
        if kf and it.get(kf) in (None, ""):
            raise InvalidRequest(f"Each {name} item needs {kf}.")
        if kf == "vlanId" and not (isinstance(it["vlanId"], int) and 1 <= it["vlanId"] <= 4094):
            raise InvalidRequest("vlanId is a VLAN number, 1-4094.")
        k = item_key(name, it)
        if k in seen:
            raise InvalidRequest(f"{name} item {k} is given twice.")
        seen.add(k)
        if keys_only:
            continue
        out.append({"configType": ctype, **it} if ctype and "configType" not in it else dict(it))
    return out


def changes(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    o = norm(old or {})
    n = norm(new)
    return {f: {"from": o.get(f, UNSET), "to": n[f]} for f in sorted(n) if o.get(f) != n[f]}


def cli_text(preview: Any) -> tuple[list[dict[str, Any]], list[str], str | None]:
    """(CLI per config item, error messages, status) from GET .../configurationModels/{id}/config."""
    p = preview.get("response", preview) if isinstance(preview, dict) else {}
    p = p if isinstance(p, dict) else {}
    rows: list[dict[str, Any]] = []
    errs: list[str] = []
    for it in ensure_list(p.get("previewItems")):
        if not isinstance(it, dict):
            continue
        rows.append(
            compact(
                {"name": it.get("name"), "config_type": it.get("configType"), "cli": it.get("configPreview")}
            )
        )
        errs += [str(e) for e in ensure_list(it.get("errorMessages")) if e]
    return rows, errs, p.get("status")


async def deployments(app: CatcApp, did: str, activity: str | None = None) -> list[dict[str, Any]]:
    params = {"deployActivityId": safe_id(activity, "activity id")} if activity else None
    got = await app.get_response(f"{WIRED}/{did}/configFeatures/intended/deviceDeployments", params=params)
    rows = [d for d in ensure_list(got) if isinstance(d, dict)]
    return sorted(rows, key=lambda d: int(d.get("startTime") or d.get("createTime") or 0), reverse=True)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Wired feature config")
    async def catc_get_wired_config(
        ctx: Context,
        device: Annotated[str, Field(description="Switch: hostname, management IP, serial or id")],
        feature: Annotated[
            str | None,
            Field(
                description="One layer-2 feature in full, e.g. vlanConfig, stpGlobalConfig, "
                "switchportInterfaceConfig, dhcpSnoopingGlobalConfig (default: a count per supported feature)"
            ),
        ] = None,
        state: Annotated[
            State,
            Field(
                description="'intended' (what Catalyst Center pushes) or 'deployed' (read back from the "
                "switch)"
            ),
        ] = "intended",
        diff: Annotated[
            bool, Field(description="Compare intended with deployed per feature (ignores `state`)")
        ] = False,
        item: Annotated[
            str | None, Field(description="With `feature`: only the item with this VLAN id or interface name")
        ] = None,
    ) -> Any:
        """Wired layer-2 configuration Catalyst Center keeps for a switch with Per Device Configuration
        (PDC) enabled: VLANs, STP, VTP, CDP/LLDP, DHCP/IGMP/MLD snooping, 802.1X/MAB, switchport, trunk and
        port-channel settings, as an intended model (what Catalyst Center will push) and a deployed one
        (read back from the switch). Without `feature`: the supported features with a count and the item
        keys (VLAN ids, interfaces). With `feature`: its items in full. diff=true reports, per feature, the
        intended items the switch lacks and the fields that differ. Without PDC it says how to enable it."""
        app: CatcApp = get_client(ctx)
        if item is not None and feature is None:
            raise InvalidRequest("`item` applies to one `feature`.")
        dev, did = await wired_target(app, device)
        out: dict[str, Any] = {"device": brief([dev])[0], "software": dev.get("softwareVersion")}
        names, reason = await supported(app, did)
        if reason:
            out |= {"per_device_configuration": "not enabled", "note": PDC_NOTE, "catc_says": reason}
            return object_result(out)
        out["supported_features"] = sorted(names)
        feats = [pick_feature(feature, names)] if feature else sorted(names)

        if diff:
            result, in_sync, errors = await diff_all(app, did, feats, item=item)
            out |= {"diff": result, "in_sync": in_sync}
            if not result and not in_sync:
                out["note"] = "Nothing intended for " + (feature or "any feature") + ": nothing to deploy."
            out["deploy_note"] = (
                "Deploy is additive: configuration on the switch that the intent doesn't name stays."
            )
            if errors:
                out["unavailable"] = errors
            return object_result(out)

        out["state"] = state
        if feature:
            f = feats[0]
            items = await read_items(app, did, state, f)
            if item is not None:
                items = [x for x in items if item_key(f, x) == item]
            out |= {"feature": f, "count": len(items), "items": [shown(x) for x in items]}
            if not items:
                what = f" {item}" if item else ""
                out["note"] = f"No {state} {f}{what} on this switch." + (
                    " The intended model starts empty after PDC is enabled: it holds only what is changed "
                    "through Catalyst Center."
                    if state == "intended" and not item
                    else ""
                )
            return object_result(out)

        sec, errors = await gated({f: read_items(app, did, state, f) for f in feats})
        summary: dict[str, Any] = {}
        empty: list[str] = []
        for f in feats:
            got = sec.get(f)
            if got is None:
                continue
            if not got:
                empty.append(f)
                continue
            keys = sorted(item_key(f, x) for x in got)
            row: dict[str, Any] = {"count": len(got)}
            if key_field(f):
                row["keys"] = keys[:KEYS_SHOWN]
                if len(keys) > KEYS_SHOWN:
                    row["more"] = len(keys) - KEYS_SHOWN
            summary[f] = row
        out |= {"features": summary, "no_data": empty}
        if not summary and state == "intended":
            out["note"] = (
                "Nothing intended yet: the intended model holds only what is changed through Catalyst Center "
                "(catc_set_wired_feature). state='deployed' shows what was learned from the switch."
            )
        if errors:
            out["unavailable"] = errors
        return object_result(out)

    @reg.write(title="Set wired feature")
    async def catc_set_wired_feature(
        ctx: Context,
        device: Annotated[str, Field(description="Switch: hostname, management IP, serial or id")],
        feature: Annotated[
            str,
            Field(description="Layer-2 feature, e.g. vlanConfig, stpGlobalConfig, switchportInterfaceConfig"),
        ],
        items: Annotated[
            list[dict[str, Any]],
            Field(
                description="Feature items with the schema's fields (catc_get_definition), e.g. vlanConfig "
                "[{'vlanId': 999, 'name': 'mcp-999'}], switchportInterfaceConfig [{'interfaceName': "
                "'GigabitEthernet1/0/5', 'mode': 'ACCESS', 'accessVlan': 999}], stpGlobalConfig [{'stpMode': "
                "'RSTP'}]. configType is filled in. mode='remove' needs only the keys (vlanId, interfaceName)"
            ),
        ] = [],  # noqa: B006 - FastMCP copies defaults per call
        mode: Annotated[
            Mode,
            Field(
                description="'merge' (default): the given fields into the intended items (added when new); "
                "'replace': the items become the feature's whole intent; 'remove': take these items out of "
                "the intent; 'delete': drop the feature's intent entirely"
            ),
        ] = "merge",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Store a change to a switch's per-device intended layer-2 configuration (Per Device Configuration
        enabled): add or change VLANs, STP/VTP/CDP/LLDP/snooping globals, or per-interface switchport, trunk,
        802.1X/MAB settings. Nothing reaches the switch until catc_deploy_wired_config. Preview-first: the
        preview lists each item added, changed or removed, field by field."""
        app: CatcApp = get_client(ctx)
        if mode == "delete" and items:
            raise InvalidRequest("mode='delete' drops the whole feature intent: give no items.")
        if mode != "delete" and not items:
            raise InvalidRequest("Give the items to " + mode + ".")
        dev, did = await wired_target(app, device)
        names, reason = await supported(app, did)
        if reason:
            raise InvalidRequest(f"{PDC_NOTE} (Catalyst Center: '{reason}')")
        feat = pick_feature(feature, names)
        if canonical(feat) not in FEATURES:
            raise InvalidRequest(
                f"{feat} has no known schema here; use catc_api_call with catc_get_definition."
            )
        given = check_items(feat, items, keys_only=mode == "remove")
        keys_given = [item_key(feat, x) for x in items]
        want, have = await asyncio.gather(
            read_items(app, did, "intended", feat), read_items(app, did, "deployed", feat)
        )
        cur = {item_key(feat, x): x for x in want}
        dep = {item_key(feat, x): x for x in have}
        blockers: list[str] = []
        plan_items: dict[str, Any] = {}
        result: list[dict[str, Any]]
        if mode == "merge":
            merged = dict(cur)
            for g in given:
                k = item_key(feat, g)
                base = cur.get(k) or dep.get(k)
                src = "intended" if k in cur else "deployed (learned from the switch)" if k in dep else "new"
                new = {**(base or {}), **g}
                diff = changes(base, new)
                if diff:
                    plan_items[k] = {
                        "action": "add" if k not in cur else "update",
                        "source": src,
                        "fields": diff,
                    }
                    merged[k] = new
            result = list(merged.values())
        elif mode == "replace":
            new_keys = {item_key(feat, g): g for g in given}
            for k, g in new_keys.items():
                diff = changes(cur.get(k), g)
                if diff or k not in cur:
                    plan_items[k] = {"action": "add" if k not in cur else "replace", "fields": diff}
            for k in sorted(cur.keys() - new_keys.keys()):
                plan_items[k] = {"action": "remove from intent"}
            result = list(new_keys.values())
        elif mode == "remove":
            for k in keys_given:
                if k in cur:
                    plan_items[k] = {"action": "remove from intent"}
                else:
                    blockers.append(
                        f"{feat} {k} is not in the intended model"
                        + (" (only deployed: learned from the switch, never intended)" if k in dep else "")
                        + "."
                    )
            result = [x for k, x in cur.items() if k not in keys_given]
        else:
            plan_items = {k: {"action": "remove from intent"} for k in sorted(cur)}
            result = []
            if not cur:
                blockers.append(f"No intended {feat} on this switch: nothing to delete.")
        if not plan_items and not blockers:
            blockers.append(f"The intended {feat} already has these values; nothing to change.")

        per_feature = feature_path(did, "intended", feat)
        if not result:
            method, path = "DELETE", per_feature
        elif cur:
            method, path = "PUT", per_feature
        else:
            method, path = "POST", per_feature
        # TODO(live): whether 3.2.2 read records carry an id or other read-only fields to leave out.
        send = [{k: v for k, v in x.items() if k != "id"} for x in result]
        if any(has_mask(x) for x in send):
            blockers.append(
                "An intended item holds a masked secret (the DHCP snooping database URL password): give the "
                "whole item with the URL so it isn't lost."
            )
        details: dict[str, Any] = {
            "device": brief([dev])[0],
            "feature": feat,
            "mode": mode,
            "items": plan_items,
            "intended_after": [item_key(feat, x) for x in result] if key_field(feat) else len(result),
            "request": f"{method} {path}",
            "next": "catc_get_wired_config(diff=true), then catc_deploy_wired_config pushes it",
        }
        if mode in ("remove", "delete", "replace") and any(
            v.get("action") == "remove from intent" for v in plan_items.values()
        ):
            details["removal_note"] = (
                "Removing an item from the intent is not a 'no' on the switch by itself: deploy is additive. "
                "catc_deploy_wired_config's CLI preview shows what the switch gets."
            )
        plan = Plan(
            f"{'Delete' if method == 'DELETE' else 'Store'} intended {feat} on {brief([dev])[0]} ({mode})",
            details=details,
            side_effects=[STAGED],
            fingerprint={"intended": norm(want), "mode": mode},
            blockers=blockers,
        )

        async def apply() -> Any:
            if method == "DELETE":
                job = await app.run_job("DELETE", path, ctx=ctx, what=f"delete intended {feat}")
            elif method == "PUT":
                job = await app.run_job(
                    "PUT", path, body(feat, send), ctx=ctx, what=f"update intended {feat}"
                )
            else:
                try:
                    job = await app.run_job(
                        "POST", path, body(feat, send), ctx=ctx, what=f"create intended {feat}"
                    )
                except UpstreamError as first:
                    # The spec: "POST .../intended/layer2 is needed the first time any intended features are
                    # added for a device". TODO(live): which one 3.2.2 wants for the first feature.
                    if isinstance(first, NotFound) or getattr(first, "status_code", None) in (
                        400,
                        404,
                        409,
                        500,
                    ):
                        job = await app.run_job(
                            "POST",
                            f"{WIRED}/{did}/configFeatures/intended/layer2",
                            body(feat, send),
                            ctx=ctx,
                            what=f"create intended layer-2 features ({feat})",
                        )
                        job["note"] = (
                            f"Per-feature create refused ({str(first)[:200]}); "
                            "created through intended/layer2."
                        )
                    else:
                        raise
            return {**job, "next": "catc_deploy_wired_config"}

        return await preview_or_apply(
            ctx,
            tool="catc_set_wired_feature",
            args={"device": device, "feature": feature, "items": items, "mode": mode},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Deploy wired config", task=True)
    async def catc_deploy_wired_config(
        ctx: Context,
        device: Annotated[str, Field(description="Switch: hostname, management IP, serial or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Deploy a switch's per-device intended layer-2 configuration (what catc_set_wired_feature stored).
        The preview builds a Catalyst Center configuration model and shows the exact CLI the switch will get
        (the model is discarded unless confirmed), plus the intended-vs-deployed diff per feature; confirm
        deploys that model and reports each config group's status. Additive: configuration the intent
        doesn't name stays on the switch. Preview-first."""
        app: CatcApp = get_client(ctx)
        dev, did = await wired_target(app, device)
        blockers = device_limit_blockers(app, 1)
        names, reason = await supported(app, did)
        pending: dict[str, Any] = {}
        in_sync: list[str] = []
        unreadable: dict[str, str] = {}
        cli: list[dict[str, Any]] = []
        errs: list[str] = []
        status: str | None = None
        pid: str | None = None
        if reason:
            blockers.append(f"{PDC_NOTE} (Catalyst Center: '{reason}')")
        else:
            pending, in_sync, unreadable = await diff_all(app, did, sorted(names))
            try:
                made = await app.run_job("POST", model_path(did), ctx=ctx, what="build configuration model")
                pid = str(made.get("task_id") or "") or None
                if pid is None:
                    raise UpstreamError(f"No preview activity id in the configuration model answer: {made}")
                await app.run_job(
                    "POST", f"{model_path(did, pid)}/config", ctx=ctx, what="generate device CLI"
                )
                cli, errs, status = cli_text(await app.api.get(f"{model_path(did, pid)}/config"))
            except UpstreamError as e:
                blockers.append(f"Catalyst Center could not build the CLI preview: {str(e)[:300]}")
            if errs:
                blockers.append("The CLI preview has errors: " + " | ".join(errs[:10]))
            if pid and not cli and not errs:
                blockers.append("The intent generates no CLI for this switch: nothing to deploy.")
        prov = await app.get_response(SETTINGS)
        prov = prov if isinstance(prov, dict) else {}
        itsm = bool(prov.get("requireItsmApproval"))
        details: dict[str, Any] = {
            "device": brief([dev])[0],
            "software": dev.get("softwareVersion"),
            "reachability": dev.get("reachabilityStatus"),
            "cli_preview": cli,
            "preview_status": status,
            "pending_changes": pending,
            "features_in_sync": sorted(in_sync),
            "request": (
                f"POST {model_path(did, pid)}/deploy"
                if pid
                else f"POST {model_path(did)}/<preview activity id>/deploy"
            ),
            "status": "per config group, from intended/deviceDeployments",
            "kept_on_the_switch": "Configuration the intent doesn't name (deploy is additive).",
        }
        if pid:
            details["preview_activity_id"] = pid
            details["preview_note"] = (
                "The preview built a configuration model to generate this CLI and discards it again; the "
                "confirmed call builds a fresh one and deploys it only if its CLI is the same."
            )
        if itsm:
            details["itsm"] = "Provisioning requires ITSM approval: the deploy waits for the ITSM change."
        if unreadable:
            details["unreadable"] = unreadable
        plan = Plan(
            f"Deploy the intended layer-2 configuration to {brief([dev])[0]}"
            + (f": {len(cli)} CLI block(s)" if cli else ""),
            details=details,
            side_effects=[
                f"Pushes the CLI above to {brief([dev])[0]}"
                + (f" ({', '.join(sorted(pending))})." if pending else "."),
                "VLAN, switchport, STP or 802.1X changes can move or drop traffic on the affected ports.",
            ],
            fingerprint={"cli": cli, "device": did, "itsm": itsm},
            blockers=blockers,
            blast_radius=1,
        )
        applied = False

        async def apply() -> Any:
            nonlocal applied
            assert pid is not None  # a plan without a model has blockers
            applied = True
            started = int(time.time() * 1000) - 5000
            job = await app.run_job(
                "POST", f"{model_path(did, pid)}/deploy", ctx=ctx, what="wired config deploy"
            )
            act = str(job.get("task_id") or "") or None
            deadline = time.monotonic() + app.settings.mcp_task_timeout
            rows: list[dict[str, Any]] = []
            while True:
                found = await deployments(app, did, act)
                found = [
                    d
                    for d in found
                    if d.get("activityId") in (act, pid)
                    or int(d.get("startTime") or d.get("createTime") or 0) >= started
                ]
                rows = [deployment_row(d) for d in found]
                if settled(rows) or time.monotonic() > deadline:
                    break
                await asyncio.sleep(DEPLOY_POLL)
            out: dict[str, Any] = {
                "deploy": job,
                "preview_activity_id": pid,
                "status": status_counts(rows),
                "groups": rows,
            }
            bad = [r for r in rows if "success" not in str(r.get("status", "")).lower()]
            if bad:
                out["outcome"] = "failed" if settled(rows) else "running"
                out["note"] = (
                    f"{len(bad)} config group(s) did not deploy: see `error`. The intent stays stored and "
                    "fails the next deploy too until it is fixed or removed (catc_set_wired_feature)."
                    if settled(rows)
                    else "Some config groups were still running; check catc_get_wired_config(diff=true)."
                )
            elif not rows:
                out["outcome"] = "deployed"
                out["note"] = (
                    "The deploy task ended; no deviceDeployments row yet. Check with "
                    "catc_get_wired_config(diff=true)."
                )
            else:
                out["outcome"] = "success"
            return out

        try:
            return await preview_or_apply(
                ctx,
                tool="catc_deploy_wired_config",
                args={"device": device},
                confirm=confirm,
                plan=plan,
                apply=apply,
            )
        finally:
            if pid and not applied:
                # A preview (or a refused confirm) leaves no model behind.
                with contextlib.suppress(UpstreamError):
                    await app.api.request("DELETE", model_path(did, pid))
