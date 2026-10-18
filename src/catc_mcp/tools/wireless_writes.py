"""Wireless per-device writes (roadmap D71): a curated few changes to a Catalyst 9800 WLC's per-device
configuration, then one deploy.

Catalyst Center keeps one intended model per 9800 feature (read with catc_get_wlc_config, D70). The set tools
stage a change in that model with `POST .../intended/<group>/update` (op MERGE: only the fields given change);
nothing reaches the WLC until catc_deploy_wlc_config, which pushes everything intended (`POST
.../intended/deploy`) and reports each config group's status from `.../intended/deviceDeployments`.

- catc_set_wlan_security: a WLAN profile's security (open, WPA2/WPA3 personal or enterprise, PSK, method list)
- catc_set_wlan_vlan: the VLAN (or VLAN group) of a policy profile, found from a WLAN through the policy tags
- catc_set_rf_profile: an RF profile's state, TX power range, DCA channel width, client limit, description

Everything else in the models (policy and site tags, AP join, flex, mDNS...) stays on catc_api_call.

Per-device configuration is read-write only for a 9800 never provisioned through site-based network profiles,
after "Enable Per-Device Configuration" in its device details (GUI only in 3.2.2) and a resync; a WLC
provisioned with site-based profiles (catc_provision_wireless_controller) answers 404 NCWS70003. Deploy is
refused while the global provisioning settings require preview or ITSM approval. See
docs/wireless-per-device.md.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import hmac
import os
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, get_args

from fastmcp import Context
from pydantic import Field, SecretStr

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
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.wireless_config import (
    CAMPUS,
    FEATURES,
    UNSET,
    comparable,
    diff_features,
    feature_path,
    is_wlc_secret,
    no_models_reason,
    read_records,
    split_beta,
)

SETTINGS = "/dna/intent/api/v1/provisioningSettings"
# Per-process key: confirm tokens bind a keyed digest of the passphrase, never the value or a plain hash.
_DIGEST_KEY = os.urandom(32)
PER_DEVICE_NOTE = (
    "This WLC has no writable per-device configuration (Catalyst Center: '{reason}'). The intended models "
    "are read-write only for a 9800 never provisioned through site-based network profiles, after 'Enable "
    "Per-Device Configuration' in its device details (Catalyst Center GUI; no API in 3.2.2) and a resync. "
    "A site-based WLC changes through its design instead (catc_create_ssid, catc_create_wireless_profile, "
    "catc_provision_wireless_controller)."
)
STAGED = (
    "Stages the change in Catalyst Center's intended model only: the WLC is unchanged until "
    "catc_deploy_wlc_config."
)
DEPLOY_POLL = 2.0  # seconds between deviceDeployments reads after the deploy task ends
DONE = ("success", "fail", "error", "abort", "rollback", "complete")
SOURCE = {
    "intended": "intended model",
    "deployed": "learned from the WLC (deployed only): the change adds it to the intended model",
}
# The 9800's pre-configured RF profiles: the WLC refuses any change to them.
PRECONFIGURED_RF = frozenset(
    f"{d}_Client_Density_rf_{b}" for d in ("High", "Low", "Typical") for b in ("24gh", "5gh")
) | {"default-rf-profile-6ghz"}
FT_ADAPTIVE = "DOT11R_ADAPTIVE_ENABLED"
DEEP = ("policy_tags",)  # features whose sub-collections the deploy preview diffs

Security = Literal[
    "OPEN", "WPA2_PERSONAL", "WPA2_ENTERPRISE", "WPA3_PERSONAL", "WPA2_WPA3_PERSONAL", "WPA3_ENTERPRISE"
]
# Every AKM the curated modes touch: all are set explicitly, so a mode change clears the old one.
AKM_FLAGS = (
    "authKeyMgmtPskEnabled",
    "authKeyMgmtSaeEnabled",
    "authKeyMgmtDot1xEnabled",
    "authKeyMgmtDot1xSha256Enabled",
    "authKeyMgmtFtPskEnabled",
    "authKeyMgmtFtSaeEnabled",
    "authKeyMgmtFtDot1xEnabled",
    "authKeyMgmtOweEnabled",
)
ChannelWidth = Literal["20", "40", "80", "160", "best"]


def security_fields(security: str, auth_list: str | None) -> dict[str, Any]:
    """The WlanProfile fields (17.12+) for one curated security mode. WPA3-only modes require PMF;
    WPA2/WPA3 transition makes it optional."""
    out: dict[str, Any] = dict.fromkeys(AKM_FLAGS, False)
    if security == "OPEN":
        return out | {
            "wlanSecurityWpaEnabled": False,
            "wpa2Enabled": False,
            "wpa3Enabled": False,
            "protectedManagementFrameOptions": "APF_VAP_PMF_DISABLED",
        }
    wpa2 = security in ("WPA2_PERSONAL", "WPA2_ENTERPRISE", "WPA2_WPA3_PERSONAL")
    wpa3 = security.startswith("WPA3") or security == "WPA2_WPA3_PERSONAL"
    pmf = (
        "APF_VAP_PMF_OPTIONAL"
        if wpa2 and wpa3
        else "APF_VAP_PMF_REQUIRED"
        if wpa3
        else "APF_VAP_PMF_DISABLED"
    )
    out |= {
        "wlanSecurityWpaEnabled": True,
        "wpa2Enabled": wpa2,
        "wpa3Enabled": wpa3,
        "wpa2AesEnabled": True,  # CCMP128: WPA3 uses it too
        "protectedManagementFrameOptions": pmf,
    }
    if security.endswith("PERSONAL"):
        out |= {"authKeyMgmtPskEnabled": wpa2, "authKeyMgmtSaeEnabled": wpa3, "wlanPskKeyType": "KEY_ASCII"}
    else:
        out["authKeyMgmtDot1xEnabled" if wpa2 else "authKeyMgmtDot1xSha256Enabled"] = True
        if auth_list:
            out["wlanAuthenticationList"] = auth_list
    return out


def current_security(rec: dict[str, Any]) -> str:
    """The curated mode a WLAN profile record is in, or a short description of what it has instead."""
    if not rec.get("wlanSecurityWpaEnabled", True) or not any(rec.get(k) for k in AKM_FLAGS):
        return "OPEN"
    flags = (*AKM_FLAGS, "wpa2Enabled", "wpa3Enabled")
    for mode in get_args(Security)[1:]:
        want = security_fields(mode, None)
        if all(bool(rec.get(k)) == want[k] for k in flags):
            return str(mode)
    on = [k.removeprefix("authKeyMgmt").removesuffix("Enabled") for k in AKM_FLAGS if rec.get(k)]
    wpa = "+".join(v for v, k in (("WPA2", "wpa2Enabled"), ("WPA3", "wpa3Enabled")) if rec.get(k))
    return f"other ({wpa or 'no WPA version'}, AKM {'/'.join(on)})"


def changes(rec: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
    """{field: {from, to}} for the fields whose value would change (secrets never shown)."""
    out: dict[str, Any] = {}
    for k, v in fields.items():
        cur = rec.get(k, UNSET)
        if cur != v and not (cur == UNSET and v is False):  # an unset flag is already off
            out[k] = {"from": cur, "to": v}
    return out


def millis(ts: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(ts) / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return str(ts) if ts else None


def deployment_row(d: dict[str, Any]) -> dict[str, Any]:
    err: dict[str, Any] = d["error"] if isinstance(d.get("error"), dict) else {}
    row: dict[str, Any] = compact(
        {
            "config_group": d.get("configGroupName"),
            "version": d.get("configGroupVersion"),
            "status": d.get("status"),
            "started": millis(d.get("startTime")),
            "ended": millis(d.get("endTime")),
            "error": err.get("message"),
            "remedy": err.get("remedy"),
            "activity_id": d.get("activityId") or d.get("deployActivityId"),
        }
    )
    return row


def status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        s = str(r.get("status") or "?")
        out[s] = out.get(s, 0) + 1
    return out


def settled(rows: list[dict[str, Any]]) -> bool:
    return bool(rows) and all(any(x in str(r.get("status", "")).lower() for x in DONE) for r in rows)


async def deployments(app: CatcApp, did: str, activity: str | None = None) -> list[dict[str, Any]]:
    params = {"deployActivityId": safe_id(activity, "activity id")} if activity else None
    got = await app.get_response(f"{CAMPUS}/{did}/intended/deviceDeployments", params=params)
    rows = [d for d in ensure_list(got) if isinstance(d, dict)]
    return sorted(rows, key=lambda d: int(d.get("startTime") or d.get("createTime") or 0), reverse=True)


def activity_id(job: dict[str, Any]) -> str | None:
    """The deploy activity: an activityId in the task's data or progress, else (3.2.2) the deploy task's id,
    which deviceDeployments reports as deployActivityId."""
    for v in (job.get("data"), job.get("progress"), job.get("task_id")):
        if isinstance(v, dict):
            v = v.get("activityId") or v.get("deployActivityId")
        if isinstance(v, str) and len(v) == 36 and v.count("-") == 4:
            return v
    return None


async def wlc_target(app: CatcApp, wlc: str) -> tuple[dict[str, Any], str]:
    dev = await resolve_device(app, wlc)
    if "Wireless Controller" not in str(dev.get("family")):
        raise InvalidRequest(f"{brief([dev])[0]} is a {dev.get('family')}, not a wireless controller.")
    return dev, safe_id(str(dev["id"]), "device id")


async def current_records(app: CatcApp, did: str, key: str) -> list[dict[str, Any]]:
    """One feature's records as the next deploy sees them: the intended ones, plus the deployed ones the
    intended model lacks (a brownfield WLC: enabling per-device configuration learns the running config
    into the deployed model only; a MERGE adds the record to the intended model). Each carries `_source`.
    Refused, with Catalyst Center's reason, on a WLC without per-device configuration."""
    feat = FEATURES[key]
    path = feature_path(did, "intended", feat)
    reason = await no_models_reason(app, path)
    if reason:
        raise InvalidRequest(PER_DEVICE_NOTE.format(reason=reason))
    (want, _), (have, _) = await asyncio.gather(
        read_records(app, path), read_records(app, feature_path(did, "deployed", feat))
    )
    names = {r.get(feat.name) for r in want}
    return [{**r, "_source": "intended"} for r in want] + [
        {**r, "_source": "deployed"} for r in have if r.get(feat.name) not in names
    ]


def pick(recs: list[dict[str, Any]], value: str, keys: tuple[str, ...], what: str) -> dict[str, Any]:
    found = [r for r in recs if value in (*(r.get(k) for k in keys), r.get("id"))]
    if not found:
        names = sorted(str(r.get(keys[0])) for r in recs)
        raise NotFound(f"No {what} {value} on this WLC (has: {', '.join(names) or 'none'}).")
    if len(found) > 1:
        raise InvalidRequest(
            f"{len(found)} {what}s match {value}: "
            + ", ".join(str(r.get(keys[0])) for r in found)
            + f"; give the {keys[0]}."
        )
    return found[0]


def merge_body(
    feature: str, rec: dict[str, Any], keys: tuple[str, ...], fields: dict[str, Any]
) -> dict[str, Any]:
    """One MERGE of `fields` into the record named by `keys` (the schema's required identifiers). A record
    learned from the WLC (deployed only) goes in whole, secrets aside, so the intended record is the WLC's
    record plus the change, never a sparse one a deploy could fill with schema defaults."""
    ident = {k: rec[k] for k in keys if rec.get(k) not in (None, "")}
    base: dict[str, Any] = {}
    if rec.get("_source") == "deployed":
        base = {
            k: v
            for k, v in rec.items()
            if k not in ("id", "_source")
            and v not in (None, "")
            and not (is_wlc_secret(k) and not isinstance(v, bool))
        }
    return {feature: {**base, "op": "MERGE", "deviceVersion": rec.get("deviceVersion"), **ident, **fields}}


async def wlan_policy_map(app: CatcApp, did: str) -> list[dict[str, str]]:
    """Every WLAN-to-policy mapping the next deploy keeps: [{policy_tag, wlan, policy}] from the policy tags
    (intended, plus deployed tags the intended model lacks), each tag's mappings read in its own state."""
    tags = [t for t in await current_records(app, did, "policy_tags") if t.get("id")]
    feat = FEATURES["policy_tags"]

    def rows(t: dict[str, Any]) -> Any:
        base = feature_path(did, str(t["_source"]), feat)
        return read_records(app, f"{base}/{safe_id(str(t['id']), 'policy tag id')}/policyTagWlanPolicies")

    out: list[dict[str, str]] = []
    for t, (maps, _) in zip(tags, await asyncio.gather(*(rows(t) for t in tags)), strict=True):
        for r in maps:
            out.append(
                {
                    "policy_tag": str(t.get("policyTagName")),
                    "wlan": str(r.get("wlanPolicyWlanProfileName")),
                    "policy": str(r.get("wlanPolicyPolicyProfileName")),
                }
            )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Set WLAN security")
    async def catc_set_wlan_security(
        ctx: Context,
        wlc: Annotated[str, Field(description="Catalyst 9800 WLC: hostname, management IP, serial or id")],
        wlan: Annotated[str, Field(description="WLAN profile name or SSID")],
        security: Annotated[Security, Field(description="Security mode")],
        passphrase: Annotated[
            SecretStr | None,
            Field(
                description="PERSONAL modes: the pre-shared key, 8-63 characters (never echoed); may be "
                "left out when the WLAN is already PERSONAL, keeping its key"
            ),
        ] = None,
        auth_list: Annotated[
            str | None,
            Field(max_length=128, description="ENTERPRISE modes: the AAA authentication method list name"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stage a WLAN's security in the WLC's per-device intended configuration: open, WPA2/WPA3 personal
        (PSK/SAE) or enterprise (802.1X with an AAA method list); PMF follows the mode. Nothing reaches the
        WLC until catc_deploy_wlc_config. Preview-first; the passphrase is masked and never stored."""
        app: CatcApp = get_client(ctx)
        dev, did = await wlc_target(app, wlc)
        rec = pick(await current_records(app, did, "wlan_profiles"), wlan, ("profileName", "ssid"), "WLAN")
        personal = security.endswith("PERSONAL")
        was = current_security(rec)
        blockers: list[str] = []
        if personal and passphrase is None and rec["_source"] == "deployed":
            blockers.append(
                f"{rec.get('profileName')} was learned from the WLC, which returns no usable PSK: give the "
                "passphrase (it becomes part of the intended record)."
            )
        elif personal and passphrase is None and not was.endswith("PERSONAL"):
            blockers.append(
                f"{security} needs a passphrase: {rec.get('profileName')} has no PSK now ({was})."
            )
        if passphrase is not None and not personal:
            raise InvalidRequest("A passphrase only applies to PERSONAL modes.")
        if passphrase is not None and not 8 <= len(passphrase.get_secret_value()) <= 63:
            raise InvalidRequest("The passphrase must be 8-63 characters.")
        if auth_list and personal:
            raise InvalidRequest("auth_list only applies to ENTERPRISE modes.")
        if security.endswith("ENTERPRISE") and not (auth_list or rec.get("wlanAuthenticationList")):
            blockers.append("802.1X needs an AAA authentication method list (auth_list).")
        fields = security_fields(security, auth_list)
        if fields["wpa3Enabled"] and rec.get("fastTransition") in (None, "", FT_ADAPTIVE):
            # 17.18 refuses adaptive 802.11r with WPA3 ("FT Adaptive is not allowed when both WPA2 and
            # WPA3 are enabled"); unset means the schema default, adaptive.
            fields["fastTransition"] = "DOT11R_DISABLED"
        diff = changes(rec, fields)
        if not diff and passphrase is None:
            blockers.append(f"{rec.get('profileName')} is already {security}; nothing to change.")
        if passphrase is not None:
            diff["passphrase"] = {"from": MASK if rec.get("passphrase") else UNSET, "to": f"{MASK} (new)"}
        path = f"{CAMPUS}/{did}/intended/ssids/update"
        keys = ("profileName", "wlanId")
        plan = Plan(
            f"Stage {security} on WLAN {rec.get('profileName')} (SSID {rec.get('ssid')}) "
            f"of {brief([dev])[0]}",
            details={
                "wlan": compact({k: rec.get(k) for k in ("profileName", "ssid", "wlanId")}),
                "source": SOURCE[rec["_source"]],
                "security": {"current": was, "new": security},
                "changes": diff,
                "passphrase": (
                    "new (masked)" if passphrase is not None else "kept" if personal else "not used"
                ),
                "request": f"POST {path} (wlanProfiles, op MERGE)",
                "next": "catc_deploy_wlc_config pushes it to the WLC",
            },
            side_effects=[STAGED],
            fingerprint={"record": comparable(rec), "version": rec.get("deviceVersion")},
            blockers=blockers,
        )

        async def apply() -> Any:
            send = dict(fields)
            if passphrase is not None:
                send["passphrase"] = passphrase.get_secret_value()
            job = await app.run_job(
                "POST", path, merge_body("wlanProfiles", rec, keys, send), ctx=ctx, what="stage WLAN security"
            )
            return {**job, "next": "catc_deploy_wlc_config"}

        return await preview_or_apply(
            ctx,
            tool="catc_set_wlan_security",
            args={
                "wlc": wlc,
                "wlan": wlan,
                "security": security,
                # bound by digest, so a different passphrase needs a new preview; never the value itself
                "passphrase": (
                    hmac.new(_DIGEST_KEY, passphrase.get_secret_value().encode(), hashlib.sha256).hexdigest()[
                        :16
                    ]
                    if passphrase
                    else None
                ),
                "auth_list": auth_list,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set WLAN VLAN")
    async def catc_set_wlan_vlan(
        ctx: Context,
        wlc: Annotated[str, Field(description="Catalyst 9800 WLC: hostname, management IP, serial or id")],
        vlan: Annotated[
            str,
            Field(
                min_length=1,
                max_length=32,
                pattern=r"^[!-~]+$",
                description="VLAN id (1-4094), VLAN name or VLAN group the clients land in",
            ),
        ],
        wlan: Annotated[
            str | None,
            Field(description="WLAN profile name or SSID: its policy profile is found from the policy tags"),
        ] = None,
        policy_profile: Annotated[
            str | None, Field(description="The policy profile, instead of `wlan`")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stage the VLAN of a WLAN's policy profile in the WLC's per-device intended configuration (the
        policy profile's interfaceName). Give the WLAN (resolved through the policy tags) or the policy
        profile; the preview lists every WLAN that uses that policy profile. Nothing reaches the WLC until
        catc_deploy_wlc_config. Preview-first."""
        app: CatcApp = get_client(ctx)
        if (wlan is None) == (policy_profile is None):
            raise InvalidRequest("Give either `wlan` or `policy_profile`.")
        if vlan.isdigit() and not 1 <= int(vlan) <= 4094:
            raise InvalidRequest("A VLAN id is 1-4094.")
        dev, did = await wlc_target(app, wlc)
        profiles = await current_records(app, did, "policy_profiles")
        mapping = await wlan_policy_map(app, did)
        target = policy_profile or ""
        if wlan is not None:
            w = pick(await current_records(app, did, "wlan_profiles"), wlan, ("profileName", "ssid"), "WLAN")
            via = sorted({m["policy"] for m in mapping if m["wlan"] == w.get("profileName")})
            if not via:
                raise NotFound(
                    f"No policy tag maps WLAN {w.get('profileName')} to a policy profile; "
                    "give `policy_profile`."
                )
            if len(via) > 1:
                raise InvalidRequest(
                    f"WLAN {w.get('profileName')} maps to {len(via)} policy profiles ({', '.join(via)}) in "
                    "different policy tags; give `policy_profile`."
                )
            target = via[0]
        rec = pick(profiles, target, ("policyProfileName",), "policy profile")
        name = str(rec.get("policyProfileName"))
        users = sorted({f"{m['wlan']} ({m['policy_tag']})" for m in mapping if m["policy"] == name})
        diff = changes(rec, {"interfaceName": vlan})
        blockers = [] if diff else [f"Policy profile {name} already uses VLAN {vlan}."]
        path = f"{CAMPUS}/{did}/intended/ssids/update"
        plan = Plan(
            f"Stage VLAN {vlan} on policy profile {name} of {brief([dev])[0]}",
            details={
                "policy_profile": name,
                "source": SOURCE[rec["_source"]],
                "changes": diff,
                "wlans_using_it": users,
                "request": f"POST {path} (policyProfiles, op MERGE)",
                "next": "catc_deploy_wlc_config pushes it; clients of these WLANs then land in the new VLAN",
            },
            side_effects=[STAGED],
            fingerprint={"record": comparable(rec), "users": users},
            blockers=blockers,
        )

        async def apply() -> Any:
            body = merge_body("policyProfiles", rec, ("policyProfileName",), {"interfaceName": vlan})
            job = await app.run_job("POST", path, body, ctx=ctx, what="stage policy profile VLAN")
            return {**job, "next": "catc_deploy_wlc_config"}

        return await preview_or_apply(
            ctx,
            tool="catc_set_wlan_vlan",
            args={"wlc": wlc, "vlan": vlan, "wlan": wlan, "policy_profile": policy_profile},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set RF profile")
    async def catc_set_rf_profile(
        ctx: Context,
        wlc: Annotated[str, Field(description="Catalyst 9800 WLC: hostname, management IP, serial or id")],
        rf_profile: Annotated[str, Field(description="RF profile name")],
        enabled: Annotated[bool | None, Field(description="Profile state (active or not)")] = None,
        tx_power_min: Annotated[int | None, Field(ge=-10, le=30, description="Minimum TX power, dBm")] = None,
        tx_power_max: Annotated[int | None, Field(ge=-10, le=30, description="Maximum TX power, dBm")] = None,
        channel_width: Annotated[
            ChannelWidth | None, Field(description="DCA channel width in MHz, or 'best'")
        ] = None,
        max_clients: Annotated[
            int | None, Field(ge=0, le=500, description="Maximum clients per AP radio")
        ] = None,
        description: Annotated[str | None, Field(max_length=64, description="Profile description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stage RF profile settings in the WLC's per-device intended configuration: state, TX power range,
        DCA channel width, client limit, description (only the ones given change). The preview names the RF
        tags that use the profile. Nothing reaches the WLC until catc_deploy_wlc_config. Preview-first."""
        app: CatcApp = get_client(ctx)
        given = {
            "rfProfileStatus": enabled,
            "rfProfileTxPowerMin": tx_power_min,
            "rfProfileTxPowerMax": tx_power_max,
            "rfProfileRfDcaChannelWidth": (
                f"RF_DCA_CHAN_WIDTH_{channel_width.upper()}" + ("" if channel_width == "best" else "_MHZ")
                if channel_width
                else None
            ),
            "rfProfileMaxRadioClients": max_clients,
            "rfProfileDescription": description,
        }
        fields = {k: v for k, v in given.items() if v is not None}
        if not fields:
            raise InvalidRequest("Nothing to change: give at least one setting.")
        dev, did = await wlc_target(app, wlc)
        rec = pick(
            await current_records(app, did, "rf_profiles"), rf_profile, ("rfProfileName",), "RF profile"
        )
        name = str(rec.get("rfProfileName"))
        if name in PRECONFIGURED_RF:
            raise InvalidRequest(
                f"{name} is one of the 9800's pre-configured RF profiles, which the WLC refuses to change "
                "(live 17.18: 'PreConfigured rf profile can not be updated'). Use a custom RF profile."
            )
        lo = fields.get("rfProfileTxPowerMin", rec.get("rfProfileTxPowerMin"))
        hi = fields.get("rfProfileTxPowerMax", rec.get("rfProfileTxPowerMax"))
        blockers = []
        if isinstance(lo, int) and isinstance(hi, int) and lo > hi:
            blockers.append(f"TX power minimum {lo} dBm would exceed the maximum {hi} dBm.")
        diff = changes(rec, fields)
        if not diff:
            blockers.append(f"RF profile {name} already has these settings.")
        try:
            tags = await current_records(app, did, "rf_tags")
        except UpstreamError:
            tags = []
        used_by = sorted(
            str(t.get("rfTagTagName")) for t in tags if any(v == name for k, v in t.items() if k != "id")
        )
        path = f"{CAMPUS}/{did}/intended/radioFrequencies/update"
        plan = Plan(
            f"Stage RF profile {name} settings on {brief([dev])[0]}",
            details={
                "rf_profile": name,
                "source": SOURCE[rec["_source"]],
                "band": rec.get("rfProfileBand"),
                "changes": diff,
                "rf_tags_using_it": used_by,
                "request": f"POST {path} (rfProfiles, op MERGE)",
                "next": "catc_deploy_wlc_config pushes it; AP radios in these RF tags then change",
            },
            side_effects=[STAGED],
            fingerprint={"record": comparable(rec), "tags": used_by},
            blockers=blockers,
        )

        async def apply() -> Any:
            body = merge_body("rfProfiles", rec, ("rfProfileName",), fields)
            job = await app.run_job("POST", path, body, ctx=ctx, what="stage RF profile")
            return {**job, "next": "catc_deploy_wlc_config"}

        return await preview_or_apply(
            ctx,
            tool="catc_set_rf_profile",
            args={
                "wlc": wlc,
                "rf_profile": rf_profile,
                "enabled": enabled,
                "tx_power_min": tx_power_min,
                "tx_power_max": tx_power_max,
                "channel_width": channel_width,
                "max_clients": max_clients,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Deploy WLC config", task=True)
    async def catc_deploy_wlc_config(
        ctx: Context,
        wlc: Annotated[str, Field(description="Catalyst 9800 WLC: hostname, management IP, serial or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Deploy a Catalyst 9800 WLC's per-device intended configuration to the WLC (what
        catc_set_wlan_security, catc_set_wlan_vlan and catc_set_rf_profile staged, and any other intended
        change). The preview is the
        intended-vs-deployed diff per feature: what the push changes. The result is each config group's
        deployment status (later: catc_get_wlc_deployments). Changes the WLC: clients of a changed WLAN may
        reconnect or move VLAN. Preview-first."""
        app: CatcApp = get_client(ctx)
        dev, did = await wlc_target(app, wlc)
        blockers = device_limit_blockers(app, 1)
        reason = await no_models_reason(app, feature_path(did, "intended", FEATURES["wlan_profiles"]))
        pending: dict[str, Any] = {}
        in_sync: list[str] = []
        unreadable: dict[str, str] = {}
        kept: dict[str, list[str]] = {}
        if reason:
            blockers.append(PER_DEVICE_NOTE.format(reason=reason))
        else:
            # Sub-collections only where a change hides in them (WLAN-to-policy mappings): one read per
            # record and feature on a brownfield WLC would run into the /dna/campus rate limits.
            flat = {k: f for k, f in FEATURES.items() if k not in DEEP}
            deep = {k: FEATURES[k] for k in DEEP}
            (p1, s1, u1), (p2, s2, u2) = await asyncio.gather(
                diff_features(app, did, flat, children=False), diff_features(app, did, deep, children=True)
            )
            diffs, in_sync, unreadable = {**p1, **p2}, s1 + s2, {**u1, **u2}
            unreadable, _ = split_beta(unreadable)
            # Deploy is additive (live 3.2.2): records only on the WLC (learned at enable time, or made on
            # the CLI) stay. Only what the intent adds or changes is pushed.
            for key, d in diffs.items():
                push = {k: d[k] for k in ("only_intended", "changed", "not_compared", "note") if d.get(k)}
                if push:
                    pending[key] = push
                else:
                    in_sync.append(key)  # only learned extras, which the deploy leaves
                if d.get("only_deployed"):
                    kept[key] = d["only_deployed"]
        prov = await app.get_response(SETTINGS)
        prov = prov if isinstance(prov, dict) else {}
        gates = [k for k in ("requirePreview", "requireItsmApproval") if prov.get(k)]
        if gates:
            blockers.append(
                "Catalyst Center refuses intended deploy while the provisioning settings have "
                f"{' and '.join(gates)} on ({SETTINGS}). That setting is global: it covers every "
                "provisioning flow, so turning it off is a separate, previewed change (catc_api_call PUT)."
            )
        changed = sorted(pending)
        details: dict[str, Any] = {
            "wlc": brief([dev])[0],
            "software": dev.get("softwareVersion"),
            "reachability": dev.get("reachabilityStatus"),
            "pending_changes": pending,
            "features_in_sync": sorted(in_sync),
            "kept_on_the_wlc": kept,
            "request": f"POST {CAMPUS}/{did}/intended/deploy",
            "status": "per config group, from intended/deviceDeployments (catc_get_wlc_deployments)",
            "not_shown": (
                "An intended record deleted since the last deploy (catc_api_call DELETE) is deleted on the "
                "WLC too, and no diff can show it."
            ),
        }
        if kept:
            details["kept_note"] = (
                "Records only on the WLC (learned when per-device configuration was enabled, or made outside "
                "Catalyst Center): the deploy is additive and leaves them."
            )
        if unreadable:
            details["unreadable"] = unreadable
        if not reason and not pending:
            details["note"] = "The intent adds or changes nothing on the WLC: the deploy pushes nothing new."
        side = [
            f"Pushes the intended configuration to {brief([dev])[0]}"
            + (f" ({', '.join(changed)})." if changed else ".")
        ]
        if {"wlan_profiles", "policy_profiles", "policy_tags"} & set(changed):
            side.append("Clients of a changed WLAN may disconnect and reconnect, or move to a new VLAN.")
        if {"rf_profiles", "rf_tags", "radio_profiles"} & set(changed):
            side.append("AP radios using a changed RF profile or tag change channel width or power.")
        plan = Plan(
            f"Deploy the intended configuration to WLC {brief([dev])[0]}"
            + (f": {len(changed)} feature(s) differ" if changed else ""),
            details=details,
            side_effects=side,
            fingerprint={"pending": pending, "kept": kept, "gates": gates, "device": did},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            started = int(time.time() * 1000) - 5000
            job = await app.run_job(
                "POST", f"{CAMPUS}/{did}/intended/deploy", ctx=ctx, what="WLC config deploy"
            )
            act = activity_id(job)
            deadline = time.monotonic() + app.settings.mcp_task_timeout
            rows: list[dict[str, Any]] = []
            while True:
                found = await deployments(app, did, act)
                if not act:  # no activity id: this deploy's groups are the ones started after the POST
                    found = [
                        d for d in found if int(d.get("startTime") or d.get("createTime") or 0) >= started
                    ]
                rows = [deployment_row(d) for d in found]
                if settled(rows) or time.monotonic() > deadline:
                    break
                await asyncio.sleep(DEPLOY_POLL)
            out: dict[str, Any] = {
                "deploy": job,
                "activity_id": act,
                "status": status_counts(rows),
                "groups": rows,
            }
            bad = [
                r
                for r in rows
                if "success" not in str(r.get("status", "")).lower()
                or "rollback" in str(r.get("status", "")).lower()
            ]
            if bad:
                out["outcome"] = "failed"
                out["note"] = (
                    f"{len(bad)} config group(s) did not deploy (Catalyst Center rolls a refused push back): "
                    "see `error`. The intended change stays staged and fails the next deploy too until it is "
                    "fixed or removed."
                )
            elif not settled(rows):
                out["outcome"] = "running"
                out["note"] = "Some config groups were still running; check with catc_get_wlc_deployments."
            else:
                out["outcome"] = "success"
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_deploy_wlc_config",
            args={"wlc": wlc},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="WLC deployments")
    async def catc_get_wlc_deployments(
        ctx: Context,
        wlc: Annotated[str, Field(description="Catalyst 9800 WLC: hostname, management IP, serial or id")],
        activity_id: Annotated[
            str | None,
            Field(description="Only this deploy (the activity_id catc_deploy_wlc_config returned)"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=200, description="Most recent config groups to show")] = 25,
    ) -> Any:
        """Configuration deployments Catalyst Center ran on a Catalyst 9800 WLC, newest first: per config
        group (WLAN, policy and RF groups, or the site settings of a site-based provision), its status, when
        it ran and Catalyst Center's error and remedy when it failed."""
        app: CatcApp = get_client(ctx)
        dev, did = await wlc_target(app, wlc)
        rows = [deployment_row(d) for d in await deployments(app, did, activity_id)]
        out: dict[str, Any] = {
            "wlc": brief([dev])[0],
            "total": len(rows),
            "status": status_counts(rows),
            "deployments": rows[:limit],
        }
        if len(rows) > limit:
            out["more"] = len(rows) - limit
        if not rows:
            out["note"] = "No deployments" + (
                f" for activity {activity_id}." if activity_id else " on this WLC."
            )
        return object_result(out)
