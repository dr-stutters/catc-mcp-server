"""Device access settings (roadmap D84): accept changed SSH host keys, the global SSH key policy, and the
inventory resync interval.

After a reimage, an RMA or `crypto key generate` a device presents a new SSH host key. With global
auto-accept off, Catalyst Center refuses it and the device stays out of sync until the new key is accepted
(GUI: Inventory > Actions > Accept SSH key, or `POST networkDevices/acceptSshKeyChange`). No endpoint lists
the pending key changes: they are read from the inventory records' collection-failure fields.

The resync interval is how often Catalyst Center re-collects a device's inventory (360-1440 minutes, global
default 1440 on 3.2.2; per device it can also be 0 = no periodic resync, or reset to the global value).
Payloads follow the bundled 3.2.2 spec: networkDevices/acceptSshKeyChange (AcceptSshKey),
networkDeviceSettings/sshKeySettings (SshKeyChangeSettings) and networkDevices[/{id}]/resyncIntervalSettings
(+ /override).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, Plan, ToolRegistrar, Undo, UpstreamError, get_client, preview_or_apply
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import pick, resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import Devices, brief, resolve_devices

ACCEPT_PATH = "/dna/intent/api/v1/networkDevices/acceptSshKeyChange"
SSH_SETTINGS_PATH = "/dna/intent/api/v1/networkDeviceSettings/sshKeySettings"
RESYNC_GLOBAL_PATH = "/dna/intent/api/v1/networkDevices/resyncIntervalSettings"
RESYNC_OVERRIDE_PATH = f"{RESYNC_GLOBAL_PATH}/override"
RESYNC_DEVICE_PATH = "/dna/intent/api/v1/networkDevices/{id}/resyncIntervalSettings"
DEVICES_PATH = "/dna/intent/api/v1/network-device"

MIN_INTERVAL, MAX_INTERVAL = 360, 1440  # the spec's range for both the global and the per-device interval
GLOBAL_DEFAULT = (
    "Global Default"  # the inventory record's collectionInterval for a device on the global value
)

# Where the inventory record says why collection failed. The key-mismatch wording is matched loosely
# ('SSH_KEY_VERIFICATION_ERROR', 'SSH host key changed', ...): the exact 3.2.2 text is not recorded yet
# (live proof of #139 records it).
FAILURE_FIELDS = (
    "errorCode",
    "reachabilityFailureReason",
    "errorDescription",
    "inventoryStatusDetail",
    "collectionStatus",
)
SSH_KEY_RE = re.compile(r"(ssh[\W_]*(host[\W_]*)?|host[\W_]*)keys?(?![a-z])", re.IGNORECASE)
SSH_KEY_HINT = "SSH key changed: accept with catc_accept_ssh_key (check the change was expected first)"

AUTO_ACCEPT_WARNING = (
    "Security posture change: with auto-accept on, Catalyst Center trusts any new SSH host key a device "
    "presents, so a reimaged or replaced device resyncs by itself but a man-in-the-middle on the management "
    "path is no longer caught. Validated deployments keep it off and accept keys per device "
    "(catc_accept_ssh_key)."
)
ACCEPT_WARNING = (
    "Catalyst Center trusts the device's new SSH host key from now on. Accept only a change you expect "
    "(reimage, RMA, 'crypto key generate'): an unexpected key change can mean a man-in-the-middle."
)


def ssh_key_failure(dev: dict[str, Any]) -> str | None:
    """The collection-failure text that says the device's SSH host key changed, or None."""
    for f in FAILURE_FIELDS:
        v = dev.get(f)
        if isinstance(v, str) and SSH_KEY_RE.search(v):
            return v.strip()[:300]
    return None


def collection_failure(dev: dict[str, Any]) -> str | None:
    """A short reason the device is not collected (None when it is managed and reachable)."""
    reach = str(dev.get("reachabilityStatus") or "")
    coll = str(dev.get("collectionStatus") or "")
    if reach.lower() == "reachable" and coll.lower() in ("managed", ""):
        return None
    parts = [
        str(dev[f]).strip()
        for f in ("errorCode", "reachabilityFailureReason")
        if isinstance(dev.get(f), str) and dev[f].strip()
    ]
    return "; ".join(parts) or coll or reach or None


async def auto_accept_state(app: CatcApp) -> bool | None:
    """The global autoAcceptSshKeys setting (None when it can't be read)."""
    with contextlib.suppress(UpstreamError):
        cur = await app.get_response(SSH_SETTINGS_PATH)
        if isinstance(cur, dict) and isinstance(cur.get("autoAcceptSshKeys"), bool):
            return bool(cur["autoAcceptSshKeys"])
    return None


async def device_interval(app: CatcApp, device_id: str) -> int | None:
    """The device's resync interval in minutes as Catalyst Center reports it (None if unreadable)."""
    with contextlib.suppress(UpstreamError):
        cur = await app.get_response(RESYNC_DEVICE_PATH.format(id=safe_id(device_id, "device id")))
        if isinstance(cur, dict) and isinstance(cur.get("interval"), int):
            return int(cur["interval"])
    return None


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Accept SSH key change", destructive=False, idempotent=True)
    async def catc_accept_ssh_key(
        ctx: Context,
        devices: Devices,
        resync: Annotated[
            bool, Field(description="Resync the devices right after accepting (recommended)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Accept the new SSH host key of devices whose key changed (after a reimage, an RMA or 'crypto key
        generate') so Catalyst Center can collect them again, and resync them. Preview-first: lists each
        device with its collection-failure reason and refuses any device that is not failing on an SSH
        host-key change. Check the global policy with catc_get_ssh_key_settings (with auto-accept on, no key
        change ever waits)."""
        app: CatcApp = get_client(ctx)
        devs = await resolve_devices(app, devices)
        rows: list[dict[str, Any]] = []
        blockers = device_limit_blockers(app, len(devs))
        for d in devs:
            key = ssh_key_failure(d)
            rows.append(
                {
                    "device": brief([d])[0],
                    "reachability": d.get("reachabilityStatus"),
                    "collection": d.get("collectionStatus"),
                    "failure": key or collection_failure(d),
                }
            )
            if key is None:
                why = collection_failure(d) or "it is reachable and managed"
                blockers.append(
                    f"{brief([d])[0]}: not failing on an SSH host-key change ({why}); nothing to accept. "
                    "Other collection failures: check credentials, SNMP and reachability (catc_device_360)."
                )
        auto = await auto_accept_state(app)
        side_effects = [ACCEPT_WARNING]
        if resync:
            side_effects.append(
                "Each device is resynced afterwards (inventory re-collected, no config pushed)."
            )
        if auto:
            side_effects.append(
                "Global SSH key auto-accept is on, so Catalyst Center normally accepts new keys by itself."
            )
        ids = [str(d["id"]) for d in devs]
        body = {"networkDeviceIds": ids, "resync": resync}
        plan = Plan(
            f"Accept the new SSH host key of {len(devs)} device(s)" + (" and resync them" if resync else ""),
            details={"devices": rows, "method": "POST", "path": ACCEPT_PATH, "body": body},
            side_effects=side_effects,
            fingerprint=sorted((str(d["id"]), ssh_key_failure(d)) for d in devs),
            blockers=blockers,
            blast_radius=len(devs),
            undo="not reversible: Catalyst Center keeps no copy of the previous key",
        )

        async def apply() -> Any:
            job = await app.run_job("POST", ACCEPT_PATH, body, ctx=ctx, what="accept SSH key")
            return {
                **job,
                "devices": brief(devs),
                "next": "Collection takes a few minutes: check reachability and collection status with "
                "catc_get_device or catc_list_devices.",
            }

        return await preview_or_apply(
            ctx,
            tool="catc_accept_ssh_key",
            args={"devices": devices, "resync": resync},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="Get SSH key settings")
    async def catc_get_ssh_key_settings(ctx: Context) -> dict[str, Any]:
        """The global policy for new SSH host keys: whether Catalyst Center accepts a changed device key by
        itself (auto-accept) or waits for catc_accept_ssh_key. Also lists the devices whose collection is
        failing on an SSH host-key change right now (read from the inventory)."""
        app: CatcApp = get_client(ctx)
        cur = await app.get_response(SSH_SETTINGS_PATH)
        auto = cur.get("autoAcceptSshKeys") if isinstance(cur, dict) else None
        inv = await fetch_all(app.pager, app.api, DEVICES_PATH)
        pending = [
            {**pick(d, ["hostname", "managementIpAddress", "id"]), "failure": key}
            for d in inv.items
            if isinstance(d, dict) and (key := ssh_key_failure(d))
        ]
        return {
            "auto_accept_ssh_keys": auto,
            "meaning": "new device keys are accepted automatically"
            if auto
            else "a changed device key blocks collection until accepted with catc_accept_ssh_key",
            "devices_with_key_change": pending,
        }

    @reg.write(title="Set SSH key settings", destructive=False, idempotent=True)
    async def catc_set_ssh_key_settings(
        ctx: Context,
        auto_accept: Annotated[
            bool, Field(description="true: accept new device SSH host keys automatically (security change)")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set the global policy for new SSH host keys. auto_accept=true makes Catalyst Center trust any new
        key a device presents (no more stuck devices after a reimage, but no man-in-the-middle check);
        false (the validated default) makes a changed key wait for catc_accept_ssh_key. Preview-first."""
        app: CatcApp = get_client(ctx)
        current = await auto_accept_state(app)
        body = {"autoAcceptSshKeys": auto_accept}
        side_effects = (
            [AUTO_ACCEPT_WARNING]
            if auto_accept
            else ["From now on a device whose SSH host key changes stops collecting until it is accepted."]
        )
        plan = Plan(
            f"{'Turn on' if auto_accept else 'Turn off'} global SSH host key auto-accept",
            details={
                "before": {"autoAcceptSshKeys": current},
                "method": "PUT",
                "path": SSH_SETTINGS_PATH,
                "body": body,
            },
            side_effects=side_effects,
            fingerprint=current,
            noop=(same := current is auto_accept),
            noop_reason=f"SSH key auto-accept is already {'on' if auto_accept else 'off'}." if same else None,
            undo=Undo("catc_set_ssh_key_settings", {"auto_accept": current})
            if current is not None
            else "set auto_accept back by hand (the current value could not be read)",
        )

        async def apply() -> Any:
            return await app.run_job("PUT", SSH_SETTINGS_PATH, body, ctx=ctx, what="SSH key settings")

        return await preview_or_apply(
            ctx,
            tool="catc_set_ssh_key_settings",
            args={"auto_accept": auto_accept},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set resync interval", destructive=False, idempotent=True)
    async def catc_set_resync_interval(
        ctx: Context,
        minutes: Annotated[
            int | None,
            Field(
                ge=0,
                le=MAX_INTERVAL,
                description="360-1440. Per device also 0 (no periodic resync) or null (use the global "
                "interval again). Global: null with override_devices=true only resets the devices.",
            ),
        ] = None,
        device: Annotated[
            str | None,
            Field(description="One device (hostname, IP, serial or id); omit for the global interval"),
        ] = None,
        override_devices: Annotated[
            bool,
            Field(
                description="Global only: also put every device with its own interval back on the global "
                "one (their own values are lost)"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set how often Catalyst Center re-collects inventory: for one device (heavy WLCs, a lagging
        config archive) or the global default the other devices follow. Preview-first: shows the current
        interval and, for the global one, how many devices follow it and how many keep their own.
        override_devices=true resets the per-device intervals too (MCP_ENABLE_DANGEROUS when any device has
        one)."""
        app: CatcApp = get_client(ctx)
        blockers: list[str] = []
        if device is not None:
            if override_devices:
                blockers.append("override_devices applies to the global interval only (omit device).")
            if minutes is not None and minutes != 0 and not MIN_INTERVAL <= minutes <= MAX_INTERVAL:
                blockers.append(
                    f"A device interval is {MIN_INTERVAL}-{MAX_INTERVAL} minutes, 0 (off) or null (global)."
                )
            dev = await resolve_device(app, device)
            did = str(dev["id"])
            path = RESYNC_DEVICE_PATH.format(id=safe_id(did, "device id"))
            current = await device_interval(app, did)
            on_global = str(dev.get("collectionInterval") or "") == GLOBAL_DEFAULT
            body: dict[str, Any] | None = {"interval": minutes}
            what = "the global interval" if minutes is None else ("off" if minutes == 0 else f"{minutes} min")
            before = {"interval": current, "collectionInterval": dev.get("collectionInterval")}
            plan = Plan(
                f"Set the resync interval of {brief([dev])[0]} to {what}",
                details={"before": before, "method": "PUT", "path": path, "body": body},
                side_effects=["Only the polling schedule changes; nothing is pushed to the device."]
                + (
                    ["Periodic resync stops: the inventory and config archive go stale."]
                    if minutes == 0
                    else []
                ),
                fingerprint={"device": did, **before},
                blockers=blockers,
                blast_radius=1,
                noop=(same := minutes is None and on_global),
                noop_reason=f"{brief([dev])[0]} already follows the global interval." if same else None,
                undo=Undo(
                    "catc_set_resync_interval", {"device": device, "minutes": None if on_global else current}
                ),
            )
            calls: list[tuple[str, str, Any]] = [("PUT", path, body)]
        else:
            if minutes is None and not override_devices:
                blockers.append(
                    f"Give the global interval in minutes ({MIN_INTERVAL}-{MAX_INTERVAL}), or "
                    "override_devices=true to put every device back on the current one."
                )
            elif minutes is not None and not MIN_INTERVAL <= minutes <= MAX_INTERVAL:
                blockers.append(
                    f"The global interval is {MIN_INTERVAL}-{MAX_INTERVAL} minutes (0 is per device only)."
                )
            inv = [
                d for d in (await fetch_all(app.pager, app.api, DEVICES_PATH)).items if isinstance(d, dict)
            ]
            followers = [
                d for d in inv if str(d.get("collectionInterval") or GLOBAL_DEFAULT) == GLOBAL_DEFAULT
            ]
            own = [d for d in inv if d not in followers]
            # No GET for the global value: a device on the global default reports it.
            current = await device_interval(app, str(followers[0]["id"])) if followers else None
            if override_devices and own and not app.settings.mcp_enable_dangerous:
                blockers.append(
                    f"{len(own)} device(s) have their own resync interval; override_devices=true replaces "
                    "them all with the global one, which needs MCP_ENABLE_DANGEROUS. Or reset them one by "
                    "one (device=..., minutes=null)."
                )
            calls = []
            if minutes is not None:
                calls.append(("PUT", RESYNC_GLOBAL_PATH, {"interval": minutes}))
            if override_devices:
                calls.append(("POST", RESYNC_OVERRIDE_PATH, None))
            affected = len(followers) + (len(own) if override_devices else 0)
            side_effects = [f"{len(followers)} device(s) follow the global interval."]
            if own:
                side_effects.append(
                    f"{len(own)} device(s) with their own interval "
                    + (
                        "are put back on the global one: their values are lost."
                        if override_devices
                        else "keep it."
                    )
                )
            parts = [f"Set the global resync interval to {minutes} min"] if minutes is not None else []
            if override_devices:
                parts.append(f"reset {len(own)} device(s) to the global interval")
            plan = Plan(
                " and ".join(parts) or "Set the global resync interval",
                details={
                    "before": {"global_interval": current},
                    "devices_with_own_interval": [
                        {
                            **pick(d, ["hostname", "managementIpAddress"]),
                            "interval": d.get("collectionInterval"),
                        }
                        for d in own[:50]
                    ],
                    "requests": [{"method": m, "path": p, "body": b} for m, p, b in calls],
                },
                side_effects=side_effects,
                fingerprint={"global": current, "own": sorted(str(d.get("id")) for d in own)},
                blockers=blockers,
                blast_radius=affected or None,
                noop=(same := minutes is not None and minutes == current and not override_devices),
                noop_reason=f"The global resync interval is already {minutes} min." if same else None,
                undo=(
                    "not reversible: the per-device intervals are replaced"
                    if override_devices and own
                    else Undo("catc_set_resync_interval", {"minutes": current})
                    if current is not None and minutes is not None
                    else None
                ),
            )

        async def apply() -> Any:
            done = []
            for method, p, b in calls:
                done.append(await app.run_job(method, p, b, ctx=ctx, what="resync interval"))
            return done[0] if len(done) == 1 else {"steps": done}

        return await preview_or_apply(
            ctx,
            tool="catc_set_resync_interval",
            args={"minutes": minutes, "device": device, "override_devices": override_devices},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
