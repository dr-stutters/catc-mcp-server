"""Operational writes: tags, discovery, device-to-site assignment, resync, compliance runs, issue
status. All preview-first."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import hashlib
import ipaddress
import json
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field, SecretStr

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    poll_until,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, job_ref, safe_id
from catc_mcp.common import ensure_list, is_ip, pick, resolve_device, resolve_site, resolve_tag
from catc_mcp.tools.credentials import all_credentials, resolve_credential
from catc_mcp.tools.discovery import DEVICE_FIELDS as DISCOVERED_FIELDS
from catc_mcp.tools.discovery import all_discoveries

Devices = Annotated[
    list[str], Field(min_length=1, max_length=100, description="Devices (hostname, IP, serial or id)")
]


async def resolve_devices(app: CatcApp, refs: list[str]) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in refs:
        d = await resolve_device(app, r)
        out[str(d["id"])] = d
    return list(out.values())


async def device_site(app: CatcApp, device_id: str) -> str | None:
    """The name hierarchy of the site a device is assigned to (None when unassigned)."""
    try:
        a = await app.get_response(f"/dna/intent/api/v1/networkDevices/{safe_id(device_id)}/assignedToSite")
    except NotFound:
        return None
    return str(a.get("siteNameHierarchy")) if isinstance(a, dict) and a.get("siteNameHierarchy") else None


MISSING_NOTE = (
    "Some addresses didn't produce a device. Usual causes: nothing answers there (ping/SSH/SNMP), wrong "
    "credentials, or the device reports the same serial number as one already found or in the inventory: "
    "Catalyst Center then merges them silently (every CML cat9000v reports CMLUADP unless its "
    "conf/vswitch.xml sets a unique serial). Check catc_list_discovery_devices and catc_list_devices."
)


def expand_addresses(ranges: list[str], limit: int = 1024) -> list[str]:
    """IPv4 addresses of 'a', 'a-b' and comma lists, for the "which addresses gave no device" note. Parts it
    can't parse (IPv6, CIDR, shorthand) are skipped; [] when the total is larger than `limit` (no note)."""
    out: list[str] = []
    for part in (x.strip() for r in ranges for x in r.split(",") if x.strip()):
        lo, _, hi = part.partition("-")
        try:
            a, b = ipaddress.IPv4Address(lo.strip()), ipaddress.IPv4Address((hi or lo).strip())
        except ValueError:
            continue
        if int(b) < int(a):
            continue
        if int(b) - int(a) + len(out) >= limit:
            return []
        out += [str(ipaddress.IPv4Address(i)) for i in range(int(a), int(b) + 1)]
    return out


def brief(devs: list[dict[str, Any]]) -> list[str]:
    return [f"{d.get('hostname') or '(not collected yet)'} ({d.get('managementIpAddress')})" for d in devs]


def register(reg: ToolRegistrar) -> None:
    # --- tags ----------------------------------------------------------------------------------

    @reg.write(title="Create tag")
    async def catc_create_tag(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Tag name")],
        description: Annotated[str | None, Field(description="Tag description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a (static) tag for grouping devices or interfaces. Preview-first; refuses a
        duplicate name. Add members with catc_update_tag_members."""
        app: CatcApp = get_client(ctx)
        try:
            await resolve_tag(app, name)
            blockers = [f"Tag {name!r} already exists."]
        except NotFound:
            blockers = []
        body = {"name": name, "description": description or ""}
        plan = Plan(
            f"Create tag {name}",
            details={"method": "POST", "path": "/dna/intent/api/v1/tag", "body": body},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job("POST", "/dna/intent/api/v1/tag", body, ctx=ctx, what="create tag")
            return {"tag_id": job.get("data"), "name": name}

        return await preview_or_apply(
            ctx,
            tool="catc_create_tag",
            args={"name": name, "description": description},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Update tag members", destructive=False)
    async def catc_update_tag_members(
        ctx: Context,
        tag: Annotated[str, Field(description="Tag name or id")],
        add: Annotated[
            list[str] | None, Field(description="Devices to add (hostname, IP, serial or id)")
        ] = None,
        remove: Annotated[
            list[str] | None, Field(description="Devices to remove (hostname, IP, serial or id)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add network devices to, or remove them from, a static tag. Preview-first: shows which
        devices change and which are already in the desired state."""
        app: CatcApp = get_client(ctx)
        if not add and not remove:
            raise InvalidRequest("Give devices to `add` and/or `remove`.")
        t = await resolve_tag(app, tag)
        members = await fetch_all(
            app.pager, app.api, f"/dna/intent/api/v1/tag/{t['id']}/member", {"memberType": "networkdevice"}
        )
        current = {str(m.get("id") or m.get("instanceUuid")) for m in members.items if isinstance(m, dict)}
        to_add = [d for d in await resolve_devices(app, add or []) if str(d["id"]) not in current]
        to_remove = [d for d in await resolve_devices(app, remove or []) if str(d["id"]) in current]
        plan = Plan(
            f"Update members of tag {t.get('name')}",
            details={"add": brief(to_add), "remove": brief(to_remove), "current_member_count": len(current)},
            fingerprint=sorted(current),
            blockers=[]
            if (to_add or to_remove)
            else ["Nothing to change: devices are already in that state."],
        )

        async def apply() -> Any:
            done: dict[str, Any] = {}
            if to_add:
                body = {"networkdevice": [str(d["id"]) for d in to_add]}
                done["added"] = await app.run_job(
                    "POST", f"/dna/intent/api/v1/tag/{t['id']}/member", body, ctx=ctx, what="add tag members"
                )
            removed: list[str] = []
            for d in to_remove:
                try:
                    await app.run_job(
                        "DELETE",
                        f"/dna/intent/api/v1/tag/{t['id']}/member/{d['id']}",
                        ctx=ctx,
                        what="remove tag member",
                    )
                except UpstreamError as e:
                    done["removed"] = removed
                    done["remove_failed"] = {"device": brief([d])[0], "error": str(e)[:300]}
                    return done
                removed += brief([d])
            done["removed"] = removed
            return done

        return await preview_or_apply(
            ctx,
            tool="catc_update_tag_members",
            args={"tag": tag, "add": add, "remove": remove},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete tag", destructive=True)
    async def catc_delete_tag(
        ctx: Context,
        tag: Annotated[str, Field(description="Tag name or id")],
        remove_members: Annotated[
            bool,
            Field(
                description="Untag its member devices first (Catalyst Center refuses to delete a tag in use)"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a user-defined tag. Catalyst Center refuses while devices are tagged with it: pass
        remove_members=true to untag them first (the devices themselves are untouched). System tags
        are refused. Preview-first: shows the member count."""
        app: CatcApp = get_client(ctx)
        t = await resolve_tag(app, tag)
        members = await fetch_all(
            app.pager, app.api, f"/dna/intent/api/v1/tag/{t['id']}/member", {"memberType": "networkdevice"}
        )
        member_ids = sorted(
            str(m.get("id") or m.get("instanceUuid"))
            for m in members.items
            if isinstance(m, dict) and (m.get("id") or m.get("instanceUuid"))
        )
        blockers = []
        if t.get("systemTag"):
            blockers.append("System tags can't be deleted.")
        if member_ids and not remove_members:
            blockers.append(
                f"{len(member_ids)} device(s) carry this tag; pass remove_members=true to untag them first."
            )
        plan = Plan(
            f"Delete tag {t.get('name')}"
            + (f" after untagging {len(member_ids)} device(s)" if member_ids else ""),
            details={
                "method": "DELETE",
                "path": f"/dna/intent/api/v1/tag/{t['id']}",
                "device_members": len(member_ids),
            },
            fingerprint={"id": t.get("id"), "members": member_ids},
            blockers=blockers,
        )

        async def apply() -> Any:
            for mid in member_ids:
                await app.run_job(
                    "DELETE",
                    f"/dna/intent/api/v1/tag/{t['id']}/member/{safe_id(mid, 'member id')}",
                    ctx=ctx,
                    what="untag device",
                )
            return await app.run_job(
                "DELETE", f"/dna/intent/api/v1/tag/{t['id']}", ctx=ctx, what="delete tag"
            )

        return await preview_or_apply(
            ctx,
            tool="catc_delete_tag",
            args={"tag": tag, "remove_members": remove_members},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    # --- discovery -------------------------------------------------------------------------------

    @reg.write(title="Create discovery", task=True)
    async def catc_create_discovery(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Discovery job name")],
        ip_ranges: Annotated[
            list[str],
            Field(
                min_length=1,
                description="IPs or ranges, e.g. ['10.0.0.1-10.0.0.50'] or ['10.0.0.1'] for CDP/LLDP seeds",
            ),
        ],
        discovery_type: Annotated[
            Literal["Range", "Multi Range", "Single", "CDP", "LLDP", "CIDR"],
            Field(description="Discovery method"),
        ] = "Range",
        cli_username: Annotated[
            str | None, Field(description="SSH username (omit to use global credentials)")
        ] = None,
        cli_password: Annotated[
            SecretStr | None, Field(description="SSH password (never echoed back)")
        ] = None,
        enable_password: Annotated[
            SecretStr | None, Field(description="Enable password (never echoed back)")
        ] = None,
        snmp_ro_community: Annotated[
            SecretStr | None, Field(description="SNMPv2c read community (never echoed back)")
        ] = None,
        snmp_rw_community: Annotated[
            SecretStr | None, Field(description="SNMPv2c write community (never echoed back)")
        ] = None,
        netconf_port: Annotated[
            int | None, Field(ge=1, le=65535, description="NETCONF port to collect over (e.g. 830)")
        ] = None,
        use_global_credentials: Annotated[
            bool, Field(description="Also try global credentials (Design > Network Settings)")
        ] = True,
        global_credentials: Annotated[
            list[str] | None,
            Field(
                description="Only these global credentials (id, description or 'TYPE:description'); "
                "default: every global credential"
            ),
        ] = None,
        hop_count: Annotated[int, Field(ge=1, le=16, description="CDP/LLDP: neighbor hops to follow")] = 1,
        timeout_seconds: Annotated[int, Field(ge=1, le=60, description="Per-device connection timeout")] = 5,
        wait: Annotated[
            bool, Field(description="Wait for the discovery to finish (can take minutes)")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Start a device discovery (IP range, CIDR, single IP, or CDP/LLDP from a seed) that adds
        what it finds to the inventory. Uses the global credentials you name (or all of them) plus any
        given inline; create them first with catc_create_global_credential. Preview-first; secrets are
        masked in the preview. A discovery takes several minutes: with wait=true the result lists each
        device found with its reachability and CLI/SNMP/NETCONF status; otherwise follow it with
        catc_list_discoveries / catc_list_discovery_devices."""
        app: CatcApp = get_client(ctx)
        cred_ids: list[str] = []
        cred_names: list[str] = []
        if use_global_credentials:
            creds = await all_credentials(app)
            if global_credentials:
                creds = [await resolve_credential(app, r, creds=creds) for r in global_credentials]
            cred_ids = [str(c["id"]) for c in creds if c.get("id")]
            cred_names = [f"{c.get('type')}:{c.get('description')}" for c in creds]
        elif global_credentials:
            raise InvalidRequest("global_credentials needs use_global_credentials=true.")
        ips = ",".join(r.strip() for r in ip_ranges)
        sent_type: str = discovery_type
        if discovery_type == "Single":
            # 3.2.2 finishes a "Single" discovery in seconds without finding anything; a one-address
            # Range works.
            if len(ip_ranges) != 1 or not is_ip(ip_ranges[0]):
                raise InvalidRequest("A Single discovery takes exactly one IP address.")
            sent_type, ips = "Range", f"{ip_ranges[0].strip()}-{ip_ranges[0].strip()}"
        elif discovery_type in ("Range", "Multi Range"):
            # Ranges must be 'first-last'; a bare address is rejected ("IPAddress for Range
            # Discovery is invalid"), so send it as a one-address range.
            parts = [x.strip() for r in ip_ranges for x in r.split(",") if x.strip()]
            bad = [x for x in parts if not all(is_ip(a) for a in x.split("-", 1))]
            if bad:
                raise InvalidRequest(f"Not an IP or 'first-last' range: {', '.join(bad)}")
            ips = ",".join(x if "-" in x else f"{x}-{x}" for x in parts)
        body: dict[str, Any] = {
            "name": name,
            "discoveryType": sent_type,
            "ipAddressList": ips,
            "protocolOrder": "ssh",
            "timeout": timeout_seconds,
            "retry": 1,
            "snmpVersion": "v2",
            "globalCredentialIdList": cred_ids,
            "preferredMgmtIPMethod": "None",
        }
        if discovery_type == "CDP":
            body["cdpLevel"] = hop_count
        if discovery_type == "LLDP":
            body["lldpLevel"] = hop_count
        secrets: dict[str, Any] = {}
        if cli_username:
            body["userNameList"] = [cli_username]
        if cli_password:
            secrets["passwordList"] = [cli_password.get_secret_value()]
        if enable_password:
            secrets["enablePasswordList"] = [enable_password.get_secret_value()]
        if snmp_ro_community:
            secrets["snmpROCommunity"] = snmp_ro_community.get_secret_value()
        if snmp_rw_community:
            secrets["snmpRWCommunity"] = snmp_rw_community.get_secret_value()
        if netconf_port:
            body["netconfPort"] = str(netconf_port)
        blockers = []
        if (cli_password or enable_password) and not cli_username:
            blockers.append("cli_password/enable_password need cli_username too.")
        if not any(n.startswith("CLI:") for n in cred_names) and not (cli_username and cli_password):
            blockers.append(
                "No CLI credentials: give cli_username/cli_password or create a global CLI credential "
                "(catc_create_global_credential)."
            )
        if any(str(d.get("name", "")).lower() == name.lower() for d in await all_discoveries(app)):
            blockers.append(f"A discovery named {name!r} already exists.")
        shown = {**body, **{k: MASK for k in secrets}}
        if cred_names:
            shown["globalCredentialIdList"] = cred_names
        plan = Plan(
            f"Start {discovery_type} discovery {name} on {body['ipAddressList']}",
            details={"method": "POST", "path": "/dna/intent/api/v1/discovery", "body": shown},
            side_effects=["Devices that answer are added to the inventory and collected."],
            fingerprint=sorted(cred_ids),
            blockers=blockers,
        )
        args = {
            "name": name,
            "ip_ranges": ip_ranges,
            "discovery_type": discovery_type,
            "cli_username": cli_username,
            # Secrets aren't stored or echoed; a digest makes the token refuse changed values.
            "secrets": hashlib.sha256(json.dumps(secrets, sort_keys=True).encode()).hexdigest(),
            "netconf_port": netconf_port,
            "use_global_credentials": use_global_credentials,
            "global_credentials": global_credentials,
            "hop_count": hop_count,
            "timeout_seconds": timeout_seconds,
            "wait": wait,
        }

        async def apply() -> Any:
            started = await app.api.post("/dna/intent/api/v1/discovery", {**body, **secrets})
            ref = job_ref(started)
            if ref is None:
                return {"discovery": name, "note": "No task id returned; check catc_list_discoveries."}
            if wait:
                job = await app.wait_job(started, ctx=ctx, what="discovery")
            else:
                # The task's `data` holds the discovery id as soon as the job is queued.
                job = await poll_until(
                    lambda: app.get_task(ref[1]),
                    done=lambda t: bool(t.get("data")) or t.get("endTime") is not None,
                    failed=lambda t: (
                        str(t.get("failureReason") or "discovery failed") if t.get("isError") else False
                    ),
                    timeout=30,
                    interval=1.0,
                    what="discovery start",
                )
            data: Any = job.get("data")
            if isinstance(data, str) and data.startswith("{"):
                with contextlib.suppress(ValueError):
                    data = json.loads(data)
            disc_id = data.get("discoveryId") if isinstance(data, dict) else data
            out: dict[str, Any] = {
                "discovery": name,
                "discovery_id": disc_id,
                "task_id": ref[1],
                "status": "finished" if wait else "running (check catc_list_discoveries)",
            }
            if wait and disc_id:
                # What it found, so "it finished" also says whether the devices are usable.
                with contextlib.suppress(UpstreamError):
                    found = ensure_list(
                        await app.get_response(
                            f"/dna/intent/api/v1/discovery/{safe_id(str(disc_id))}/network-device"
                        )
                    )
                    out["devices"] = [pick(d, DISCOVERED_FIELDS) for d in found[:100] if isinstance(d, dict)]
                    wanted = expand_addresses(ip_ranges)
                    got = {str(d.get("managementIpAddress")) for d in found if isinstance(d, dict)}
                    missing = sorted(set(wanted) - got, key=lambda a: tuple(int(x) for x in a.split(".")))
                    if wanted and missing:
                        out["not_found"] = missing[:50]
                        out["note"] = MISSING_NOTE
            return out

        return await preview_or_apply(
            ctx, tool="catc_create_discovery", args=args, confirm=confirm, plan=plan, apply=apply
        )

    # --- inventory operations ----------------------------------------------------------------------

    @reg.write(title="Assign devices to site", destructive=False)
    async def catc_assign_devices_to_site(
        ctx: Context,
        devices: Devices,
        site: Annotated[str, Field(description="Target building or floor (id or name hierarchy)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Assign (or move) unprovisioned network devices to a building or floor. Access points and
        sensors go on floors. Preview-first: shows each device's current site; devices already there are
        skipped. Provisioning is separate (catc_provision_devices)."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        devs = await resolve_devices(app, devices)
        blockers = []
        if s.get("type") not in ("building", "floor"):
            blockers.append(f"Devices go on a building or floor, not a {s.get('type')}.")
        current = {str(d["id"]): await device_site(app, str(d["id"])) for d in devs}
        moving = [d for d in devs if current[str(d["id"])] != s.get("nameHierarchy")]
        if not moving and not blockers:
            blockers.append(f"Nothing to change: the devices are already in {s.get('nameHierarchy')}.")
        body = {"deviceIds": [str(d["id"]) for d in moving], "siteId": s["id"]}
        plan = Plan(
            f"Assign {len(moving)} device(s) to {s.get('nameHierarchy')}",
            details={
                "devices": [
                    {"device": brief([d])[0], "from": current[str(d["id"])] or "(unassigned)"} for d in moving
                ],
                "method": "POST",
                "path": "/dna/intent/api/v1/networkDevices/assignToSite/apply",
            },
            fingerprint={"site": s["id"], "current": current},
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job(
                "POST",
                "/dna/intent/api/v1/networkDevices/assignToSite/apply",
                body,
                ctx=ctx,
                what="assign to site",
            )

        return await preview_or_apply(
            ctx,
            tool="catc_assign_devices_to_site",
            args={"devices": devices, "site": site},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Resync devices", destructive=False, idempotent=True)
    async def catc_resync_devices(
        ctx: Context,
        devices: Devices,
        force: Annotated[bool, Field(description="High-priority sync (fails if no worker is free)")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Re-collect inventory (config, interfaces, modules) from devices now instead of waiting for
        the next polling cycle. Preview-first. No configuration is pushed to the devices."""
        app: CatcApp = get_client(ctx)
        devs = await resolve_devices(app, devices)
        plan = Plan(
            f"Resync {len(devs)} device(s)",
            details={
                "devices": brief(devs),
                "method": "PUT",
                "path": "/dna/intent/api/v1/network-device/sync",
            },
            fingerprint=sorted(str(d["id"]) for d in devs),
            blast_radius=len(devs),
        )

        async def apply() -> Any:
            return await app.run_job(
                "PUT",
                "/dna/intent/api/v1/network-device/sync",
                [str(d["id"]) for d in devs],
                params={"forceSync": str(force).lower()},
                ctx=ctx,
                what="resync",
            )

        return await preview_or_apply(
            ctx,
            tool="catc_resync_devices",
            args={"devices": devices, "force": force},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Run compliance check", destructive=False, idempotent=True)
    async def catc_run_compliance(
        ctx: Context,
        devices: Devices,
        categories: Annotated[
            list[Literal["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT", "EOX", "NETWORK_SETTINGS"]] | None,
            Field(description="Categories to check (default: all)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Run a compliance check now for devices (all categories unless given). Preview-first; nothing
        on the devices changes. Read the results with catc_get_compliance_detail."""
        app: CatcApp = get_client(ctx)
        devs = await resolve_devices(app, devices)
        body: dict[str, Any] = {"deviceUuids": [str(d["id"]) for d in devs], "triggerFull": not categories}
        if categories:
            body["categories"] = categories
        plan = Plan(
            f"Run compliance on {len(devs)} device(s)",
            details={"devices": brief(devs), "body": body},
            fingerprint=sorted(str(d["id"]) for d in devs),
            blast_radius=len(devs),
        )

        async def apply() -> Any:
            return await app.run_job(
                "POST", "/dna/intent/api/v1/compliance/", body, ctx=ctx, what="compliance"
            )

        return await preview_or_apply(
            ctx,
            tool="catc_run_compliance",
            args={"devices": devices, "categories": categories},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Resolve or ignore issues", destructive=False)
    async def catc_update_issue_status(
        ctx: Context,
        issue_ids: Annotated[
            list[str], Field(min_length=1, max_length=100, description="Issue ids (catc_list_issues)")
        ],
        action: Annotated[
            Literal["resolve", "ignore"], Field(description="Mark resolved, or ignore for a while")
        ],
        ignore_hours: Annotated[
            int, Field(ge=1, le=720, description="With action=ignore: for how long")
        ] = 24,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Mark assurance issues as resolved, or ignore them for some hours. Preview-first. Issues
        come back if the condition recurs."""
        app: CatcApp = get_client(ctx)
        ids = [safe_id(i, "issue id") for i in issue_ids]
        body: dict[str, Any] = {"issueIds": ids}
        if action == "ignore":
            body["ignoreHours"] = ignore_hours
        path = f"/dna/intent/api/v1/assuranceIssues/{action}"
        issues: list[dict[str, Any]] = []
        blockers: list[str] = []
        for i in ids:
            try:
                issue = await app.get_response(f"/dna/data/api/v1/assuranceIssues/{i}")
            except NotFound:
                blockers.append(f"No issue with id {i}.")
                continue
            issue = issue[0] if isinstance(issue, list) and issue else issue
            if isinstance(issue, dict):
                issues.append({k: issue.get(k) for k in ("id", "name", "summary", "status", "priority")})
        plan = Plan(
            f"{action.title()} {len(ids)} issue(s)",
            details={"issues": issues, "method": "POST", "path": path, "body": body},
            fingerprint=[(x.get("id"), x.get("status")) for x in issues],
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.api.post(path, body)

        return await preview_or_apply(
            ctx,
            tool="catc_update_issue_status",
            args={"issue_ids": issue_ids, "action": action, "ignore_hours": ignore_hours},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
