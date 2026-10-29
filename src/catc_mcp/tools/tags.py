"""Tag reads, and tag membership v2 (roadmap D59): interface tagging and bulk device membership.

The v2 membership API works per member, not per tag: `PUT /dna/intent/api/v1/tags/{interfaces|networkDevices}/
membersAssociations/bulk` takes `[{"id": <member id>, "tags": [{"id": <tag id>}, ...]}]` and REPLACES each
member's tag list (an empty list untags the member from everything). So both writes read the members'
current tags first (`POST .../membersAssociations/query {"ids": [...]}`), add or drop the one tag, and send
the full list back: other tags the member carries are kept. The preview lists every member's tags before and
after. `GET tag/member/type` names the member types the appliance takes ('networkdevice', 'interface').
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    Undo,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, pick, resolve_device, resolve_tag
from catc_mcp.tools.ops_writes import brief, resolve_devices
from catc_mcp.tools.ports import find_port, load_ports

TAG_FIELDS = ["name", "description", "systemTag", "dynamicRules", "id"]
TAGS_V2 = "/dna/intent/api/v1/tags"
MEMBER_TYPE_PATH = "/dna/intent/api/v1/tag/member/type"
# member kind -> (v2 path segment, tag/member/type name)
KINDS = {"interface": ("interfaces", "interface"), "device": ("networkDevices", "networkdevice")}
QUERY_MAX = 500  # spec: at most 500 ids per membersAssociations/query and per bulk PUT
Action = Literal["add", "remove"]


async def member_type_blockers(app: CatcApp, member_type: str) -> list[str]:
    """Refuse a member type `GET tag/member/type` doesn't list (no blocker when the call itself fails)."""
    try:
        types = ensure_list(await app.get_response(MEMBER_TYPE_PATH))
    except (UpstreamError, NotFound):
        return []
    names = {str(t).lower() for t in types}
    if names and member_type.lower() not in names:
        return [
            f"This Catalyst Center doesn't take {member_type!r} tag members (tag/member/type lists: "
            + ", ".join(sorted(names))
            + ")."
        ]
    return []


def tag_blockers(tag: dict[str, Any]) -> list[str]:
    out = []
    if tag.get("systemTag"):
        out.append(f"{tag.get('name')!r} is a system tag: its members can't be set by hand.")
    if tag.get("dynamicRules"):
        out.append(
            f"{tag.get('name')!r} is a dynamic tag: its members come from its rules, not static membership."
        )
    return out


async def member_tags(app: CatcApp, kind: str, ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Each member's current tags ([{id, name}]), from membersAssociations/query. A member the query
    leaves out carries no tag."""
    out: dict[str, list[dict[str, Any]]] = {i: [] for i in ids}
    path = f"{TAGS_V2}/{KINDS[kind][0]}/membersAssociations/query"
    for start in range(0, len(ids), QUERY_MAX):
        chunk = ids[start : start + QUERY_MAX]
        data = await app.api.request("POST", path, json={"ids": chunk})
        rows = data.get("response") if isinstance(data, dict) else data
        for r in ensure_list(rows):
            if isinstance(r, dict) and str(r.get("id")) in out:
                out[str(r["id"])] = [
                    {"id": str(t.get("id")), "name": t.get("name")}
                    for t in ensure_list(r.get("tags"))
                    if isinstance(t, dict) and t.get("id")
                ]
    return out


def membership_change(
    current: dict[str, list[dict[str, Any]]], tag: dict[str, Any], action: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """(bulk PUT body for the members that change, ids already in the requested state)."""
    tid = str(tag["id"])
    body: list[dict[str, Any]] = []
    unchanged: list[str] = []
    for mid, tags in current.items():
        has = any(t["id"] == tid for t in tags)
        if (action == "add") == has:
            unchanged.append(mid)
            continue
        ids = [t["id"] for t in tags if t["id"] != tid] + ([tid] if action == "add" else [])
        body.append({"id": mid, "tags": [{"id": i} for i in ids]})
    return body, unchanged


def tag_names(tags: list[dict[str, Any]], extra: dict[str, Any] | None = None) -> list[str]:
    return sorted({str(t.get("name") or t.get("id")) for t in [*tags, *([extra] if extra else [])]})


def before_after(current: list[dict[str, Any]], tag: dict[str, Any], action: str) -> dict[str, list[str]]:
    before = tag_names(current)
    if action == "add":
        after = tag_names(current, tag)
    else:
        after = tag_names([t for t in current if t["id"] != str(tag["id"])])
    return {"before": before, "after": after}


async def put_bulk(app: CatcApp, kind: str, body: list[dict[str, Any]], ctx: Context) -> list[Any]:
    path = f"{TAGS_V2}/{KINDS[kind][0]}/membersAssociations/bulk"
    jobs = []
    for start in range(0, len(body), QUERY_MAX):
        jobs.append(
            await app.run_job("PUT", path, body[start : start + QUERY_MAX], ctx=ctx, what=f"tag {kind}s")
        )
    return jobs


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List tags")
    async def catc_list_tags(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Tag name filter ('*' wildcard ok, e.g. 'mcp-*')")
        ] = None,
        include_system: Annotated[bool, Field(description="Include built-in system tags")] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Tags used to group devices and interfaces (for templates, provisioning and filtering): name,
        description, whether it is a system tag, dynamic membership rules and id."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {"sortBy": "name", "order": "asc"}
        if name:
            params["name"] = name
        if not include_system:
            params["systemTag"] = "false"
        page = await app.pager.fetch_page(
            app.api, "/dna/intent/api/v1/tag", params, limit=limit, offset=offset
        )
        page.items = [pick(t, TAG_FIELDS) for t in page.items if isinstance(t, dict)]
        return list_result(page, fmt=response_format)

    @reg.read(title="List tag members")
    async def catc_list_tag_members(
        ctx: Context,
        tag: Annotated[str, Field(description="Tag name or id (from catc_list_tags)")],
        member_type: Annotated[
            Literal["networkdevice", "interface"], Field(description="Kind of member to list")
        ] = "networkdevice",
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Members of one tag: network devices (hostname, IP, platform) or interfaces, whether added
        statically or by a dynamic rule."""
        app: CatcApp = get_client(ctx)
        t = await resolve_tag(app, tag)
        page = await app.pager.fetch_page(
            app.api,
            f"/dna/intent/api/v1/tag/{t['id']}/member",
            {"memberType": member_type},
            limit=limit,
            offset=offset,
        )
        fields = ["hostname", "managementIpAddress", "platformId", "portName", "deviceId", "id"]
        page.items = [pick(m, fields) or m for m in page.items if isinstance(m, dict)]
        return list_result(page, fmt=response_format, extra={"tag": t.get("name")})

    @reg.write(title="Tag or untag interfaces", destructive=False)
    async def catc_tag_interfaces(
        ctx: Context,
        tag: Annotated[str, Field(description="Static tag name or id (catc_create_tag makes one)")],
        device: Annotated[
            str, Field(description="Device the interfaces are on (hostname, IP, serial or id)")
        ],
        interfaces: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=100,
                description="Interface names (GigabitEthernet1/0/3, Gi1/0/3) or interface ids",
            ),
        ],
        action: Annotated[Action, Field(description="add the tag to the interfaces, or remove it")] = "add",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a static tag to interfaces of one device, or remove it (to target templates or port actions
        by interface tag). Other tags the interfaces carry are kept. Preview-first: resolves the device and
        interface names to ids and lists each interface's tags before and after; interfaces already in the
        requested state are reported and left alone. Refuses system and dynamic (rule-based) tags. List the
        result with catc_list_tag_members(member_type='interface')."""
        app: CatcApp = get_client(ctx)
        t = await resolve_tag(app, tag)
        dev = await resolve_device(app, device)
        ports = await load_ports(app, dev)
        picked: dict[str, dict[str, Any]] = {}
        for ref in interfaces:
            p = find_port(ports, ref)
            picked[str(p.get("id") or p.get("instanceUuid"))] = p
        current = await member_tags(app, "interface", list(picked))
        body, unchanged = membership_change(current, t, action)
        names = {pid: str(p.get("portName") or pid) for pid, p in picked.items()}
        changing = [names[b["id"]] for b in body]
        blockers = [*tag_blockers(t), *await member_type_blockers(app, KINDS["interface"][1])]
        verb = "Tag" if action == "add" else "Untag"
        plan = Plan(
            f"{verb} {len(changing)} interface(s) of {brief([dev])[0]} "
            + ("with" if action == "add" else "from")
            + f" {t.get('name')}",
            details={
                "tag": {"name": t.get("name"), "id": t.get("id")},
                "device": {"hostname": dev.get("hostname"), "id": dev.get("id")},
                "interfaces": [
                    {"name": names[pid], "id": pid, **before_after(current[pid], t, action)} for pid in picked
                ],
                "unchanged": [names[pid] for pid in unchanged],
                "method": "PUT",
                "path": f"{TAGS_V2}/interfaces/membersAssociations/bulk",
                "body": body,
            },
            fingerprint={"tag": t.get("id"), "current": current},
            blockers=blockers,
            blast_radius=len(body),
            noop=not body,
            noop_reason=None
            if body
            else f"Every interface already {'carries' if action == 'add' else 'lacks'} "
            f"tag {t.get('name')!r}.",
            undo=Undo(
                "catc_tag_interfaces",
                {
                    "tag": str(t.get("name")),
                    "device": device,
                    "interfaces": changing,
                    "action": "remove" if action == "add" else "add",
                },
            )
            if changing
            else None,
        )

        async def apply() -> Any:
            jobs = await put_bulk(app, "interface", body, ctx)
            return {
                "tag": t.get("name"),
                "device": dev.get("hostname"),
                ("tagged" if action == "add" else "untagged"): changing,
                "unchanged": [names[pid] for pid in unchanged],
                "tasks": jobs,
            }

        return await preview_or_apply(
            ctx,
            tool="catc_tag_interfaces",
            args={"tag": tag, "device": device, "interfaces": interfaces, "action": action},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Tag or untag devices in bulk", destructive=False)
    async def catc_tag_devices(
        ctx: Context,
        tag: Annotated[str, Field(description="Static tag name or id (catc_create_tag makes one)")],
        devices: Annotated[
            list[str],
            Field(min_length=1, max_length=500, description="Devices (hostname, IP, serial or id)"),
        ],
        action: Annotated[Action, Field(description="add the tag to the devices, or remove it")] = "add",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a static tag to many network devices in one request, or remove it (bulk membership over
        tags/networkDevices/membersAssociations/bulk; up to 500 devices). Other tags the devices carry are
        kept. Preview-first: resolves every device and lists its tags before and after; devices already in
        the requested state are reported and left alone. Refuses system and dynamic (rule-based) tags. For a
        few devices catc_update_tag_members does the same per tag."""
        app: CatcApp = get_client(ctx)
        if len({d.strip().lower() for d in devices}) != len(devices):
            raise InvalidRequest("A device is listed twice.")
        t = await resolve_tag(app, tag)
        devs = {str(d["id"]): d for d in await resolve_devices(app, devices)}
        current = await member_tags(app, "device", list(devs))
        body, unchanged = membership_change(current, t, action)
        label = {did: brief([d])[0] for did, d in devs.items()}
        changing = [label[b["id"]] for b in body]
        blockers = [*tag_blockers(t), *await member_type_blockers(app, KINDS["device"][1])]
        verb = "Tag" if action == "add" else "Untag"
        plan = Plan(
            f"{verb} {len(changing)} device(s) "
            + ("with" if action == "add" else "from")
            + f" {t.get('name')}",
            details={
                "tag": {"name": t.get("name"), "id": t.get("id")},
                "devices": [
                    {"device": label[did], "id": did, **before_after(current[did], t, action)} for did in devs
                ],
                "unchanged": [label[did] for did in unchanged],
                "method": "PUT",
                "path": f"{TAGS_V2}/networkDevices/membersAssociations/bulk",
                "body": body,
            },
            side_effects=[
                "Templates, provisioning and filters that target this tag pick up (or drop) these devices."
            ],
            fingerprint={"tag": t.get("id"), "current": current},
            blockers=blockers,
            blast_radius=len(body),
            noop=not body,
            noop_reason=None
            if body
            else f"Every device already {'carries' if action == 'add' else 'lacks'} tag {t.get('name')!r}.",
            undo=Undo(
                "catc_tag_devices",
                {
                    "tag": str(t.get("name")),
                    "devices": [str(devs[b["id"]].get("managementIpAddress") or b["id"]) for b in body],
                    "action": "remove" if action == "add" else "add",
                },
            )
            if body
            else None,
        )

        async def apply() -> Any:
            jobs = await put_bulk(app, "device", body, ctx)
            return {
                "tag": t.get("name"),
                ("tagged" if action == "add" else "untagged"): changing,
                "unchanged": [label[did] for did in unchanged],
                "tasks": jobs,
            }

        return await preview_or_apply(
            ctx,
            tool="catc_tag_devices",
            args={"tag": tag, "devices": devices, "action": action},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
