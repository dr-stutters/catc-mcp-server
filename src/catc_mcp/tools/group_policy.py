"""Group-based access control, as a switch enforces it (roadmap D91): Catalyst Center as the verifier.

ISE stays the policy owner (security groups, SGACLs and the egress matrix; ise-mcp-server writes them with
ise_set_sgt / ise_set_egress_policy). Without Catalyst Center's policy migration (which hands the matrix to
Catalyst Center and makes ISE's copy read-only) Catalyst Center's own group-based policy API is not usable, so
this module reads what a fabric edge (or any TrustSec switch) actually downloaded and enforces, through the
command runner: the environment data (the security group name table and the servers), the permissions per
source/destination cell, the enforcement counters and the IP-to-SGT bindings. That is the proof that an ISE
matrix change reached the edge.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import InvalidRequest, ToolRegistrar, get_client
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_device
from catc_mcp.tools.smart import run_show

SgtRef = Annotated[
    str | None,
    Field(description="Security group: its tag number ('5') or name ('Contractors'), as the switch names it"),
]

_CELL = re.compile(
    r"^IPv(?P<af>[46]) Role-based permissions from group (?P<src>\S+) to group (?P<dst>\S+?)"
    r"(?:\s*\((?P<kind>[^)]*)\))?:\s*$"
)
_DEFAULT = re.compile(r"^IPv(?P<af>[46]) Role-based permissions default:\s*$")
_GROUP = re.compile(r"^(?P<tag>\d+|Unknown)(?::(?P<name>.+))?$")
_COUNTER = re.compile(r"^(?P<src>\*|\d+)\s+(?P<dst>\*|\d+)((?:\s+\d+){6})\s*$")
_BINDING = re.compile(r"^(?P<ip>[0-9a-fA-F:.]+(?:/\d+)?)\s+(?P<sgt>\d+)\s+(?P<source>[A-Z_-]+)\s*$")
_NAME_ROW = re.compile(r"^\s*(?P<tag>\d+)-[0-9A-Fa-f]+:(?P<name>\S.*?)\s*$")
# `show vrf`: "  MCP_VN   <not set>   ipv4   Vl1040" (the header's second column has no colon or <not set>)
_VRF = re.compile(r"^\s{1,4}(?P<name>[A-Za-z0-9_.:-]+)\s+(?:<not set>|\S+:\S+)\s+\S")
VRF_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
MGMT_VRFS = frozenset({"Mgmt-vrf", "Mgmt-intf"})
MAX_VRFS = 4  # with the global table: one 5-command runner request
_SERVER = re.compile(r"^\s*\*?Server:\s*(?P<ip>[0-9a-fA-F:.]+), port (?P<port>\d+)")
COUNTER_COLS = ["sw_denied", "hw_denied", "sw_permitted", "hw_permitted", "sw_monitored", "hw_monitored"]


def _group(token: str) -> dict[str, Any]:
    m = _GROUP.match(token)
    if not m:
        return {"sgt": None, "name": token}
    tag = m["tag"]
    return {
        "sgt": int(tag) if tag.isdigit() else None,
        "name": m["name"] or (tag if not tag.isdigit() else None),
    }


def _acl_name(line: str) -> str:
    """'Deny IP-00' -> 'Deny IP' (the suffix is the SGACL's generation)."""
    return re.sub(r"-\d{2}$", "", line.strip())


def parse_permissions(text: str) -> dict[str, Any]:
    """`show cts role-based permissions`: the default policy and one entry per downloaded cell."""
    default: list[str] = []
    cells: list[dict[str, Any]] = []
    target: list[str] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if m := _DEFAULT.match(line.strip()):
            target = default if m["af"] == "4" else None
            continue
        if m := _CELL.match(line.strip()):
            acls: list[str] = []
            cell: dict[str, Any] = {
                "ip_version": int(m["af"]),
                "from": _group(m["src"]),
                "to": _group(m["dst"]),
                "sgacls": acls,
            }
            if m["kind"]:
                cell["kind"] = m["kind"]
            cells.append(cell)
            target = acls
            continue
        if not line.strip() or line.strip().startswith("RBACL Monitor"):
            target = None
            continue
        if target is not None and raw[:1].isspace():
            target.append(_acl_name(line))
    return {"default": default, "cells": cells}


def parse_counters(text: str) -> list[dict[str, Any]]:
    """`show cts role-based counters`: SW/HW denied, permitted and monitored packets per cell."""
    rows = []
    for line in text.splitlines():
        if m := _COUNTER.match(line.strip()):
            nums = [int(x) for x in m.group(3).split()]
            rows.append(
                {
                    "from": None if m["src"] == "*" else int(m["src"]),
                    "to": None if m["dst"] == "*" else int(m["dst"]),
                    **dict(zip(COUNTER_COLS, nums, strict=True)),
                }
            )
    return rows


def parse_bindings(text: str) -> list[dict[str, Any]]:
    """`show cts role-based sgt-map all`: IP (or prefix) -> SGT with where the binding came from."""
    return [
        {"ip": m["ip"], "sgt": int(m["sgt"]), "source": m["source"]}
        for line in text.splitlines()
        if (m := _BINDING.match(line.strip()))
    ]


def parse_vrfs(text: str) -> list[str]:
    """`show vrf`: the VRF names, without the management VRF. SD-Access puts each layer 3 VN in a VRF of
    its name, and the clients' IP-to-SGT bindings live there, not in the global table."""
    names: list[str] = []
    for line in text.splitlines():
        m = _VRF.match(line)
        if m and m["name"] not in MGMT_VRFS and m["name"] not in names:
            names.append(m["name"])
    return names


def parse_environment(text: str) -> dict[str, Any]:
    """`show cts environment-data`: download state, the device's own SGT, servers and the SGT name table."""
    out: dict[str, Any] = {"state": None, "servers": [], "groups": {}}
    in_table = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Current state ="):
            out["state"] = line.split("=", 1)[1].strip()
        elif line.startswith("Last status ="):
            out["last_status"] = line.split("=", 1)[1].strip()
        elif line.startswith("SGT tag ="):
            out["device_sgt"] = line.split("=", 1)[1].strip()
        elif line.startswith("Last update time ="):
            out["last_update"] = line.split("=", 1)[1].strip()
        elif m := _SERVER.match(raw):
            out["servers"].append({"ip": m["ip"], "port": int(m["port"]), "preferred": "*Server" in raw})
        elif line.startswith("Status =") and out["servers"]:
            out["servers"][-1]["status"] = line.split("=", 1)[1].strip()  # ALIVE / DEAD
        elif line.startswith("Security Group Name Table"):
            in_table = True
        elif in_table:
            if m := _NAME_ROW.match(raw):
                out["groups"][int(m["tag"])] = m["name"]
            elif line and not line[0].isdigit():
                in_table = False
    return out


def resolve_sgt(ref: str | None, groups: dict[int, str], cells: list[dict[str, Any]]) -> int | None:
    """A tag number or a group name (case-insensitive), using the switch's own name table."""
    if ref is None:
        return None
    ref = ref.strip()
    if ref.isdigit():
        return int(ref)
    names = dict(groups)
    for c in cells:
        for side in (c["from"], c["to"]):
            if side.get("sgt") is not None and side.get("name"):
                names.setdefault(side["sgt"], side["name"])
    for tag, name in names.items():
        if name.lower() == ref.lower():
            return tag
    raise InvalidRequest(
        f"The switch knows no security group named {ref!r} (its name table: "
        f"{', '.join(f'{t}:{n}' for t, n in sorted(names.items())) or 'empty: no environment data'})."
    )


def verdict(
    src: int | None, dst: int | None, perms: dict[str, Any], counters: list[dict[str, Any]]
) -> dict[str, Any]:
    """What the switch does from src to dst: the cell's SGACLs, else the default; with its counters."""
    cell = next(
        (
            c
            for c in perms["cells"]
            if c["ip_version"] == 4 and c["from"]["sgt"] == src and c["to"]["sgt"] == dst
        ),
        None,
    )
    row = next((r for r in counters if r["from"] == src and r["to"] == dst), None)
    return {
        "from": src,
        "to": dst,
        "policy": cell["sgacls"] if cell else perms["default"],
        "source_of_policy": "cell downloaded from ISE" if cell else "default (no cell for this pair)",
        "counters": row,
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Group-based policy enforcement on a switch")
    async def catc_get_group_policy_enforcement(
        ctx: Context,
        device: Annotated[
            str, Field(description="Fabric edge or TrustSec switch (hostname, IP, serial or id)")
        ],
        source: SgtRef = None,
        destination: SgtRef = None,
        ips: Annotated[
            list[str] | None,
            Field(max_length=20, description="Client IPs to look up in the switch's IP-to-SGT bindings"),
        ] = None,
        vrfs: Annotated[
            list[str] | None,
            Field(
                max_length=MAX_VRFS,
                description="VRFs (SD-Access virtual networks) whose IP-to-SGT bindings to read as well; "
                "default: every VRF on the switch except the management VRF",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """What a switch actually enforces for group-based access control (TrustSec / SD-Access), read live
        through the command runner: the environment data it downloaded from ISE (state, servers, the
        security group name table), every source -> destination cell with its SGACLs and the default
        policy, the enforcement counters (SW/HW denied and permitted per cell) and the IP-to-SGT bindings,
        global and per VRF (on an SD-Access edge the clients' bindings are in their VN's VRF).
        With source and destination (tag or name) it answers for that pair: the SGACLs that apply (the cell,
        or the default when the switch has none) and that cell's counters; with ips, each client's SGT.
        Use it after an ISE matrix change (ise_set_egress_policy) to prove the edge has the new cell, and
        after a test flow to see the counters move. Read-only; clear counters on the switch to start fresh."""
        app: CatcApp = get_client(ctx)
        for v in vrfs or []:
            if not VRF_NAME.fullmatch(v):
                raise InvalidRequest(f"Not a VRF name: {v!r}")
        dev = await resolve_device(app, device)
        env_cmd, perms_cmd, counters_cmd, enforce_cmd = (
            "show cts environment-data",
            "show cts role-based permissions",
            "show cts role-based counters",
            "show running-config | include cts role-based enforcement",
        )
        global_cmd, vrf_cmd = "show cts role-based sgt-map all", "show cts role-based sgt-map vrf {} all"
        # Two command-runner calls of at most 5 commands each (the 3.2.2 runner's limit): the TrustSec state
        # and the VRF list, then the bindings (global and per VRF: SD-Access clients are in their VN's VRF).
        first = [
            env_cmd,
            perms_cmd,
            counters_cmd,
            enforce_cmd,
            global_cmd if vrfs is not None else "show vrf",
        ]
        result = (await run_show(app, ctx, [dev], first))[0]
        out_by_cmd: dict[str, str] = dict(result.get("output") or {})
        if vrfs is None:
            vrfs = parse_vrfs(out_by_cmd.get("show vrf", ""))[:MAX_VRFS]
            second = [global_cmd, *(vrf_cmd.format(v) for v in vrfs)]
        else:
            second = [vrf_cmd.format(v) for v in vrfs]
        if second:
            more = (await run_show(app, ctx, [dev], second))[0]
            out_by_cmd.update(more.get("output") or {})
            for key in ("failed", "blocked_by_catalyst_center"):
                if more.get(key):  # {command: message}
                    result[key] = {**(result.get(key) or {}), **more[key]}

        def text(cmd: str) -> str:
            t = out_by_cmd.get(cmd, "")
            return "" if t == "(no output)" else t

        env = parse_environment(text(env_cmd))
        perms = parse_permissions(text(perms_cmd))
        counters = parse_counters(text(counters_cmd))
        bindings = parse_bindings(text(global_cmd))
        for v in vrfs:
            bindings += [{**b, "vrf": v} for b in parse_bindings(text(vrf_cmd.format(v)))]
        enforcement = [ln.strip() for ln in text(enforce_cmd).splitlines() if ln.strip().startswith("cts ")]
        out: dict[str, Any] = {
            "device": result.get("device"),
            "environment": {
                **env,
                "groups": [{"sgt": t, "name": n} for t, n in sorted(env["groups"].items())],
            },
            "enforcement": {
                "global": any(ln == "cts role-based enforcement" for ln in enforcement),
                "config": enforcement,
            },
            "default_policy": perms["default"],
            "cells": perms["cells"],
            "counters": counters,
            "bindings": bindings,
        }
        notes: list[str] = []
        if env["state"] not in (None, "COMPLETE"):
            notes.append(f"Environment data is {env['state']}: the switch has no complete download from ISE.")
        if env["state"] is None:
            notes.append("No TrustSec environment data: the switch is not a TrustSec device of ISE yet.")
        if not out["enforcement"]["global"]:
            notes.append(
                "'cts role-based enforcement' is not configured: cells are downloaded but not enforced."
            )
        if source is not None or destination is not None:
            if source is None or destination is None:
                raise InvalidRequest("Give both source and destination for a pair verdict.")
            src = resolve_sgt(source, env["groups"], perms["cells"])
            dst = resolve_sgt(destination, env["groups"], perms["cells"])
            out["pair"] = verdict(src, dst, perms, counters)
            for side in ("from", "to"):
                tag = out["pair"][side]
                out["pair"][f"{side}_name"] = env["groups"].get(tag) if tag is not None else None
        if ips:
            # A client's binding is in its VN's VRF on a fabric edge; the global table also holds the SVIs.
            by_ip = {b["ip"].split("/")[0]: b for b in sorted(bindings, key=lambda b: "vrf" in b)}
            clients: list[dict[str, Any]] = []
            for ip in ips:
                b = by_ip.get(ip)
                if b is None:
                    clients.append({"ip": ip, "note": "no binding"})
                    continue
                row: dict[str, Any] = {"ip": ip, **{k: b[k] for k in ("sgt", "source", "vrf") if k in b}}
                row["sgt_name"] = env["groups"].get(b["sgt"])
                clients.append(row)
            out["clients"] = clients
        for key, cmd in (("failed", "failed"), ("blocked", "blocked_by_catalyst_center")):
            if result.get(cmd):
                out[key] = result[cmd]
        if notes:
            out["notes"] = notes
        return out
