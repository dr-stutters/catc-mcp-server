"""SD-Access fabric AAA readiness (roadmap D110): can every fabric device at a fabric site do AAA with ISE?

Fabric provisioning sends RADIUS from Loopback0 (the RLOC: `ip radius source-interface Loopback0`, global
and in `dnac-client-radius-group`), and the NADs Catalyst Center creates in ISE carry the RLOC /32 under
`Location#All Locations`. When ISE has no route back to the RLOCs, the NAD is missing or sits in a location
the policy set doesn't match, the device marks ISE DEAD, TrustSec environment data never completes and
nobody behind the edge authenticates. Finding that took four tools across two servers plus a console in the
live run.

This module reads every fabric device live through the command runner (one request, five commands: the 3.2.2
runner's limit), works out the address its RADIUS comes from, and gives a verdict per device with the fix.
The ISE half (which NAD covers that address, in which location, with TrustSec settings) comes from
ise-mcp-server: the caller passes ise_list_nads results as `ise_nads`, or runs ise_audit_nads with the rows
the result gives under `ise_check`.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import ipaddress
import re
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from catc_mcp._core import InvalidRequest, ToolRegistrar, get_client
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, resolve_device
from catc_mcp.tools.group_policy import parse_environment
from catc_mcp.tools.sda import FabricRef, resolve_fabric, sda_list
from catc_mcp.tools.smart import check_show_command, run_show

# cat9000v 17.18 prints "%Failed to update configuration in the database ..." in the middle of
# `show aaa servers`, and the command runner then reports the whole command as FAILED; the filter drops that
# one line (seen live on the lab fabric, 2026-10-22).
AAA_CMD = "show aaa servers | exclude Failed to update"
ENV_CMD = "show cts environment-data"
PAC_CMD = "show cts pacs"
RADIUS_CMD = "show running-config | section radius"
IP_CMD = "show ip interface brief | exclude unassigned"
COMMANDS = [AAA_CMD, ENV_CMD, PAC_CMD, RADIUS_CMD, IP_CMD]  # one runner request (5 is the 3.2.2 limit)

MAX_DEVICES = 20
MAX_NADS = 1000
DEFAULT_LOCATION = "Location#All Locations"
ROLE_ORDER = {"CONTROL_PLANE_NODE": 0, "BORDER_NODE": 1, "EDGE_NODE": 2}

_AAA_SERVER = re.compile(
    r"^RADIUS: id \d+, priority \d+, host (?P<host>[^,\s]+), auth-port (?P<auth>\d+), "
    r"acct-port (?P<acct>\d+)(?:, hostname (?P<name>\S+))?"
)
_STATE = re.compile(r"^State: current (?P<state>\w+), duration (?P<dur>\d+)s")
_DEAD = re.compile(r"^Dead: total time (?P<total>\d+)s, count (?P<count>\d+)")
_AUTHEN = re.compile(r"^Authen: request (?P<req>\d+), timeouts (?P<to>\d+)")
_RESPONSE = re.compile(r"^Response: accept (?P<acc>\d+), reject (?P<rej>\d+)")
_IF_IP = re.compile(r"^(?P<name>\S+)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?:YES|NO)\s")
_PAC_FIELD = re.compile(r"^\s*(?P<key>AID|I-ID|A-ID-Info|Credential Lifetime):\s*(?P<val>.+?)\s*$")


class IseNad(BaseModel):
    """One ISE network device as ise-mcp's ise_list_nads(response_format='json') returns it in `results`;
    ise_get_nad's full record works too."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str = Field(description="NAD name")
    ips: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ips", "NetworkDeviceIPList"),
        description="Its IPs or subnets, 'a.b.c.d/nn'",
    )
    groups: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("groups", "NetworkDeviceGroupList"),
        description="Its device group paths, e.g. 'Location#All Locations#SYD'",
    )
    trustsec: str | None = Field(
        default=None,
        validation_alias=AliasChoices("trustsec", "trustsecsettings"),
        description="'yes' when the NAD has TrustSec settings (device id and password)",
    )

    @field_validator("ips", mode="before")
    @classmethod
    def _ips(cls, v: Any) -> list[str]:
        out = []
        for item in ensure_list(v):
            if isinstance(item, dict) and item.get("ipaddress"):
                out.append(f"{item['ipaddress']}/{item.get('mask', 32)}")
            elif isinstance(item, str):
                out.append(item)
        return out

    @field_validator("trustsec", mode="before")
    @classmethod
    def _trustsec(cls, v: Any) -> str | None:
        if v is None or isinstance(v, str):
            return v.strip().lower() if isinstance(v, str) else None
        return "yes" if v else "no"  # ise_get_nad: the trustsecsettings object, or bool


# --- parsers -------------------------------------------------------------------------------------


def parse_aaa_servers(text: str) -> list[dict[str, Any]]:
    """`show aaa servers`: per RADIUS server its state (UP/DEAD) and for how long, how often it was dead, and
    the authentication requests, timeouts and answers since the counters were cleared."""
    servers: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    in_authen = False
    for raw in text.splitlines():
        line = raw.strip()
        if m := _AAA_SERVER.match(line):
            cur = {"host": m["host"], "auth_port": int(m["auth"]), "acct_port": int(m["acct"])}
            if m["name"]:
                cur["name"] = m["name"]
            servers.append(cur)
            in_authen = False
        elif re.match(r"^[A-Z][A-Z+]+: id \d+", line):  # TACACS+ / LDAP servers: not this check's
            cur = None
        elif cur is None:
            continue
        elif m := _STATE.match(line):
            cur["state"] = m["state"].upper()
            cur["state_for_s"] = int(m["dur"])
        elif m := _DEAD.match(line):
            cur["dead_count"] = int(m["count"])
            cur["dead_total_s"] = int(m["total"])
        elif m := _AUTHEN.match(line):
            cur["authen_requests"], cur["authen_timeouts"] = int(m["req"]), int(m["to"])
            in_authen = True
        elif line.startswith(("Author:", "Account:")):
            in_authen = False
        elif m := re.match(r"^Elapsed time since counters last cleared: (\S+)", line):
            cur["counters_cleared"] = f"{m[1]} ago"
        elif in_authen and "authen_accepts" not in cur and (m := _RESPONSE.match(line)):
            cur["authen_accepts"], cur["authen_rejects"] = int(m["acc"]), int(m["rej"])
    return servers


def parse_radius_config(text: str) -> dict[str, Any]:
    """`show running-config | section radius`: RADIUS servers (address, automate-tester), server groups with
    their source interface, the global source interface, the dot1x group and the dead timer."""
    out: dict[str, Any] = {"servers": {}, "groups": {}, "source_interface": None}
    group: dict[str, Any] | None = None
    server: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        words = line.split()
        if not words:
            continue
        if not raw[:1].isspace():
            group = server = None
            if m := re.match(r"^aaa group server radius (\S+)", line):
                group = out["groups"].setdefault(m[1], {"servers": []})
            elif m := re.match(r"^radius server (\S+)", line):
                server = out["servers"].setdefault(m[1], {})
            elif m := re.match(r"^radius-server host (\S+)", line):  # legacy syntax
                out["servers"].setdefault(m[1], {"address": m[1]})
            elif m := re.match(r"^ip radius source-interface (\S+)", line):
                out["source_interface"] = m[1]
            elif m := re.match(r"^radius-server deadtime (\d+)", line):
                out["deadtime_min"] = int(m[1])
            elif m := re.match(r"^radius-server dead-criteria (.+)$", line):
                out["dead_criteria"] = m[1].strip()
            elif m := re.match(r"^aaa authentication dot1x default group (\S+)", line):
                out["dot1x_group"] = m[1]
        elif group is not None:
            if m := re.match(r"^\s+server name (\S+)", line):
                group["servers"].append(m[1])
            elif m := re.match(r"^\s+ip radius source-interface (\S+)", line):
                group["source_interface"] = m[1]
        elif server is not None:
            if m := re.match(r"^\s+address ipv[46] (\S+)", line):
                server["address"] = m[1]
            elif words[0] == "automate-tester":
                server["automate_tester"] = True
    return out


def parse_interface_ips(text: str) -> dict[str, str]:
    """`show ip interface brief`: {interface: IPv4 address} for the interfaces that have one."""
    return {m["name"]: m["ip"] for line in text.splitlines() if (m := _IF_IP.match(line))}


def parse_pacs(text: str, now: datetime | None = None) -> dict[str, Any] | None:
    """`show cts pacs`: the TrustSec PAC ISE provisioned (never the PAC-Opaque blob), or None without one."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("PAC-Opaque"):
            continue
        if (m := _PAC_FIELD.match(line)) and m["key"] not in fields:
            fields[m["key"]] = m["val"]
    if "AID" not in fields:
        return None
    pac: dict[str, Any] = {"a_id": fields["AID"]}
    for key, out_key in (("I-ID", "i_id"), ("A-ID-Info", "a_id_info"), ("Credential Lifetime", "lifetime")):
        if key in fields:
            pac[out_key] = fields[key]
    if m := re.search(r"Refresh timer is set for (\S+)", text):
        pac["refresh_in"] = m[1]
    with contextlib.suppress(KeyError, ValueError):
        ends = datetime.strptime(fields["Credential Lifetime"], "%H:%M:%S UTC %a %b %d %Y").replace(
            tzinfo=UTC
        )
        pac["expired"] = ends < (now or datetime.now(UTC))
    return pac


# --- ISE side ------------------------------------------------------------------------------------


def covering_nad(nads: list[IseNad], ip: str) -> tuple[IseNad, str] | None:
    """The NAD whose IP list or subnet covers `ip`, most specific first, with the entry that matched."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: tuple[int, IseNad, str] | None = None
    for nad in nads:
        for entry in nad.ips:
            try:
                net = ipaddress.ip_network(entry.strip(), strict=False)
            except ValueError:
                continue
            if net.version == addr.version and addr in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, nad, str(net))
    return (best[1], best[2]) if best else None


def locations(groups: list[str]) -> list[str]:
    return [g for g in groups if g.lower().startswith("location#")]


def in_location(groups: list[str], want: str) -> bool:
    """A NAD's group path matches a full path ('Location#All Locations#SYD'), its tail ('All Locations#SYD')
    or its last part ('SYD'), case-insensitively."""
    w = want.strip().lower()
    return any(g.lower() == w or g.lower().endswith("#" + w) for g in groups)


# --- verdict -------------------------------------------------------------------------------------


def _finding(check: str, severity: str, detail: str, fix: str | None = None) -> dict[str, Any]:
    out = {"check": check, "severity": severity, "detail": detail}
    if fix:
        out["fix"] = fix
    return out


def _text(outputs: dict[str, str], cmd: str) -> str:
    t = outputs.get(cmd) or ""
    return "" if t == "(no output)" else t


def assess(
    host: str,
    management_ip: str | None,
    roles: list[str],
    outputs: dict[str, str],
    failed: dict[str, str],
    nads: list[IseNad] | None,
    expected_location: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """One fabric device's AAA readiness from its command outputs (and ISE's NADs when given)."""
    row: dict[str, Any] = {"device": host, "management_ip": management_ip, "roles": roles}
    if not outputs:
        row["verdict"] = "unknown"
        if failed:
            row["failed"] = failed
        row["findings"] = [
            _finding(
                "unreadable",
                "fail",
                "The command runner got no output from the device (unreachable, or the CLI credential fails)",
                "catc_get_device for its reachability and collection status",
            )
        ]
        return row
    findings: list[dict[str, Any]] = []
    notes: list[str] = []
    cfg = parse_radius_config(_text(outputs, RADIUS_CMD))
    ips = parse_interface_ips(_text(outputs, IP_CMD))
    servers = parse_aaa_servers(_text(outputs, AAA_CMD))
    env = parse_environment(_text(outputs, ENV_CMD))
    pac = parse_pacs(_text(outputs, PAC_CMD), now)

    # Where RADIUS leaves from: the dot1x group's own source interface, else the global one.
    group_name = cfg.get("dot1x_group")
    group = cfg["groups"].get(group_name) if group_name else None
    iface = (group or {}).get("source_interface") or cfg["source_interface"]
    nad_ip: str | None = None
    if iface:
        scope = str(group_name) if group and group.get("source_interface") else "global"
        row["radius_source"] = {"interface": iface, "ip": ips.get(iface), "set_in": scope}
        nad_ip = ips.get(iface)
        if not nad_ip and _text(outputs, IP_CMD):
            findings.append(
                _finding(
                    "source_without_ip",
                    "fail",
                    f"RADIUS is sourced from {iface}, which has no IPv4 address: requests can't leave",
                    f"Bring {iface} up with its address (fabric provisioning gives Loopback0 the RLOC), or "
                    "provision the device again (catc_provision_devices)",
                )
            )
    else:
        nad_ip = management_ip
        row["radius_source"] = {
            "interface": None,
            "ip": management_ip,
            "set_in": "none: the egress interface (assumed)",
        }
        if cfg["servers"]:
            findings.append(
                _finding(
                    "no_source_interface",
                    "warning",
                    "No 'ip radius source-interface': RADIUS leaves from the interface toward ISE, so "
                    f"the NAD must cover that address (assumed the management IP {management_ip})",
                    "Fabric provisioning sources RADIUS from Loopback0: provision the device again "
                    "(catc_provision_devices) if it should be a fabric device",
                )
            )
    row["nad_ip"] = nad_ip
    by_address = {str(s.get("address")): (n, s) for n, s in cfg["servers"].items() if s.get("address")}
    if cfg.get("deadtime_min") is not None:
        row["deadtime_min"] = cfg["deadtime_min"]

    # ISE's NAD for that address.
    nad_hit = covering_nad(nads, nad_ip) if nads is not None and nad_ip else None
    nad: IseNad | None = nad_hit[0] if nad_hit else None
    if nads is not None and nad_ip:
        if nad_hit:
            row["ise_nad"] = {
                "name": nad_hit[0].name,
                "covers": nad_hit[1],
                "location": locations(nad_hit[0].groups),
                "trustsec": nad_hit[0].trustsec,
            }
        else:
            row["ise_nad"] = None
            mgmt_hit = covering_nad(nads, management_ip) if management_ip else None
            if mgmt_hit and management_ip != nad_ip:
                findings.append(
                    _finding(
                        "missing_nad",
                        "fail",
                        f"ISE NAD {mgmt_hit[0].name} covers the management IP {management_ip} but not "
                        f"{nad_ip}, where RADIUS comes from: ISE drops those requests silently (11007)",
                        f"ise_update_nad(device={mgmt_hit[0].name!r}) adding '{nad_ip}/32' to its IPs "
                        "(preview first)",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "missing_nad",
                        "fail",
                        f"No ISE NAD covers {nad_ip}, where RADIUS comes from: ISE drops those requests "
                        "silently (11007)",
                        f"ise_create_nad(name={host!r}, ips=['{nad_ip}/32'], the RADIUS shared secret and "
                        "TrustSec settings) (preview first), or provision the device again "
                        "(catc_provision_devices), which recreates it",
                    )
                )
        if nad is not None:
            locs = locations(nad.groups)
            if expected_location and not in_location(nad.groups, expected_location):
                findings.append(
                    _finding(
                        "wrong_location",
                        "fail",
                        f"NAD {nad.name} is in {', '.join(locs) or 'no location'}, not {expected_location}: "
                        "the policy set that matches that location never sees this device's logins",
                        f"ise_update_nad(device={nad.name!r}) with groups including {expected_location} "
                        f"(preview first); check with ise_policy_explain(nad='{nad_ip}', flow='wired-mab')",
                    )
                )
            elif not expected_location and locs and all(g == DEFAULT_LOCATION for g in locs):
                findings.append(
                    _finding(
                        "default_location",
                        "warning",
                        f"NAD {nad.name} is only in {DEFAULT_LOCATION} (where Catalyst Center creates fabric "
                        "NADs): a policy set that matches a location won't see this device's logins",
                        f"ise_policy_explain(nad='{nad_ip}', flow='wired-mab') shows the policy set its "
                        "logins hit; if it's the wrong one, move the NAD (ise_update_nad), or pass "
                        "expected_location",
                    )
                )
            if nad.trustsec == "no":
                findings.append(
                    _finding(
                        "nad_without_trustsec",
                        "fail",
                        f"NAD {nad.name} has no TrustSec settings: the device can't get a PAC or environment "
                        "data from ISE",
                        f"ise_update_nad(device={nad.name!r}) with the TrustSec device id and password the "
                        "device's 'cts credentials' use (preview first)",
                    )
                )

    # RADIUS server state.
    dead = [s for s in servers if s.get("state") == "DEAD"]
    row["radius_servers"] = []
    for s in servers:
        conf = by_address.get(s["host"], (None, {}))[1]
        entry = {**s, "automate_tester": bool(conf.get("automate_tester"))}
        row["radius_servers"].append(entry)
        if s.get("state") == "UP" and s.get("dead_count"):
            timeouts = (
                f"; {s['authen_timeouts']} of {s['authen_requests']} authentication requests timed out"
                if s.get("authen_timeouts")
                else ""
            )
            notes.append(
                f"{s['host']} is UP (for {s.get('state_for_s')} s) but was DEAD {s['dead_count']} time(s), "
                f"{s.get('dead_total_s')} s in all, since the counters were last cleared"
                + (f" ({s['counters_cleared']})" if s.get("counters_cleared") else "")
                + timeouts
            )
    if not servers and not cfg["servers"]:
        findings.append(
            _finding(
                "no_radius_server",
                "fail",
                "No RADIUS server is configured: nothing behind this device can authenticate",
                "Set the site's client AAA to ISE (catc_update_site_aaa_settings) and provision the "
                "device again (catc_provision_devices)",
            )
        )
    elif not servers:
        why = failed.get(AAA_CMD) or "no RADIUS server in its output"
        findings.append(
            _finding(
                "radius_state_unknown",
                "warning",
                f"Couldn't read the RADIUS server state ('{AAA_CMD}': {why[:160]})",
            )
        )
    for s in dead:
        name, conf = by_address.get(s["host"], (s.get("name"), {}))
        src = f"{nad_ip or '?'} ({iface})" if iface else str(nad_ip or "?")
        if nads is not None and nad is None:
            fix = "ISE drops RADIUS from an address no NAD covers (11007): fix missing_nad first"
        elif nad is not None:
            fix = (
                f"ISE has NAD {nad.name} for {nad_ip}, so ISE isn't answering or its answers don't "
                f"arrive: give ISE a route back to {nad_ip} (fabric RADIUS leaves from the RLOC; ping "
                f"{nad_ip} from the ISE CLI), then check the shared secret (ISE logs 11036 for a wrong one: "
                "ise_recent_auth_failures)"
            )
        else:
            fix = (
                f"Check ISE: a NAD covering {nad_ip} (ise_get_nad('{nad_ip}'); none means silent drops, "
                f"11007), a route from ISE back to {nad_ip} (fabric RADIUS leaves from the RLOC), and the "
                "shared secret (11036 in ise_recent_auth_failures)"
            )
        if conf.get("automate_tester"):
            fix += f". automate-tester probes {s['host']}: it comes back UP by itself once ISE answers"
        else:
            dt = cfg.get("deadtime_min")
            fix += (
                f". Without automate-tester on 'radius server {name}', the device keeps {s['host']} DEAD for "
                f"radius-server deadtime ({dt if dt is not None else '?'} min) after ISE answers again"
            )
        findings.append(
            _finding(
                "radius_dead",
                "fail",
                f"RADIUS server {s['host']} is DEAD (for {s.get('state_for_s')} s) from {src}",
                fix,
            )
        )

    # TrustSec: environment data and the PAC.
    trustsec: dict[str, Any] = {
        "environment": env["state"],
        "last_status": env.get("last_status"),
        "servers": env["servers"],
        "groups": len(env["groups"]),
    }
    if env.get("last_update"):
        trustsec["last_update"] = env["last_update"]
    trustsec["pac"] = pac
    row["trustsec"] = trustsec
    if env["state"] is None:
        if ENV_CMD in failed:
            findings.append(
                _finding("trustsec_unknown", "warning", f"Couldn't read '{ENV_CMD}': {failed[ENV_CMD][:160]}")
            )
        else:
            findings.append(
                _finding(
                    "no_trustsec",
                    "warning",
                    "No TrustSec environment data: CTS isn't set up on the device, so it has no security "
                    "groups and enforces no group-based policy",
                    "Fabric provisioning configures CTS when ISE is integrated (catc_get_policy_servers); "
                    "provision the device again (catc_provision_devices)",
                )
            )
    elif env["state"] != "COMPLETE":
        if dead:
            fix = "Fix RADIUS first (radius_dead): environment data is downloaded over RADIUS"
        elif nad is not None and nad.trustsec == "no":
            fix = "Fix nad_without_trustsec first"
        else:
            fix = (
                "Check the NAD's TrustSec device id and password in ISE (ise_get_nad shows trustsecsettings) "
                "against the device's 'cts credentials'; the device retries every 60 s (or run 'cts refresh "
                "environment-data' on it)"
            )
        findings.append(
            _finding(
                "environment_data",
                "fail",
                f"TrustSec environment data is {env['state']} (last status {env.get('last_status') or '?'}): "
                "no security groups or SGACLs from ISE",
                fix,
            )
        )
    if env["state"] is not None:
        if pac is None:
            findings.append(
                _finding(
                    "no_pac",
                    "warning" if env["state"] == "COMPLETE" else "fail",
                    "No TrustSec PAC from ISE: the device couldn't provision it (RADIUS to ISE, or the NAD's "
                    "TrustSec device id and password)",
                    "Once RADIUS works and the NAD has TrustSec settings, the device provisions the "
                    "PAC itself",
                )
            )
        elif pac.get("expired"):
            findings.append(
                _finding(
                    "pac_expired",
                    "fail",
                    f"The TrustSec PAC expired ({pac.get('lifetime')})",
                    "Once RADIUS to ISE works, run 'cts refresh pac' on the device (exec)",
                )
            )

    if failed:
        row["failed"] = failed
    worst = {f["severity"] for f in findings}
    row["verdict"] = "fail" if "fail" in worst else "warning" if "warning" in worst else "ok"
    row["findings"] = findings
    if notes:
        row["notes"] = notes
    return row


def summary(site: str, rows: list[dict[str, Any]], nads_given: bool) -> str:
    text = _summary(site, rows, nads_given)
    if rows and not nads_given:
        text += " ISE's side (the NAD covering each RLOC) is not checked: see ise_check."
    return text


def _summary(site: str, rows: list[dict[str, Any]], nads_given: bool) -> str:
    bad = [r for r in rows if r["verdict"] in ("fail", "unknown")]
    warn = [r for r in rows if r["verdict"] == "warning"]
    if not rows:
        return f"{site} has no fabric devices to check."
    if not bad:
        lead = (
            f"All {len(rows)} fabric device(s) at {site} can do AAA with ISE: RADIUS UP from the RLOC, "
            "TrustSec environment data COMPLETE" + (", and an ISE NAD covers each RLOC" if nads_given else "")
        )
        if warn:
            lead += f"; {len(warn)} with warnings: " + "; ".join(
                f"{r['device']}: {r['findings'][0]['check']}" for r in warn
            )
        return lead + "."
    parts = [
        f"{r['device']}: " + ", ".join(f["check"] for f in r["findings"] if f["severity"] == "fail")
        for r in bad
    ]
    return (
        f"{len(bad)} of {len(rows)} fabric device(s) at {site} can't do AAA with ISE: "
        + "; ".join(parts)
        + ". Each device's findings carry the fix."
    )


def ise_hand_off(rows: list[dict[str, Any]], expected_location: str | None) -> dict[str, Any]:
    """What to run on ise-mcp-server when the caller gave no NADs: the address each device's RADIUS comes
    from, ready as ise_audit_nads(expected=...) rows."""
    expected = []
    for r in rows:
        if not r.get("nad_ip"):
            continue
        item: dict[str, Any] = {"name": r["device"], "ip": r["nad_ip"]}
        hosts = [s["host"] for s in r.get("radius_servers") or []]
        if hosts:
            item["aaa_server"] = hosts[0]
        if expected_location:
            item["ndg"] = expected_location
        expected.append(item)
    first = expected[0]["ip"] if expected else "<RLOC>"
    return {
        "not_checked": "ISE's side (the NAD covering each device's RADIUS source, its location and TrustSec "
        "settings) needs ise-mcp-server",
        "ise_audit_nads": {"expected": expected, "check_stale": False},
        "next": [
            "ise_audit_nads with the arguments above: missing_nad, wrong_ndg and aaa_elsewhere per device",
            "or ise_list_nads(response_format='json', limit=500) and call catc_check_fabric_aaa again with "
            "ise_nads = its results, for one verdict per device",
            f"ise_policy_explain(nad='{first}', flow='wired-mab'): the policy set a login through it hits",
        ],
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-Access fabric AAA readiness")
    async def catc_check_fabric_aaa(
        ctx: Context,
        fabric_site: FabricRef,
        ise_nads: Annotated[
            list[IseNad] | None,
            Field(
                max_length=MAX_NADS,
                description="ISE's network devices, to check which NAD covers each device's RADIUS source "
                "address, its location and TrustSec settings: the `results` of ise-mcp's "
                "ise_list_nads(response_format='json', limit=500) as they are (ise_get_nad records work "
                "too). Leave out and the result says which ise tool to run",
            ),
        ] = None,
        expected_location: Annotated[
            str | None,
            Field(
                description="The ISE location group the fabric's policy set matches, e.g. "
                "'Location#All Locations#SYD' or 'SYD': each NAD must be in it (checked with ise_nads)",
            ),
        ] = None,
        devices: Annotated[
            list[str] | None,
            Field(
                max_length=MAX_DEVICES,
                description="Only these fabric devices (hostname, management IP or id); default every "
                f"fabric device at the site, up to {MAX_DEVICES}",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Whether every fabric device at an SD-Access fabric site can do AAA with ISE, with a verdict and
        the fix per device. Reads each device live through the command runner (show aaa servers, show cts
        environment-data, show cts pacs, the RADIUS config, the interface addresses; one request) and
        returns: the address its RADIUS comes from (fabric provisioning sources it from Loopback0, the RLOC,
        and the ISE NAD must cover that /32), each RADIUS server's state (UP/DEAD, dead count, timeouts,
        automate-tester), TrustSec environment data (COMPLETE or not, servers) and PAC, with given ise_nads
        the NAD that covers the address, its location and TrustSec settings, and the verdict (ok, warning,
        fail) whose findings each carry the fix to preview: ISE needs a route back to the RLOC, the NAD is
        missing, the NAD's location doesn't match the policy set (expected_location), the RADIUS server is
        DEAD (deadtime, automate-tester), environment data or the PAC is missing. Without ise_nads the
        result's ise_check gives the ise_audit_nads arguments."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        records = await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
        by_id = {str(r.get("networkDeviceId")): r for r in records if r.get("networkDeviceId")}
        site_name = str(site.get("nameHierarchy") or fabric_site)
        out: dict[str, Any] = {"fabric_site": site_name}
        if devices:
            invs = [await resolve_device(app, d) for d in devices]
            outside = [str(d.get("hostname") or d.get("id")) for d in invs if str(d.get("id")) not in by_id]
            if outside:
                raise InvalidRequest(
                    f"Not fabric devices at {site_name}: {', '.join(outside)} (catc_get_sda_fabric "
                    "lists them)."
                )
        else:
            ordered = sorted(
                by_id.values(),
                key=lambda r: min((ROLE_ORDER.get(x, 9) for x in r.get("deviceRoles") or []), default=9),
            )
            ids = [str(r["networkDeviceId"]) for r in ordered]
            if len(ids) > MAX_DEVICES:
                out["note"] = (
                    f"{len(ids) - MAX_DEVICES} more fabric device(s) not checked: pass devices=[...] "
                    "for them."
                )
                ids = ids[:MAX_DEVICES]
            found: dict[str, dict[str, Any]] = {}
            if ids:
                rows = ensure_list(
                    await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids)})
                )
                found = {str(r.get("id")): r for r in rows if isinstance(r, dict)}
            missing = [i for i in ids if i not in found]
            if missing:
                out["not_in_inventory"] = missing
            invs = [found[i] for i in ids if i in found]
        if not invs:
            out["verdict"] = summary(site_name, [], ise_nads is not None)
            out["devices"] = []
            return out
        results = await run_show(app, ctx, invs, [check_show_command(c) for c in COMMANDS])
        by_name = {str(r.get("device")): r for r in results}
        rows_out: list[dict[str, Any]] = []
        for inv in invs:
            host = str(inv.get("hostname") or inv.get("managementIpAddress"))
            res = by_name.get(host) or by_name.get(str(inv.get("id"))) or {}
            failed = {
                **(res.get("failed") or {}),
                **(res.get("blocked_by_catalyst_center") or {}),
            }
            rows_out.append(
                assess(
                    host,
                    inv.get("managementIpAddress"),
                    list(by_id.get(str(inv.get("id")), {}).get("deviceRoles") or []),
                    dict(res.get("output") or {}),
                    failed,
                    ise_nads,
                    expected_location,
                )
            )
        out["verdict"] = summary(site_name, rows_out, ise_nads is not None)
        out["devices"] = rows_out
        if ise_nads is None:
            out["ise_check"] = ise_hand_off(rows_out, expected_location)
        return out
