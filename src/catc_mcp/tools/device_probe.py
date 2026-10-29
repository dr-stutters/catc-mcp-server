"""Reachability tests from a managed device: catc_ping and catc_traceroute (roadmap D74), read-only.

Both run through the same command-runner flow as catc_run_show_commands (POST
/dna/intent/api/v1/network-device-poller/cli/read-request -> task -> output file), which stays show-only.
The runner's own keyword list (GET .../cli/legit-reads, checked live on 3.2.2 on 2026-10-28) accepts ping and
traceroute, but also debug, monitor, test, crypto, verify and more; this server never trusts it wholesale.
Every command is built here from checked arguments and checked once more against a fixed allow-list
(show, ping, traceroute, dir) with a fixed grammar per verb (check_runner_command).

The IOS-XE output is parsed: ping -> sent/received, success and loss %, min/avg/max RTT; traceroute -> one
row per hop with its responders, RTTs, timeouts, MPLS labels and unreachable codes, and whether the target
answered.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import InvalidRequest, ToolRegistrar, get_client, object_result
from catc_mcp.client import CatcApp
from catc_mcp.common import is_ip, resolve_device
from catc_mcp.tools.smart import check_show_command, run_show

# --- allow-list --------------------------------------------------------------------------------

ALLOWED_VERBS = ("show", "ping", "traceroute", "dir")
MAX_PING_COUNT = 100
MAX_HOPS = 30
PING_TIMEOUT_S = 2  # IOS-XE default per echo
TRACE_TIMEOUT_S = 2  # per probe (IOS-XE default is 3)
RUNNER_CAP_S = 300  # the runner's own timeout limit (see smart._run_show_once)

_FORBIDDEN = re.compile(r"[\n\r;`&<>|\"'\\]|\$\(")
_LABEL_RE = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})"
_HOSTNAME = re.compile(rf"(?=.{{1,253}}$){_LABEL_RE}(?:\.{_LABEL_RE})*\.?")
_INTERFACE = re.compile(r"[A-Za-z][A-Za-z-]*\d+(?:[/.:]\d+)*")
_VRF = re.compile(r"[A-Za-z0-9_.:-]{1,32}")
_PATH = re.compile(r"[A-Za-z0-9_.\-/:]{1,128}")
# Words that must not be read as a target, VRF or source: IOS would take them as a protocol or an option.
_RESERVED = {
    "ip",
    "ipv6",
    "clns",
    "mpls",
    "tag",
    "appletalk",
    "vrf",
    "repeat",
    "source",
    "timeout",
    "size",
    "numeric",
    "ttl",
    "probe",
    "port",
    "df-bit",
    "validate",
    "data",
    "sweep",
    "verbose",
}
# Option keyword -> number of values (each value checked by _option_value).
_PING_OPTIONS = {"repeat": 1, "source": 1, "timeout": 1, "size": 1}
_TRACE_OPTIONS = {"source": 1, "timeout": 1, "probe": 1, "ttl": 2, "numeric": 0}
_NUMERIC = {
    "repeat": (1, MAX_PING_COUNT),
    "timeout": (0, 10),
    "size": (36, 18024),
    "probe": (1, 10),
    "ttl": (1, 255),
}


def _refuse(cmd: str, why: str) -> InvalidRequest:
    return InvalidRequest(f"Refused {cmd!r}: {why}")


def check_target(target: str) -> str:
    t = target.strip()
    if is_ip(t):
        return str(ipaddress.ip_address(t))
    if not t.isascii() or not _HOSTNAME.fullmatch(t) or t.lower() in _RESERVED:
        raise InvalidRequest(f"{target!r} is not an IP address or host name.")
    return t


def check_source(source: str) -> str:
    """An IP address or an interface name ('Loopback0', 'GigabitEthernet1/0/1', 'Vlan10', 'Loopback 0')."""
    s = source.strip()
    if is_ip(s):
        return str(ipaddress.ip_address(s))
    s = re.sub(r"^([A-Za-z-]+)\s+(\d)", r"\1\2", s)
    if not s.isascii() or not _INTERFACE.fullmatch(s) or s.lower() in _RESERVED:
        raise InvalidRequest(f"{source!r} is not a source interface (e.g. Loopback0) or IP address.")
    return s


def check_vrf(vrf: str) -> str:
    v = vrf.strip()
    if not v.isascii() or not _VRF.fullmatch(v) or v.lower() in _RESERVED:
        raise InvalidRequest(f"{vrf!r} is not a VRF name.")
    return v


def _option_value(cmd: str, key: str, value: str) -> None:
    if key == "source":
        check_source(value)
        return
    lo, hi = _NUMERIC[key]
    if not value.isdigit() or not lo <= int(value) <= hi:
        raise _refuse(cmd, f"{key} takes a number from {lo} to {hi}.")


def _check_probe(cmd: str, words: list[str], options: dict[str, int]) -> None:
    i = 1
    if len(words) > 2 and words[1].lower() == "vrf":
        check_vrf(words[2])
        i = 3
    if i >= len(words):
        raise _refuse(cmd, "give a target.")
    check_target(words[i])
    i += 1
    while i < len(words):
        key = words[i].lower()
        if key not in options:
            allowed = ", ".join(options)
            raise _refuse(cmd, f"{words[i]!r} is not an allowed {words[0]} option ({allowed}).")
        n = options[key]
        values = words[i + 1 : i + 1 + n]
        if len(values) != n:
            raise _refuse(cmd, f"{key} needs {n} value(s).")
        for v in values:
            _option_value(cmd, key, v)
        i += 1 + n


def check_runner_command(cmd: str) -> str:
    """The normalised command if it is on the fixed allow-list, else InvalidRequest. `show` goes through
    check_show_command; ping and traceroute take an optional `vrf <name>`, one target and only the options
    in _PING_OPTIONS / _TRACE_OPTIONS; `dir` takes at most one path. Nothing else (debug, monitor, test,
    crypto, verify, ... that the command runner itself would accept) is let through."""
    c = " ".join(cmd.split())
    words = c.split()
    if not words or not c.isascii() or not c.isprintable():
        raise _refuse(cmd, "empty or not plain ASCII.")
    verb = words[0].lower()
    if verb not in ALLOWED_VERBS:
        raise _refuse(cmd, f"only {', '.join(ALLOWED_VERBS)} commands are allowed.")
    if verb == "show":
        return check_show_command(c)
    if _FORBIDDEN.search(cmd):
        raise _refuse(cmd, "no pipes, quotes, ;, &, <, > or newlines.")
    words[0] = verb
    if verb == "ping":
        _check_probe(c, words, _PING_OPTIONS)
    elif verb == "traceroute":
        _check_probe(c, words, _TRACE_OPTIONS)
    elif len(words) > 2 or (len(words) == 2 and not _PATH.fullmatch(words[1])):
        raise _refuse(cmd, "dir takes at most one file system or path, e.g. 'dir flash:'.")
    return " ".join(words)


def ping_command(target: str, count: int, source: str | None, vrf: str | None) -> str:
    parts = ["ping"]
    if vrf:
        parts += ["vrf", check_vrf(vrf)]
    parts += [check_target(target), "repeat", str(count)]
    if source:
        parts += ["source", check_source(source)]
    return check_runner_command(" ".join(parts))


def traceroute_command(target: str, max_hops: int, source: str | None, vrf: str | None) -> str:
    parts = ["traceroute"]
    if vrf:
        parts += ["vrf", check_vrf(vrf)]
    parts.append(check_target(target))
    if source:
        parts += ["source", check_source(source)]
    parts += ["numeric", "timeout", str(TRACE_TIMEOUT_S), "ttl", "1", str(max_hops)]
    return check_runner_command(" ".join(parts))


# --- parsing -----------------------------------------------------------------------------------

_SUCCESS = re.compile(
    r"Success rate is (\d+) percent \((\d+)/(\d+)\)"
    r"(?:,\s*round-trip min/avg/max\s*=\s*(\d+)/(\d+)/(\d+)\s*ms)?"
)
_SENDING = re.compile(r"Sending (\d+), (\d+)-byte ICMP Echos to (\S+?), timeout is (\d+) seconds")
_SOURCE_ADDR = re.compile(r"Packet sent with a source address of (\S+)")


def _errors(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("%")]


def parse_ping(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if m := _SENDING.search(text):
        out["sent"] = int(m.group(1))
        out["size_bytes"] = int(m.group(2))
        out["timeout_s"] = int(m.group(4))
    if m := _SOURCE_ADDR.search(text):
        out["source_address"] = m.group(1)
    m = _SUCCESS.search(text)
    if not m:
        out["parsed"] = False
        errs = _errors(text)
        if errs:
            out["error"] = errs[0]
        return out
    pct, received, sent = int(m.group(1)), int(m.group(2)), int(m.group(3))
    out.update(
        {
            "parsed": True,
            "sent": sent,
            "received": received,
            "success_percent": pct,
            "loss_percent": 100 - pct,
            "reachable": received > 0,
        }
    )
    if m.group(4) is not None:
        out["rtt_ms"] = {"min": int(m.group(4)), "avg": int(m.group(5)), "max": int(m.group(6))}
    return out


_TRACING = re.compile(r"Tracing the route to (\S+)(?: \(([0-9A-Fa-f.:]+)\))?")
_HOP = re.compile(r"^\s*(\d+)\s+(.*)$")
_CONT = re.compile(r"^\s{2,}(\S.*)$")
_LABEL = re.compile(r"\[MPLS: ([^\]]*)\]")
_NAMED = re.compile(r"([A-Za-z0-9][\w.-]*) \(([0-9A-Fa-f.:]+)\)")
_RTT = re.compile(r"(\d+(?:\.\d+)?)\s*msec")
_CODE = re.compile(r"(?<!\S)!([A-Z])(?!\S)")


def _addr(token: str) -> str | None:
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def _hop_row(n: int, text: str) -> dict[str, Any]:
    row: dict[str, Any] = {"hop": n, "responders": [], "rtt_ms": [], "timeouts": 0}
    labels = _LABEL.findall(text)
    text = _LABEL.sub(" ", text)
    for name, ip in _NAMED.findall(text):
        row["responders"].append({"name": name, "ip": ip})
    text = _NAMED.sub(" ", text)
    row["rtt_ms"] = [float(x) if "." in x else int(x) for x in _RTT.findall(text)]
    text = _RTT.sub(" ", text)
    codes = _CODE.findall(text)
    text = _CODE.sub(" ", text)
    for tok in text.split():
        if tok == "*":
            row["timeouts"] += 1
        elif (ip := _addr(tok)) and not any(r["ip"] == ip for r in row["responders"]):
            row["responders"].append({"ip": ip})
    if labels:
        row["mpls_labels"] = labels
    if codes:
        row["unreachable_codes"] = sorted(set(codes))
    return row


def parse_traceroute(text: str, target: str, max_hops: int | None = None) -> dict[str, Any]:
    """Parse IOS/IOS-XE traceroute text. ``reached`` is True when the last hop's responder is the target,
    or when the trace stopped short of ``max_hops`` and its last hop answered without an unreachable code:
    IOS stops once the destination replies (port unreachable), and a router sources that reply from the
    interface the probe arrived on, not the probed loopback. ``reached_via`` names the answering address."""
    out: dict[str, Any] = {}
    target_ip = _addr(target)
    if m := _TRACING.search(text):
        target_ip = _addr(m.group(2) or m.group(1)) or target_ip
    if target_ip:
        out["target_ip"] = target_ip
    hops: list[dict[str, Any]] = []
    current: list[str] | None = None
    numbers: list[int] = []
    for line in text.splitlines():
        if m := _HOP.match(line):
            current = [m.group(2)]
            numbers.append(int(m.group(1)))
            hops.append({})
        elif current is not None and (m := _CONT.match(line)):
            current.append(m.group(1))
        else:
            continue
        hops[-1] = _hop_row(numbers[-1], " ".join(current))
    for h in hops:
        h["responders"] = h["responders"] or None
        if not h["rtt_ms"]:
            h.pop("rtt_ms")
        if not h["timeouts"]:
            h.pop("timeouts")
        if h["responders"] is None:
            h.pop("responders")
    out["hops"] = hops
    out["hop_count"] = len(hops)
    last = hops[-1] if hops else {}
    answered = [r["ip"] for r in last.get("responders", [])]
    reached = bool(target_ip) and target_ip in answered
    if reached:
        out["reached_via"] = target_ip
    elif max_hops is not None and answered and last["hop"] < max_hops and not last.get("unreachable_codes"):
        reached = True
        out["reached_via"] = f"{answered[-1]} (destination answered from another interface)"
    out["reached"] = reached
    out["parsed"] = bool(hops)
    if not hops and (errs := _errors(text)):
        out["error"] = errs[0]
    return out


# --- shared runner call ------------------------------------------------------------------------


async def run_probe(
    app: CatcApp, ctx: Context, device: str, command: str, wait_s: float
) -> tuple[str, dict[str, Any], str | None]:
    """Run one allow-listed command on one device: (device name, runner entry, output text or None)."""
    command = check_runner_command(command)
    dev = await resolve_device(app, device)
    wait = min(max(float(app.settings.command_runner_timeout), wait_s), RUNNER_CAP_S)
    results = await run_show(app, ctx, [dev], [command], name="catc-mcp-probe", wait_s=wait)
    entry: dict[str, Any] = results[0] if results else {"device": dev.get("hostname") or device}
    text = (entry.get("output") or {}).get(command)
    if text is None:
        # The runner can file a probe whose target didn't answer under FAILURE: keep that text too.
        text = (entry.get("failed") or {}).get(command)
    return str(entry.get("device")), entry, text


def _base(name: str, command: str, entry: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"device": name, "command": command}
    for key in ("failed", "blocked_by_catalyst_center"):
        if entry.get(key):
            out[key] = entry[key]
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Ping from a device", idempotent=False)
    async def catc_ping(
        ctx: Context,
        device: Annotated[str, Field(description="Managed device to ping from (hostname, IP, serial or id)")],
        target: Annotated[str, Field(description="Address or host name to ping")],
        source: Annotated[
            str | None, Field(description="Source interface (e.g. Loopback0, Vlan10) or source IP")
        ] = None,
        count: Annotated[int, Field(ge=1, le=MAX_PING_COUNT, description="Echoes to send")] = 5,
        vrf: Annotated[str | None, Field(description="VRF to ping in (default: global table)")] = None,
    ) -> ToolResult:
        """Ping from a managed IOS-XE device live through Catalyst Center's command runner and return
        the parsed result: sent/received, success and loss %, min/avg/max round-trip time, reachable, a
        one-line verdict, and the raw output. The first reachability check for 'this site can't
        authenticate / resolve names' (ping ISE, DHCP or DNS from the access switch with its source
        interface) without SSH. The command is built from the arguments and checked against a fixed
        allow-list; nothing else is sent. A path as Catalyst Center models it: catc_path_trace; hop by hop
        from the device: catc_traceroute."""
        app: CatcApp = get_client(ctx)
        command = ping_command(target, count, source, vrf)
        name, entry, text = await run_probe(app, ctx, device, command, count * PING_TIMEOUT_S + 30)
        out = _base(name, command, entry)
        if text is not None:
            out.update(parse_ping(text))
            out["output"] = text
        if "success_percent" in out:
            rtt = out.get("rtt_ms")
            out["verdict"] = (
                f"{name} -> {target}: {out['success_percent']}% success ({out['received']}/{out['sent']})"
                + (f", RTT min/avg/max {rtt['min']}/{rtt['avg']}/{rtt['max']} ms" if rtt else "")
                + ("" if out["reachable"] else ": no reply")
            )
        else:
            out["verdict"] = f"{name} -> {target}: no ping result" + (
                f" ({out['error']})" if out.get("error") else " (see failed/output)"
            )
        return object_result(out, shape=False)

    @reg.read(title="Traceroute from a device", idempotent=False)
    async def catc_traceroute(
        ctx: Context,
        device: Annotated[
            str, Field(description="Managed device to trace from (hostname, IP, serial or id)")
        ],
        target: Annotated[str, Field(description="Address or host name to trace to")],
        max_hops: Annotated[int, Field(ge=1, le=MAX_HOPS, description="Maximum TTL")] = MAX_HOPS,
        source: Annotated[
            str | None, Field(description="Source interface (e.g. Loopback0) or source IP")
        ] = None,
        vrf: Annotated[str | None, Field(description="VRF to trace in (default: global table)")] = None,
    ) -> ToolResult:
        """Traceroute from a managed IOS-XE device live through Catalyst Center's command runner and
        return the parsed hops: per hop the responders (IP, name when resolved), RTTs, timeouts, MPLS
        labels and unreachable codes (!H, !N, !A ...), whether the target answered (reached, reached_via: a
        trace that stops short of max_hops on an answering hop counts, since a router replies from its
        ingress interface rather than the probed loopback), a one-line verdict and the raw output. Numeric
        (no DNS lookups), 2 s per probe. The command is built from the arguments
        and checked against a fixed allow-list. Catalyst Center's own model of the path (interfaces,
        ACLs): catc_path_trace."""
        app: CatcApp = get_client(ctx)
        command = traceroute_command(target, max_hops, source, vrf)
        name, entry, text = await run_probe(app, ctx, device, command, max_hops * 3 * TRACE_TIMEOUT_S + 30)
        out = _base(name, command, entry)
        if text is not None:
            out.update(parse_traceroute(text, target, max_hops))
            out["output"] = text
        if out.get("parsed"):
            last = out["hops"][-1]
            if out["reached"]:
                out["verdict"] = f"{name} -> {target}: reached in {out['hop_count']} hop(s)"
                if out.get("reached_via") != out.get("target_ip"):
                    via = str(out["reached_via"]).split(" ", 1)[0]
                    out["verdict"] += f"; the destination answered from {via}, another of its interfaces"
            else:
                where = [r["ip"] for h in out["hops"] for r in h.get("responders", [])]
                out["verdict"] = f"{name} -> {target}: not reached after {out['hop_count']} hop(s)" + (
                    f"; last answer from {where[-1]}" if where else "; no hop answered"
                )
                if last.get("unreachable_codes"):
                    codes = ", ".join("!" + c for c in last["unreachable_codes"])
                    out["verdict"] += f" (unreachable {codes})"
        else:
            out["verdict"] = f"{name} -> {target}: no traceroute result" + (
                f" ({out['error']})" if out.get("error") else " (see failed/output)"
            )
        return object_result(out, shape=False)
