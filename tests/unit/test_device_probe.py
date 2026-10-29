"""D74: catc_ping / catc_traceroute through the command runner, and the fixed command allow-list.

The command-runner outputs are synthetic IOS-XE 17.x text (tests/fixtures/device_probe), in the shape the
3.2.2 runner returns: the echoed command first, the device prompt last."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.device_probe import (
    check_runner_command,
    parse_ping,
    parse_traceroute,
    ping_command,
    traceroute_command,
)

from .test_read_tools import call

FIX = Path(__file__).parent.parent / "fixtures" / "device_probe"
READ_REQUEST = "/dna/intent/api/v1/network-device-poller/cli/read-request"
DEV_ID = "aaaabbbb-cccc-dddd-eeee-000000000001"
EDGE = {
    "id": DEV_ID,
    "hostname": "edge-r1.example.com",
    "managementIpAddress": "192.0.2.1",
    "family": "Routers",
    "role": "BORDER ROUTER",
}


def text(name: str) -> str:
    return (FIX / name).read_text()


def mock_runner(
    api: respx.MockRouter, outputs: dict[str, str], where: str = "SUCCESS"
) -> list[dict[str, Any]]:
    """Device lookup + read-request -> task -> file; returns the read-request bodies sent."""

    def by_query(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if q.get("hostname") in ("edge-r1", "edge-r1.*") or q.get("managementIpAddress") == "192.0.2.1":
            return httpx.Response(200, json={"response": [EDGE]})
        return httpx.Response(200, json={"response": []})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=by_query)
    sent: list[dict[str, Any]] = []

    def start(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(202, json={"response": {"taskId": "t-probe"}})

    api.post(READ_REQUEST).mock(side_effect=start)
    api.get("/dna/intent/api/v1/task/t-probe").respond(
        json={"response": {"progress": '{"fileId":"f-probe"}', "endTime": 1}}
    )
    responses = {"SUCCESS": {}, "FAILURE": {}, "BLACKLISTED": {}}
    responses[where] = outputs
    api.get("/dna/intent/api/v1/file/f-probe").respond(
        json=[{"deviceUuid": DEV_ID, "commandResponses": responses}]
    )
    return sent


# --- allow-list --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "show ip int brief",
        "ping 192.0.2.9",
        "ping vrf CORP 192.0.2.9 repeat 100 source Loopback0",
        "ping 2001:db8::1 repeat 3",
        "traceroute 198.51.100.20 numeric timeout 2 ttl 1 30",
        "traceroute vrf CORP ise.example.com source GigabitEthernet1/0/1",
        "dir",
        "dir flash:",
    ],
)
def test_allow_list_accepts(cmd: str) -> None:
    assert check_runner_command(cmd) == " ".join(cmd.split())


@pytest.mark.parametrize(
    "cmd",
    [
        "debug ip packet",  # in the runner's legit-reads, not on ours
        "monitor capture cap start",
        "test cable-diagnostics tdr interface Gi1/0/1",
        "crypto pki export TP pem terminal",
        "verify /md5 flash:image.bin",
        "undebug all",
        "configure terminal",
        "ping 192.0.2.9 ; reload",
        "ping 192.0.2.9 | redirect flash:x",
        "ping 192.0.2.9 repeat 101",
        "ping 192.0.2.9 data abcd",
        "ping 192.0.2.9 sweep",
        "ping vrf",
        "ping ip",
        "traceroute 192.0.2.9 port 80",
        "traceroute 192.0.2.9 ttl 1",
        "dir flash: nvram:",
        "dir flash:$(x)",
    ],
)
def test_allow_list_refuses(cmd: str) -> None:
    with pytest.raises(Exception, match="Refused|not an|is not"):
        check_runner_command(cmd)


def test_built_commands() -> None:
    assert (
        ping_command("198.51.100.20", 5, "Loopback 0", None) == "ping 198.51.100.20 repeat 5 source Loopback0"
    )
    assert ping_command("ise.example.com", 2, "192.0.2.1", "CORP") == (
        "ping vrf CORP ise.example.com repeat 2 source 192.0.2.1"
    )
    assert traceroute_command("198.51.100.20", 30, None, None) == (
        "traceroute 198.51.100.20 numeric timeout 2 ttl 1 30"
    )
    # A bare word is a host name to IOS (a DNS lookup of 'debug'), not the debug command.
    assert ping_command("debug", 1, None, None) == "ping debug repeat 1"


@pytest.mark.parametrize(
    "args",
    [
        {"target": "192.0.2.9 ; reload"},
        {"target": "192.0.2.9", "source": "Lo0 repeat 1"},
        {"target": "192.0.2.9", "vrf": "x debug"},
        {"target": "ip"},
    ],
)
async def test_ping_bad_arguments_never_reach_the_runner(api: respx.MockRouter, args: dict[str, Any]) -> None:
    sent = mock_runner(api, {})
    with pytest.raises(ToolError):
        await call("catc_ping", {"device": "edge-r1", **args})
    assert sent == []


# --- parsing -----------------------------------------------------------------------------------


def test_parse_ping_ok() -> None:
    p = parse_ping(text("ping_ok.txt"))
    assert p["success_percent"] == 100 and p["loss_percent"] == 0
    assert (p["sent"], p["received"]) == (5, 5) and p["reachable"] is True
    assert p["rtt_ms"] == {"min": 1, "avg": 2, "max": 4}
    assert p["source_address"] == "192.0.2.1"


def test_parse_ping_partial() -> None:
    p = parse_ping(text("ping_partial.txt"))
    assert (p["success_percent"], p["loss_percent"], p["received"], p["sent"]) == (80, 20, 8, 10)
    assert p["rtt_ms"] == {"min": 3, "avg": 5, "max": 12}


def test_parse_ping_unreachable_is_zero_percent() -> None:
    p = parse_ping(text("ping_unreachable.txt"))
    assert p["parsed"] is True
    assert p["success_percent"] == 0 and p["loss_percent"] == 100 and p["reachable"] is False
    assert "rtt_ms" not in p


def test_parse_ping_error() -> None:
    p = parse_ping(text("ping_bad_host.txt"))
    assert p["parsed"] is False and p["error"].startswith("% Unrecognized host")


def test_parse_traceroute_ok() -> None:
    t = parse_traceroute(text("traceroute_ok.txt"), "198.51.100.20")
    assert t["reached"] is True and t["hop_count"] == 3
    h1, h2, h3 = t["hops"]
    assert h1 == {"hop": 1, "responders": [{"ip": "192.0.2.2"}], "rtt_ms": [1, 1, 0]}
    assert [r["ip"] for r in h2["responders"]] == ["192.0.2.6", "192.0.2.10"]
    assert h2["mpls_labels"] == ["Label 16 Exp 0"] * 3 and h2["rtt_ms"] == [3, 2, 3]
    assert h3["timeouts"] == 1 and h3["rtt_ms"] == [2, 2]


def test_parse_traceroute_unreachable() -> None:
    t = parse_traceroute(text("traceroute_unreachable.txt"), "203.0.113.99")
    assert t["reached"] is False and t["hop_count"] == 4
    assert t["hops"][1]["unreachable_codes"] == ["H"] and t["hops"][1]["timeouts"] == 1
    assert t["hops"][3] == {"hop": 4, "timeouts": 3}


def test_parse_traceroute_named_hops() -> None:
    out = (
        "Tracing the route to ise.example.com (198.51.100.20)\n"
        "  1 gw.example.com (192.0.2.2) 1 msec 1 msec 1 msec\n"
        "  2 ise.example.com (198.51.100.20) 2 msec 2 msec 3 msec\n"
    )
    t = parse_traceroute(out, "ise.example.com")
    assert t["target_ip"] == "198.51.100.20" and t["reached"] is True
    assert t["hops"][0]["responders"] == [{"name": "gw.example.com", "ip": "192.0.2.2"}]


def test_parse_traceroute_exact_target_reports_reached_via() -> None:
    t = parse_traceroute(text("traceroute_ok.txt"), "198.51.100.20", 30)
    assert t["reached"] is True and t["reached_via"] == "198.51.100.20"


def test_parse_traceroute_destination_answers_from_another_interface() -> None:
    """#307 live shape: the router answers from its ingress interface, the trace stops short of max_hops."""
    t = parse_traceroute(text("traceroute_other_interface.txt"), "198.51.100.3", 5)
    assert t["reached"] is True and t["hop_count"] == 2
    assert t["reached_via"] == "192.0.2.6 (destination answered from another interface)"
    assert t["hops"][1]["timeouts"] == 1


def test_parse_traceroute_other_ip_without_max_hops_is_not_reached() -> None:
    t = parse_traceroute(text("traceroute_other_interface.txt"), "198.51.100.3")
    assert t["reached"] is False and "reached_via" not in t


TRACE_HEAD = "Tracing the route to 198.51.100.3\n  1 192.0.2.1 1 msec 1 msec 1 msec\n"


@pytest.mark.parametrize(
    ("last", "max_hops"),
    [
        ("  2 192.0.2.6 1 msec 1 msec 1 msec\n", 2),  # every hop up to max_hops tried
        ("  2  *  *  * \n", 5),  # last hop all timeouts
        ("  2 192.0.2.6 !H  *  !H \n", 5),
        ("  2 192.0.2.6 !N  !N  !N \n", 5),
        ("  2 192.0.2.6 !A  !A  !A \n", 5),
    ],
)
def test_parse_traceroute_not_reached_cases(last: str, max_hops: int) -> None:
    t = parse_traceroute(TRACE_HEAD + last, "198.51.100.3", max_hops)
    assert t["reached"] is False and "reached_via" not in t


# --- tools -------------------------------------------------------------------------------------


async def test_catc_ping(api: respx.MockRouter) -> None:
    cmd = "ping 198.51.100.20 repeat 5 source Loopback0"
    sent = mock_runner(api, {cmd: text("ping_ok.txt")})
    out = await call("catc_ping", {"device": "edge-r1", "target": "198.51.100.20", "source": "Loopback0"})
    (body,) = sent
    assert body["commands"] == [cmd] and body["deviceUuids"] == [DEV_ID]
    assert body["name"] == "catc-mcp-probe"
    assert out["device"] == "edge-r1.example.com" and out["command"] == cmd
    assert out["success_percent"] == 100 and out["rtt_ms"]["avg"] == 2
    assert out["verdict"] == (
        "edge-r1.example.com -> 198.51.100.20: 100% success (5/5), RTT min/avg/max 1/2/4 ms"
    )
    assert not out["output"].startswith("ping ") and not out["output"].endswith("edge-r1#")


async def test_catc_ping_unreachable(api: respx.MockRouter) -> None:
    cmd = "ping 203.0.113.99 repeat 5"
    mock_runner(api, {cmd: text("ping_unreachable.txt")})
    out = await call("catc_ping", {"device": "edge-r1", "target": "203.0.113.99"})
    assert out["success_percent"] == 0 and out["loss_percent"] == 100 and out["reachable"] is False
    assert out["verdict"].endswith("0% success (0/5): no reply")


async def test_catc_ping_result_filed_as_failure(api: respx.MockRouter) -> None:
    """If the runner files a ping with no answer under FAILURE, the text is still parsed."""
    cmd = "ping 203.0.113.99 repeat 5"
    mock_runner(api, {cmd: text("ping_unreachable.txt")}, where="FAILURE")
    out = await call("catc_ping", {"device": "edge-r1", "target": "203.0.113.99"})
    assert out["success_percent"] == 0 and cmd in out["failed"]


async def test_catc_ping_long_count_waits_longer(api: respx.MockRouter) -> None:
    cmd = "ping 203.0.113.99 repeat 100"
    sent = mock_runner(api, {cmd: text("ping_unreachable.txt")})
    await call("catc_ping", {"device": "edge-r1", "target": "203.0.113.99", "count": 100})
    assert sent[0]["timeout"] == 230


async def test_catc_ping_count_limit(api: respx.MockRouter) -> None:
    sent = mock_runner(api, {})
    with pytest.raises(ToolError):
        await call("catc_ping", {"device": "edge-r1", "target": "192.0.2.9", "count": 101})
    assert sent == []


async def test_catc_traceroute(api: respx.MockRouter) -> None:
    cmd = "traceroute 198.51.100.20 numeric timeout 2 ttl 1 30"
    sent = mock_runner(api, {cmd: text("traceroute_ok.txt")})
    out = await call("catc_traceroute", {"device": "edge-r1", "target": "198.51.100.20"})
    assert sent[0]["commands"] == [cmd]
    assert out["reached"] is True and out["hop_count"] == 3
    assert out["verdict"] == "edge-r1.example.com -> 198.51.100.20: reached in 3 hop(s)"


async def test_catc_traceroute_not_reached(api: respx.MockRouter) -> None:
    cmd = "traceroute 203.0.113.99 numeric timeout 2 ttl 1 4"
    mock_runner(api, {cmd: text("traceroute_unreachable.txt")})
    out = await call("catc_traceroute", {"device": "edge-r1", "target": "203.0.113.99", "max_hops": 4})
    assert out["reached"] is False
    assert out["verdict"] == (
        "edge-r1.example.com -> 203.0.113.99: not reached after 4 hop(s); last answer from 192.0.2.6"
    )


async def test_catc_traceroute_destination_answers_from_another_interface(api: respx.MockRouter) -> None:
    cmd = "traceroute 198.51.100.3 source Loopback0 numeric timeout 2 ttl 1 5"
    mock_runner(api, {cmd: text("traceroute_other_interface.txt")})
    out = await call(
        "catc_traceroute",
        {"device": "edge-r1", "target": "198.51.100.3", "source": "Loopback0", "max_hops": 5},
    )
    assert out["reached"] is True and out["hop_count"] == 2
    assert out["reached_via"] == "192.0.2.6 (destination answered from another interface)"
    assert out["verdict"] == (
        "edge-r1.example.com -> 198.51.100.3: reached in 2 hop(s); "
        "the destination answered from 192.0.2.6, another of its interfaces"
    )


async def test_run_show_commands_still_show_only(api: respx.MockRouter) -> None:
    route = api.post(READ_REQUEST)
    with pytest.raises(ToolError, match="only 'show"):
        await call("catc_run_show_commands", {"devices": ["edge-r1"], "commands": ["ping 192.0.2.9"]})
    assert route.call_count == 0
