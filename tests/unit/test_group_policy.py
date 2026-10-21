"""D91: group-based policy as a switch enforces it (catc_get_group_policy_enforcement).

Permissions, counters and bindings are the cat9000v 17.18.2 outputs recorded in ise-mcp-server's
docs/trustsec.md (I51/I55 run, 2026-10-18); the environment data follows the same release's full format.
"""

import json
from typing import Any

import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.group_policy import (
    parse_bindings,
    parse_counters,
    parse_environment,
    parse_permissions,
    resolve_sgt,
    verdict,
)

from .test_find_host import SW1_ID, mock_sw1
from .test_read_tools import call

ENV = """CTS Environment Data
====================
Current state = COMPLETE
Last status = Successful
Local Device SGT:
  SGT tag = 2-00:TrustSec_Devices
Server List Info:
Installed list: CTSServerList1-0001, 1 server(s):
 *Server: 198.18.134.35, port 1812, A-ID DDDC056F4339C0EA4D56FA3DB6FFE275
          Status = ALIVE
          auto-test = FALSE, keywrap-enable = FALSE, idle-time = 60 mins, deadtime = 20 secs
Security Group Name Table:
    0-00:Unknown
    2-00:TrustSec_Devices
    4-00:Employees
    5-00:Contractors
    11-00:Production_Servers
Environment Data Lifetime = 86400 secs
Last update time = 11:07:50 UTC Sun Oct 18 2026
Env-data expires in   0:23:59:58 (dd:hr:mm:sec)
State Machine is running
"""
PERMS = """IPv4 Role-based permissions default:
        Permit IP-00
IPv4 Role-based permissions from group 5:Contractors to group 11:Production_Servers:
        Deny IP-00
RBACL Monitor All for Dynamic Policies : FALSE
RBACL Monitor All for Configured Policies : FALSE
"""
COUNTERS = """Role-based IP traffic permissions
From    To      SW-Denied  HW-Denied  SW-Permitt HW-Permitt SW-Monitor HW-Monitor
*       *       0          0          0          1          0          0
5       11      0          5          0          0          0          0
"""
BINDINGS = """Active IPv4-SGT Bindings Information

IP Address              SGT     Source
============================================
10.10.10.1              2       INTERNAL
10.10.10.50             5       LOCAL
10.10.10.100            11      CLI
198.18.128.154          2       INTERNAL

IP-SGT Active Bindings Summary
============================================
Total number of CLI      bindings = 1
Total number of LOCAL    bindings = 1
Total number of INTERNAL bindings = 2
Total number of active   bindings = 4
"""
CMDS = {
    "show cts environment-data": ENV,
    "show cts role-based permissions": PERMS,
    "show cts role-based counters": COUNTERS,
    "show cts role-based sgt-map all": BINDINGS,
    "show running-config | include cts role-based enforcement": "cts role-based enforcement\n"
    "cts role-based enforcement vlan-list 1021-1023",
}


def test_parsers_on_recorded_output() -> None:
    env = parse_environment(ENV)
    assert env["state"] == "COMPLETE" and env["device_sgt"] == "2-00:TrustSec_Devices"
    assert env["servers"] == [{"ip": "198.18.134.35", "port": 1812, "preferred": True}]
    assert env["groups"] == {
        0: "Unknown",
        2: "TrustSec_Devices",
        4: "Employees",
        5: "Contractors",
        11: "Production_Servers",
    }
    perms = parse_permissions(PERMS)
    assert perms["default"] == ["Permit IP"]
    assert perms["cells"] == [
        {
            "ip_version": 4,
            "from": {"sgt": 5, "name": "Contractors"},
            "to": {"sgt": 11, "name": "Production_Servers"},
            "sgacls": ["Deny IP"],
        }
    ]
    counters = parse_counters(COUNTERS)
    assert counters[1] == {
        "from": 5,
        "to": 11,
        "sw_denied": 0,
        "hw_denied": 5,
        "sw_permitted": 0,
        "hw_permitted": 0,
        "sw_monitored": 0,
        "hw_monitored": 0,
    }
    assert counters[0]["from"] is None and counters[0]["hw_permitted"] == 1
    assert [b["ip"] for b in parse_bindings(BINDINGS)] == [
        "10.10.10.1",
        "10.10.10.50",
        "10.10.10.100",
        "198.18.128.154",
    ]


def test_cell_variants() -> None:
    text = (
        "IPv4 Role-based permissions from group Unknown to group 11:Production_Servers (configured):\n"
        "        Permit_Web-01\n"
        "        Deny IP-00\n"
        "IPv6 Role-based permissions from group 4:Employees to group 5:Contractors:\n"
        "        Deny IP-00\n"
    )
    cells = parse_permissions(text)["cells"]
    assert cells[0]["from"] == {"sgt": None, "name": "Unknown"} and cells[0]["kind"] == "configured"
    assert cells[0]["sgacls"] == ["Permit_Web", "Deny IP"] and cells[1]["ip_version"] == 6


def test_verdict_cell_vs_default_and_names() -> None:
    perms, counters = parse_permissions(PERMS), parse_counters(COUNTERS)
    env = parse_environment(ENV)
    assert resolve_sgt("contractors", env["groups"], perms["cells"]) == 5
    assert resolve_sgt("11", env["groups"], perms["cells"]) == 11
    v = verdict(5, 11, perms, counters)
    assert v["policy"] == ["Deny IP"] and v["counters"]["hw_denied"] == 5 and "cell" in v["source_of_policy"]
    v = verdict(4, 11, perms, counters)
    assert v["policy"] == ["Permit IP"] and v["counters"] is None and "default" in v["source_of_policy"]
    with pytest.raises(Exception, match="no security group named 'Guests'"):
        resolve_sgt("Guests", env["groups"], perms["cells"])


def mock_cli(api: respx.MockRouter, outputs: dict[str, str]) -> respx.Route:
    route = api.post("/dna/intent/api/v1/network-device-poller/cli/read-request").respond(
        202, json={"response": {"taskId": "t-cts"}}
    )
    api.get("/dna/intent/api/v1/task/t-cts").respond(
        json={"response": {"progress": json.dumps({"fileId": "f-cts"}), "endTime": 1}}
    )
    api.get("/dna/intent/api/v1/file/f-cts").respond(
        json=[
            {"deviceUuid": SW1_ID, "commandResponses": {"SUCCESS": outputs, "FAILURE": {}, "BLACKLISTED": {}}}
        ]
    )
    return route


async def test_tool_pair_and_clients(api: respx.MockRouter) -> None:
    mock_sw1(api)
    route = mock_cli(api, CMDS)
    out: dict[str, Any] = await call(
        "catc_get_group_policy_enforcement",
        {
            "device": "mcp-sw1",
            "source": "Contractors",
            "destination": "Production_Servers",
            "ips": ["10.10.10.50", "10.10.10.9"],
        },
    )
    sent = json.loads(route.calls[0].request.content)
    assert sent["deviceUuids"] == [SW1_ID] and "show cts role-based permissions" in sent["commands"]
    assert out["pair"]["policy"] == ["Deny IP"] and out["pair"]["from_name"] == "Contractors"
    assert out["enforcement"]["global"] is True and len(out["enforcement"]["config"]) == 2
    assert out["clients"] == [
        {"ip": "10.10.10.50", "sgt": 5, "source": "LOCAL", "sgt_name": "Contractors"},
        {"ip": "10.10.10.9", "note": "no binding"},
    ]
    assert "notes" not in out


async def test_tool_flags_a_switch_without_trustsec(api: respx.MockRouter) -> None:
    mock_sw1(api)
    mock_cli(api, {c: "" for c in CMDS})
    out = await call("catc_get_group_policy_enforcement", {"device": "198.18.128.154"})
    text = " ".join(out["notes"])
    assert "No TrustSec environment data" in text and "not configured" in text
    assert out["cells"] == [] and out["bindings"] == []
    with pytest.raises(ToolError, match="both source and destination"):
        await call("catc_get_group_policy_enforcement", {"device": "mcp-sw1", "source": "5"})


async def test_tool_reports_pending_download(api: respx.MockRouter) -> None:
    mock_sw1(api)
    mock_cli(api, {**CMDS, "show cts environment-data": ENV.replace("= COMPLETE", "= WAITING_RESPONSE")})
    out = await call("catc_get_group_policy_enforcement", {"device": "mcp-sw1"})
    assert "WAITING_RESPONSE" in out["notes"][0]
