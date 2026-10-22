"""D110: SD-Access fabric AAA readiness (catc_check_fabric_aaa).

The all-green outputs are the ones the lab fabric gave on 2026-10-22 (tests/fixtures/fabric_aaa_322.json: bcp
and edge1, cat9000v 17.18.2, Catalyst Center 3.2.2, plus ISE 3.5's ise_list_nads rows). The broken states are
the ones the 2026-10-21 live run hit before ISE had a route back to the RLOCs (#20, #146): the RADIUS server
DEAD and the edge's environment data stuck in START / Failed with no PAC. They were not kept verbatim, so they
are the same 17.18.2 outputs with those states.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.sda_aaa import (
    AAA_CMD,
    COMMANDS,
    ENV_CMD,
    PAC_CMD,
    IseNad,
    assess,
    covering_nad,
    in_location,
    parse_aaa_servers,
    parse_interface_ips,
    parse_pacs,
    parse_radius_config,
)
from catc_mcp.tools.smart import check_show_command

from .test_read_tools import call
from .test_sda import FID, mock_fabric

FX = json.loads((Path(__file__).parent.parent / "fixtures" / "fabric_aaa_322.json").read_text())
EDGE, BCP = "mcp-catc-fab-edge1.mcp.lab", "mcp-catc-fab-bcp.mcp.lab"
EDGE_ID, BCP_ID = FX["inventory"][0]["id"], FX["inventory"][1]["id"]
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
NADS = [IseNad.model_validate(n) for n in FX["ise_nads"]]

DEAD_AAA = (
    "RADIUS: id 1, priority 1, host 198.18.134.35, auth-port 1812, acct-port 1813, "
    "hostname dnac-radius_198.18.134.35\n"
    "     State: current DEAD, duration 1185s, previous duration 0s\n"
    "     Dead: total time 1185s, count 1\n"
    "     Quarantined: No\n"
    "     Authen: request 412, timeouts 412, failover 0, retransmission 309\n"
    "             Response: accept 0, reject 0, challenge 0\n"
    "     Author: request 0, timeouts 0, failover 0, retransmission 0\n"
    "             Response: accept 0, reject 0, challenge 0\n"
    "     Elapsed time since counters last cleared: 25m\n"
)
START_ENV = """CTS Environment Data
====================
Current state = START
Last status = Failed
Service Info Table:
Local Device SGT:
  SGT tag = 0-00:Unknown
Server List Info:
Environment Data Lifetime = 86400 secs
State Machine is running
Retry_timer (60 secs) is running"""


def outputs(device: str = EDGE, **over: str) -> dict[str, str]:
    return {**FX["outputs"][device], **over}


def broken() -> dict[str, str]:
    return outputs(**{AAA_CMD: DEAD_AAA, ENV_CMD: START_ENV, PAC_CMD: "(no output)"})


def checks(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["check"]: f for f in row["findings"]}


def test_commands_pass_the_show_filter_and_fit_one_runner_request() -> None:
    assert [check_show_command(c) for c in COMMANDS] == COMMANDS
    assert len(COMMANDS) == 5


def test_parsers_on_live_output() -> None:
    edge = FX["outputs"][EDGE]
    [srv] = parse_aaa_servers(edge[AAA_CMD])
    assert srv == {
        "host": "198.18.134.35",
        "auth_port": 1812,
        "acct_port": 1813,
        "name": "dnac-radius_198.18.134.35",
        "state": "UP",
        "state_for_s": 22583,
        "dead_count": 3,
        "dead_total_s": 14502,
        "authen_requests": 676,
        "authen_timeouts": 672,
        "authen_accepts": 2,
        "authen_rejects": 2,
        "counters_cleared": "10h18m ago",
    }
    cfg = parse_radius_config(edge["show running-config | section radius"])
    assert cfg["source_interface"] == "Loopback0" and cfg["dot1x_group"] == "dnac-client-radius-group"
    assert cfg["groups"]["dnac-client-radius-group"] == {
        "servers": ["dnac-radius_198.18.134.35"],
        "source_interface": "Loopback0",
    }
    assert cfg["servers"]["dnac-radius_198.18.134.35"] == {
        "address": "198.18.134.35",
        "automate_tester": True,
    }
    assert cfg["deadtime_min"] == 3 and cfg["dead_criteria"] == "time 5 tries 3"
    ips = parse_interface_ips(edge["show ip interface brief | exclude unassigned"])
    assert ips["Loopback0"] == "10.255.255.12" and ips["GigabitEthernet1/0/1"] == "198.18.128.175"
    pac = parse_pacs(edge[PAC_CMD], NOW)
    assert pac == {
        "a_id": "DDDC056F4339C0EA4D56FA3DB6FFE275",
        "i_id": "9994d71bcb154454baf2e37e5a127d18",
        "a_id_info": "Identity Services Engine",
        "lifetime": "02:33:38 UTC Wed Jan 20 2027",
        "refresh_in": "12w4d",
        "expired": False,
    }
    assert "PLACEHOLDER" not in json.dumps(pac)
    assert parse_pacs(edge[PAC_CMD], datetime(2027, 2, 1, tzinfo=UTC))["expired"] is True  # type: ignore[index]
    assert parse_pacs("") is None


def test_dead_server_and_other_protocols() -> None:
    [srv] = parse_aaa_servers(DEAD_AAA + "TACACS+: id 2, priority 1, host 10.0.0.9\n     State: current UP\n")
    assert srv["state"] == "DEAD" and srv["state_for_s"] == 1185 and srv["authen_timeouts"] == 412
    assert srv["authen_accepts"] == 0


def test_ise_nad_shapes_and_matching() -> None:
    # ise_get_nad's full record works as well as an ise_list_nads row.
    full = IseNad.model_validate(
        {
            "name": "edge1",
            "NetworkDeviceIPList": [{"ipaddress": "10.255.255.0", "mask": 24}],
            "NetworkDeviceGroupList": ["Location#All Locations"],
            "trustsecsettings": {"deviceAuthenticationSettings": {"sgaDeviceId": "x"}},
        }
    )
    assert full.ips == ["10.255.255.0/24"] and full.trustsec == "yes"
    assert IseNad.model_validate({"name": "n", "trustsecsettings": None}).trustsec is None
    hit = covering_nad([full, *NADS], "10.255.255.12")
    assert hit and hit[0].name == EDGE and hit[1] == "10.255.255.12/32"  # most specific wins
    assert covering_nad(NADS, "10.255.255.99") is None
    assert covering_nad(NADS, "not-an-ip") is None
    groups = NADS[0].groups
    assert in_location(groups, "mcp-test-lab") and in_location(groups, "Location#All Locations#mcp-test-lab")
    assert in_location(groups, "all locations#MCP-TEST-LAB") and not in_location(groups, "SYD")


def test_assess_live_edge_is_ok_with_its_nad() -> None:
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], outputs(), {}, NADS, "mcp-test-lab", NOW)
    assert row["verdict"] == "ok" and row["findings"] == []
    assert row["radius_source"] == {
        "interface": "Loopback0",
        "ip": "10.255.255.12",
        "set_in": "dnac-client-radius-group",
    }
    assert row["nad_ip"] == "10.255.255.12" and row["deadtime_min"] == 3
    assert row["ise_nad"] == {
        "name": EDGE,
        "covers": "10.255.255.12/32",
        "location": ["Location#All Locations#mcp-test-lab"],
        "trustsec": "yes",
    }
    assert row["radius_servers"][0]["state"] == "UP" and row["radius_servers"][0]["automate_tester"] is True
    assert row["trustsec"]["environment"] == "COMPLETE" and row["trustsec"]["groups"] == 18
    assert row["trustsec"]["servers"] == [
        {"ip": "198.18.134.35", "port": 1812, "preferred": True, "status": "ALIVE"}
    ]
    # The live run's DEAD spell is history now: a note, not a finding.
    assert "was DEAD 3 time(s), 14502 s in all" in row["notes"][0]
    assert "(10h18m ago); 672 of 676 authentication requests timed out" in row["notes"][0]


def test_assess_dead_radius_without_ise_data() -> None:
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], broken(), {}, None, None, NOW)
    found = checks(row)
    assert row["verdict"] == "fail" and "ise_nad" not in row
    assert set(found) == {"radius_dead", "environment_data", "no_pac"}
    dead = found["radius_dead"]
    assert dead["detail"] == "RADIUS server 198.18.134.35 is DEAD (for 1185 s) from 10.255.255.12 (Loopback0)"
    assert (
        "ise_get_nad('10.255.255.12')" in dead["fix"]
        and "route from ISE back to 10.255.255.12" in dead["fix"]
    )
    assert "comes back UP by itself" in dead["fix"]  # automate-tester is configured
    assert found["environment_data"]["detail"].startswith(
        "TrustSec environment data is START (last status Failed)"
    )
    assert found["environment_data"]["fix"].startswith("Fix RADIUS first")
    assert found["no_pac"]["severity"] == "fail"


def test_assess_dead_radius_with_the_nad_points_at_the_route() -> None:
    no_tester = outputs()["show running-config | section radius"].replace(
        " automate-tester username dummy ignore-acct-port probe-on\n", ""
    )
    out = {**broken(), "show running-config | section radius": no_tester}
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], out, {}, NADS, None, NOW)
    fix = checks(row)["radius_dead"]["fix"]
    assert fix.startswith(f"ISE has NAD {EDGE} for 10.255.255.12") and "route back to 10.255.255.12" in fix
    assert "keeps 198.18.134.35 DEAD for radius-server deadtime (3 min)" in fix
    assert "missing_nad" not in checks(row)


def test_assess_nad_on_the_management_ip_only() -> None:
    mgmt_only = [IseNad(name="edge1-old", ips=["198.18.128.175/32"], groups=["Location#All Locations"])]
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], broken(), {}, mgmt_only, None, NOW)
    found = checks(row)
    assert row["ise_nad"] is None
    assert "covers the management IP 198.18.128.175 but not 10.255.255.12" in found["missing_nad"]["detail"]
    assert found["missing_nad"]["fix"].startswith(
        "ise_update_nad(device='edge1-old') adding '10.255.255.12/32'"
    )
    assert found["radius_dead"]["fix"].startswith("ISE drops RADIUS from an address no NAD covers")
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], broken(), {}, [], None, NOW)
    assert checks(row)["missing_nad"]["fix"].startswith(
        f"ise_create_nad(name='{EDGE}', ips=['10.255.255.12/32']"
    )


def test_assess_location_and_trustsec_settings() -> None:
    default_loc = [
        IseNad(name=EDGE, ips=["10.255.255.12/32"], groups=["Location#All Locations"], trustsec="yes")
    ]
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], outputs(), {}, default_loc, "mcp-test-lab", NOW)
    wrong = checks(row)["wrong_location"]
    assert row["verdict"] == "fail" and "is in Location#All Locations, not mcp-test-lab" in wrong["detail"]
    assert "ise_policy_explain(nad='10.255.255.12', flow='wired-mab')" in wrong["fix"]
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], outputs(), {}, default_loc, None, NOW)
    assert row["verdict"] == "warning" and set(checks(row)) == {"default_location"}
    no_ts = [IseNad(name=EDGE, ips=["10.255.255.12/32"], groups=NADS[1].groups, trustsec="no")]
    out = {**outputs(), ENV_CMD: START_ENV, PAC_CMD: "(no output)"}
    row = assess(EDGE, "198.18.128.175", ["EDGE_NODE"], out, {}, no_ts, "mcp-test-lab", NOW)
    found = checks(row)
    assert found["nad_without_trustsec"]["severity"] == "fail"
    assert found["environment_data"]["fix"] == "Fix nad_without_trustsec first"


def test_assess_unreadable_and_unknown_state() -> None:
    row = assess(EDGE, "198.18.128.175", [], {}, {AAA_CMD: "timed out"}, None, None, NOW)
    assert row["verdict"] == "unknown" and checks(row)["unreadable"]["severity"] == "fail"
    out = {k: v for k, v in outputs().items() if k != AAA_CMD}
    row = assess(EDGE, "198.18.128.175", [], out, {AAA_CMD: FX["aaa_servers_unfiltered_failure"]}, None, None)
    assert (
        row["verdict"] == "warning"
        and "Failed to update configuration" in checks(row)["radius_state_unknown"]["detail"]
    )
    # No RADIUS at all, no source interface, no TrustSec.
    bare = {
        "show ip interface brief | exclude unassigned": FX["outputs"][EDGE][
            "show ip interface brief | exclude unassigned"
        ]
    }
    row = assess(EDGE, "198.18.128.175", [], bare, {}, None, None, NOW)
    assert set(checks(row)) == {"no_radius_server", "no_trustsec"} and row["nad_ip"] == "198.18.128.175"


OTHER = {
    "id": "99999999-0000-0000-0000-000000000009",
    "hostname": "other-sw",
    "managementIpAddress": "10.0.0.9",
}


def inventory(request: httpx.Request) -> httpx.Response:
    q = request.url.params
    rows = [*FX["inventory"], OTHER]
    if "id" in q:
        rows = [r for r in rows if r["id"] in q["id"].split(",")]
    elif "hostname" in q:
        rows = [r for r in rows if r["hostname"] == q["hostname"]]
    else:
        rows = []
    return httpx.Response(200, json={"response": rows})


def mock_lab(api: respx.MockRouter, outs: dict[str, dict[str, str]]) -> respx.Route:
    mock_fabric(api, FX["fabric_devices"])
    api.get("/dna/intent/api/v1/network-device").mock(side_effect=inventory)
    route = api.post("/dna/intent/api/v1/network-device-poller/cli/read-request").respond(
        202, json={"response": {"taskId": "t-aaa"}}
    )
    api.get("/dna/intent/api/v1/task/t-aaa").respond(
        json={"response": {"progress": json.dumps({"fileId": "f-aaa"}), "endTime": 1}}
    )
    ids = {EDGE: EDGE_ID, BCP: BCP_ID}
    api.get("/dna/intent/api/v1/file/f-aaa").respond(
        json=[
            {"deviceUuid": ids[name], "commandResponses": {"SUCCESS": o, "FAILURE": {}, "BLACKLISTED": {}}}
            for name, o in outs.items()
        ]
    )
    return route


async def test_tool_live_fabric_all_green(api: respx.MockRouter) -> None:
    route = mock_lab(api, {EDGE: outputs(EDGE), BCP: outputs(BCP)})
    out = await call(
        "catc_check_fabric_aaa",
        {"fabric_site": FID, "ise_nads": FX["ise_nads"], "expected_location": "mcp-test-lab"},
    )
    assert route.call_count == 1  # one runner request: 5 commands, both devices
    sent = json.loads(route.calls[0].request.content)
    assert sent["commands"] == COMMANDS and sent["deviceUuids"] == [BCP_ID, EDGE_ID]  # control plane first
    assert out["verdict"].startswith("All 2 fabric device(s) at Global/AU/SYD-1 can do AAA with ISE")
    assert out["verdict"].endswith("and an ISE NAD covers each RLOC.")
    assert [(d["device"], d["verdict"], d["nad_ip"]) for d in out["devices"]] == [
        (BCP, "ok", "10.255.255.11"),
        (EDGE, "ok", "10.255.255.12"),
    ]
    assert out["devices"][0]["roles"] == ["BORDER_NODE", "CONTROL_PLANE_NODE"]
    assert "ise_check" not in out and "PLACEHOLDER" not in json.dumps(out)


async def test_tool_dead_edge_hands_off_to_ise(api: respx.MockRouter) -> None:
    mock_lab(api, {EDGE: broken(), BCP: outputs(BCP)})
    out = await call("catc_check_fabric_aaa", {"fabric_site": FID})
    assert out["verdict"] == (
        "1 of 2 fabric device(s) at Global/AU/SYD-1 can't do AAA with ISE: "
        f"{EDGE}: radius_dead, environment_data, no_pac. Each device's findings carry the fix. ISE's side "
        "(the NAD covering each RLOC) is not checked: see ise_check."
    )
    check = out["ise_check"]
    assert check["ise_audit_nads"] == {
        "expected": [
            {"name": BCP, "ip": "10.255.255.11", "aaa_server": "198.18.134.35"},
            {"name": EDGE, "ip": "10.255.255.12", "aaa_server": "198.18.134.35"},
        ],
        "check_stale": False,
    }
    assert "ise_policy_explain(nad='10.255.255.11', flow='wired-mab')" in check["next"][2]


async def test_tool_devices_filter(api: respx.MockRouter) -> None:
    mock_lab(api, {EDGE: outputs(EDGE)})
    out = await call(
        "catc_check_fabric_aaa", {"fabric_site": FID, "devices": [EDGE], "expected_location": "SYD"}
    )
    assert [d["device"] for d in out["devices"]] == [EDGE]
    assert out["ise_check"]["ise_audit_nads"]["expected"][0]["ndg"] == "SYD"
    with pytest.raises(ToolError, match="Not fabric devices at Global/AU/SYD-1: other-sw"):
        await call("catc_check_fabric_aaa", {"fabric_site": FID, "devices": ["other-sw"]})
