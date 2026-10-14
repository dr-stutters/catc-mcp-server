"""Read tools against respx-mocked Catalyst Center responses (fixtures captured from a 3.2.2 lab,
plus hand-made device payloads shaped like the spec since the lab inventory is empty)."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools.inventory import redact_config
from catc_mcp.tools.smart import check_show_command

from .conftest import make_settings

FIX = Path(__file__).parent.parent / "fixtures"
DEV_ID = "11111111-2222-3333-4444-555555555555"
DEVICE = {
    "id": DEV_ID,
    "hostname": "edge-sw1.lab.local",
    "managementIpAddress": "10.0.0.11",
    "platformId": "C9300-24U",
    "softwareVersion": "17.9.4",
    "role": "ACCESS",
    "reachabilityStatus": "Reachable",
    "serialNumber": "FOC1234X0AB",
    "family": "Switches and Hubs",
    "upTime": "10 days",
    "series": "Cisco Catalyst 9300 Series Switches",
}
GLOBAL = {
    "id": "2fc7ff5c-c456-45d1-a818-f027e1517d43",
    "name": "Global",
    "nameHierarchy": "Global",
    "type": "global",
}
AREA = {
    "id": "aaaaaaaa-0000-0000-0000-000000000001",
    "name": "AU",
    "nameHierarchy": "Global/AU",
    "type": "area",
}
BLDG = {
    "id": "aaaaaaaa-0000-0000-0000-000000000002",
    "name": "SYD-1",
    "nameHierarchy": "Global/AU/SYD-1",
    "type": "building",
}


def fixture(name: str) -> Any:
    return json.loads((FIX / name).read_text())


async def call(name: str, args: dict[str, Any] | None = None, **settings: Any) -> Any:
    async with Client(create_server(make_settings(**settings))) as c:
        res = await c.call_tool(name, args or {})
    if res.structured_content is not None:
        return res.structured_content
    text = "\n".join(getattr(x, "text", "") for x in res.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


def mock_device_lookup(api: respx.MockRouter) -> None:
    def by_query(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if (
            q.get("hostname") in ("edge-sw1", "edge-sw1.*", "edge-sw1.lab.local")
            or q.get("managementIpAddress") == "10.0.0.11"
            or q.get("id")
        ):
            return httpx.Response(200, json={"response": [DEVICE]})
        return httpx.Response(200, json={"response": []})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=by_query)
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": DEVICE})


# --- pure helpers ------------------------------------------------------------------------------


def test_redact_config() -> None:
    cfg = (
        "hostname sw1\n"
        "enable secret 9 $9$abc\n"
        "username admin privilege 15 password 7 0822455D0A16\n"
        "snmp-server community s3cr3t RO\n"
        " key 7 1234ABCD\n"
        "interface Gi1/0/1\n description uplink\n"
    )
    out = redact_config(cfg)
    assert "$9$abc" not in out and "0822455D0A16" not in out and "s3cr3t" not in out and "1234ABCD" not in out
    assert "hostname sw1" in out and "description uplink" in out
    assert "enable secret 9 ********" in out


@pytest.mark.parametrize(
    "cmd",
    ["show ip int brief", "sh run | sec bgp", "show logging | include %LINK", "show version | count Gi"],
)
def test_show_allowed(cmd: str) -> None:
    assert check_show_command(cmd)


@pytest.mark.parametrize(
    "cmd",
    [
        "conf t",
        "reload",
        "show run | redirect flash:x",
        "show run > flash:x",
        "show run ; reload",
        "show ver\nreload",
        "show tech | tee flash:t",
        "more flash:config.text",
        "ping 1.1.1.1",
        "show",
    ],
)
def test_show_refused(cmd: str) -> None:
    from stutters_mcp_core import InvalidRequest

    with pytest.raises(InvalidRequest):
        check_show_command(cmd)


# --- sites -------------------------------------------------------------------------------------


async def test_site_hierarchy_tree(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/sites").respond(json={"response": [BLDG, GLOBAL, AREA]})
    md = await call("catc_get_site_hierarchy")
    lines = md.splitlines()
    assert "3 sites" in lines[0]
    assert (
        lines[2].startswith("- Global")
        and lines[3].startswith("  - AU")
        and lines[4].startswith("    - SYD-1")
    )
    out = await call("catc_get_site_hierarchy", {"root": "Global/AU", "response_format": "json"})
    assert [s["nameHierarchy"] for s in out["sites"]] == ["Global/AU", "Global/AU/SYD-1"]


async def test_resolve_site_short_name_and_ambiguity(api: respx.MockRouter) -> None:
    def sites(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if q.get("name") == "SYD-1" or q.get("nameHierarchy") == "Global/AU/SYD-1":
            return httpx.Response(200, json={"response": [BLDG]})
        if q.get("name") == "Floor 1":
            return httpx.Response(
                200,
                json={
                    "response": [
                        {"name": "Floor 1", "nameHierarchy": "Global/A/F"},
                        {"name": "Floor 1", "nameHierarchy": "Global/B/F"},
                    ]
                },
            )
        if not q:
            return httpx.Response(200, json={"response": [GLOBAL, AREA, BLDG]})
        return httpx.Response(200, json={"response": []})

    api.get("/dna/intent/api/v1/sites").mock(side_effect=sites)
    api.get(f"/dna/intent/api/v2/buildings/{BLDG['id']}").respond(
        json={"response": {"address": "1 George St", "latitude": -33.8, "longitude": 151.2}}
    )
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite/count").respond(json={"response": {"count": 2}})
    out = await call("catc_get_site", {"site": "SYD-1"})
    assert out["detail"]["address"] == "1 George St" and out["assigned_devices"] == 2
    out = await call("catc_get_site", {"site": "AU/SYD-1"})  # 'Global/' prefix is added
    assert out["id"] == BLDG["id"]
    with pytest.raises(ToolError, match="ambiguous"):
        await call("catc_get_site", {"site": "Floor 1"})


# --- inventory ---------------------------------------------------------------------------------


async def test_list_devices_projects_fields(api: respx.MockRouter) -> None:
    route = api.get("/dna/intent/api/v1/network-device").respond(json={"response": [{**DEVICE, "noise": 1}]})
    out = await call("catc_list_devices", {"family": "Switches and Hubs", "response_format": "json"})
    assert out["results"][0]["hostname"] == "edge-sw1.lab.local" and "noise" not in out["results"][0]
    q = route.calls.last.request.url.params
    assert q["family"] == "Switches and Hubs" and q["offset"] == "1"


async def test_list_devices_by_site(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/sites").respond(json={"response": [BLDG]})
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite").respond(
        json={"response": [{"deviceId": DEV_ID, "siteId": BLDG["id"]}]}
    )
    mock_device_lookup(api)
    out = await call("catc_list_devices", {"site": "Global/AU/SYD-1", "response_format": "json"})
    assert out["total"] == 1 and out["site"] == "Global/AU/SYD-1"
    out = await call(
        "catc_list_devices", {"site": "Global/AU/SYD-1", "role": "CORE", "response_format": "json"}
    )
    assert out["total"] == 0


async def test_get_device_by_short_hostname(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    out = await call("catc_get_device", {"device": "edge-sw1"})
    assert out["id"] == DEV_ID
    out = await call("catc_get_device", {"device": "10.0.0.11"})
    assert out["serialNumber"] == "FOC1234X0AB"
    with pytest.raises(ToolError, match="No network device"):
        await call("catc_get_device", {"device": "nope"})


async def test_device_interfaces_filter(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"/dna/intent/api/v1/interface/network-device/{DEV_ID}").respond(
        json={
            "response": [
                {"portName": "GigabitEthernet1/0/1", "status": "up", "adminStatus": "UP"},
                {"portName": "GigabitEthernet1/0/2", "status": "down", "adminStatus": "UP"},
                {"portName": "Vlan10", "status": "up", "adminStatus": "UP", "ipv4Address": "10.10.0.1"},
            ]
        }
    )
    out = await call(
        "catc_list_device_interfaces", {"device": DEV_ID, "status": "down", "response_format": "json"}
    )
    assert [i["portName"] for i in out["results"]] == ["GigabitEthernet1/0/2"]


async def test_device_config_sections_and_redaction(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}/config").respond(
        json={
            "response": "hostname edge-sw1\nenable secret 9 $9$x\nrouter bgp 65000\n"
            " neighbor 1.1.1.1 password 0 pw\n"
            "interface Vlan10\n ip address 10.10.0.1 255.255.255.0\n"
        }
    )
    text = await call("catc_get_device_config", {"device": "edge-sw1", "match": "router bgp"})
    assert "router bgp 65000" in text and "Vlan10" not in text and " pw" not in text


# --- smart -------------------------------------------------------------------------------------


async def test_device_360_tolerates_missing_sections(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"/dna/data/api/v1/networkDevices/{DEV_ID}").respond(
        json={"response": {"siteHierarchy": "Global/AU/SYD-1", "overallHealthScore": 8, "cpuUtilization": 12}}
    )
    api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={"response": [{"id": "i1", "name": "switch_cpu_high", "priority": "P2"}], "page": {"count": 1}}
    )
    api.get(f"/dna/intent/api/v1/interface/network-device/{DEV_ID}").respond(
        json={
            "response": [
                {"portName": "Gi1/0/1", "status": "up", "adminStatus": "UP"},
                {"portName": "Gi1/0/2", "status": "down", "adminStatus": "UP"},
                {"portName": "Gi1/0/3", "status": "down", "adminStatus": "DOWN"},
            ]
        }
    )
    api.get("/dna/intent/api/v1/compliance").respond(
        json={"response": [{"complianceStatus": "NON_COMPLIANT"}]}
    )
    api.get(f"/dna/intent/api/v1/eox-status/device/{DEV_ID}").respond(500, text="Http Error Code:500")
    out = await call("catc_device_360", {"device": "edge-sw1"})
    assert out["site"] == "Global/AU/SYD-1"
    assert out["health"]["overallHealthScore"] == 8
    assert out["active_issues"][0]["name"] == "switch_cpu_high"
    assert out["interfaces"] == {
        "total": 3,
        "up": 1,
        "admin_down": 1,
        "down_but_enabled": [{"portName": "Gi1/0/2", "status": "down", "adminStatus": "UP"}],
    }
    assert out["compliance"]["complianceStatus"] == "NON_COMPLIANT"
    assert "eox" in out["unavailable"]


async def test_client_360(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/client-detail").respond(
        json={
            "detail": {
                "hostName": "laptop1",
                "hostIpV4": "10.10.0.50",
                "hostType": "WIRELESS",
                "healthScore": [{}],
            },
            "topology": {"nodes": [{"name": "AP1", "deviceType": "Unified AP"}]},
        }
    )
    api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    ev = api.get("/dna/data/api/v1/assuranceEvents").respond(json={"response": [{"name": "Onboarding"}]})
    out = await call("catc_client_360", {"mac": "AABB.CCDD.EEFF"})
    assert out["mac"] == "aa:bb:cc:dd:ee:ff"
    assert out["client"]["hostName"] == "laptop1" and out["path"][0]["name"] == "AP1"
    assert ev.calls.last.request.url.params["deviceFamily"] == "Wireless Client"


async def test_path_trace_failed_fixture(api: respx.MockRouter) -> None:
    fid = "aeb4c1b6-0c13-4dba-9210-6a4627d81a3b"
    api.post("/dna/intent/api/v1/flow-analysis").respond(
        202, json={"response": {"flowAnalysisId": fid, "taskId": "t"}}
    )
    api.get(f"/dna/intent/api/v1/flow-analysis/{fid}").respond(json=fixture("flow_analysis_failed.json"))
    out = await call("catc_path_trace", {"source_ip": "10.1.1.1", "dest_ip": "10.2.2.2"})
    assert out["status"] == "FAILED" and "source ip" in out["failureReason"]


async def test_path_trace_hops(api: respx.MockRouter) -> None:
    fid = "bbbbbbbb-0000-0000-0000-000000000001"
    api.get(f"/dna/intent/api/v1/flow-analysis/{fid}").mock(
        side_effect=[
            httpx.Response(200, json={"response": {"request": {"id": fid, "status": "INPROGRESS"}}}),
            httpx.Response(
                200,
                json={
                    "response": {
                        "request": {
                            "id": fid,
                            "status": "COMPLETED",
                            "sourceIP": "10.1.1.1",
                            "destIP": "10.2.2.2",
                        },
                        "networkElementsInfo": [
                            {"ip": "10.1.1.1", "type": "wired"},
                            {
                                "name": "edge-sw1",
                                "ip": "10.0.0.11",
                                "role": "ACCESS",
                                "ingressInterface": {"physicalInterface": {"name": "Gi1/0/5"}},
                                "egressInterface": {
                                    "physicalInterface": {"name": "Gi1/1/1"},
                                    "virtualInterface": [{"name": "Vlan10"}],
                                },
                                "linkInformationSource": "OSPF",
                            },
                        ],
                    }
                },
            ),
        ]
    )
    out = await call("catc_path_trace", {"flow_analysis_id": fid})
    assert out["status"] == "COMPLETED"
    assert out["hops"][1] == {
        "hop": 2,
        "name": "edge-sw1",
        "ip": "10.0.0.11",
        "role": "ACCESS",
        "ingress": "Gi1/0/5",
        "egress": "Gi1/1/1 / Vlan10",
        "learned_from": "OSPF",
    }


async def test_run_show_commands(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    req = api.post("/dna/intent/api/v1/network-device-poller/cli/read-request").respond(
        202, json={"response": {"taskId": "t-cli"}}
    )
    api.get("/dna/intent/api/v1/task/t-cli").respond(
        json={"response": {"progress": '{"fileId":"f-1"}', "endTime": 1}}
    )
    api.get("/dna/intent/api/v1/file/f-1").respond(
        json=[
            {
                "deviceUuid": DEV_ID,
                "commandResponses": {
                    "SUCCESS": {"show run | i secret": "enable secret 9 $9$zzz\n"},
                    "FAILURE": {},
                    "BLACKLISTED": {},
                },
            }
        ]
    )
    out = await call("catc_run_show_commands", {"devices": ["edge-sw1"], "commands": ["show run | i secret"]})
    res = out["results"][0]
    assert res["device"] == "edge-sw1.lab.local"
    assert "$9$zzz" not in res["output"]["show run | i secret"]
    body = json.loads(req.calls.last.request.content)
    assert body["commands"] == ["show run | i secret"] and body["deviceUuids"] == [DEV_ID]


async def test_run_show_commands_refuses_config(api: respx.MockRouter) -> None:
    route = api.post("/dna/intent/api/v1/network-device-poller/cli/read-request")
    with pytest.raises(ToolError, match="only 'show"):
        await call(
            "catc_run_show_commands", {"devices": ["edge-sw1"], "commands": ["show ver", "write erase"]}
        )
    assert route.call_count == 0


# --- assurance / system ------------------------------------------------------------------------


async def test_network_health_falls_back_on_500(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/network-health").respond(500, text="Http Error Code:500")
    api.get("/dna/intent/api/v1/site-health").respond(
        json={"response": [{"siteName": "SYD-1", "networkHealthAverage": 90, "siteType": "building"}]}
    )
    out = await call("catc_get_network_health")
    assert "unavailable" in out["network_health"]
    assert out["sites"][0]["networkHealthAverage"] == 90


async def test_issues_filters_and_paging(api: respx.MockRouter) -> None:
    route = api.get("/dna/data/api/v1/assuranceIssues").mock(
        side_effect=[
            httpx.Response(
                200, json={"response": [{"id": f"i{i}"} for i in range(25)], "page": {"count": 30}}
            ),
            httpx.Response(
                200, json={"response": [{"id": f"i{i}"} for i in range(25, 30)], "page": {"count": 30}}
            ),
        ]
    )
    out = await call(
        "catc_list_issues", {"priority": ["P1", "P2"], "site": "AU/*", "limit": 40, "response_format": "json"}
    )
    assert out["returned"] == 30 and out["total"] == 30
    first = route.calls[0].request.url.params
    assert first.get_list("priority") == ["P1", "P2"] and first["siteHierarchy"] == "Global/AU/*"
    assert first["limit"] == "25" and route.calls[1].request.url.params["offset"] == "26"


async def test_audit_logs_zero_based(api: respx.MockRouter) -> None:
    route = api.get("/dna/data/api/v1/event/event-series/audit-logs").respond(json=fixture("audit_logs.json"))
    out = await call("catc_list_audit_logs", {"limit": 3, "response_format": "json"})
    assert out["returned"] == 3 and out["results"][0]["userId"] == "admin"
    assert route.calls.last.request.url.params["offset"] == "0"


# --- templates ---------------------------------------------------------------------------------


async def test_templates(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=fixture("templates.json"))
    tid = "72a0afc4-0b5c-4c69-b47f-f647eb34d71b"
    api.get(f"/dna/intent/api/v1/template-programmer/template/{tid}").respond(
        json=fixture("template_aaa.json")
    )
    preview = api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(
        json={"cliPreview": "aaa new-model", "validationErrors": []}
    )
    out = await call("catc_list_templates", {"project": "reference templates", "response_format": "json"})
    assert out["total"] == 4
    full = await call("catc_get_template", {"template": "Reference Templates/AAA-Configuration"})
    assert full["language"] == "JINJA" and "aaa new-model" in full["templateContent"]
    out = await call("catc_preview_template", {"template": tid, "params": {"x": 1}})
    assert out["cliPreview"] == "aaa new-model"
    assert json.loads(preview.calls.last.request.content) == {"templateId": tid, "params": {"x": 1}}


async def test_spec_tools_use_bundled_spec(api: respx.MockRouter) -> None:
    out = await call("catc_search_spec", {"query": "assign network devices site"})
    assert any("assignToSite" in h["name"] for h in out["results"])
    d = await call(
        "catc_get_definition", {"name": "POST /dna/intent/api/v1/networkDevices/assignToSite/apply"}
    )
    assert d["operations"][0]["method"] == "POST"
    status = await call("catc_status")
    assert status["server"]["spec_sources"] == ["intent"]


def test_redact_more_forms() -> None:
    cfg = (
        "snmp-server host 10.1.1.1 version 2c c0mm\n"
        "snmp-server user u1 g1 v3 auth sha AUTHK priv aes 128 PRIVK\n"
        "key chain KC\n key 1\n  key-string 7 KS123\n"
        "radius server R1\n key RKEY\n"
        "tacacs-server key T4c\n"
        "crypto key generate rsa modulus 2048\n"
    )
    out = redact_config(cfg)
    for secret in ("c0mm", "AUTHK", "PRIVK", "KS123", "RKEY", "T4c"):
        assert secret not in out, secret
    assert "key chain KC" in out and " key 1" in out and "crypto key generate rsa" in out


def test_show_refuses_control_chars() -> None:
    from stutters_mcp_core import InvalidRequest

    with pytest.raises(InvalidRequest):
        check_show_command("show ver\x1a")
