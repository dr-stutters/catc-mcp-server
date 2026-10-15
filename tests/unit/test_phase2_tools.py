"""Phase 2 tools (respx-mocked; payloads shaped like the 3.2.2 lab responses seen live)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.assurance import event_row
from catc_mcp.tools.smart import clean_output
from catc_mcp.tools.template_writes import template_task_result

from .test_dangerous_tools import flow
from .test_read_tools import BLDG, DEV_ID, DEVICE, GLOBAL, call, mock_device_lookup
from .test_write_tools import AREA, mock_sites, preview_then_apply, task_ok

CREDS = [
    {
        "id": "aaaaaaaa-1111-0000-0000-000000000001",
        "type": "CLI",
        "description": "lab",
        "username": "netadmin",
    },
    {"id": "aaaaaaaa-1111-0000-0000-000000000002", "type": "SNMPV2_READ_COMMUNITY", "description": "lab-ro"},
    {"id": "aaaaaaaa-1111-0000-0000-000000000003", "type": "SNMPV2_WRITE_COMMUNITY", "description": "lab-rw"},
    {"id": "aaaaaaaa-1111-0000-0000-000000000004", "type": "NETCONF", "description": "nc", "port": 830},
]


def mock_creds(api: respx.MockRouter, creds: list[dict[str, Any]] | None = None) -> None:
    api.get("/dna/intent/api/v1/globalCredentials").respond(
        json={"response": CREDS if creds is None else creds}
    )


# --- credentials -------------------------------------------------------------------------------


async def test_list_credentials_has_no_secrets(api: respx.MockRouter) -> None:
    mock_creds(api, [{**CREDS[0], "password": "NO!$DATA!$"}, CREDS[1]])
    out = await call("catc_list_global_credentials", {"response_format": "json"})
    assert [r["description"] for r in out["results"]] == ["lab", "lab-ro"]
    assert "password" not in json.dumps(out)


async def test_create_cli_credential_masks_secrets(api: respx.MockRouter) -> None:
    mock_creds(api)
    post = api.post("/dna/intent/api/v1/globalCredentials").respond(202, json={"response": {"taskId": "tc"}})
    api.get("/dna/intent/api/v1/task/tc").respond(
        json={"response": {"progress": "bbbbbbbb-0000-0000-0000-000000000009", "endTime": 1}}
    )
    args = {
        "credential_type": "CLI",
        "description": "new",
        "username": "u",
        "password": "Pw-S3cret",
        "enable_password": "En-S3cret",
    }
    preview, done = await preview_then_apply("catc_create_global_credential", args)
    assert "S3cret" not in json.dumps(preview) + json.dumps(done)
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "type": "CLI",
        "description": "new",
        "username": "u",
        "password": "Pw-S3cret",
        "enablePassword": "En-S3cret",
    }
    assert done["result"]["credential_id"] == "bbbbbbbb-0000-0000-0000-000000000009"


async def test_create_credential_blockers(api: respx.MockRouter) -> None:
    mock_creds(api)
    preview, _ = await preview_then_apply(
        "catc_create_global_credential", {"credential_type": "CLI", "description": "lab", "username": "u"}
    )
    assert preview["status"] == "blocked"
    assert any("password" in b for b in preview["blockers"]) and any(
        "exists" in b for b in preview["blockers"]
    )
    preview, _ = await preview_then_apply(
        "catc_create_global_credential",
        {"credential_type": "SNMPV3", "description": "v3", "username": "u", "snmpv3_mode": "AUTHPRIV"},
    )
    assert any("auth type" in b for b in preview["blockers"])


async def test_create_snmp_and_netconf_bodies(api: respx.MockRouter) -> None:
    mock_creds(api, [])
    post = api.post("/dna/intent/api/v1/globalCredentials").respond(202, json={"response": {"taskId": "tc"}})
    task_ok(api, "tc", data="x")
    await preview_then_apply(
        "catc_create_global_credential",
        {"credential_type": "SNMPV2_WRITE_COMMUNITY", "description": "rw", "community": "c0mm"},
    )
    assert json.loads(post.calls.last.request.content)["writeCommunity"] == "c0mm"
    await preview_then_apply(
        "catc_create_global_credential", {"credential_type": "NETCONF", "description": "nc"}
    )
    assert json.loads(post.calls.last.request.content) == {
        "type": "NETCONF",
        "description": "nc",
        "port": 830,
    }


async def test_delete_credential_by_type_prefix(api: respx.MockRouter) -> None:
    mock_creds(
        api,
        [
            *CREDS,
            {
                **CREDS[1],
                "id": "aaaaaaaa-1111-0000-0000-00000000000a",
                "type": "SNMPV3",
                "description": "lab-ro",
            },
        ],
    )
    with pytest.raises(ToolError, match="ambiguous"):
        await preview_then_apply("catc_delete_global_credential", {"credential": "lab-ro"})
    delete = api.delete(f"/dna/intent/api/v1/globalCredentials/{CREDS[1]['id']}").respond(
        202, json={"response": {"taskId": "td"}}
    )
    task_ok(api, "td")
    _, done = await preview_then_apply(
        "catc_delete_global_credential", {"credential": "SNMPV2_READ_COMMUNITY:lab-ro"}
    )
    assert done["status"] == "applied" and delete.called


async def test_assign_site_credentials(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_creds(api)
    api.get(f"/dna/intent/api/v1/sites/{AREA['id']}/deviceCredentials").respond(
        json={"response": {"cliCredentialsId": {"credentialsId": CREDS[0]["id"]}}}
    )
    put = api.put(f"/dna/intent/api/v1/sites/{AREA['id']}/deviceCredentials").respond(
        202, json={"response": {"taskId": "ts"}}
    )
    task_ok(api, "ts")
    preview, done = await preview_then_apply(
        "catc_assign_site_credentials", {"site": "Global/AU", "credentials": ["lab", "lab-ro"]}
    )
    # CLI is unchanged, so only the SNMP read slot shows as a change.
    assert list(preview["preview"]["changes"]) == ["snmpv2cReadCredentialsId"]
    assert json.loads(put.calls.last.request.content) == {
        "cliCredentialsId": {"credentialsId": CREDS[0]["id"]},
        "snmpv2cReadCredentialsId": {"credentialsId": CREDS[1]["id"]},
    }
    assert done["status"] == "applied"
    preview, _ = await preview_then_apply(
        "catc_assign_site_credentials", {"site": "Global/AU", "credentials": ["lab"]}
    )
    assert preview["status"] == "blocked" and "Nothing to change" in preview["blockers"][0]
    preview, _ = await preview_then_apply(
        "catc_assign_site_credentials", {"site": "Global/AU", "credentials": ["nc"]}
    )
    assert "can't be assigned" in preview["blockers"][0]


async def test_site_settings_shows_credential_names(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    mock_creds(api)
    api.get(f"/dna/intent/api/v1/sites/{AREA['id']}/deviceCredentials").respond(
        json={"response": {"cliCredentialsId": {"credentialsId": CREDS[0]["id"]}}}
    )
    out = await call("catc_get_site_settings", {"site": "Global/AU", "categories": ["credentials"]})
    assert out["settings"]["credentials"]["cliCredentialsId"]["credential"] == "CLI:lab"


# --- discovery ---------------------------------------------------------------------------------


@pytest.mark.parametrize("dtype", ["Single", "Range"])
async def test_discovery_named_credentials_single_and_summary(api: respx.MockRouter, dtype: str) -> None:
    mock_creds(api)
    api.get("/dna/intent/api/v1/discovery/count").respond(json={"response": 0})
    post = api.post("/dna/intent/api/v1/discovery").respond(202, json={"response": {"taskId": "t9"}})
    api.get("/dna/intent/api/v1/task/t9").respond(
        json={"response": {"data": '{"discoveryId": "12"}', "progress": "x", "endTime": 1}}
    )
    api.get("/dna/intent/api/v1/discovery/12/network-device").respond(
        json={
            "response": [
                {"hostname": "r1", "managementIpAddress": "10.0.0.1", "cliStatus": "SUCCESS", "x": 1}
            ]
        }
    )
    args = {
        "name": "d",
        "ip_ranges": ["10.0.0.1"],
        "discovery_type": dtype,
        "global_credentials": ["lab", "lab-rw"],
        "snmp_rw_community": "rw-S3cret",
        "netconf_port": 830,
        "wait": True,
    }
    preview, done = await preview_then_apply("catc_create_discovery", args)
    assert preview["preview"]["body"]["globalCredentialIdList"] == [
        "CLI:lab",
        "SNMPV2_WRITE_COMMUNITY:lab-rw",
    ]
    assert "rw-S3cret" not in json.dumps(preview)
    sent = json.loads(post.calls.last.request.content)
    assert sent["discoveryType"] == "Range" and sent["ipAddressList"] == "10.0.0.1-10.0.0.1"
    assert sent["globalCredentialIdList"] == [CREDS[0]["id"], CREDS[2]["id"]]
    assert sent["snmpRWCommunity"] == "rw-S3cret" and sent["netconfPort"] == "830"
    assert done["result"]["devices"] == [
        {"hostname": "r1", "managementIpAddress": "10.0.0.1", "cliStatus": "SUCCESS"}
    ]


async def test_discovery_multi_range_mix_and_bad_entry(api: respx.MockRouter) -> None:
    mock_creds(api)
    api.get("/dna/intent/api/v1/discovery/count").respond(json={"response": 0})
    preview = await call(
        "catc_create_discovery",
        {
            "name": "d",
            "ip_ranges": ["10.0.0.1", "10.0.0.5-10.0.0.9,10.0.0.20"],
            "discovery_type": "Multi Range",
        },
        mcp_enable_writes=True,
    )
    assert (
        preview["preview"]["body"]["ipAddressList"]
        == "10.0.0.1-10.0.0.1,10.0.0.5-10.0.0.9,10.0.0.20-10.0.0.20"
    )
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError, match="Not an IP"):
        await call("catc_create_discovery", {"name": "d", "ip_ranges": ["sw1.lab"]}, mcp_enable_writes=True)


async def test_discovery_needs_a_cli_credential(api: respx.MockRouter) -> None:
    mock_creds(api, [CREDS[1]])
    api.get("/dna/intent/api/v1/discovery/count").respond(json={"response": 0})
    preview, _ = await preview_then_apply(
        "catc_create_discovery", {"name": "d", "ip_ranges": ["10.0.0.1-10.0.0.2"]}
    )
    assert any("catc_create_global_credential" in b for b in preview["blockers"])


# --- network settings --------------------------------------------------------------------------


async def test_update_site_settings_merges_current(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    base = f"/dna/intent/api/v1/sites/{AREA['id']}"
    api.get(f"{base}/dnsSettings").respond(
        json={
            "response": {
                "dns": {"domainName": "old.lab", "dnsServers": ["1.1.1.1"], "inheritedSiteName": "Global"}
            }
        }
    )
    api.get(f"{base}/telemetrySettings").respond(
        json={"response": {"syslogs": {"useBuiltinSyslogServer": True, "externalSyslogServers": []}}}
    )
    dns_put = api.put(f"{base}/dnsSettings").respond(202, json={"response": {"taskId": "a"}})
    tel_put = api.put(f"{base}/telemetrySettings").respond(202, json={"response": {"taskId": "b"}})
    task_ok(api, "a")
    task_ok(api, "b")
    preview, done = await preview_then_apply(
        "catc_update_site_settings",
        {"site": "Global/AU", "dns_servers": ["10.0.0.53"], "syslog_servers": ["10.0.0.5"]},
    )
    assert preview["preview"]["changes"]["dns"] == {
        "dns.dnsServers": {"from": ["1.1.1.1"], "to": ["10.0.0.53"]}
    }
    # The PUT keeps the domain name it didn't change, and drops the inheritance markers.
    assert json.loads(dns_put.calls.last.request.content) == {
        "dns": {"domainName": "old.lab", "dnsServers": ["10.0.0.53"]}
    }
    assert json.loads(tel_put.calls.last.request.content) == {
        "syslogs": {"useBuiltinSyslogServer": True, "externalSyslogServers": ["10.0.0.5"]}
    }
    assert done["result"]["updated"] == {"dns": "SUCCESS", "telemetry": "SUCCESS"}


async def test_update_site_settings_validation(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get(f"/dna/intent/api/v1/sites/{AREA['id']}/ntpSettings").respond(
        json={"response": {"ntp": {"servers": ["10.0.0.1"]}}}
    )
    with pytest.raises(ToolError, match="not an IP"):
        await preview_then_apply(
            "catc_update_site_settings", {"site": "Global/AU", "ntp_servers": ["ntp.example"]}
        )
    with pytest.raises(ToolError, match="at least one"):
        await preview_then_apply("catc_update_site_settings", {"site": "Global/AU"})
    preview, _ = await preview_then_apply(
        "catc_update_site_settings", {"site": "Global/AU", "ntp_servers": ["10.0.0.1"]}
    )
    assert preview["status"] == "blocked"


# --- IP pools ----------------------------------------------------------------------------------

GPOOL = {
    "id": "cccccccc-0000-0000-0000-000000000001",
    "name": "corp",
    "poolType": "Generic",
    "addressSpace": {
        "subnet": "10.200.0.0",
        "prefixLength": 16,
        "gatewayIpAddress": "10.200.0.1",
        "totalAddresses": "65536",
        "assignedAddresses": "256",
    },
}
RPOOL = {
    "id": "cccccccc-0000-0000-0000-000000000002",
    "name": "syd-lan",
    "poolType": "LAN",
    "siteId": BLDG["id"],
    "siteName": "SYD-1",
    "ipV4AddressSpace": {
        "subnet": "10.200.1.0",
        "prefixLength": 24,
        "gatewayIpAddress": "10.200.1.1",
        "globalPoolId": GPOOL["id"],
        "totalAddresses": "256",
        "assignedAddresses": "0",
    },
}


def mock_pools(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/ipam/globalIpAddressPools").respond(json={"response": [GPOOL]})
    api.get("/dna/intent/api/v1/ipam/siteIpAddressPools").respond(json={"response": [RPOOL]})


async def test_list_ip_pools(api: respx.MockRouter) -> None:
    mock_pools(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    out = await call("catc_list_ip_pools", {"response_format": "json"})
    assert [(r["name"], r["scope"], r["subnet"], r["used"]) for r in out["results"]] == [
        ("corp", "global", "10.200.0.0/16", "256/65536"),
        ("syd-lan", "reserved", "10.200.1.0/24", "0/256"),
    ]
    out = await call("catc_list_ip_pools", {"site": "SYD-1", "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["syd-lan"]


async def test_create_ip_pool_checks(api: respx.MockRouter) -> None:
    mock_pools(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    preview, _ = await preview_then_apply("catc_create_ip_pool", {"name": "x", "subnet": "10.200.5.0/24"})
    assert "Overlaps global pool corp" in preview["blockers"][0]
    preview, _ = await preview_then_apply(
        "catc_create_ip_pool",
        {"name": "x", "subnet": "10.9.0.0/24", "site": "SYD-1", "global_pool": "corp", "pool_type": "LAN"},
    )
    assert "not inside" in preview["blockers"][0]
    preview, _ = await preview_then_apply(
        "catc_create_ip_pool",
        {"name": "x", "subnet": "10.200.1.128/25", "site": "SYD-1", "global_pool": "corp"},
    )
    assert "Overlaps existing reservation" in preview["blockers"][0]
    with pytest.raises(ToolError, match="host bits|has host bits"):
        await preview_then_apply("catc_create_ip_pool", {"name": "x", "subnet": "10.1.1.1/24"})


async def test_reserve_ip_pool_body(api: respx.MockRouter) -> None:
    mock_pools(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    post = api.post("/dna/intent/api/v1/ipam/siteIpAddressPools").respond(
        202, json={"response": {"taskId": "tp"}}
    )
    api.get("/dna/intent/api/v1/task/tp").respond(json={"response": {"progress": "new-pool", "endTime": 1}})
    _, done = await preview_then_apply(
        "catc_create_ip_pool",
        {
            "name": "syd-mgmt",
            "subnet": "10.200.2.0/24",
            "site": "SYD-1",
            "global_pool": "corp",
            "pool_type": "Management",
            "dhcp_servers": ["10.0.0.5"],
        },
    )
    assert json.loads(post.calls.last.request.content) == {
        "name": "syd-mgmt",
        "poolType": "Management",
        "siteId": BLDG["id"],
        "ipV4AddressSpace": {
            "subnet": "10.200.2.0",
            "prefixLength": 24,
            "gatewayIpAddress": "10.200.2.1",
            "dhcpServers": ["10.0.0.5"],
            "dnsServers": [],
            "globalPoolId": GPOOL["id"],
        },
    }
    assert done["result"]["pool_id"] == "new-pool"


async def test_delete_global_pool_with_reservations_blocked(api: respx.MockRouter) -> None:
    mock_pools(api)
    preview, _ = await preview_then_apply("catc_delete_ip_pool", {"pool": "corp", "reserved": False})
    assert "still has reservations" in preview["blockers"][0]
    delete = api.delete(f"/dna/intent/api/v1/ipam/siteIpAddressPools/{RPOOL['id']}").respond(
        202, json={"response": {"taskId": "tdel"}}
    )
    task_ok(api, "tdel")
    _, done = await preview_then_apply("catc_delete_ip_pool", {"pool": "syd-lan"})
    assert done["status"] == "applied" and delete.called


# --- config archive ----------------------------------------------------------------------------

FILES = [
    {
        "id": "f-run-new",
        "fileType": "RUNNINGCONFIG",
        "createdBy": "CONFIG_CHANGE_EVENT",
        "createdTime": 1792001709000,
    },
    {
        "id": "f-start-new",
        "fileType": "STARTUPCONFIG",
        "createdBy": "CONFIG_CHANGE_EVENT",
        "createdTime": 1792001709000,
    },
    {
        "id": "f-run-old",
        "fileType": "RUNNINGCONFIG",
        "createdBy": "SCHEDULED_FIRST_TIME",
        "createdTime": 1792000014000,
    },
]
LO0 = "hostname r1\ninterface Loopback0\n ip address 10.0.0.1 255.255.255.255\n"
SNMP = "snmp-server community s3cret RO"
ROUTES = "".join(f"ip route 10.{i}.0.0 255.255.0.0 Null0\n" for i in range(10))
TEXT = {
    "f-run-old": LO0 + SNMP,
    "f-run-new": LO0 + "interface Loopback77\n description new\n" + ROUTES + SNMP,
    "f-start-new": LO0 + SNMP,
}


def mock_archive(api: respx.MockRouter, files: list[dict[str, Any]] = FILES) -> None:
    def listing(request: httpx.Request) -> httpx.Response:
        ft = request.url.params.get("fileType")
        return httpx.Response(200, json={"response": [f for f in files if not ft or f["fileType"] == ft]})

    api.get("/dna/intent/api/v1/networkDeviceConfigFiles").mock(side_effect=listing)
    for fid, text in TEXT.items():
        api.post(f"/dna/intent/api/v1/networkDeviceConfigFiles/{fid}/downloadMasked").respond(json=text)


async def test_list_config_archive(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_archive(api)
    out = await call("catc_list_config_archive", {"device": "edge-sw1", "response_format": "json"})
    assert (
        out["results"][0]["created"] == "2026-10-14 18:15:09 UTC" and out["results"][-1]["id"] == "f-run-old"
    )


async def test_compare_configs(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_archive(api)
    out = await call("catc_compare_device_configs", {"device": "edge-sw1"})
    assert out["lines_added"] == 12 and out["lines_removed"] == 0 and "+interface Loopback77" in out["diff"]
    assert "s3cret" not in json.dumps(out)
    out = await call(
        "catc_compare_device_configs", {"device": "edge-sw1", "compare": "startup", "max_lines": 10}
    )
    assert out["from"].startswith("STARTUPCONFIG") and out["truncated"].startswith("diff cut at 10")
    out = await call(
        "catc_compare_device_configs",
        {"device": "edge-sw1", "compare": "files", "from_file": "f-start-new", "to_file": "f-run-old"},
    )
    assert out["identical"] is True
    with pytest.raises(ToolError, match="from_file and to_file"):
        await call("catc_compare_device_configs", {"device": "edge-sw1", "compare": "files"})


async def test_compare_with_one_version(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_archive(api, [FILES[2]])
    out = await call("catc_compare_device_configs", {"device": "edge-sw1"})
    assert "Only one" in out["note"]


# --- hardware ----------------------------------------------------------------------------------


async def test_device_hardware(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}/stack").respond(
        json={
            "response": {
                "stackSwitchInfo": [{"stackMemberNumber": 1, "role": "ACTIVE", "state": "READY", "x": 1}]
            }
        }
    )
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}/poe").respond(
        json={"response": {"powerAllocated": 740, "powerConsumed": 30, "powerRemaining": 710}}
    )
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}/interface/poe-detail").respond(
        json={
            "response": [
                {"interfaceName": "Gi1/0/1", "operStatus": "on", "portPowerDrawn": "15.4"},
                {"interfaceName": "Gi1/0/2", "operStatus": "off"},
            ]
        }
    )
    api.get("/dna/intent/api/v1/network-device/module/count").respond(json={"response": 3})
    lic = api.get("/dna/intent/api/v1/networkDeviceLicenses").respond(
        json={
            "response": [
                {"managementAddress": "10.9.9.9", "licenseMode": "X"},
                {
                    "managementAddress": "10.0.0.11",
                    "licenseMode": "SMART_LICENSE",
                    "licenses": [{"name": "network-advantage", "status": "IN_USE", "count": 1}],
                },
            ]
        }
    )
    out = await call("catc_get_device_hardware", {"device": "edge-sw1"})
    assert out["stack"] == [{"stackMemberNumber": 1, "role": "ACTIVE", "state": "READY"}]
    assert out["poe"]["powerRemaining"] == 710 and [p["interfaceName"] for p in out["poe_ports"]] == [
        "Gi1/0/1"
    ]
    assert out["module_count"] == 3 and out["licensing"]["licenseMode"] == "SMART_LICENSE"
    assert lic.calls.last.request.url.params["family"] == "SWITCHES_AND_HUBS"


# --- platform reads ----------------------------------------------------------------------------


async def test_system_health(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/diagnostics/system/health").respond(
        json={
            "healthEvents": [
                {"state": "HEALTHY", "subDomain": "a"},
                {"state": "OK", "subDomain": "b"},
                {"state": "UNHEALTHY", "subDomain": "kafka", "description": "down"},
            ]
        }
    )
    api.get("/dna/system/api/v1/backups").respond(json={"response": []})
    api.get("/dna/system/api/v1/backupConfiguration").respond(
        json={"response": {"type": "", "mountPath": ""}}
    )
    api.get("/dna/system/api/v1/license/status").respond(
        json={
            "response": {
                "registrationStatus": {"status": "UNREGISTERED"},
                "authorizationStatus": {"status": "EVAL"},
            }
        }
    )
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(500, text="boom")
    out = await call("catc_get_system_health")
    assert out["services"]["by_state"] == {"HEALTHY": 1, "OK": 1, "UNHEALTHY": 1}
    assert [e["subDomain"] for e in out["services"]["not_healthy"]] == ["kafka"]
    assert out["backups"] == "no backups taken" and out["backup_target"] == "not configured"
    assert out["license"] == {"registration": "UNREGISTERED", "authorization": "EVAL"}
    assert "aaa_servers" in out["unavailable"]


async def test_network_profiles(api: respx.MockRouter) -> None:
    pid = "dddddddd-0000-0000-0000-000000000001"
    api.get("/dna/intent/api/v1/networkProfilesForSites").respond(
        json={"response": [{"id": pid, "name": "campus", "type": "Switching"}]}
    )
    api.get(f"/dna/intent/api/v1/networkProfilesForSites/{pid}/siteAssignments").respond(
        json={"response": [{"id": "s1"}, {"id": "s2"}]}
    )
    api.get(f"/dna/intent/api/v1/networkProfilesForSites/{pid}/templates").respond(
        json={"response": [{"name": "dayn-vlans"}]}
    )
    out = await call("catc_list_network_profiles", {"response_format": "json"})
    assert out["results"] == [
        {"name": "campus", "type": "Switching", "id": pid, "sites": 2, "templates": "dayn-vlans"}
    ]


async def test_pnp_devices(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/onboarding/pnp-device").respond(
        json=[
            {
                "id": "p1",
                "deviceInfo": {
                    "serialNumber": "FOC1",
                    "pid": "C9300-24U",
                    "state": "Unclaimed",
                    "onbState": "Initialized",
                    "lastContact": 5,
                },
            }
        ]
    )
    out = await call("catc_list_pnp_devices", {"state": "Unclaimed", "response_format": "json"})
    assert out["results"] == [
        {
            "serial": "FOC1",
            "pid": "C9300-24U",
            "state": "Unclaimed",
            "onboarding": "Initialized",
            "lastContact": 5,
            "id": "p1",
        }
    ]


async def test_sda_fabric(api: respx.MockRouter) -> None:
    fid = "eeeeeeee-0000-0000-0000-000000000001"
    api.get("/dna/intent/api/v1/sda/fabricSites").respond(
        json={
            "response": [{"id": fid, "siteId": BLDG["id"], "authenticationProfileName": "No Authentication"}]
        }
    )
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_device_lookup(api)
    api.get("/dna/intent/api/v1/sda/fabricDevices").respond(
        json={"response": [{"networkDeviceId": DEV_ID, "deviceRoles": ["EDGE_NODE"], "fabricId": fid}]}
    )
    api.get("/dna/intent/api/v1/sda/anycastGateways").respond(
        json={
            "response": [
                {"virtualNetworkName": "CORP", "ipPoolName": "syd-lan", "vlanId": 1021, "fabricId": fid}
            ]
        }
    )
    api.get("/dna/intent/api/v1/sda/layer3VirtualNetworks").respond(
        json={"response": [{"virtualNetworkName": "CORP", "fabricIds": [fid]}]}
    )
    api.get("/dna/intent/api/v1/sda/portAssignments").respond(
        json={"response": [{"id": "pa1", "interfaceName": "GigabitEthernet1/0/3", "dataVlanName": "CORP_VLAN"}]}
    )
    out = await call("catc_get_sda_fabric")
    site = out["fabric_sites"][0]
    assert site["port_assignments"][0]["id"] == "pa1"
    assert site["site"] == BLDG["nameHierarchy"] and site["devices"][0]["hostname"] == DEVICE["hostname"]
    assert (
        site["anycast_gateways"][0]["vlanId"] == 1021
        and out["layer3_virtual_networks"][0]["virtualNetworkName"] == "CORP"
    )


async def test_sda_fabric_empty(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/sda/fabricSites").respond(json={"response": []})
    out = await call("catc_get_sda_fabric")
    assert out["fabric_sites"] == []


async def test_list_ssids(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL])
    api.get(f"/dna/intent/api/v1/sites/{GLOBAL['id']}/wirelessSettings/ssids").respond(
        json={
            "response": [
                {"ssid": "corp", "authType": "WPA2_ENTERPRISE", "isEnabled": True, "passphrase": "x"}
            ]
        }
    )
    out = await call("catc_list_ssids", {"response_format": "json"})
    assert out["results"] == [{"ssid": "corp", "authType": "WPA2_ENTERPRISE", "isEnabled": True}]


# --- SWIM --------------------------------------------------------------------------------------

IMG = {
    "id": "ffffffff-0000-0000-0000-000000000001",
    "name": "cat9k_iosxe.17.12.04.SPA.bin",
    "version": "17.12.4",
}


async def test_device_images(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get("/dna/intent/api/v1/networkDeviceImages").respond(
        json={
            "response": [
                {
                    "id": DEV_ID,
                    "managementAddress": "10.0.0.11",
                    "networkDeviceImageStatus": "NON_COMPLIANT",
                    "installedImages": [{"name": "CAT9K[17.9.4]"}],
                    "networkDevice": {"productName": "C9300"},
                }
            ]
        }
    )
    out = await call("catc_list_device_images", {"image_status": "NON_COMPLIANT", "response_format": "json"})
    assert (
        out["results"][0]["hostname"] == DEVICE["hostname"]
        and out["results"][0]["running"] == "CAT9K[17.9.4]"
    )


async def test_tag_golden_image(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get("/dna/intent/api/v1/images").respond(json={"response": [IMG]})
    api.get(f"/dna/intent/api/v1/images/{IMG['id']}/siteWiseProductNames").respond(
        json={
            "response": [
                {"productName": "Cisco Catalyst 9300 Switch", "productNameOrdinal": 286315874},
                {"productName": "Cisco Catalyst 9400 Switch", "productNameOrdinal": 286315875},
            ]
        }
    )
    with pytest.raises(ToolError, match="Pick one"):
        await preview_then_apply("catc_tag_golden_image", {"image": IMG["name"]})
    post = api.post(f"/dna/intent/api/v1/images/{IMG['id']}/sites/{AREA['id']}/tagGolden").respond(
        202, json={"response": {"taskId": "tg"}}
    )
    task_ok(api, "tg")
    golden = (
        f"/dna/intent/api/v1/image/importation/golden/site/{AREA['id']}/family/286315874"
        f"/role/ACCESS/image/{IMG['id']}"
    )
    state = {"taggedGolden": True, "inheritedSiteId": GLOBAL["id"], "inheritedSiteName": "Global"}
    route = api.get(golden).mock(side_effect=lambda r: httpx.Response(200, json={"response": state}))
    args = {"image": IMG["name"], "site": "Global/AU", "product": "286315874", "device_roles": ["ACCESS"]}
    preview, done = await preview_then_apply("catc_tag_golden_image", args)
    assert route.called
    assert preview["preview"]["current_golden_state"]["ACCESS"]["inherited_from"] == "Global"
    assert json.loads(post.calls.last.request.content) == {
        "productNameOrdinal": 286315874,
        "deviceRoles": ["ACCESS"],
    }
    assert done["status"] == "applied"
    state.update(inheritedSiteId=AREA["id"], inheritedSiteName="AU")
    again = await call("catc_tag_golden_image", args, mcp_enable_writes=True)
    assert again["status"] == "blocked" and "Already golden" in again["blockers"][0]
    # Untagging where the tag is only inherited from Global can't work: blocked.
    state.update(inheritedSiteId=GLOBAL["id"], inheritedSiteName="Global")
    untag = await call("catc_tag_golden_image", {**args, "untag": True}, mcp_enable_writes=True)
    assert untag["status"] == "blocked" and "only inherited" in untag["blockers"][0]


# --- templates ---------------------------------------------------------------------------------


def test_template_task_result() -> None:
    assert template_task_result("abc") == ("abc", [])
    data = json.dumps(
        {
            "templateId": "t1",
            "templateErrors": [{"type": "POTENTIAL_CONFLICT", "message": "reserved", "lineNumber": 2}],
        }
    )
    assert template_task_result(data) == ("t1", ["line 2: POTENTIAL_CONFLICT: reserved"])


async def test_template_deployment_status(api: respx.MockRouter) -> None:
    dep = "de8092f8-baf8-41b5-b1d7-02b53d42c376"
    api.get(f"/dna/intent/api/v1/template-programmer/template/deploy/status/{dep}").respond(
        json={
            "deploymentId": dep,
            "status": "FAILURE",
            "templateName": "t",
            "devices": [
                {
                    "name": "r1",
                    "status": "FAILURE",
                    "detailedStatusMessage": "Invalid input: snmp-server community s3cret",
                }
            ],
        }
    )
    out = await call("catc_get_template_deployment", {"deployment_id": dep})
    assert out["status"] == "FAILURE" and "s3cret" not in json.dumps(out)
    assert out["devices"][0]["status"] == "FAILURE"


# --- provisioning ------------------------------------------------------------------------------


async def test_reprovision_and_moved_blocker(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_device_lookup(api)
    rec = {"id": "prov-1", "networkDeviceId": DEV_ID, "siteId": BLDG["id"]}
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": [rec]})
    put = api.put("/dna/intent/api/v1/sda/provisionDevices").respond(202, json={"response": {"taskId": "tr"}})
    task_ok(api, "tr")
    preview, done = await flow("catc_provision_devices", {"devices": ["edge-sw1"], "site": "SYD-1"})
    assert preview["preview"]["re_provision"] and not preview["preview"]["provision"]
    assert json.loads(put.calls.last.request.content) == [
        {"id": "prov-1", "networkDeviceId": DEV_ID, "siteId": BLDG["id"]}
    ]
    assert done["result"]["re_provisioned"]["status"] == "SUCCESS"
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(
        json={"response": [{**rec, "siteId": "elsewhere"}]}
    )
    preview, _ = await flow("catc_provision_devices", {"devices": ["edge-sw1"], "site": "SYD-1"})
    assert "catc_delete_device" in preview["blockers"][0]


# --- assurance, command runner, config ----------------------------------------------------------


async def test_events_infer_family(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    route = api.get("/dna/data/api/v1/assuranceEvents").respond(
        json={
            "response": [
                {
                    "timestamp": 1792001845925,
                    "name": "SYS:CONFIG_I",
                    "networkDeviceName": "edge-sw1",
                    "details": "x",
                }
            ],
            "page": {"count": 1},
        }
    )
    out = await call("catc_list_events", {"device": "edge-sw1", "response_format": "json"})
    q = route.calls.last.request.url.params
    assert q["deviceFamily"] == "Switches and Hubs" and q["networkDeviceName"] == DEVICE["hostname"]
    assert out["results"][0]["time"] == "2026-10-14 18:17:25"
    with pytest.raises(ToolError, match="device_family"):
        await call("catc_list_events", {})


def test_event_row_drops_empty() -> None:
    assert event_row({"name": "x", "details": "", "timestamp": None}) == {"name": "x"}


def test_clean_output() -> None:
    raw = "show ip ospf neighbor\n\nNeighbor ID     Pri\n10.255.255.2      0\nr1#"
    assert clean_output("show ip ospf neighbor", raw) == "Neighbor ID     Pri\n10.255.255.2      0"
    assert clean_output("show x", "other\nline") == "other\nline"


async def test_config_match_is_a_prefix(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}/config").respond(
        json={
            "response": "ip domain lookup source-interface Loopback0\n"
            "interface Loopback0\n ip address 1.1.1.1 255.255.255.255\n"
        }
    )
    out = await call("catc_get_device_config", {"device": "edge-sw1", "match": "interface loopback"})
    assert "interface Loopback0" in out and "ip domain lookup" not in out


async def test_credential_description_with_colon(api: respx.MockRouter) -> None:
    mock_creds(api, [{**CREDS[0], "description": "site:prod"}])
    delete = api.delete(f"/dna/intent/api/v1/globalCredentials/{CREDS[0]['id']}").respond(
        202, json={"response": {"taskId": "tdc"}}
    )
    task_ok(api, "tdc")
    _, done = await preview_then_apply("catc_delete_global_credential", {"credential": "site:prod"})
    assert done["status"] == "applied" and delete.called


async def test_settings_bad_timezone_and_local_base(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    base = f"/dna/intent/api/v1/sites/{AREA['id']}/dnsSettings"

    def dns(request: httpx.Request) -> httpx.Response:
        inherited = request.url.params.get("_inherited") == "true"
        body = {"dns": {"domainName": "g.lab", "dnsServers": ["1.1.1.1"]}} if inherited else {}
        return httpx.Response(200, json={"response": body})

    api.get(base).mock(side_effect=dns)
    put = api.put(base).respond(202, json={"response": {"taskId": "tz"}})
    task_ok(api, "tz")
    with pytest.raises(ToolError, match="Unknown time zone"):
        await preview_then_apply("catc_update_site_settings", {"site": "Global/AU", "timezone": "Mars/Base"})
    await preview_then_apply("catc_update_site_settings", {"site": "Global/AU", "domain_name": "au.lab"})
    # The inherited DNS servers are not copied into the area as a local override.
    assert json.loads(put.calls.last.request.content) == {"dns": {"domainName": "au.lab"}}
