"""D56 (+ G20): EoX, security advisories, field notices, network bugs, insecure configurations (respx).

The NOT_SCANNED records are the 3.2.2 lab appliance's live answers without a Cisco (CCO) connection
(2026-10-28: eox-status/device comment MLCN10323, eox-status/device/{id} 404 MLCN10301, networkBugs scanMode
NOT_AVAILABLE, securityAdvisories 403 for the rw role, empty insecureConfigurations). The scanned records
follow the 3.2.2 spec's response schemas."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools.lifecycle import NO_CCO, PSIRT_DENIED, eox_bulletin, past

from .conftest import make_settings
from .test_read_tools import BLDG, DEV_ID, DEVICE, GLOBAL, call, mock_device_lookup
from .test_write_tools import mock_sites, preview_then_apply, task_ok

API = "/dna/intent/api/v1"
DEV2 = "22222222-3333-4444-5555-666666666666"
DEVICE2 = {**DEVICE, "id": DEV2, "hostname": "edge-sw2.lab.local", "managementIpAddress": "192.0.2.12"}
MLCN10323 = (
    "MLCN10323: The device was not scanned, possibly due to pending Consent to Connect authorization or not "
    "being a part of the inventory during the previous scan. The next scheduled scan will attempt to update "
    "any EoX alerts."
)


def eox_row(did: str, status: str = "NOT_SCANNED", alerts: int = 0, types: list[str] | None = None) -> dict:
    row: dict[str, Any] = {
        "deviceId": did,
        "alertCount": alerts,
        "summary": [{"eoxType": t} for t in types or []],
        "scanStatus": status,
        "lastScanTime": 0 if status == "NOT_SCANNED" else 1767225600000,
    }
    if status == "NOT_SCANNED":
        row["comments"] = [MLCN10323]
    return row


def scan_row(did: str, key: str, n: int = 0, status: str = "NOT_SCANNED", **extra: Any) -> dict:
    return {
        "networkDeviceId": did,
        key: n,
        "scanStatus": status,
        "lastScanTime": 0 if status == "NOT_SCANNED" else 1767225600000,
        **extra,
    }


def by_device(rows: list[dict[str, Any]]) -> Any:
    """networkDeviceId filter like the API's."""

    def handler(request: httpx.Request) -> httpx.Response:
        did = request.url.params.get("networkDeviceId")
        return httpx.Response(
            200, json={"response": [r for r in rows if did in (None, r["networkDeviceId"])], "version": "1.0"}
        )

    return handler


def mock_two_device_site(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, BLDG])
    api.get(f"{API}/networkDevices/assignedToSite").respond(
        json={
            "response": [{"deviceId": DEV_ID, "siteId": BLDG["id"]}, {"deviceId": DEV2, "siteId": BLDG["id"]}]
        }
    )

    def devices(request: httpx.Request) -> httpx.Response:
        ids = set(str(request.url.params.get("id", "")).split(","))
        return httpx.Response(200, json={"response": [d for d in (DEVICE, DEVICE2) if d["id"] in ids]})

    api.get(f"{API}/network-device").mock(side_effect=devices)


def mock_not_scanned(api: respx.MockRouter, ids: list[str], *, psirt_denied: bool = True) -> None:
    """The lab appliance without a CCO connection."""
    api.get(f"{API}/eox-status/summary").respond(json={"response": {"totalCount": 0}, "version": "1.0"})
    api.get(f"{API}/eox-status/device").respond(
        json={"response": [eox_row(i) for i in ids], "version": "1.0"}
    )
    for i in ids:
        api.get(f"{API}/eox-status/device/{i}").respond(
            404,
            json={
                "response": {
                    "errorCode": "MLCN10301",
                    "message": "EoX details for this device could not be found.",
                }
            },
        )
        api.get(f"{API}/networkDevices/{i}/insecureConfigurations").respond(
            json={"response": [], "version": "1.0"}
        )
    bugs = [scan_row(i, "bugCount", scanMode="NOT_AVAILABLE") for i in ids]
    bugs[-1]["comments"] = "This device family is currently not supported for identifying bugs."
    api.get(f"{API}/networkBugs/results/networkDevices").mock(side_effect=by_device(bugs))
    api.get(f"{API}/fieldNotices/results/networkDevices").mock(
        side_effect=by_device([scan_row(i, "noticeCount", potentialNoticeCount=0) for i in ids])
    )
    if psirt_denied:
        api.get(f"{API}/securityAdvisories/results/networkDevices").respond(
            403, json={"message": "Role does not have valid permissions to access the API"}
        )
    else:
        api.get(f"{API}/securityAdvisories/results/networkDevices").mock(
            side_effect=by_device([scan_row(i, "advisoryCount", scanMode="NOT_AVAILABLE") for i in ids])
        )


ADV_HIGH = {
    "id": "cisco-sa-iosxe-webui-privesc-j22SaA4z",
    "deviceCount": 2,
    "cveIds": ["CVE-2023-20198"],
    "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/x",
    "cvssBaseScore": 10.0,
    "securityImpactRating": "CRITICAL",
    "firstFixedVersionsList": [{"vulnerableVersion": "17.9.4", "fixedVersions": ["17.9.4a"]}],
}
ADV_MED = {
    "id": "cisco-sa-snmp-dos-7TcnzxTK",
    "deviceCount": 1,
    "cveIds": ["CVE-2025-20001"],
    "cvssBaseScore": 5.3,
    "securityImpactRating": "MEDIUM",
}


# --- pure helpers ---------------------------------------------------------------------------------


def test_bulletin_flags_past_support() -> None:
    b = eox_bulletin(
        {
            "eoxAlertType": "SOFTWARE",
            "name": "17.9.4",
            "bulletinHeadline": "End-of-Sale and End-of-Life Announcement for IOS XE 17.9",
            "bulletinNumber": "EOL12345",
            "endOfSaleDate": "2024-07-31",
            "lastDateOfSupport": "2020-07-31",
            "bulletinURL": "https://www.cisco.com/c/en/us/products/eos-eol-listing.html",
            "endOfSignatureReleasesDate": "",
        }
    )
    assert b["type"] == "SOFTWARE" and b["past_last_date_of_support"] is True
    assert "endOfSignatureReleasesDate" not in b and b["end_of_sale"] == "2024-07-31"
    assert past("2999-01-01") is False and past("n/a") is None


# --- EoX --------------------------------------------------------------------------------------------


async def test_eox_not_scanned_says_no_data(api: respx.MockRouter) -> None:
    mock_not_scanned(api, [DEV_ID, DEV2])
    api.get(f"{API}/network-device").respond(json={"response": [DEVICE, DEVICE2]})
    out = await call("catc_eox_report", {})
    assert out["scope"] == "Global (whole network)"
    assert out["verdict"].startswith("EoX: no data, none of the 2 device(s) has been scanned (NOT_SCANNED 2)")
    assert out["note"].startswith(NO_CCO) and "MLCN10323" in out["note"]
    assert out["network_summary"] == {"totalCount": 0}
    assert {d["device"] for d in out["devices"]} == {"edge-sw1.lab.local", "edge-sw2.lab.local"}
    assert "bulletins" not in out  # no alerts, so no detail calls


async def test_eox_device_with_alerts(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"{API}/eox-status/device").respond(
        json={"response": [eox_row(DEV_ID, "SUCCESS", 2, ["HARDWARE", "SOFTWARE"]), eox_row(DEV2, "SUCCESS")]}
    )
    detail = api.get(f"{API}/eox-status/device/{DEV_ID}").respond(
        json={
            "response": {
                "deviceId": DEV_ID,
                "alertCount": 2,
                "scanStatus": "SUCCESS",
                "eoxDetails": [
                    {
                        "eoxAlertType": "HARDWARE",
                        "name": "C9300-24U",
                        "bulletinPID": "C9300-24U",
                        "lastDateOfSupport": "2030-10-31",
                    },
                    {"eoxAlertType": "SOFTWARE", "name": "17.9.4", "lastDateOfSupport": "2021-01-31"},
                ],
            }
        }
    )
    summary = api.get(f"{API}/eox-status/summary")
    out = await call("catc_eox_report", {"device": "edge-sw1"})
    assert out["scope"] == "edge-sw1.lab.local" and detail.call_count == 1 and summary.call_count == 0
    assert out["verdict"] == "EoX: 1 of 1 scanned device(s) affected (2 alerts)."
    assert out["by_type"] == {"HARDWARE": 1, "SOFTWARE": 1}
    hw, sw = out["bulletins"]["edge-sw1.lab.local"]
    assert hw["pid"] == "C9300-24U" and hw["past_last_date_of_support"] is False
    assert sw["past_last_date_of_support"] is True
    assert [d["device"] for d in out["devices"]] == ["edge-sw1.lab.local"]  # the other device is filtered out


async def test_device_and_site_together_refused(api: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="not both"):
        await call("catc_eox_report", {"device": "edge-sw1", "site": "Global/AU/SYD-1"})


# --- security advisories ------------------------------------------------------------------------------


async def test_advisories_403_names_the_permission(api: respx.MockRouter) -> None:
    mock_not_scanned(api, [DEV_ID])
    mock_device_lookup(api)
    out = await call("catc_security_advisories", {"device": "edge-sw1"})
    assert out["unavailable"] == PSIRT_DENIED and "Security.Security Advisory" in out["unavailable"]


async def test_advisories_for_a_site_aggregate_by_advisory(api: respx.MockRouter) -> None:
    mock_two_device_site(api)
    api.get(f"{API}/securityAdvisories/results/networkDevices").mock(
        side_effect=by_device(
            [
                scan_row(DEV_ID, "advisoryCount", 2, "SUCCESS", scanMode="ESSENTIALS"),
                scan_row(DEV2, "advisoryCount", 1, "SUCCESS", scanMode="ESSENTIALS"),
                scan_row("99999999-0000-0000-0000-000000000000", "advisoryCount", 5, "SUCCESS"),  # other site
            ]
        )
    )
    one = api.get(f"{API}/securityAdvisories/results/networkDevices/{DEV_ID}/advisories").respond(
        json={"response": [ADV_MED, ADV_HIGH]}
    )
    api.get(f"{API}/securityAdvisories/results/networkDevices/{DEV2}/advisories").respond(
        json={"response": [ADV_HIGH]}
    )
    out = await call(
        "catc_security_advisories", {"site": "Global/AU/SYD-1", "impact": ["CRITICAL", "MEDIUM"]}
    )
    assert out["verdict"] == "Security advisories: 2 of 2 scanned device(s) affected (3 advisories)."
    assert one.calls.last.request.url.params["securityImpactRating"] == "CRITICAL,MEDIUM"
    first, second = out["advisories"]
    assert first["id"] == ADV_HIGH["id"] and first["devices"] == ["edge-sw1.lab.local", "edge-sw2.lab.local"]
    assert first["first_fixed"] == {"17.9.4": ["17.9.4a"]} and second["cvss"] == 5.3
    assert out["by_impact"] == {"CRITICAL": 1, "MEDIUM": 1} and len(out["devices"]) == 2
    out = await call("catc_security_advisories", {"site": "Global/AU/SYD-1", "min_cvss": 9})
    assert [a["id"] for a in out["advisories"]] == [ADV_HIGH["id"]]


async def test_advisories_whole_network_uses_the_advisory_list(api: respx.MockRouter) -> None:
    api.get(f"{API}/securityAdvisories/results/networkDevices").mock(
        side_effect=by_device([scan_row(DEV_ID, "advisoryCount", 1, "SUCCESS")])
    )
    api.get(f"{API}/network-device").respond(json={"response": [DEVICE]})
    lst = api.get(f"{API}/securityAdvisories/results/advisories").respond(json={"response": [ADV_HIGH]})
    out = await call("catc_security_advisories", {})
    assert lst.call_count == 1 and out["advisories"][0]["device_count"] == 2
    assert out["devices"][0]["device"] == "edge-sw1.lab.local"


# --- lifecycle signals ------------------------------------------------------------------------------


async def test_signals_not_scanned_lab(api: respx.MockRouter) -> None:
    mock_two_device_site(api)
    mock_not_scanned(api, [DEV_ID, DEV2])
    out = await call("catc_lifecycle_signals", {"site": "SYD-1"})
    assert out["scope"] == "Global/AU/SYD-1" and out["note"] == NO_CCO
    assert out["verdict"] == [
        "EoX: no data, none of the 2 device(s) has been scanned (NOT_SCANNED 2).",
        "Field notices: no data, none of the 2 device(s) has been scanned (NOT_SCANNED 2).",
        "Bugs: no data, none of the 2 device(s) has been scanned (NOT_SCANNED 2).",
        "Insecure configurations: 0 on 0 of 2 device(s) checked.",
    ]
    assert out["unavailable"]["security_advisories"] == PSIRT_DENIED
    assert out["signals"]["bugs"]["scan_mode"] == {"NOT_AVAILABLE": 2}
    assert "26.1.1" in out["signals"]["insecure_configurations"]["note"]  # 17.9.4 reports none
    assert out["devices"][0] == {
        "device": "edge-sw1.lab.local",
        "eox": "NOT_SCANNED",
        "field_notices": "NOT_SCANNED",
        "bugs": "NOT_SCANNED",
        "insecure_configurations": 0,
    }


async def test_signals_one_device_lists_findings(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get(f"{API}/eox-status/device").respond(json={"response": [eox_row(DEV_ID, "SUCCESS")]})
    api.get(f"{API}/eox-status/device/{DEV_ID}").respond(
        json={"response": {"deviceId": DEV_ID, "eoxDetails": []}}
    )
    api.get(f"{API}/securityAdvisories/results/networkDevices").mock(
        side_effect=by_device([scan_row(DEV_ID, "advisoryCount", 1, "SUCCESS", scanMode="ESSENTIALS")])
    )
    api.get(f"{API}/securityAdvisories/results/networkDevices/{DEV_ID}/advisories").respond(
        json={"response": [ADV_HIGH]}
    )
    api.get(f"{API}/fieldNotices/results/networkDevices").mock(
        side_effect=by_device([scan_row(DEV_ID, "noticeCount", 1, "SUCCESS", potentialNoticeCount=0)])
    )
    api.get(f"{API}/fieldNotices/results/networkDevices/{DEV_ID}/notices").respond(
        json={
            "response": [
                {
                    "id": "FN72510",
                    "name": "FN72510 - Catalyst 9300 power supply",
                    "type": "HARDWARE",
                    "matchConfidence": "VULNERABLE",
                    "matchReason": "PID and serial number match",
                    "firstPublishDate": 1700000000000,
                    "networkDeviceId": DEV_ID,
                }
            ]
        }
    )
    api.get(f"{API}/networkBugs/results/networkDevices").mock(
        side_effect=by_device([scan_row(DEV_ID, "bugCount", 0, "NOT_SCANNED", scanMode="NOT_AVAILABLE")])
    )
    bugs = api.get(f"{API}/networkBugs/results/networkDevices/{DEV_ID}/bugs")
    insecure = api.get(f"{API}/networkDevices/{DEV_ID}/insecureConfigurations").respond(
        json={
            "response": [
                {
                    "id": "c1",
                    "module": "TELNET",
                    "severity": "HIGH",
                    "cliCommand": "transport input telnet",
                    "parentCommand": "line vty 0 4",
                    "configMode": "line",
                    "reason": "Telnet sends credentials in clear text",
                    "remediation": "transport input ssh",
                    "status": "ACTIVE",
                },
                {"id": "c2", "module": "SNMP", "cliCommand": "snmp-server community <masked> RO"},
            ]
        }
    )
    out = await call("catc_lifecycle_signals", {"device": "edge-sw1", "insecure_modules": ["TELNET", "SNMP"]})
    assert insecure.calls.last.request.url.params["module"] == "TELNET,SNMP"
    assert bugs.call_count == 0  # not scanned: no detail call
    assert out["verdict"] == [
        "EoX: 0 of 1 scanned device(s) affected (0 alerts).",
        "Security advisories: 1 of 1 scanned device(s) affected (1 advisories).",
        "Field notices: 1 of 1 scanned device(s) affected (1 notices).",
        "Bugs: no data, none of the 1 device(s) has been scanned (NOT_SCANNED 1).",
        "Insecure configurations: 2 on 1 of 1 device(s) checked (TELNET 1, SNMP 1).",
    ]
    assert out["note"] == NO_CCO and "note" not in out["signals"]["bugs"]
    assert out["security_advisories"][0]["cves"] == ["CVE-2023-20198"]
    assert out["field_notices"][0]["match"] == "VULNERABLE" and out["field_notices"][0]["published"]
    assert out["insecure_configurations"][0]["remediation"] == "transport input ssh"
    assert out["devices"] == [
        {
            "device": "edge-sw1.lab.local",
            "eox": 0,
            "security_advisories": 1,
            "field_notices": 1,
            "bugs": "NOT_SCANNED",
            "insecure_configurations": 2,
        }
    ]


async def test_signals_whole_network_skips_insecure(api: respx.MockRouter) -> None:
    mock_not_scanned(api, [DEV_ID], psirt_denied=False)
    api.get(f"{API}/network-device").respond(json={"response": [DEVICE]})
    out = await call("catc_lifecycle_signals", {})
    assert out["signals"]["insecure_configurations"]["verdict"].startswith(
        "Insecure configurations: per device"
    )
    assert out["signals"]["security_advisories"]["scan_status"] == {"NOT_SCANNED": 1}
    assert "unavailable" not in out


# --- trigger scan (write) -----------------------------------------------------------------------------


async def test_trigger_scan_preview_then_apply(api: respx.MockRouter) -> None:
    fn = api.post(f"{API}/fieldNotices/triggerScan").respond(
        202, json={"response": {"taskId": "t-fn", "url": "/api/v1/task/t-fn"}, "version": "1.0"}
    )
    bugs = api.post(f"{API}/networkBugs/triggerScan").respond(
        403, json={"message": "Role does not have valid permissions to access the API"}
    )
    psirt = api.post(f"{API}/securityAdvisories/triggerScan")
    task_ok(api, "t-fn")
    preview, done = await preview_then_apply(
        "catc_trigger_lifecycle_scan", {"scans": ["field_notices", "bugs"], "failed_only": True}
    )
    assert preview["action"] == "Trigger field notices, network bugs scan (failed devices only)"
    assert [r["path"] for r in preview["preview"]["requests"]] == [
        f"{API}/fieldNotices/triggerScan",
        f"{API}/networkBugs/triggerScan",
    ]
    assert fn.call_count == 1 and bugs.call_count == 1 and psirt.call_count == 0
    assert fn.calls.last.request.url.params["failedDevicesOnly"] == "true"
    scans = done["result"]["scans"]
    assert scans["field_notices"]["status"] == "SUCCESS" and scans["field_notices"]["task_id"] == "t-fn"
    assert scans["bugs"]["status"] == "FAILED" and "403" in scans["bugs"]["error"]


async def test_trigger_scan_is_write_tier() -> None:
    async with Client(create_server(make_settings())) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_lifecycle_signals" in names and "catc_trigger_lifecycle_scan" not in names
