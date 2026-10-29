"""D55: licensing summary and device licence list (respx). The unregistered answers are the 3.2.2 lab
appliance's live shapes (2026-10-28: UNREGISTERED / IN_EVALUATION_PERIOD, evaluation end in epoch seconds,
empty smartAccounts and licenseUsage); the registered, expiring and query payloads follow the bundled spec."""

import json
import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.licensing import epoch_seconds

from .test_read_tools import call

STATUS = "/dna/system/api/v1/license/status"
SMART = "/dna/intent/api/v1/licenses/smartAccounts"
SUMMARY = "/dna/intent/api/v1/networkDeviceLicenses/summary"
DEVICES = "/dna/intent/api/v1/networkDeviceLicenses"
QUERY = "/dna/intent/api/v1/networkDeviceLicenses/query"
USAGE = "/dna/intent/api/v1/licenseUsage"
DAY = 86400


def record(host: str, addr: str, **kw: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "id": f"lic-{host}",
        "managementAddress": addr,
        "hostname": host,
        "family": "SWITCHES_AND_HUBS",
        "series": "Cisco Catalyst 9000 Series Virtual Switches",
        "siteHierarchy": "Global/AU/SYD-1",
        "softwareVersion": "17.18.2",
        "licenseMode": "SMART_LICENSE",
        "licenses": [
            {"type": "NETWORK_ADVANTAGE", "name": "network-advantage", "status": "IN_USE", "count": 1},
            {"type": "DNA_ADVANTAGE", "name": "dna-advantage", "status": "IN_USE", "count": 1},
        ],
        "registrationStatus": "REGISTERED",
        "authorizationStatus": "AUTHORIZED",
        "authCodeStatus": "NA",
        "networkDeviceId": f"dev-{host}",
    }
    rec.update(kw)
    return rec


SUMMARY_BODY = {
    "response": {
        "networkDeviceLicenseSummary": {
            "networkLicenseSummary": {"essentialCount": 0, "advantageCount": 14},
            "dnaLicenseSummary": {"essentialCount": 0, "advantageCount": 14},
            "cnsLicenseSummary": {"essentialCount": 0, "advantageCount": 0},
        },
        "unregisteredNetworkDeviceCount": 20,
        "outOfComplianceNetworkDeviceCount": 0,
        "expiredNetworkDeviceLicenseCount": 0,
        "expiringNetworkDeviceLicenseCount": 0,
    },
    "version": "1.0",
}


def mock_unregistered(api: respx.MockRouter, devices: list[dict[str, Any]]) -> None:
    eval_end = int(time.time()) + 79 * DAY  # epoch seconds, as the 3.2.2 lab appliance sends it
    api.get(STATUS).respond(
        json={
            "response": {
                "registrationStatus": {"status": "UNREGISTERED", "lastAttemptFailReason": ""},
                "authorizationStatus": {
                    "status": "IN_EVALUATION_PERIOD",
                    "evaluationRemainderTimestamp": eval_end,
                    "lastAttemptStatus": "SUCCESS",
                    "lastAttemptFailReason": "",
                },
                "entitlements": [
                    {
                        "tag": "regid.2022-10.com.cisco.VDNAC_ENT,1.0_example",
                        "description": "regid.2022-10.com.cisco.VDNAC_ENT,1.0_example",
                        "usageCount": 1,
                        "status": "IN_EVALUATION_PERIOD",
                    }
                ],
                "exportControl": "NOT_ALLOWED",
            },
            "version": "1.0",
        }
    )
    api.get(SMART).respond(json={"version": "1.0.0", "response": []})
    api.get(SUMMARY).respond(json=SUMMARY_BODY)
    api.get(DEVICES).respond(json={"response": devices, "version": "1.0"})
    api.get(USAGE).respond(json={"response": [], "version": "1.0"})


async def test_unregistered_is_reported_not_raised(api: respx.MockRouter) -> None:
    unreg = record(
        "r1.example.com",
        "192.0.2.1",
        family="ROUTERS",
        licenses=[{"type": "OTHER", "name": "hseck9", "status": "INACTIVE", "count": 0, "owned": True}],
        registrationStatus="NA",
        authorizationStatus="UNKNOWN",
        authCodeStatus="NOT_INSTALLED",
    )
    mock_unregistered(api, [unreg])
    out = await call("catc_license_summary")
    app = out["appliance"]
    assert app["registration"] == "UNREGISTERED" and app["authorization"] == "IN_EVALUATION_PERIOD"
    assert 78 <= app["evaluation_days_left"] <= 79 and app["evaluation_ends"].endswith("Z")
    # tag == description: shown once
    assert app["entitlements"] == [
        {
            "description": "regid.2022-10.com.cisco.VDNAC_ENT,1.0_example",
            "status": "IN_EVALUATION_PERIOD",
            "usageCount": 1,
        }
    ]
    assert out["smart_account"]["registered"] is False
    assert "not registered with a Cisco Smart Account" in out["smart_account"]["note"]
    assert "not registered" in out["usage"]
    dev = out["devices"]
    assert dev["consumed"]["network"] == {"essentialCount": 0, "advantageCount": 14}
    assert dev["unregistered"] == 20 and dev["expired"] == 0
    assert dev["by_registration"] == {"NA": 1} and dev["by_authorization"] == {"UNKNOWN": 1}
    assert dev["expired_devices"] == "none" and dev["expiring_within_30_days"] == "none"
    assert "unavailable" not in out


async def test_registered_with_usage_and_expiring(api: respx.MockRouter) -> None:
    now_ms = int(time.time() * 1000)
    soon = record(
        "edge-1.example.com",
        "192.0.2.11",
        licenses=[
            {
                "type": "DNA_ADVANTAGE",
                "name": "dna-advantage",
                "status": "EVALUATION_IN_USE",
                "count": 1,
                "evaluationExpiryTime": now_ms + 10 * DAY * 1000,
            }
        ],
        authorizationStatus="EVALUATION_MODE",
    )
    later = record(
        "edge-2.example.com",
        "192.0.2.12",
        licenses=[
            {
                "type": "DNA_ADVANTAGE",
                "status": "EVALUATION_IN_USE",
                "evaluationExpiryTime": now_ms + 80 * DAY * 1000,
            }
        ],
    )
    gone = record(
        "edge-3.example.com",
        "192.0.2.13",
        licenses=[{"type": "DNA_ADVANTAGE", "status": "EXPIRED_IN_USE", "count": 1}],
        authorizationStatus="EVALUATION_EXPIRED",
    )
    ok = record("core-1.example.com", "192.0.2.1")
    api.get(STATUS).respond(
        json={
            "response": {
                "registrationStatus": {"status": "REGISTERED", "expiryTimestamp": now_ms + 300 * DAY * 1000},
                "authorizationStatus": {"status": "AUTHORIZED", "expiryTimestamp": now_ms + 60 * DAY * 1000},
                "entitlements": [
                    {
                        "tag": "regid.example",
                        "description": "Catalyst Center",
                        "status": "AUTHORIZED",
                        "usageCount": 1,
                    }
                ],
                "smartAccountId": "example.com",
                "virtualAccountId": "Lab-VA",
                "exportControl": "ALLOWED",
            },
            "version": "1.0",
        }
    )
    api.get(SMART).respond(
        json={
            "response": [
                {"domain": "example.com", "id": "sa-1", "is_active_smart_account": True, "name": "Example SA"}
            ],
            "version": "1.0.0",
        }
    )
    summary = json.loads(json.dumps(SUMMARY_BODY))
    summary["response"].update(expiredNetworkDeviceLicenseCount=1, expiringNetworkDeviceLicenseCount=1)
    api.get(SUMMARY).respond(json=summary)
    api.get(DEVICES).respond(json={"response": [ok, later, gone, soon], "version": "1.0"})
    api.get(USAGE).respond(
        json={
            "response": [
                {
                    "smartAccountId": "sa-1",
                    "virtualAccountId": "va-1",
                    "licenseCountsSummary": [
                        {
                            "productFamily": "SWITCH",
                            "licenses": [
                                {
                                    "type": "DNA_ADVANTAGE",
                                    "counts": {
                                        "purchased": 10,
                                        "used": 4,
                                        "available": 6,
                                        "usedByManagedNetworkDevices": 3,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ],
            "version": "1.0",
        }
    )
    out = await call("catc_license_summary")
    app = out["appliance"]
    assert app["registration"] == "REGISTERED" and app["smartAccountId"] == "example.com"
    assert 299 <= app["registration_days_left"] <= 300 and 59 <= app["authorization_days_left"] <= 60
    assert app["entitlements"][0]["tag"] == "regid.example"
    sa = out["smart_account"]
    assert sa["registered"] is True and sa["accounts"][0]["name"] == "Example SA" and "note" not in sa
    assert out["usage"] == [
        {
            "smart_account": "sa-1",
            "virtual_account": "va-1",
            "family": "SWITCH",
            "type": "DNA_ADVANTAGE",
            "purchased": 10,
            "used": 4,
            "available": 6,
            "used_by_managed_devices": 3,
        }
    ]
    dev = out["devices"]
    assert [d["hostname"] for d in dev["expired_devices"]] == ["edge-3.example.com"]
    expiring = dev["expiring_within_30_days"]
    assert [d["hostname"] for d in expiring] == ["edge-1.example.com"]
    assert 9 <= expiring[0]["days_left"] <= 10 and "DNA_ADVANTAGE/dna-advantage" in expiring[0]["licenses"]
    # a longer window takes in the 80-day evaluation too, soonest first
    out = await call("catc_license_summary", {"expiring_days": 90})
    assert [d["hostname"] for d in out["devices"]["expiring_within_90_days"]] == [
        "edge-1.example.com",
        "edge-2.example.com",
    ]


async def test_summary_sections_fail_alone(api: respx.MockRouter) -> None:
    mock_unregistered(api, [])
    api.get(USAGE).respond(403, json={"message": "Role does not have valid permissions"})
    out = await call("catc_license_summary")
    assert "usage" in out["unavailable"] and out["appliance"]["registration"] == "UNREGISTERED"


async def test_list_filter_pass_through(api: respx.MockRouter) -> None:
    rows = api.post(QUERY).respond(
        json={
            "response": [
                record(
                    "edge-1.example.com",
                    "192.0.2.11",
                    licenses=[
                        {
                            "type": "DNA_ADVANTAGE",
                            "status": "EVALUATION_IN_USE",
                            "evaluationExpiryTime": int(time.time() * 1000) + 5 * DAY * 1000,
                        }
                    ],
                    authorizationStatus="EVALUATION_MODE",
                )
            ],
            "version": "1.0",
        }
    )
    count = api.post(f"{QUERY}/count").respond(json={"response": {"count": 7}, "version": "1.0"})
    out = await call(
        "catc_list_device_licenses",
        {
            "hostname": "edge",
            "family": "SWITCHES_AND_HUBS",
            "authorization_status": "EVALUATION_MODE",
            "filters": [{"key": "authCodeStatus", "operator": "in", "value": ["NA", "INSTALLED"]}],
            "logical_operator": "AND",
            "sort_by": "registrationStatus",
            "order": "desc",
            "limit": 1,
            "offset": 2,
            "response_format": "json",
        },
    )
    sent = json.loads(rows.calls.last.request.content)
    flt = {
        "filters": [
            {"key": "hostname", "operator": "contains", "value": "edge"},
            {"key": "family", "operator": "eq", "value": "SWITCHES_AND_HUBS"},
            {"key": "authorizationStatus", "operator": "eq", "value": "EVALUATION_MODE"},
            {"key": "authCodeStatus", "operator": "in", "value": ["NA", "INSTALLED"]},
        ],
        "logicalOperator": "AND",
    }
    assert sent == {
        "page": {"limit": 1, "offset": 3, "sortBy": {"name": "registrationStatus", "order": "desc"}},
        "filter": flt,
    }
    assert json.loads(count.calls.last.request.content) == {"filter": flt}
    assert out["total"] == 7 and out["filter"] == flt
    item = out["results"][0]
    assert item["hostname"] == "edge-1.example.com" and 4 <= item["days_left"] <= 5
    assert item["authorization"] == "EVALUATION_MODE"


async def test_list_no_filter_and_count_failure(api: respx.MockRouter) -> None:
    rows = api.post(QUERY).respond(json={"response": [record("core-1.example.com", "192.0.2.1")]})
    post_count = api.post(f"{QUERY}/count")
    api.get(f"{DEVICES}/count").mock(return_value=httpx.Response(500, json={"message": "boom"}))
    out = await call("catc_list_device_licenses", {"response_format": "json"})
    # the appliance requires `filter` and rejects an empty list: the no-argument call sends a match-all
    assert json.loads(rows.calls.last.request.content)["filter"] == {
        "filters": [{"key": "hostname", "operator": "contains", "value": ""}],
        "logicalOperator": "AND",
    }
    # query/count requires a filter: the unfiltered total comes from GET networkDeviceLicenses/count
    assert not post_count.called
    assert out["results"][0]["licenses"].startswith("NETWORK_ADVANTAGE/network-advantage (IN_USE)")
    assert "count" in out["unavailable"]


async def test_list_rejects_bad_filters(api: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="Unknown filter operator"):
        await call(
            "catc_list_device_licenses", {"filters": [{"key": "family", "operator": "ne", "value": "X"}]}
        )
    with pytest.raises(ToolError, match="takes a list"):
        await call(
            "catc_list_device_licenses", {"filters": [{"key": "family", "operator": "in", "value": "X"}]}
        )
    with pytest.raises(ToolError, match="needs a `key`"):
        await call("catc_list_device_licenses", {"filters": [{"operator": "eq", "value": "X"}]})


async def test_list_unfiltered_total_from_get_count(api: respx.MockRouter) -> None:
    api.post(QUERY).respond(json={"response": [record("core-1.example.com", "192.0.2.1")]})
    api.get(f"{DEVICES}/count").respond(json={"response": {"count": 12}, "version": "1.0"})
    out = await call("catc_list_device_licenses", {"response_format": "json"})
    assert out["total"] == 12 and "unavailable" not in out
    # the match-all filter is a request detail, not a filter the caller set
    assert "filter" not in out


def test_epoch_seconds_reads_both_units() -> None:
    assert epoch_seconds(1799974984) == 1799974984.0
    assert epoch_seconds(1799974984000) == 1799974984.0
    assert epoch_seconds(None) is None and epoch_seconds(0) is None and epoch_seconds(True) is None
