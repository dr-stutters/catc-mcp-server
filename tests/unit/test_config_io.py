"""D39: config export (pure serializer on a recorded fixture) and diff."""

import copy
import json
import os
import random
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp._core import InvalidRequest
from catc_mcp.tools import config_io
from catc_mcp.tools.config_io import (
    FORMAT,
    SECTIONS,
    VERSION,
    build_export,
    canonical,
    diff_exports,
    dump_export,
    load_export,
)

from .test_read_tools import call

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
# Raw records as collect() read them from the lab (3.2.2), plus pools, SSIDs, a wireless profile, a
# dynamic tag and a compliance policy shaped per the 3.2.2 spec (the lab had none).
RAW: dict[str, Any] = json.loads((FIXTURES / "config_export_raw.json").read_text())
GOLDEN = FIXTURES / "config_export.yaml"


def export_text(raw: dict[str, Any] | None = None) -> str:
    return dump_export(build_export(copy.deepcopy(raw or RAW)))


def test_export_matches_golden() -> None:
    """The fixture's export is the committed YAML (UPDATE_CONFIG_EXPORT_GOLDEN=1 accepts a change)."""
    text = export_text()
    if os.environ.get("UPDATE_CONFIG_EXPORT_GOLDEN"):
        GOLDEN.write_text(text)
    assert text == GOLDEN.read_text()


def test_round_trip_is_byte_identical() -> None:
    text = export_text()
    assert dump_export(load_export(text)) == text
    doc = load_export(text)
    assert canonical(canonical(doc)) == canonical(doc)


def shuffled(raw: dict[str, Any], seed: int) -> dict[str, Any]:
    """The raw records in another order: every mapping's keys, and every collection the API returns
    (sites, credentials, templates, profiles, pools, SSIDs, tags, policies and their rules). Lists
    inside a record (DNS servers, template params) keep their order: that order means something."""
    rng = random.Random(seed)

    def keys(v: Any) -> Any:
        if isinstance(v, dict):
            items = list(v.items())
            rng.shuffle(items)
            return {k: keys(x) for k, x in items}
        if isinstance(v, list):
            return [keys(x) for x in v]
        return v

    def mix(items: list[Any]) -> list[Any]:
        items = list(items)
        rng.shuffle(items)
        return items

    out = keys(copy.deepcopy(raw))
    for key in ("sites", "credentials_raw", "network_profiles", "ip_pools", "ip_reservations"):
        out[key] = mix(out[key])
    for key in ("wireless_profiles", "tags", "compliance_policies"):
        out[key] = mix(out[key])
    out["templates"]["projects"] = mix(out["templates"]["projects"])
    out["templates"]["templates"] = mix(out["templates"]["templates"])
    out["ssids"] = {k: mix(v) for k, v in out["ssids"].items()}
    for pol in out["compliance_policies"]:
        pol["rules"] = mix(pol["rules"])
        pol["site_ids"] = mix(pol["site_ids"])
    for prof in out["network_profiles"]:
        prof["site_ids"] = mix(prof["site_ids"])
    return out


def test_stable_ordering_whatever_the_api_order() -> None:
    base = export_text()
    for seed in range(10):
        assert export_text(shuffled(RAW, seed)) == base, seed


def test_header_and_section_order() -> None:
    doc = load_export(export_text())
    assert list(doc)[:3] == ["format", "version", "meta"]
    assert doc["format"] == FORMAT and doc["version"] == VERSION
    assert [k for k in doc if k in SECTIONS] == list(SECTIONS)


def test_no_ids_timestamps_or_secrets() -> None:
    text = export_text()
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text)
    assert "should-not-appear" not in text and "hunter2" not in text
    assert "1792201723848" not in text  # createTime
    doc = load_export(text)
    psk = next(s for s in doc["ssids"] if s["ssid"] == "mcp-test-psk")
    assert psk["passphrase"] == "********"
    http = next(c for c in doc["credentials"] if c["type"] == "HTTP_READ")
    assert "password" not in http and http["username"] == "api"


def test_sections_by_name() -> None:
    doc = load_export(export_text())
    assert [s["path"] for s in doc["sites"]][0] == "Global/mcp-test-lab"
    lab = doc["settings"]["Global/mcp-test-lab"]
    assert lab["credentials"]["cliCredentials"] == "CLI:mcp-test-cli"
    assert lab["dns"]["dns"] == {"dnsServers": ["198.18.133.1"], "domainName": "mcp.lab"}
    # The building's assignment implies its floor: only the root is exported.
    (profile,) = doc["network_profiles"]
    assert profile["sites"] == ["Global/mcp-test-lab/mcp-test-bldg"]
    assert profile["templates"] == ["mcp-test-dayn/mcp-test-cdp"]
    (res,) = doc["ip_reservations"]
    assert (
        res["site"] == "Global/mcp-test-lab/mcp-test-bldg" and res["ipv4"]["globalPool"] == "mcp-test-global"
    )
    assert "totalAddresses" not in res["ipv4"]
    # Defined at Global; the area's inherited copy is not repeated.
    assert [(s["site"], s["ssid"]) for s in doc["ssids"]] == [("Global", "mcp-test-psk")]
    (wl,) = doc["wireless_profiles"]
    assert wl["name"] == "mcp-test-wl" and "dot11beProfileId" not in wl["ssidDetails"][0]
    assert [t["name"] for t in doc["tags"]] == ["AUTO_INV_EVENT_SYNC_DISABLED", "mcp-test-routers"]
    (pol,) = doc["compliance_policies"]
    assert pol["sites"] == ["Global/mcp-test-lab"] and pol["rules"][0]["deviceFamilies"] == ["Routers"]
    # System templates (Reference Templates) are left out; user ones are in, content kept.
    assert all(t["project"] != "Reference Templates" for t in doc["templates"])
    assert "Reference Templates" not in [p["name"] for p in doc["template_projects"]]
    cdp = next(t for t in doc["templates"] if t["name"] == "mcp-test-cdp")
    assert cdp["content"].startswith("cdp run\n")


def test_scope_limits_site_bound_sections() -> None:
    raw = copy.deepcopy(RAW)
    raw["meta"]["scope"] = "Global/mcp-test-lab/mcp-test-bldg"
    doc = build_export(raw)
    assert [s["path"] for s in doc["sites"]] == [
        "Global/mcp-test-lab",  # ancestor, so an import can create the chain
        "Global/mcp-test-lab/mcp-test-bldg",
        "Global/mcp-test-lab/mcp-test-bldg/mcp-test-floor1",
    ]
    assert list(doc["settings"]) == []
    assert doc["ssids"] == [] and doc["compliance_policies"][0]["sites"] == [
        "Global/mcp-test-lab/mcp-test-bldg"
    ]


def test_failed_section_is_named_not_exported() -> None:
    raw = copy.deepcopy(RAW)
    raw["meta"]["errors"] = {"ssids": "403 Forbidden"}
    doc = build_export(raw)
    assert "ssids" not in doc and doc["meta"]["errors"] == {"ssids": "403 Forbidden"}


def test_load_rejects_other_documents() -> None:
    with pytest.raises(InvalidRequest, match="Not a Catalyst Center config export"):
        load_export("a: 1\n")
    with pytest.raises(InvalidRequest, match="version"):
        load_export(f"format: {FORMAT}\nversion: {VERSION + 1}\n")
    with pytest.raises(InvalidRequest, match="YAML"):
        load_export("a: [1\n")


def test_diff_identical_and_reordered() -> None:
    a = load_export(export_text())
    raw = shuffled(RAW, 1)
    raw["meta"]["exported_at"] = "2026-10-24T06:00:00Z"
    b = load_export(export_text(raw))
    # Reordered items within a section are not changes either.
    b["tags"].reverse()
    b["sites"].reverse()
    out = diff_exports(a, b)
    assert out["identical"] and out["changes"] == [] and out["not_compared"] == []


def test_diff_one_setting() -> None:
    a = load_export(export_text())
    b = copy.deepcopy(a)
    b["settings"]["Global/mcp-test-lab"]["dns"]["dns"]["domainName"] = "changed.lab"
    out = diff_exports(a, b)
    assert out["changes"] == [
        {
            "section": "settings",
            "item": "Global/mcp-test-lab",
            "change": "changed",
            "field": "dns.dns.domainName",
            "before": "mcp.lab",
            "after": "changed.lab",
        }
    ]
    assert out["summary"] == {"settings": {"added": 0, "removed": 0, "changed": 1}}


def test_diff_added_removed_and_not_compared() -> None:
    a = load_export(export_text())
    b = copy.deepcopy(a)
    b["tags"] = [t for t in b["tags"] if t["name"] != "mcp-test-routers"]
    b["sites"].append({"path": "Global/mcp-d39-new", "type": "area"})
    b["settings"]["Global/mcp-d39-new"] = {"ntp": {"ntp": {"servers": ["192.0.2.1"]}}}
    del b["ssids"]
    out = diff_exports(a, b)
    kinds = {(c["section"], c["item"], c["change"]) for c in out["changes"]}
    assert kinds == {
        ("tags", "mcp-test-routers", "removed"),
        ("sites", "Global/mcp-d39-new", "added"),
        ("settings", "Global/mcp-d39-new", "added"),
    }
    assert out["not_compared"] == ["ssids"]


async def test_diff_tool_two_exports(api: respx.MockRouter) -> None:
    a = export_text()
    doc = load_export(a)
    doc["tags"][1]["description"] = "all lab routers"
    out = await call("catc_diff_config", {"before": a, "after": dump_export(doc)})
    assert out["changes"] == [
        {
            "section": "tags",
            "item": "mcp-test-routers",
            "change": "changed",
            "field": "description",
            "before": "lab routers",
            "after": "all lab routers",
        }
    ]
    assert out["before"] == "2026-10-17T06:00:00Z"


def mock_sites_and_settings(api: respx.MockRouter, domain: str) -> None:
    sites = RAW["sites"]
    api.get("/dna/intent/api/v1/sites", params={"nameHierarchy": "Global/mcp-test-lab"}).respond(
        json={"response": [s for s in sites if s["nameHierarchy"] == "Global/mcp-test-lab"]}
    )
    api.get("/dna/intent/api/v1/sites").respond(json={"response": sites})
    api.get("/dna/intent/api/v1/globalCredentials").respond(json={"response": RAW["credentials_raw"]})
    by_suffix = {
        "aaaSettings": "aaa",
        "bannerSettings": "banner",
        "dhcpSettings": "dhcp",
        "dnsSettings": "dns",
        "ntpSettings": "ntp",
        "telemetrySettings": "telemetry",
        "timeZoneSettings": "timezone",
        "imageDistributionSettings": "image_distribution",
        "deviceCredentials": "credentials",
    }

    def setting(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("_inherited") == "false"
        _, sid, suffix = request.url.path.rsplit("/", 2)
        body = copy.deepcopy(RAW["settings"].get(sid, {}).get(by_suffix[suffix]))
        if suffix == "dnsSettings" and body and body.get("dns"):
            body["dns"]["domainName"] = domain
        return httpx.Response(200, json={"response": body})

    api.get(path__regex=r"^/dna/intent/api/v1/sites/[0-9a-f-]+/\w+$").mock(side_effect=setting)


async def test_export_tool_and_live_diff(api: respx.MockRouter) -> None:
    mock_sites_and_settings(api, "mcp.lab")
    text = await call(
        "catc_export_config", {"scope": "Global/mcp-test-lab", "sections": ["sites", "settings"]}
    )
    doc = load_export(text)
    assert doc["meta"]["scope"] == "Global/mcp-test-lab" and doc["meta"]["sections"] == ["sites", "settings"]
    assert doc["meta"]["catalyst_center"] == "3.2.2-75131"
    assert list(doc["settings"]) == ["Global/mcp-test-lab"]
    assert dump_export(load_export(text)) == text

    api.routes.clear()
    with respx.mock(base_url="https://catc.test", assert_all_called=False) as live:
        live.post("/dna/system/api/v1/auth/token").respond(json={"Token": "t"})
        live.get("/dna/intent/api/v1/dnac-release").respond(json={"response": {"installedVersion": "3.2.2"}})
        live.get("/dna/system/api/v1/user").respond(json={"response": {"users": []}})
        mock_sites_and_settings(live, "changed.lab")
        out = await call("catc_diff_config", {"before": text})
    assert out["after"] == "live" and out["scope"] == "Global/mcp-test-lab"
    assert [(c["item"], c["field"], c["before"], c["after"]) for c in out["changes"]] == [
        ("Global/mcp-test-lab", "dns.dns.domainName", "mcp.lab", "changed.lab")
    ]


async def test_export_over_the_response_limit_says_what_to_narrow(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cut-off export would not parse: refuse it and give the size of each section instead."""
    mock_sites_and_settings(api, "mcp.lab")
    monkeypatch.setattr(config_io, "max_chars", lambda: 1000)
    with pytest.raises(ToolError, match=r"over the response limit .* sites \d+, settings \d+"):
        await call("catc_export_config", {"sections": ["sites", "settings"]})
