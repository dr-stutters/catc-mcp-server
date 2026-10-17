"""D39: config export (pure serializer on a recorded fixture) and diff."""

import asyncio
import copy
import json
import os
import random
import re
from functools import partial
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
    SET_LISTS,
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
    (sites, credentials, templates, profiles, pools, SSIDs, tags, policies and their rules), and every
    set-like list inside a record (SET_LISTS: SSID details, AP zones, dynamic rules, conditions...).
    Ordered lists (DNS servers, composite members) keep their order: that order means something."""
    rng = random.Random(seed)

    def keys(v: Any, name: str | None = None) -> Any:
        if isinstance(v, dict):
            items = list(v.items())
            rng.shuffle(items)
            return {k: keys(x, k) for k, x in items}
        if isinstance(v, list):
            out = [keys(x) for x in v]
            if name in SET_LISTS or name in ("templateParams", "rules"):
                rng.shuffle(out)
            return out
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
    for seed in range(20):
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
    # Planted in the fixture under keys the core's regex doesn't know (authPhrase, privKeyValue,
    # sharedKeyValue, apiToken), in Velocity/Jinja set lines, in IOS lines and in param defaults.
    assert "SECRET" not in text, [line for line in text.splitlines() if "SECRET" in line]
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


def test_template_secrets_are_masked() -> None:
    doc = load_export(export_text())
    t = next(x for x in doc["templates"] if x["name"] == "mcp-test-secrets")
    assert t["content"].splitlines()[:4] == [
        '#set($password = "********")',
        '#set( $hostname = "r1" )',  # not a secret name: unchanged
        '{% set enable_secret = "********" %}',
        "{% set vlan = 10 %}",
    ]
    defaults = {p["parameterName"]: p.get("defaultValue") for p in t["params"]}
    assert defaults == {
        "enable_pw": "********",
        "snmp_community": "********",
        "vault": "********",
        "vlan": "10",
    }


def test_settings_secrets_under_unusual_keys() -> None:
    lab = load_export(export_text())["settings"]["Global/mcp-test-lab"]
    v3 = lab["telemetry"]["snmpTraps"]["snmpv3"]
    assert v3 == {
        "authPhrase": "********",
        "authProtocol": "SHA",
        "privKeyValue": "********",
        "privacyProtocol": "AES128",
        "userName": "trapuser",
    }
    assert lab["aaa"]["aaaNetwork"]["sharedSecret"] == "********"
    assert lab["credentials"]["cliCredentials"] == "CLI:mcp-test-cli"  # labels are not secrets


def test_ties_on_the_sort_field_are_stable() -> None:
    """Two conditions with sequenceNumber 1 and two credentials named CLI:mcp-dup sort by content."""
    doc = load_export(export_text())
    conds = doc["compliance_policies"][0]["rules"][0]["conditions"]
    assert [c["sequenceNumber"] for c in conds] == [1, 1]
    assert conds == sorted(conds, key=config_io.canon_json)  # the tie is broken by content
    dups = [c["username"] for c in doc["credentials"] if c["description"] == "mcp-dup"]
    assert dups == ["alice", "bob"]
    assert any("CLI:mcp-dup" in w for w in doc["meta"]["warnings"])


def test_diff_keeps_duplicates_apart() -> None:
    a = load_export(export_text())
    b = copy.deepcopy(a)
    assert diff_exports(a, b)["identical"]
    bob = next(c for c in b["credentials"] if c.get("username") == "bob")
    bob["port"] = 2222
    # Unchanged alice pairs with herself, so the one change is bob's port (on '#2').
    out = diff_exports(a, b)
    assert [(c["item"], c["field"], c["after"]) for c in out["changes"]] == [("CLI:mcp-dup #2", "port", 2222)]
    b["credentials"] = [c for c in b["credentials"] if c.get("username") != "alice"]
    out = diff_exports(a, b)
    # Two items became one: one is reported removed, nothing disappears silently.
    assert out["summary"]["credentials"]["removed"] == 1
    assert {c["item"] for c in out["changes"]} == {"CLI:mcp-dup", "CLI:mcp-dup #2"}


def test_diff_values_are_capped() -> None:
    a = load_export(export_text())
    b = copy.deepcopy(a)
    t = next(x for x in b["templates"] if x["name"] == "mcp-test-cdp")
    t["content"] = "\n".join(f"interface Loopback{i}" for i in range(500))
    out = diff_exports(a, b)
    rows, note = config_io.cap_changes(out["changes"], 200, 20_000)
    (row,) = rows
    assert len(row["after"]) < 500 and "characters; compare the exports" in row["after"] and note is None
    many = [dict(row, item=f"x{i}") for i in range(500)]
    rows, note = config_io.cap_changes(many, 2000, 20_000)
    assert 0 < len(rows) < 500 and note and "response size" in note
    rows, note = config_io.cap_changes(many, 10, 10**9)
    assert len(rows) == 10 and note and "limit" in note


async def test_one_failing_site_is_a_warning_not_a_lost_section(api: respx.MockRouter) -> None:
    floor = next(s for s in RAW["sites"] if s["type"] == "floor")
    api.get(f"/dna/intent/api/v1/sites/{floor['id']}/dnsSettings").respond(404, json={"response": {}})
    mock_sites_and_settings(api, "mcp.lab")
    text = await call("catc_export_config", {"sections": ["sites", "settings"]})
    doc = load_export(text)
    assert (
        "settings" in doc and doc["settings"]["Global/mcp-test-lab"]["dns"]["dns"]["domainName"] == "mcp.lab"
    )
    (warning,) = doc["meta"]["warnings"]
    assert warning.startswith(f"settings {floor['nameHierarchy']} dns:")


async def test_system_compliance_policies_are_left_out(api: respx.MockRouter) -> None:
    mock_sites_and_settings(api, "mcp.lab")
    cp = "/dna/intent/api/v1/compliancePolicys"
    user = "11111111-0000-0000-0000-00000000000a"
    api.get(cp).respond(
        json={
            "response": [
                {"id": user, "name": "mcp-user", "source": "USER"},
                {"id": "11111111-0000-0000-0000-00000000000b", "name": "Built-in", "source": "SYSTEM"},
            ]
        }
    )
    api.get(f"{cp}/{user}/rules").respond(json={"response": []})
    api.get(f"{cp}/{user}/siteAssignments").respond(json={"response": {"siteIds": []}})
    doc = load_export(await call("catc_export_config", {"sections": ["compliance_policies"]}))
    assert [p["name"] for p in doc["compliance_policies"]] == ["mcp-user"]


async def test_many_profiles_and_policies_do_not_deadlock(api: respx.MockRouter) -> None:
    """20 profiles and 20 policies (more than PARALLEL) with nested reads per item finish: the
    per-item wrappers hold no slot, only the API calls do."""
    mock_sites_and_settings(api, "mcp.lab")
    np, cp = "/dna/intent/api/v1/networkProfilesForSites", "/dna/intent/api/v1/compliancePolicys"
    pid = "aaaaaaaa-0000-0000-0000-{:012d}".format
    qid = "bbbbbbbb-0000-0000-0000-{:012d}".format
    rid = "cccccccc-0000-0000-0000-000000000001"
    api.get("/dna/intent/api/v1/template-programmer/project").respond(json=[])
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[])
    api.get(np).respond(
        json={"response": [{"id": pid(n), "name": f"p{n:02d}", "type": "Switching"} for n in range(20)]}
    )
    api.get(path__regex=rf"^{np}/[0-9a-f-]+/templates$").respond(json={"response": []})
    api.get(path__regex=rf"^{np}/[0-9a-f-]+/siteAssignments$").respond(json={"response": []})
    api.get(cp).respond(
        json={"response": [{"id": qid(n), "name": f"q{n:02d}", "source": "USER"} for n in range(20)]}
    )
    api.get(path__regex=rf"^{cp}/[0-9a-f-]+/rules$").respond(json={"response": [{"id": rid, "name": "r"}]})
    api.get(path__regex=rf"^{cp}/[0-9a-f-]+/rules/[0-9a-f-]+/conditions$").respond(json={"response": []})
    api.get(path__regex=rf"^{cp}/[0-9a-f-]+/siteAssignments$").respond(json={"response": {"siteIds": []}})
    text = await asyncio.wait_for(
        call("catc_export_config", {"sections": ["network_profiles", "compliance_policies"]}), timeout=30
    )
    doc = load_export(text)
    assert len(doc["network_profiles"]) == 20 and len(doc["compliance_policies"]) == 20


async def test_reader_never_exceeds_the_limit() -> None:
    """Nested Reader use (each -> item -> get) stays within PARALLEL and completes."""
    live = peak = 0

    class FakeApp:
        async def get_response(self, path: str, params: Any = None) -> Any:
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.001)
            live -= 1
            return path

    r = config_io.Reader(FakeApp())  # type: ignore[arg-type]

    async def item(n: int) -> list[Any]:
        return list(await asyncio.gather(*(r.get(f"/{n}/{k}") for k in range(5))))

    out = await asyncio.wait_for(r.each({str(n): partial(item, n) for n in range(40)}, "x"), timeout=10)
    assert len(out) == 40 and 1 < peak <= config_io.PARALLEL


def test_core_not_secret_keys_are_left_alone() -> None:
    data = {
        "passwordPolicy": {"minLength": 8, "complexity": "high"},
        "passwordIDStore": "Internal Users",
        "secretStorage": "vault",
        "enableMultiSecret": "true",
        "authPhrase": "x",
    }
    assert config_io.mask_doc(data) == {**data, "authPhrase": "********"}


def test_velocity_set_lines_with_several_directives() -> None:
    body = '#set($password = "a)b") #set($secret=$x) #set( $host = "h" )\n#set($enable_pw = \'y\')'
    assert config_io.redact_template(body).splitlines() == [
        '#set($password = "********") #set($secret=$x) #set( $host = "h" )',  # a variable stays
        '#set($enable_pw = "********")',
    ]


def test_dynamic_rule_values_with_secret_keys_are_masked() -> None:
    doc = load_export(export_text())
    tag = next(t for t in doc["tags"] if t["name"] == "mcp-test-routers")
    rules = [r["rules"] for r in tag["dynamicRules"]]
    assert {"apiToken": "********", "name": "portName", "operation": "ILIKE", "value": "Gi%"} in rules
    assert {"name": "hostname", "operation": "ILIKE", "value": "%lab-r%"} in rules


async def test_site_request_budget_stops_with_a_warning(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_sites_and_settings(api, "mcp.lab")
    monkeypatch.setattr(config_io, "MAX_SITE_REQUESTS", 2 * 9)  # two sites' worth of settings reads
    doc = load_export(await call("catc_export_config", {"sections": ["sites", "settings"]}))
    assert list(doc["settings"]) == ["Global", "Global/mcp-test-lab"]
    (warning,) = doc["meta"]["warnings"]
    assert warning.startswith("settings: 4 sites in scope, read the first 2 by path (18-request budget)")
