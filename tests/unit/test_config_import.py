"""D40: config import. The planner is pure (export + live export -> steps), the applier runs steps
against a fake client, and the tool is checked end to end with a stubbed live export."""

import copy
from typing import Any

import pytest
import respx
from fastmcp import Client

from catc_mcp._core import NotFound
from catc_mcp._core.formatting import MASK
from catc_mcp.server import create_server
from catc_mcp.tools import config_import
from catc_mcp.tools.config_import import IMPORT_ORDER, Applier, Step, plan_import
from catc_mcp.tools.config_io import FORMAT, VERSION, canonical, dump_export

from .conftest import make_settings
from .test_write_tools import run

HEADER = {"format": FORMAT, "version": VERSION, "meta": {"scope": "Global/mcp-d40"}}

DOC: dict[str, Any] = {
    **HEADER,
    "sites": [
        {"path": "Global/mcp-d40", "type": "area"},
        {
            "path": "Global/mcp-d40/Bldg",
            "type": "building",
            "address": "1 Example St",
            "country": "Australia",
            "latitude": -33.8,
            "longitude": 151.2,
        },
        {"path": "Global/mcp-d40/Bldg/F1", "type": "floor", "floorNumber": 1, "rfModel": "Free Space"},
    ],
    "settings": {
        "Global/mcp-d40": {
            "dns": {"dns": {"domainName": "d40.example", "dnsServers": ["192.0.2.53"]}},
            "credentials": {"cliCredentials": "CLI:mcp-d40"},
        }
    },
    "credentials": [{"type": "CLI", "description": "mcp-d40", "username": "admin"}],
    "template_projects": [{"name": "mcp-d40-proj", "description": "d40"}],
    "templates": [
        {
            "project": "mcp-d40-proj",
            "name": "hosts",
            "language": "JINJA",
            "softwareType": "IOS-XE",
            "content": "ip host d40 192.0.2.40",
        },
        {"project": "mcp-d40-other", "name": "banner", "content": "banner motd ^hi^"},
    ],
    "network_profiles": [
        {
            "name": "mcp-d40-sw",
            "type": "Switching",
            "templates": ["mcp-d40-proj/hosts"],
            "sites": ["Global/mcp-d40/Bldg"],
        },
        {"name": "mcp-d40-wlan", "type": "Wireless", "sites": ["Global/mcp-d40"]},
    ],
    "ip_pools": [
        {"name": "mcp-d40-pool", "type": "Generic", "ipv4": {"subnet": "10.40.0.0", "prefixLength": 16}}
    ],
    "ip_reservations": [
        {
            "site": "Global/mcp-d40/Bldg",
            "name": "mcp-d40-lan",
            "type": "LAN",
            "ipv4": {"subnet": "10.40.1.0", "prefixLength": 24, "globalPool": "mcp-d40-pool"},
        }
    ],
    "tags": [{"name": "mcp-d40-tag", "description": "d40"}],
    "ssids": [{"site": "Global/mcp-d40", "ssid": "d40"}],
    "compliance_policies": [{"name": "mcp-d40-policy", "rules": [], "sites": []}],
}
EMPTY_LIVE: dict[str, Any] = {**HEADER, "sites": [], "settings": {}, "credentials": []}
SECRETS = {"CLI:mcp-d40": {"password"}}


def doc(**overrides: Any) -> dict[str, Any]:
    out = copy.deepcopy(DOC)
    out.update(overrides)
    return canonical(out)


def by_action(plan: config_import.ImportPlan) -> list[tuple[str, str, str]]:
    return [(s.section, s.action, s.item) for s in plan.steps]


def test_empty_target_creates_everything_in_dependency_order() -> None:
    plan = plan_import(doc(), EMPTY_LIVE, secrets=SECRETS)
    assert plan.blockers == []
    steps = by_action(plan)
    assert steps[:3] == [
        ("sites", "create", "Global/mcp-d40"),
        ("sites", "create", "Global/mcp-d40/Bldg"),
        ("sites", "create", "Global/mcp-d40/Bldg/F1"),
    ]
    # The export's order of sections never matters: steps follow IMPORT_ORDER.
    order = [IMPORT_ORDER.index(s[0]) for s in steps]
    assert order == sorted(order)
    assert ("credentials", "create", "CLI:mcp-d40") in steps
    assert ("settings", "update", "Global/mcp-d40 dns") in steps
    assert ("settings", "update", "Global/mcp-d40 credentials") in steps
    assert ("ip_reservations", "create", "Global/mcp-d40/Bldg:mcp-d40-lan") in steps
    # A project named only by a template is created just before it.
    i = steps.index(("template_projects", "create", "mcp-d40-other"))
    assert steps[i + 1] == ("templates", "create", "mcp-d40-other/banner")
    assert ("network_profiles", "create", "mcp-d40-sw") in steps
    assert ("network_profiles", "attach", "mcp-d40-sw") in steps
    assert ("network_profiles", "assign", "mcp-d40-sw") in steps
    wlan = next(s for s in plan.steps if s.item == "mcp-d40-wlan")
    assert wlan.action == "skip" and "UI" in str(wlan.note)
    assert set(plan.not_imported) == {"ssids", "compliance_policies"}
    assert plan.summary()["sites"] == {"create": 3}


def test_identical_target_changes_nothing() -> None:
    live = doc()
    plan = plan_import(doc(), live, secrets={})
    assert plan.blockers == [] and plan.changes == []
    assert plan.unchanged["sites"] == 3 and plan.unchanged["templates"] == 2
    assert plan.unchanged["network_profiles"] == 2


def test_existing_items_update_sites_and_settings_but_never_overwrite_the_rest() -> None:
    live = doc()
    live["sites"][1]["address"] = "2 Old Rd"
    live["settings"]["Global/mcp-d40"]["dns"]["dns"]["domainName"] = "old.example"
    next(t for t in live["templates"] if t["name"] == "hosts")["content"] = "ip host d40 192.0.2.99"
    live["ip_pools"][0]["ipv4"]["prefixLength"] = 20
    live["credentials"][0]["username"] = "other"
    live["network_profiles"][0]["sites"] = ["Global/mcp-d40"]  # a parent already covers Bldg
    plan = plan_import(doc(), live, secrets={})
    rows = {(s.section, s.item): s for s in plan.steps}
    site = rows[("sites", "Global/mcp-d40/Bldg")]
    assert site.action == "update" and site.changes == [
        {"field": "address", "before": "2 Old Rd", "after": "1 Example St"}
    ]
    dns = rows[("settings", "Global/mcp-d40 dns")]
    assert dns.action == "update" and dns.payload["body"]["dns"]["domainName"] == "d40.example"
    assert rows[("templates", "mcp-d40-proj/hosts")].action == "skip"
    assert rows[("ip_pools", "mcp-d40-pool")].action == "skip"
    assert rows[("credentials", "CLI:mcp-d40")].action == "skip"
    assert ("network_profiles", "mcp-d40-sw") not in rows  # covered by the parent assignment
    assert all(s.action in ("update", "skip") for s in plan.steps)


def test_new_credential_needs_its_secrets() -> None:
    plan = plan_import(doc(), EMPTY_LIVE, secrets={})
    assert any("CLI:mcp-d40 is new and needs password" in b for b in plan.blockers)
    snmp = {"type": "SNMPV3", "description": "v3", "username": "u", "snmpMode": "AUTHPRIV", "authType": "SHA"}
    plan = plan_import(
        doc(credentials=[snmp], settings={}), EMPTY_LIVE, secrets={"SNMPV3:v3": {"authPassword"}}
    )
    assert any("privacyPassword" in b for b in plan.blockers)
    plan = plan_import(doc(), EMPTY_LIVE, secrets={**SECRETS, "CLI:nope": {"password"}})
    assert any("doesn't create: CLI:nope" in b for b in plan.blockers)


def test_masked_values_block_their_items() -> None:
    settings = {"Global/mcp-d40": {"aaa": {"aaaNetwork": {"serverType": "ISE", "sharedSecret": MASK}}}}
    plan = plan_import(doc(settings=settings), EMPTY_LIVE, secrets=SECRETS)
    assert any("aaa" in b and "aaaNetwork.sharedSecret" in b and MASK in b for b in plan.blockers)
    templates = [{"project": "mcp-d40-proj", "name": "secret", "content": f"enable secret {MASK}"}]
    plan = plan_import(doc(templates=templates, network_profiles=[]), EMPTY_LIVE, secrets=SECRETS)
    assert any("push the mask" in b for b in plan.blockers)
    creds = [{"type": "CLI", "description": "mcp-d40", "username": MASK}]
    plan = plan_import(doc(credentials=creds), EMPTY_LIVE, secrets=SECRETS)
    assert any("credentials CLI:mcp-d40: username" in b for b in plan.blockers)


def test_references_to_missing_objects_block() -> None:
    d = doc(
        sites=[
            {"path": "Global/mcp-d40", "type": "area"},
            {"path": "Global/nowhere/Bldg", "type": "building", "country": "Australia", "address": "x"},
        ],
        settings={
            "Global/mcp-d40": {"credentials": {"cliCredentials": "CLI:ghost"}},
            "Global/elsewhere": {"dns": {"dns": {"domainName": "x"}}},
        },
        credentials=[],
    )
    d["ip_reservations"][0]["ipv4"]["globalPool"] = "ghost-pool"
    d["network_profiles"][0]["templates"] = ["ghost/tpl"]
    plan = plan_import(d, EMPTY_LIVE, secrets={})
    text = "\n".join(plan.blockers)
    assert "parent Global/nowhere is neither here nor in the export" in text
    assert "credential CLI:ghost" in text
    assert "global pool ghost-pool" in text
    assert "template ghost/tpl" in text
    assert "Settings for Global/elsewhere: the site is neither here nor in the export" in text


def test_building_needs_country_and_location() -> None:
    d = doc(sites=[{"path": "Global/mcp-d40", "type": "building"}], settings={})
    plan = plan_import(d, EMPTY_LIVE, secrets=SECRETS)
    assert any("needs a country" in b for b in plan.blockers)


def test_site_type_mismatch_and_live_read_errors_block() -> None:
    live = doc()
    live["sites"][0]["type"] = "building"
    plan = plan_import(doc(), live, secrets={})
    assert any("is a building here, a area in the export" in b for b in plan.blockers)
    live = {**EMPTY_LIVE, "meta": {"errors": {"templates": "403 Forbidden"}}}
    plan = plan_import(doc(), live, secrets=SECRETS)
    assert plan.blockers == ["Can't read the live templates to compare with: 403 Forbidden"]


def test_sections_filter_and_uncommitted_templates() -> None:
    plan = plan_import(doc(), EMPTY_LIVE, secrets={}, sections=["tags"])
    assert by_action(plan) == [("tags", "create", "mcp-d40-tag")] and plan.not_imported == {}
    plan = plan_import(doc(), EMPTY_LIVE, secrets=SECRETS, commit_templates=False)
    assert all(s.note is None for s in plan.steps if s.section == "templates")


def test_live_sections_include_what_items_refer_to() -> None:
    assert config_import.live_sections(["settings"]) == ["credentials", "settings", "sites"]
    assert "templates" in config_import.live_sections(["network_profiles"])
    assert "ip_pools" in config_import.live_sections(["ip_reservations"])


# --- applier -----------------------------------------------------------------------------------------


class FakeApp:
    """Records run_job calls; a path in `fail` raises once it is reached."""

    def __init__(self, fail: str | None = None) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.fail = fail
        self.n = 0

    async def run_job(self, method: str, path: str, body: Any = None, **_: Any) -> dict[str, Any]:
        if self.fail and self.fail in path:
            raise RuntimeError(f"boom at {path}")
        self.calls.append((method, path, body))
        self.n += 1
        return {"data": f"00000000-0000-0000-0000-{self.n:012d}"}


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve_site(_app: Any, path: str) -> dict[str, Any]:
        if path.lower() in ("global", "global/existing"):
            return {"id": f"site-{path.lower()}", "nameHierarchy": path}
        raise NotFound(path)

    async def creds(_app: Any) -> list[dict[str, Any]]:
        return [{"id": "cred-old", "type": "CLI", "description": "old"}]

    monkeypatch.setattr(config_import, "resolve_site", resolve_site)
    monkeypatch.setattr(config_import, "all_credentials", creds)


async def test_applier_builds_bodies_and_reuses_new_ids(lookups: None) -> None:
    app = FakeApp()
    steps = [
        Step("sites", "create", "Global/mcp-d40", {"path": "Global/mcp-d40", "type": "area", "fields": {}}),
        Step(
            "sites",
            "create",
            "Global/mcp-d40/F",
            {"path": "Global/mcp-d40/F", "type": "floor", "fields": {"floorNumber": 2}},
        ),
        Step(
            "credentials",
            "create",
            "SNMPV3:v3",
            {
                "type": "SNMPV3",
                "description": "v3",
                "username": "u",
                "snmpMode": "AUTHNOPRIV",
                "authType": "SHA",
            },
        ),
        Step(
            "settings",
            "update",
            "Global/mcp-d40 credentials",
            {"site": "Global/mcp-d40", "category": "credentials", "body": {"cliCredentials": "CLI:old"}},
        ),
    ]
    secrets = {"SNMPV3:v3": {"authPassword": "s3cret", "privacyPassword": "ignored"}}
    out = await Applier(app, None, secrets).run(steps, True)  # type: ignore[arg-type]
    assert out["status"] == "applied" and len(out["applied"]) == 4
    area, floor, cred, settings = app.calls
    assert area == ("POST", "/dna/intent/api/v1/areas", {"name": "mcp-d40", "parentId": "site-global"})
    # The area's new id (from its create task) is the floor's parent: cached under its path.
    assert floor[2]["parentId"] == "00000000-0000-0000-0000-000000000001"
    assert floor[2]["floorNumber"] == 2 and floor[2]["rfModel"] == "Cubes And Walled Offices"
    assert cred[2] == {
        "type": "SNMPV3",
        "description": "v3",
        "username": "u",
        "mode": "AUTHNOPRIV",
        "authType": "SHA",
        "authPassword": "s3cret",
    }
    assert settings[1] == "/dna/intent/api/v1/sites/00000000-0000-0000-0000-000000000001/deviceCredentials"
    assert settings[2] == {"cliCredentialsId": {"credentialsId": "cred-old"}}


async def test_applier_stops_at_the_first_failure(lookups: None) -> None:
    app = FakeApp(fail="/dna/intent/api/v1/tag")
    steps = [
        Step("tags", "skip", "same"),
        Step(
            "ip_pools",
            "create",
            "p",
            {"name": "p", "type": "Generic", "ipv4": {"subnet": "10.0.0.0", "prefixLength": 8}},
        ),
        Step("tags", "create", "t1", {"name": "t1"}),
        Step("tags", "create", "t2", {"name": "t2"}),
    ]
    out = await Applier(app, None, {}).run(steps, True)  # type: ignore[arg-type]
    assert out["status"] == "stopped"
    assert [r["item"] for r in out["applied"]] == ["p"]
    assert out["failed"]["item"] == "t1" and "boom" in out["failed"]["error"]
    assert [r["item"] for r in out["not_applied"]] == ["t2"]
    assert app.calls[0][2] == {
        "name": "p",
        "poolType": "Generic",
        "addressSpace": {"subnet": "10.0.0.0", "prefixLength": 8},
    }


# --- tool --------------------------------------------------------------------------------------------


async def tool_flow(
    args: dict[str, Any], live: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, Any]:
    async def fake_live(_app: Any, _scope: str, _wanted: list[str]) -> dict[str, Any]:
        return copy.deepcopy(live)

    applied: list[list[Step]] = []

    async def fake_run(self: Applier, steps: list[Step], commit: bool) -> dict[str, Any]:
        applied.append(steps)
        return {
            "status": "applied",
            "applied": [s.row() for s in steps if s.action != "skip"],
            "commit": commit,
        }

    monkeypatch.setattr(config_import, "live_export", fake_live)
    monkeypatch.setattr(Applier, "run", fake_run)
    settings = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(settings)) as c:
        preview = await run(c, "catc_import_config", args)
        if preview["status"] != "preview":
            return preview, None
        done = await run(c, "catc_import_config", {**args, "confirm": preview["confirm"]})
    return preview, done


async def test_tool_preview_and_apply(api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    text = dump_export(doc())
    args = {"export": text, "secrets": {"CLI:mcp-d40": {"password": "pw"}}}
    preview, done = await tool_flow(args, EMPTY_LIVE, monkeypatch)
    assert preview["status"] == "preview", preview
    assert preview["preview"]["summary"]["sites"] == {"create": 3}
    assert preview["preview"]["not_imported"]["ssids"].startswith("1 item(s)")
    assert "pw" not in str(preview)
    assert done["result"]["status"] == "applied"


async def test_tool_blocks_without_secrets_and_when_nothing_changes(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = dump_export(doc())
    preview, _ = await tool_flow({"export": text}, EMPTY_LIVE, monkeypatch)
    assert preview["status"] == "blocked" and any("needs password" in b for b in preview["blockers"])
    preview, _ = await tool_flow({"export": text}, doc(), monkeypatch)
    assert preview["status"] == "blocked" and "Nothing to import" in preview["blockers"][0]


async def test_tool_refuses_masked_secret_values(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = dump_export(doc())
    with pytest.raises(Exception, match="real secret"):
        await tool_flow(
            {"export": text, "secrets": {"CLI:mcp-d40": {"password": MASK}}}, EMPTY_LIVE, monkeypatch
        )


async def test_tool_is_dangerous_tier(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_import_config" not in names


# --- review fixes ------------------------------------------------------------------------------------


def test_incomplete_live_reads_block() -> None:
    live = {**EMPTY_LIVE, "meta": {"warnings": ["settings Global/mcp-d40 dns: 429 Too Many Requests"]}}
    plan = plan_import(doc(), live, secrets=SECRETS)
    assert plan.blockers == [
        "The live read was incomplete, so the plan could be wrong: "
        "settings Global/mcp-d40 dns: 429 Too Many Requests"
    ]
    # A warning about a section that isn't imported doesn't block.
    plan = plan_import(doc(), live, secrets=SECRETS, sections=["tags"])
    assert plan.blockers == []


def test_settings_merge_over_what_is_set() -> None:
    live = doc()
    live["credentials"].append({"type": "HTTP_READ", "description": "keep"})
    live["settings"]["Global/mcp-d40"]["credentials"] = {
        "cliCredentials": "CLI:mcp-d40",
        "httpReadCredentials": "HTTP_READ:keep",
    }
    live["settings"]["Global/mcp-d40"]["dns"]["dns"]["dnsServers"] = ["192.0.2.1"]
    live["settings"]["Global/mcp-d40"]["dns"]["dns"]["extra"] = "stays"
    plan = plan_import(doc(), live, secrets={})
    rows = {s.item: s for s in plan.steps if s.section == "settings"}
    # The export's credential slot equals what is set; the extra slot is kept, so nothing changes.
    assert "Global/mcp-d40 credentials" not in rows
    dns = rows["Global/mcp-d40 dns"].payload["body"]["dns"]
    assert dns == {"domainName": "d40.example", "dnsServers": ["192.0.2.53"], "extra": "stays"}


def test_dual_stack_global_pool_blocks() -> None:
    pools = [
        {"name": "ds", "type": "Generic", "ipv4": {"subnet": "10.0.0.0"}, "ipv6": {"subnet": "2001:db8::"}}
    ]
    plan = plan_import(doc(ip_pools=pools, ip_reservations=[]), EMPTY_LIVE, secrets=SECRETS)
    assert any("dual-stack" in b for b in plan.blockers)


def test_settings_hint_names_the_missing_section() -> None:
    plan = plan_import(doc(), EMPTY_LIVE, secrets={}, sections=["sites", "settings"])
    assert any("add 'credentials' to `sections`" in b for b in plan.blockers)


def test_secret_field_names_are_normalised_and_checked() -> None:
    from pydantic import SecretStr

    out = config_import._secret_values(
        {"CLI:x": {"PASSWORD": SecretStr("pw"), "enablepassword": SecretStr("en")}}
    )
    assert out == {"CLI:x": {"password": "pw", "enablePassword": "en"}}
    with pytest.raises(Exception, match="unknown field 'pass'"):
        config_import._secret_values({"CLI:x": {"pass": SecretStr("pw")}})


async def test_failure_text_masks_secret_values(lookups: None) -> None:
    class Leaky(FakeApp):
        async def run_job(self, method: str, path: str, body: Any = None, **_: Any) -> dict[str, Any]:
            raise RuntimeError(f"rejected body {body}")

    steps = [Step("credentials", "create", "CLI:c", {"type": "CLI", "description": "c", "username": "u"})]
    out = await Applier(Leaky(), None, {"CLI:c": {"password": "hunter2-secret"}}).run(steps, True)  # type: ignore[arg-type]
    assert out["status"] == "stopped"
    assert "hunter2-secret" not in out["failed"]["error"] and MASK in out["failed"]["error"]
