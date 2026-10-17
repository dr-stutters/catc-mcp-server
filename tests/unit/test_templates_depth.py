"""D36 templates depth: versions, diff, export/import, clone, usage, drift (respx-mocked; payloads
recorded from the 3.2.2 lab in tests/fixtures/templates_d36.json: project mcp-d36-src with
mcp-d36-hosts (v1, v2; v1 deployed to r1) and mcp-d36-vars (v1 plus an uncommitted draft))."""

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp._core import InvalidRequest
from catc_mcp.tools.templates import (
    mask_template_lines,
    parse_templates_export,
    redact_template,
    serialize_templates,
    template_diff,
)

from .test_dangerous_tools import flow
from .test_read_tools import DEV_ID, call, mock_device_lookup
from .test_write_tools import preview_then_apply, task_ok

FIX = json.loads((Path(__file__).parent.parent / "fixtures" / "templates_d36.json").read_text())
TP = "/dna/intent/api/v1/template-programmer"
HOSTS = next(t for t in FIX["templates"] if t["name"] == "mcp-d36-hosts")
VARS = next(t for t in FIX["templates"] if t["name"] == "mcp-d36-vars")
R1 = "f64d8d9f-30b2-48f6-a6fe-73d2aaed0fa3"


def mock_lab(api: respx.MockRouter, templates: list[dict[str, Any]] | None = None) -> None:
    """The recorded mcp-d36-src project: template list, full records, versions, deploy task + status."""
    api.get(f"{TP}/template").respond(json=FIX["templates"] if templates is None else templates)
    api.get(f"{TP}/project").respond(json=FIX["project"])
    for tid, full in FIX["full"].items():
        api.get(f"{TP}/template/{tid}").respond(json=full)
        api.get(f"/dna/intent/api/v1/templates/{tid}/versions").respond(json=FIX["versions"][tid])
        for v in FIX["versions"][tid]["response"]:
            api.get(f"{TP}/template/{v['versionId']}").respond(
                json={**full, "templateContent": v["templateContent"]}
            )
        api.get(f"/dna/intent/api/v1/templates/{tid}/networkProfilesForSites").respond(json={"response": []})
    api.get("/dna/intent/api/v1/task").respond(json=FIX["tasks"])
    dep = FIX["deploy_status"]["deploymentId"]
    api.get(f"{TP}/template/deploy/status/{dep}").respond(json=FIX["deploy_status"])


def full_with_versions(t: dict[str, Any]) -> dict[str, Any]:
    tid = t["templateId"]
    comments = {v["id"]: v.get("versionComment") for v in t["versionsInfo"]}
    versions = [
        {**v, "versionComment": comments.get(v["versionId"])} for v in FIX["versions"][tid]["response"]
    ]
    return {**FIX["full"][tid], "versions": versions}


def export_doc(**kw: Any) -> dict[str, Any]:
    return serialize_templates(
        [{"name": "mcp-d36-src", "description": "D36"}],
        [full_with_versions(VARS), full_with_versions(HOSTS)],
        **kw,
    )


# --- pure functions ------------------------------------------------------------------------------


def test_serialize_templates_is_stable_and_keeps_versions() -> None:
    doc = export_doc(exported_at="2026-10-17T00:00:00Z")
    assert doc["format"] == "catc-mcp-templates" and doc["format_version"] == 1
    (proj,) = doc["projects"]
    assert [t["name"] for t in proj["templates"]] == ["mcp-d36-hosts", "mcp-d36-vars"]  # sorted
    hosts, tvars = proj["templates"]
    assert [(v["version"], v["comment"]) for v in hosts["versions"]] == [
        (1, "v1: host a"),
        (2, "v2: add host b"),
    ]
    assert hosts["versions"][0]["content"] == "ip host mcp-d36-a 192.0.2.61"
    assert tvars["content"].endswith("! d36 draft line") and len(tvars["versions"]) == 1
    assert [p["parameterName"] for p in tvars["params"]] == ["host_name", "host_ip"]
    assert "id" not in json.dumps(tvars["params"])
    # Same input in another order -> the same document.
    again = serialize_templates(
        [{"name": "mcp-d36-src", "description": "D36"}],
        [full_with_versions(HOSTS), full_with_versions(VARS)],
        exported_at="2026-10-17T00:00:00Z",
    )
    assert json.dumps(again) == json.dumps(doc)
    assert export_doc(versions="latest")["projects"][0]["templates"][0]["versions"][0]["version"] == 2
    assert export_doc(versions="none")["projects"][0]["templates"][0]["versions"] == []


def test_serialize_templates_masks_secret_lines() -> None:
    t = full_with_versions(HOSTS)
    t["templateContent"] = "username admin secret 9 $9$abc\nip host x 192.0.2.1"
    next(v for v in t["versions"] if v["version"] == 1)["templateContent"] = "enable secret s3cr3t"
    tpl = serialize_templates([], [t])["projects"][0]["templates"][0]
    assert "$9$abc" not in json.dumps(tpl) and "s3cr3t" not in json.dumps(tpl)
    assert tpl["masked_lines"] == ["draft:1", "v1:1"]
    raw = serialize_templates([], [t], redact=False)["projects"][0]["templates"][0]
    assert "$9$abc" in raw["content"] and "masked_lines" not in raw


def test_parse_templates_export_validates() -> None:
    doc = export_doc()
    assert [t["name"] for _, t in parse_templates_export(json.dumps(doc))] == [
        "mcp-d36-hosts",
        "mcp-d36-vars",
    ]
    for bad, why in [
        ({"format": "other"}, "Not a template export"),
        ({**doc, "format_version": 99}, "newer"),
        ({**doc, "projects": [{"name": "p", "templates": [{"content": "x"}]}]}, "no name"),
        ({**doc, "projects": []}, "no templates"),
        ("{nope", "not valid JSON"),
    ]:
        with pytest.raises(InvalidRequest, match=why):
            parse_templates_export(bad)


def test_template_diff() -> None:
    d = template_diff("a\nb", "a\nc\nd", "v1", "v2")
    assert (d["added"], d["removed"], d["identical"]) == (2, 1, False)
    assert d["diff"].startswith("--- v1\n+++ v2")
    assert template_diff("x", "x", "a", "b")["identical"] is True


# --- read tools ----------------------------------------------------------------------------------


async def test_list_template_versions(api: respx.MockRouter) -> None:
    mock_lab(api)
    out = await call(
        "catc_list_template_versions", {"template": "mcp-d36-src/mcp-d36-hosts", "response_format": "json"}
    )
    assert [r["version"] for r in out["results"]] == [2, 1]  # newest first
    assert out["results"][0]["changes"] == "+1 -0" and out["results"][0]["comment"] == "v2: add host b"
    assert out["uncommitted_changes"] is False
    out = await call(
        "catc_list_template_versions", {"template": "mcp-d36-src/mcp-d36-vars", "response_format": "json"}
    )
    assert out["uncommitted_changes"] is True


async def test_diff_template_versions(api: respx.MockRouter) -> None:
    mock_lab(api)
    out = await call("catc_diff_template_versions", {"template": "mcp-d36-src/mcp-d36-hosts"})
    assert (out["from"], out["to"], out["added"], out["removed"]) == ("version 1", "version 2", 1, 0)
    assert "+ip host mcp-d36-b 192.0.2.62" in out["diff"]
    out = await call("catc_diff_template_versions", {"template": "mcp-d36-src/mcp-d36-vars", "draft": True})
    assert out["to"] == "draft (uncommitted)" and "+! d36 draft line" in out["diff"]
    with pytest.raises(ToolError, match="No version 7"):
        await call("catc_diff_template_versions", {"template": "mcp-d36-src/mcp-d36-hosts", "to_version": 7})


async def test_export_templates_project(api: respx.MockRouter) -> None:
    mock_lab(api)
    doc = await call("catc_export_templates", {"project": "mcp-d36-src"})
    assert doc["source"] == {"catalyst_center": "3.2.2-75131"} and doc["redacted"] is True
    names = [(p["name"], t["name"], len(t["versions"])) for p, t in parse_templates_export(doc)]
    assert names == [("mcp-d36-src", "mcp-d36-hosts", 2), ("mcp-d36-src", "mcp-d36-vars", 1)]
    one = await call("catc_export_templates", {"template": "mcp-d36-src/mcp-d36-vars", "versions": "none"})
    assert [t["name"] for t in one["projects"][0]["templates"]] == ["mcp-d36-vars"]
    with pytest.raises(ToolError, match="exactly one"):
        await call("catc_export_templates", {})


async def test_template_drift_flags_old_version(api: respx.MockRouter) -> None:
    mock_lab(api)
    tasks = api.get("/dna/intent/api/v1/task").respond(json=FIX["tasks"])
    out = await call("catc_template_drift", {"project": "mcp-d36-src", "response_format": "json"})
    (row,) = out["results"]
    assert (row["device"], row["deployed"], row["latest"], row["state"]) == ("r1.mcp.lab", 1, 2, "behind")
    assert out["drifted"] == 1 and out["deployments_scanned"] == 1
    # /task pages from 0 (offset=1 would skip the newest task, seen live on 3.2.2).
    assert tasks.calls.last.request.url.params["offset"] == "0"
    # After v1 is the latest (e.g. v2 never committed), the same deployment is current.
    hosts_v1 = {**HOSTS, "versionsInfo": [v for v in HOSTS["versionsInfo"] if v["version"] == "1"]}
    api.get(f"{TP}/template").respond(json=[hosts_v1, VARS])
    out = await call("catc_template_drift", {"drifted_only": True, "response_format": "json"})
    assert out["results"] == [] and out["drifted"] == 0


async def test_template_drift_failed_and_retried(api: respx.MockRouter) -> None:
    mock_lab(api)
    dep2 = "11111111-0000-0000-0000-00000000dead"
    tasks = copy.deepcopy(FIX["tasks"])
    tasks["response"].append(
        {**tasks["response"][0], "progress": f"Template Deployemnt Id: {dep2}", "startTime": 1792300000000}
    )
    api.get("/dna/intent/api/v1/task").respond(json=tasks)
    failed = copy.deepcopy(FIX["deploy_status"])
    v2_id = next(v["id"] for v in HOSTS["versionsInfo"] if v["version"] == "2")
    failed.update(deploymentId=dep2, templateId=v2_id, templateVersion="2")
    failed["devices"][0]["status"] = "FAILURE"
    api.get(f"{TP}/template/deploy/status/{dep2}").respond(json=failed)
    out = await call(
        "catc_template_drift", {"template": "mcp-d36-src/mcp-d36-hosts", "response_format": "json"}
    )
    (row,) = out["results"]
    assert row["state"] == "behind" and row["deployed"] == 1  # the v2 attempt failed
    assert row["last_attempt"].startswith("v2 FAILURE")


async def test_template_usage(api: respx.MockRouter) -> None:
    mock_lab(api)
    out = await call("catc_template_usage", {"template": "mcp-d36-src/mcp-d36-hosts"})
    assert out["latest_version"] == 2 and out["uncommitted_changes"] is False
    assert out["profiles"] == [] and out["drifted_devices"] == 1
    (dev,) = out["devices"]
    assert (dev["device"], dev["deviceId"], dev["deployed_version"], dev["state"]) == (
        "r1.mcp.lab",
        R1,
        1,
        "behind",
    )
    out = await call("catc_template_usage", {"template": "mcp-d36-src/mcp-d36-vars"})
    assert out["uncommitted_changes"] is True and out["devices"] == []


# --- writes --------------------------------------------------------------------------------------


def mock_import_target(api: respx.MockRouter, existing: list[dict[str, Any]]) -> dict[str, Any]:
    """An empty appliance (no project 'mcp-d36-copy') that accepts creates, updates and commits."""
    calls: dict[str, Any] = {"created": [], "puts": [], "commits": []}
    api.get(f"{TP}/project").respond(json=[])
    api.get(f"{TP}/template").respond(json=existing)
    api.post(f"{TP}/project").respond(202, json={"response": {"taskId": "tproj"}})
    task_ok(api, "tproj", data="pppppppp-0000-0000-0000-000000000001")
    content: dict[str, str] = {}

    def create(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        tid = f"tttttttt-0000-0000-0000-00000000000{len(calls['created']) + 1}"
        calls["created"].append(body)
        content[tid] = body["templateContent"]
        api.get(f"/dna/intent/api/v1/task/c-{tid}").respond(
            json={"response": {"data": tid, "progress": "created", "endTime": 1}}
        )
        api.get(f"{TP}/template/{tid}").mock(
            side_effect=lambda _r, tid=tid: httpx.Response(
                200,
                json={
                    "id": tid,
                    "name": body["name"],
                    "templateContent": content[tid],
                    "validationErrors": {},
                },
            )
        )
        return httpx.Response(202, json={"response": {"taskId": f"c-{tid}"}})

    def put(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls["puts"].append(body)
        content[body["id"]] = body["templateContent"]
        return httpx.Response(202, json={"response": {"taskId": "tput"}})

    def commit(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls["commits"].append((body["templateId"], body["comments"], content[body["templateId"]]))
        return httpx.Response(202, json={"response": {"taskId": "tcommit"}})

    api.post(url__regex=rf"{TP}/project/[^/]+/template$").mock(side_effect=create)
    api.put(f"{TP}/template").mock(side_effect=put)
    api.post(f"{TP}/template/version").mock(side_effect=commit)
    task_ok(api, "tput")
    task_ok(api, "tcommit")
    return calls


async def test_import_templates_replays_versions(api: respx.MockRouter) -> None:
    calls = mock_import_target(api, [])
    args = {"export": export_doc(), "project": "mcp-d36-copy"}
    preview, done = await preview_then_apply("catc_import_templates", args)
    assert preview["preview"]["new_projects"] == ["mcp-d36-copy"]
    rows = {r["template"]: r for r in preview["preview"]["templates"]}
    assert rows["mcp-d36-copy/mcp-d36-hosts"]["versions_to_commit"] == [1, 2]
    assert rows["mcp-d36-copy/mcp-d36-vars"]["draft_after"] is True
    imported = {r["template"]: r for r in done["result"]["imported"]}
    assert imported["mcp-d36-copy/mcp-d36-hosts"]["versions_committed"] == 2
    assert imported["mcp-d36-copy/mcp-d36-vars"]["uncommitted_draft"] is True
    hosts_id = imported["mcp-d36-copy/mcp-d36-hosts"]["template_id"]
    assert [(c[1], c[2]) for c in calls["commits"] if c[0] == hosts_id] == [
        ("v1: host a", "ip host mcp-d36-a 192.0.2.61"),
        ("v2: add host b", "ip host mcp-d36-a 192.0.2.61\nip host mcp-d36-b 192.0.2.62"),
    ]
    vars_create = next(c for c in calls["created"] if c["name"] == "mcp-d36-vars")
    assert vars_create["projectName"] == "mcp-d36-copy"
    assert [p["parameterName"] for p in vars_create["templateParams"]] == ["host_name", "host_ip"]
    # The draft goes on top, with the variables too.
    assert calls["puts"][-1]["templateContent"].endswith("! d36 draft line")
    assert [p["parameterName"] for p in calls["puts"][-1]["templateParams"]] == ["host_name", "host_ip"]


async def test_import_templates_as_copy_and_blockers(api: respx.MockRouter) -> None:
    mock_import_target(api, [])
    api.get(f"{TP}/project").respond(json=FIX["project"])
    api.get(f"{TP}/template").respond(json=FIX["templates"])
    preview, _ = await preview_then_apply("catc_import_templates", {"export": export_doc()})
    assert preview["status"] == "blocked" and "already exists" in preview["blockers"][0]
    preview, done = await preview_then_apply(
        "catc_import_templates",
        {"export": export_doc(), "templates": ["mcp-d36-hosts"], "name": "mcp-d36-hosts-copy"},
    )
    assert preview["preview"]["templates"][0]["template"] == "mcp-d36-src/mcp-d36-hosts-copy"
    assert done["result"]["imported"][0]["versions_committed"] == 2
    with pytest.raises(ToolError, match="renames one template"):
        await preview_then_apply("catc_import_templates", {"export": export_doc(), "name": "x"})
    with pytest.raises(ToolError, match="Not in the export"):
        await preview_then_apply("catc_import_templates", {"export": export_doc(), "templates": ["nope"]})
    secret = full_with_versions(HOSTS)
    secret["templateContent"] = "enable secret s3cr3t"
    doc = serialize_templates([{"name": "mcp-d36-src"}], [secret])
    preview, _ = await preview_then_apply("catc_import_templates", {"export": doc, "project": "mcp-d36-new"})
    assert preview["status"] == "blocked" and any("push the mask" in b for b in preview["blockers"])


async def test_clone_template(api: respx.MockRouter) -> None:
    mock_lab(api)
    hid, pid = HOSTS["templateId"], HOSTS["projectId"]
    api.get(f"{TP}/project/{pid}").respond(json=FIX["project"][0])
    post = api.post(f"{TP}/clone/name/mcp-d36-hosts-clone/project/{pid}/template/{hid}").respond(
        202, json={"response": {"taskId": "tclone"}}
    )
    task_ok(api, "tclone", data="cccccccc-0000-0000-0000-000000000001")
    preview, done = await preview_then_apply(
        "catc_clone_template", {"template": "mcp-d36-src/mcp-d36-hosts", "name": "mcp-d36-hosts-clone"}
    )
    assert preview["preview"]["source_versions"] == 2 and post.call_count == 1
    assert done["result"] == {
        "template_id": "cccccccc-0000-0000-0000-000000000001",
        "name": "mcp-d36-src/mcp-d36-hosts-clone",
        "committed": False,
    }
    preview, _ = await preview_then_apply(
        "catc_clone_template", {"template": "mcp-d36-src/mcp-d36-hosts", "name": "mcp-d36-vars"}
    )
    assert preview["status"] == "blocked"


async def test_deploy_template_old_version(api: respx.MockRouter) -> None:
    tpl = {
        **json.loads((Path(__file__).parent.parent / "fixtures" / "templates.json").read_text())[0],
        "versionsInfo": [
            {"version": "1", "id": "vvvvvvvv-0000-0000-0000-000000000001", "versionComment": "first"},
            {"version": "2", "id": "vvvvvvvv-0000-0000-0000-000000000002"},
        ],
    }
    api.get(f"{TP}/template").respond(json=[tpl])
    mock_device_lookup(api)
    prev = api.put(f"{TP}/template/preview").respond(json={"cliPreview": "aaa new-model"})
    post = api.post("/dna/intent/api/v2/template-programmer/template/deploy").respond(
        202, json={"response": {"taskId": "td"}}
    )
    task_ok(api, "td", progress="no deployment id")
    args = {"template": tpl["templateId"], "devices": ["edge-sw1"], "version": 1}
    preview, done = await flow("catc_deploy_template", args)
    assert preview["preview"]["template_version"]["version"] == "1"
    assert preview["preview"]["template_version"]["comment"] == "first"
    assert json.loads(prev.calls.last.request.content)["templateId"] == "vvvvvvvv-0000-0000-0000-000000000001"
    body = json.loads(post.calls.last.request.content)
    assert body["templateId"] == "vvvvvvvv-0000-0000-0000-000000000001" and done["status"] == "applied"
    assert body["targetInfo"][0]["id"] == DEV_ID
    preview, _ = await flow("catc_deploy_template", {**args, "version": 9})
    assert preview["status"] == "blocked" and "no committed version 9" in preview["blockers"][0]


def test_serialize_masks_sensitive_variables_but_not_variable_references() -> None:
    t = full_with_versions(VARS)
    t["templateContent"] = (
        "username admin secret {{ pw }}\nenable secret $enable\nsnmp-server community s3cr3t RO\n"
    )
    t["templateParams"] = [
        {"parameterName": "pw", "dataType": "STRING", "sensitiveField": True, "defaultValue": "Hunter2"},
        {"parameterName": "enable", "dataType": "STRING", "description": "enable secret Hunter3"},
    ]
    tpl = serialize_templates([], [t])["projects"][0]["templates"][0]
    text = json.dumps(tpl)
    assert "Hunter2" not in text and "Hunter3" not in text and "s3cr3t" not in text
    assert tpl["content"].startswith("username admin secret {{ pw }}\nenable secret $enable\n")
    assert tpl["content"].endswith("\n")  # line endings kept
    assert tpl["masked_lines"] == ["draft:3", "param:pw", "param:enable"]


async def test_import_blocks_only_unfixed_masks(api: respx.MockRouter) -> None:
    mock_import_target(api, [])
    t = full_with_versions(HOSTS)
    t["templateContent"] = "ip host a 192.0.2.1\nusername admin secret {{ pw }}\nenable secret s3cr3t"
    doc = serialize_templates([{"name": "p"}], [t])
    tpl = doc["projects"][0]["templates"][0]
    assert tpl["masked_lines"] == ["draft:3"]
    preview, _ = await preview_then_apply("catc_import_templates", {"export": doc, "project": "mcp-d36-new"})
    assert preview["status"] == "blocked" and "draft:3" in preview["blockers"][0]
    tpl["content"] = tpl["content"].replace("secret ********", "secret {{ enable }}")
    preview, _ = await preview_then_apply("catc_import_templates", {"export": doc, "project": "mcp-d36-new"})
    assert preview["status"] == "preview"


async def test_import_failure_names_the_partial_template(api: respx.MockRouter) -> None:
    calls = mock_import_target(api, [])
    api.post(f"{TP}/template/version").respond(500, json={"response": {"message": "boom"}})
    with pytest.raises(ToolError, match="incomplete.*Imported before it: none"):
        await preview_then_apply("catc_import_templates", {"export": export_doc(), "project": "mcp-d36-copy"})
    assert len(calls["created"]) == 1  # stopped at the first template


async def test_template_drift_deploying_and_unreadable(api: respx.MockRouter) -> None:
    mock_lab(api)
    dep2, dep3 = "11111111-0000-0000-0000-00000000beef", "11111111-0000-0000-0000-00000000f00d"
    tasks = copy.deepcopy(FIX["tasks"])
    tasks["response"] = [
        {**tasks["response"][0], "progress": f"Template Deployemnt Id: {d}", "startTime": 1792300000000}
        for d in (dep2, dep3)
    ]
    api.get("/dna/intent/api/v1/task").respond(json=tasks)
    running = copy.deepcopy(FIX["deploy_status"])
    running.update(deploymentId=dep2, status="IN_PROGRESS")
    running["devices"][0]["status"] = "IN_PROGRESS"
    api.get(f"{TP}/template/deploy/status/{dep2}").respond(json=running)
    api.get(f"{TP}/template/deploy/status/{dep3}").respond(503)
    out = await call("catc_template_drift", {"project": "mcp-d36-src", "response_format": "json"})
    (row,) = out["results"]
    assert row["state"] == "deploying"
    assert out["warnings"] == ["1 deployment record(s) could not be read; their devices may be missing."]


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        ('#set($password = "Cisco123")', "Cisco123"),
        ('#set($enable_secret="x9x")', "x9x"),
        ('{% set snmp_community = "pub" %}', "pub"),
        ('{% set api_token = "tok9" %}', "tok9"),
        ("{%- set psk = 'abc123' -%}", "abc123"),
        ('#set($a = 1) #set($password = "Two2") #set($b = "ok")', "Two2"),
        ("username admin privilege 15 secret 9 $9$hash", "$9$hash"),
    ],
)
def test_template_set_assignments_masked(line: str, secret: str) -> None:
    out, lines = mask_template_lines(f"hostname r1\n{line}\n")
    assert secret not in out and lines == [2]
    assert out.startswith("hostname r1\n") and out.endswith("\n")
    assert redact_template(line) == out.splitlines()[1]


@pytest.mark.parametrize(
    "line",
    [
        '#set($passwordPolicy = "strong")',  # core NOT_SECRET_KEYS: a name, not a secret
        "#set($password = $vault_pw)",  # a variable reference
        '{% set hostname = "r1" %}',
        '#set($a = 1) #set($b = "x")',
        "username admin secret {{ admin_pw }}",
        "enable secret $enable",
    ],
)
def test_template_lines_left_alone(line: str) -> None:
    assert mask_template_lines(line) == (line, [])


def test_serialize_masks_secret_named_and_typed_variables() -> None:
    t = full_with_versions(VARS)
    t["templateParams"] = [
        {"parameterName": "password", "dataType": "STRING", "defaultValue": "Cisco123", "order": "2"},
        {"parameterName": "key_blob", "dataType": "SECUREDSTRING", "defaultValue": "Zz9", "order": 10},
        {"parameterName": "passwordPolicy", "dataType": "STRING", "defaultValue": "strong", "order": 1},
        {"parameterName": "vlan", "dataType": "INTEGER", "defaultValue": "10"},
    ]
    t["deviceTypes"] = [{"productFamily": "Switches and Hubs"}, {"productFamily": "Routers"}]
    tpl = serialize_templates([], [t])["projects"][0]["templates"][0]
    assert "Cisco123" not in json.dumps(tpl) and "Zz9" not in json.dumps(tpl)
    by_name = {p["parameterName"]: p for p in tpl["params"]}
    assert by_name["passwordPolicy"]["defaultValue"] == "strong" and by_name["vlan"]["defaultValue"] == "10"
    assert [p["parameterName"] for p in tpl["params"]] == ["vlan", "passwordPolicy", "password", "key_blob"]
    assert tpl["deviceTypes"] == [{"productFamily": "Routers"}, {"productFamily": "Switches and Hubs"}]
    assert {"param:password", "param:key_blob"} <= set(tpl["masked_lines"])


def test_serialize_orders_case_variants_stably() -> None:
    a, b = full_with_versions(HOSTS), full_with_versions(HOSTS)
    a["name"], b["name"] = "Edge", "edge"
    one = serialize_templates([], [a, b])["projects"][0]["templates"]
    two = serialize_templates([], [b, a])["projects"][0]["templates"]
    assert [t["name"] for t in one] == [t["name"] for t in two] == ["Edge", "edge"]


async def test_diff_masks_set_assignments(api: respx.MockRouter) -> None:
    mock_lab(api)
    tid = HOSTS["templateId"]
    versions = copy.deepcopy(FIX["versions"][tid])
    for v in versions["response"]:
        v["templateContent"] = f'#set($password = "Old{v["version"]}")\nip host x 192.0.2.{v["version"]}'
    api.get(f"/dna/intent/api/v1/templates/{tid}/versions").respond(json=versions)
    out = await call("catc_diff_template_versions", {"template": "mcp-d36-src/mcp-d36-hosts"})
    assert "Old1" not in out["diff"] and "Old2" not in out["diff"]
    assert "+ip host x 192.0.2.2" in out["diff"]


async def test_import_blocks_mask_without_masked_lines(api: respx.MockRouter) -> None:
    mock_import_target(api, [])
    doc = export_doc()
    tpl = doc["projects"][0]["templates"][0]
    tpl["versions"][0]["content"] = "enable secret ********"  # edited or trimmed: no masked_lines
    tpl.pop("masked_lines", None)
    preview, _ = await preview_then_apply("catc_import_templates", {"export": doc, "project": "mcp-d36-new"})
    assert preview["status"] == "blocked"
    assert any("v1:1" in b and "push the mask" in b for b in preview["blockers"])
    # Importing only the latest version leaves the masked v1 out.
    preview, _ = await preview_then_apply(
        "catc_import_templates", {"export": doc, "project": "mcp-d36-new", "keep_versions": False}
    )
    assert preview["status"] == "preview"


async def test_usage_reads_only_its_own_deployments(api: respx.MockRouter) -> None:
    mock_lab(api)
    other = "22222222-0000-0000-0000-000000000000"
    tasks = copy.deepcopy(FIX["tasks"])
    tasks["response"].append(
        {
            **tasks["response"][0],
            "progress": f"Deployment of  Template: {other}.ApplicableTargets: []"
            f"Template Deployemnt Id: {other}",
        }
    )
    api.get("/dna/intent/api/v1/task").respond(json=tasks)
    foreign = api.get(f"{TP}/template/deploy/status/{other}").respond(json={})
    out = await call("catc_template_usage", {"template": "mcp-d36-src/mcp-d36-hosts"})
    assert [d["state"] for d in out["devices"]] == ["behind"] and not foreign.called
    await call("catc_template_drift", {"response_format": "json"})  # unfiltered: every deployment
    assert foreign.called


async def test_drift_unknown_version(api: respx.MockRouter) -> None:
    mock_lab(api)
    status = copy.deepcopy(FIX["deploy_status"])
    status.update(templateId=None, templateVersion=None)
    tasks = copy.deepcopy(FIX["tasks"])
    tasks["response"][0]["progress"] = "Template Deployemnt Id: " + status["deploymentId"]  # no version id
    api.get("/dna/intent/api/v1/task").respond(json=tasks)
    api.get(f"{TP}/template/deploy/status/{status['deploymentId']}").respond(json=status)
    out = await call("catc_template_drift", {"project": "mcp-d36-src", "response_format": "json"})
    assert [r["state"] for r in out["results"]] == ["unknown version"]


PARITY_CONTENT = "\n".join(
    [
        "username admin privilege 15 secret 9 $9$hash",
        "enable secret $enable",
        '#set($password = "Cisco123") #set($host = "r1") #set($enable_secret=$vault)',
        '{% set snmp_community = "pub" %}{% set api_token = "T0k9x" %}',
        '#set($passwordPolicy = "strong")',
        "ip host {{ host }} 192.0.2.1",
    ]
)
PARITY_PARAMS = [
    {"parameterName": "password", "dataType": "STRING", "defaultValue": "Cisco123"},
    {"parameterName": "blob", "dataType": "STRING", "defaultValue": "s3", "sensitiveField": True},
    {"parameterName": "k", "dataType": "SECUREDSTRING", "defaultValue": "s4"},
    {"parameterName": "passwordPolicy", "dataType": "STRING", "defaultValue": "strong"},
    {"parameterName": "host", "dataType": "STRING", "defaultValue": "r1"},
]


def test_masking_parity_with_config_export() -> None:
    """The template export (D36) and config export (D39) mask a template identically."""
    from catc_mcp.tools import config_io

    raw = {
        "id": "t-1",
        "name": "parity",
        "projectName": "p",
        "templateContent": PARITY_CONTENT,
        "templateParams": PARITY_PARAMS,
        "versions": [],
    }
    mine = serialize_templates([{"name": "p"}], [raw])["projects"][0]["templates"][0]
    _, (theirs,) = config_io._templates({"projects": [], "templates": [raw]})
    assert mine["content"] == theirs["content"]
    for secret in ("$9$hash", "Cisco123", '"pub"', "T0k9x"):
        assert secret not in mine["content"]
    for kept in ("$enable", "$vault", '"strong"', '"r1"', "{{ host }}"):
        assert kept in mine["content"]

    def masked(params: list[dict[str, Any]]) -> set[str]:
        return {str(p["parameterName"]) for p in params if p.get("defaultValue") == "********"}

    assert masked(mine["params"]) == masked(theirs["params"]) == {"password", "blob", "k"}


async def test_import_sends_variables_with_every_version(api: respx.MockRouter) -> None:
    calls = mock_import_target(api, [])
    t = full_with_versions(VARS)
    second = {
        **t["versions"][0],
        "version": 2,
        "versionId": "v2",
        "templateContent": "ip host {{ host_name }} {{ host_ip }}\n! v2",
    }
    t["versions"] = [t["versions"][0], second]
    doc = serialize_templates([{"name": "mcp-d36-src"}], [t])
    _, done = await preview_then_apply("catc_import_templates", {"export": doc, "project": "mcp-d36-copy"})
    assert done["result"]["imported"][0]["versions_committed"] == 2
    bodies = calls["created"] + calls["puts"]  # create (v1), update (v2), update (draft)
    assert len(bodies) == 3
    assert all([p["parameterName"] for p in b["templateParams"]] == ["host_name", "host_ip"] for b in bodies)
    assert [c[2] for c in calls["commits"]] == [
        t["versions"][0]["templateContent"],
        second["templateContent"],
    ]
