"""D36 live test: template versions, diff, export / import as a copy, clone, and deployed-version
drift on CATC_LIVE_ROUTER1.

Creates project mcp-d36-live-<run> with a two-version template, exports it, imports it as a copy
into mcp-d36-live-copy-<run>, clones it, deploys the OLD version 1 to router 1 and checks that
catc_template_drift / catc_template_usage flag the router as behind. Cleans up: removes the
`ip host` line from the router with a negation template and deletes both projects."""

import asyncio
import contextlib
import time
from typing import Any

import pytest
from fastmcp import Client

from catc_mcp.tools.templates import parse_templates_export

from .conftest import ROUTER1, need, require_reachable
from .test_live_phase2 import RUN
from .test_live_writes import apply, call

pytestmark = pytest.mark.live

V1 = "ip host mcp-d36-live-a 192.0.2.71"
V2 = f"{V1}\nip host mcp-d36-live-b 192.0.2.72"


def strip(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The templates of an export without what legitimately differs on a copy (names, times, authors)."""
    out = []
    for _, t in parse_templates_export(doc):
        out.append(
            {
                "content": t["content"],
                "versions": [(v["version"], v["comment"], v["content"]) for v in t["versions"]],
                "deviceTypes": t["deviceTypes"],
                "language": t["language"],
            }
        )
    return out


async def test_templates_depth_round_trip_and_drift(lab_rw: Client) -> None:  # type: ignore[type-arg]
    need("CATC_LIVE_ROUTER1")
    require_reachable(ROUTER1, "router 1")
    proj, copy = f"mcp-d36-live-{RUN}", f"mcp-d36-live-copy-{RUN}"
    ref = f"{proj}/mcp-d36-live"
    await apply(lab_rw, "catc_create_template_project", {"name": proj})
    deployed = False
    try:
        await apply(
            lab_rw,
            "catc_create_template",
            {"project": proj, "name": "mcp-d36-live", "content": V1, "device_families": ["Routers"]},
        )
        await apply(lab_rw, "catc_commit_template", {"template": ref, "comment": "d36 v1"})
        await apply(lab_rw, "catc_update_template", {"template": ref, "content": V2})
        await apply(lab_rw, "catc_commit_template", {"template": ref, "comment": "d36 v2"})

        # Version history and diff.
        hist = await call(lab_rw, "catc_list_template_versions", {"template": ref, "response_format": "json"})
        assert [r["version"] for r in hist["results"]] == [2, 1] and hist["uncommitted_changes"] is False
        diff = await call(lab_rw, "catc_diff_template_versions", {"template": ref, "from_version": 1})
        assert (diff["added"], diff["removed"]) == (1, 0) and "+ip host mcp-d36-live-b" in diff["diff"]

        # Export the project, import it as a renamed copy into a new project: same history.
        doc = await call(lab_rw, "catc_export_templates", {"project": proj})
        assert [len(t["versions"]) for _, t in parse_templates_export(doc)] == [2]
        result = await apply(
            lab_rw, "catc_import_templates", {"export": doc, "project": copy, "name": "mcp-d36-live-imported"}
        )
        assert result["imported"][0]["versions_committed"] == 2
        copy_doc = await call(lab_rw, "catc_export_templates", {"project": copy})
        assert strip(copy_doc) == strip(doc)
        names = [t["name"] for _, t in parse_templates_export(copy_doc)]
        assert names == ["mcp-d36-live-imported"]

        # Clone: same content, no versions.
        await apply(
            lab_rw, "catc_clone_template", {"template": ref, "name": "mcp-d36-live-clone", "project": copy}
        )
        clone = await call(
            lab_rw,
            "catc_list_template_versions",
            {"template": f"{copy}/mcp-d36-live-clone", "response_format": "json"},
        )
        assert clone["total"] == 0 and clone["uncommitted_changes"] is True

        # Deploy the OLD version to router 1: drift shows it behind the latest.
        done = await apply(
            lab_rw, "catc_deploy_template", {"template": ref, "devices": [ROUTER1], "version": 1}
        )
        deployed = True
        assert done["deployment"]["status"] == "SUCCESS", done
        assert done["deployment"]["templateVersion"] == "1"
        t0 = time.monotonic()
        for _ in range(6):
            drift = await call(
                lab_rw, "catc_template_drift", {"template": ref, "hours": 2, "response_format": "json"}
            )
            if drift["results"]:
                break
            await asyncio.sleep(10)
        print(f"drift saw the deployment after {time.monotonic() - t0:.0f} s")
        (row,) = drift["results"]
        assert (row["ipAddress"], row["deployed"], row["latest"], row["state"]) == (ROUTER1, 1, 2, "behind")
        usage = await call(lab_rw, "catc_template_usage", {"template": ref, "hours": 2})
        assert [(d["ipAddress"], d["state"]) for d in usage["devices"]] == [(ROUTER1, "behind")]
    finally:
        if deployed:
            with contextlib.suppress(Exception):
                undo = f"{proj}/mcp-d36-live-undo"
                await apply(
                    lab_rw,
                    "catc_create_template",
                    {
                        "project": proj,
                        "name": "mcp-d36-live-undo",
                        "content": "no ip host mcp-d36-live-a",
                        "device_families": ["Routers"],
                    },
                )
                await apply(lab_rw, "catc_commit_template", {"template": undo, "comment": "undo"})
                await apply(lab_rw, "catc_deploy_template", {"template": undo, "devices": [ROUTER1]})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_template_project", {"project": copy})
        await apply(lab_rw, "catc_delete_template_project", {"project": proj})
