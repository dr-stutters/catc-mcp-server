"""D40 live: build a small design, export it, delete it, import the export, and the diff against live
is empty for it.

Everything is named `mcp-d40-*` and removed at the end. Assertions look only at this test's objects:
other objects on a shared lab come and go meanwhile."""

import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastmcp import Client

from catc_mcp.client import CatcApp
from catc_mcp.config import Settings
from catc_mcp.tools.config_io import load_export
from catc_mcp.tools.credentials import CRED_PATH, all_credentials
from catc_mcp.tools.ipam import GLOBAL, RESERVED
from catc_mcp.tools.ipam import _all as all_pools
from catc_mcp.tools.template_writes import TP

pytestmark = pytest.mark.live

AREA = "Global/mcp-d40"
BLDG = f"{AREA}/mcp-d40-bldg"
PROJECT = "mcp-d40-proj"
TEMPLATE = "mcp-d40-hosts"
CRED = "mcp-d40-cli"
POOL = "mcp-d40-pool"
RES = "mcp-d40-lan"
TAG = "mcp-d40-tag"
SECTIONS = [
    "sites",
    "settings",
    "credentials",
    "ip_pools",
    "ip_reservations",
    "template_projects",
    "templates",
    "tags",
]


async def call(c: Client, name: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    res = await c.call_tool(name, args)
    if res.structured_content is not None:
        return res.structured_content
    text = "\n".join(getattr(x, "text", "") for x in res.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


async def apply(c: Client, name: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    preview = await call(c, name, args)
    assert preview["status"] == "preview", preview
    done = await call(c, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done.get("result")


@pytest.fixture
async def raw(lab_rw_settings: Settings) -> AsyncIterator[CatcApp]:
    app = CatcApp(lab_rw_settings)
    yield app
    await app.aclose()


def mine(item: Any) -> bool:
    return "mcp-d40" in json.dumps(item)


async def teardown(app: CatcApp) -> None:
    """Remove every mcp-d40 object, children first; ignore what isn't there."""

    async def delete(path: str) -> None:
        with contextlib.suppress(Exception):
            await app.run_job("DELETE", path)

    for p in await all_pools(app, RESERVED):
        if str(p.get("name")) == RES:
            await delete(f"{RESERVED}/{p['id']}")
    for p in await all_pools(app, GLOBAL):
        if str(p.get("name")) == POOL:
            await delete(f"{GLOBAL}/{p['id']}")
    projects = await app.api.get(f"{TP}/project", {"name": PROJECT})
    for proj in projects if isinstance(projects, list) else []:
        for t in proj.get("templates") or []:
            await delete(f"{TP}/template/{t['id']}")
        await delete(f"{TP}/project/{proj['id']}")
    for c in await all_credentials(app):
        if c.get("description") == CRED:
            await delete(f"{CRED_PATH}/{c['id']}")
    tags = await app.get_response("/dna/intent/api/v1/tag", {"name": TAG})
    for t in tags if isinstance(tags, list) else []:
        await delete(f"/dna/intent/api/v1/tag/{t['id']}")
    for path, kind in ((BLDG, "v2/buildings"), (AREA, "v1/areas")):
        found = await app.get_response("/dna/intent/api/v1/sites", {"nameHierarchy": path})
        for s in found if isinstance(found, list) else []:
            await delete(f"/dna/intent/api/{kind}/{s['id']}")


async def test_export_delete_import_round_trip(lab_rw: Client, raw: CatcApp) -> None:  # type: ignore[type-arg]
    await teardown(raw)
    try:
        # 1. Build the design with the server's own tools (a tag through the API: no tag tool yet).
        await apply(lab_rw, "catc_create_site", {"site_type": "area", "name": "mcp-d40"})
        await apply(
            lab_rw,
            "catc_create_site",
            {
                "site_type": "building",
                "name": "mcp-d40-bldg",
                "parent": AREA,
                "country": "Australia",
                "address": "1 Martin Place, Sydney NSW 2000",
                "latitude": -33.8675,
                "longitude": 151.2094,
            },
        )
        await apply(
            lab_rw,
            "catc_update_site_settings",
            {"site": AREA, "domain_name": "d40.lab", "ntp_servers": ["192.0.2.123"]},
        )
        await apply(
            lab_rw,
            "catc_create_global_credential",
            {"credential_type": "CLI", "description": CRED, "username": "d40", "password": "d40-Secret-1"},
        )
        await apply(lab_rw, "catc_create_ip_pool", {"name": POOL, "subnet": "10.240.0.0/16"})
        await apply(
            lab_rw,
            "catc_create_ip_pool",
            {"name": RES, "subnet": "10.240.1.0/24", "site": BLDG, "global_pool": POOL, "pool_type": "LAN"},
        )
        await apply(lab_rw, "catc_create_template_project", {"name": PROJECT, "description": "D40 live"})
        await apply(
            lab_rw,
            "catc_create_template",
            {
                "project": PROJECT,
                "name": TEMPLATE,
                "content": "ip host mcp-d40 192.0.2.40",
                "device_families": ["Routers"],
            },
        )
        await apply(lab_rw, "catc_commit_template", {"template": f"{PROJECT}/{TEMPLATE}", "comment": "d40"})
        await raw.run_job("POST", "/dna/intent/api/v1/tag", {"name": TAG, "description": "D40 live"})

        # 2. Export the area's subtree (global sections come whole) and keep only what is ours.
        text = await call(lab_rw, "catc_export_config", {"scope": AREA, "sections": SECTIONS})
        doc = load_export(text)
        assert [s["path"] for s in doc["sites"]] == [AREA, BLDG]
        assert doc["settings"][AREA]["dns"]["dns"]["domainName"] == "d40.lab"
        assert any(c["description"] == CRED for c in doc["credentials"])
        assert any(t["name"] == TEMPLATE for t in doc["templates"])

        # Nothing to do while everything still exists.
        preview = await call(lab_rw, "catc_import_config", {"export": text, "sections": SECTIONS})
        ours = [s for s in preview.get("preview", {}).get("steps", []) if mine(s) and s["action"] != "skip"]
        assert ours == [], preview

        # 3. Delete it all, then import the export back.
        await teardown(raw)
        args = {
            "export": text,
            "sections": SECTIONS,
            "secrets": {f"CLI:{CRED}": {"password": "d40-Secret-1"}},
        }
        preview = await call(lab_rw, "catc_import_config", args)
        assert preview["status"] == "preview", preview
        planned = {(s["section"], s["action"], s["item"]) for s in preview["preview"]["steps"] if mine(s)}
        assert {
            ("sites", "create", AREA),
            ("sites", "create", BLDG),
            ("credentials", "create", f"CLI:{CRED}"),
            ("settings", "update", f"{AREA} dns"),
            ("ip_pools", "create", POOL),
            ("ip_reservations", "create", f"{BLDG}:{RES}"),
            ("template_projects", "create", PROJECT),
            ("templates", "create", f"{PROJECT}/{TEMPLATE}"),
            ("tags", "create", TAG),
        } <= planned, preview
        assert "d40-Secret-1" not in json.dumps(preview)
        done = await call(lab_rw, "catc_import_config", {**args, "confirm": preview["confirm"]})
        assert done["status"] == "applied", done
        assert done["result"]["status"] == "applied", done

        # 4. The diff against live is empty for our objects.
        out = await call(lab_rw, "catc_diff_config", {"before": text, "limit": 2000})
        left = [c for c in out["changes"] if mine(c)]
        assert left == [], left
    finally:
        await teardown(raw)
