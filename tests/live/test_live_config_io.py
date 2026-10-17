"""D39 live: export, change one site setting, the diff shows exactly that change.

Uses its own site (`mcp-d39-site`) and limits assertions to it: other objects on a shared lab come
and go between the export and the diff."""

import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastmcp import Client

from catc_mcp.client import CatcApp
from catc_mcp.config import Settings
from catc_mcp.tools.config_io import dump_export, load_export

pytestmark = pytest.mark.live

SITE = "mcp-d39-site"
PATH = f"Global/{SITE}"


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


async def test_export_change_one_setting_diff(lab_rw: Client, raw: CatcApp) -> None:  # type: ignore[type-arg]
    site_id = None
    try:
        r = await apply(lab_rw, "catc_create_site", {"site_type": "area", "name": SITE})
        site_id = r["site_id"]
        await apply(lab_rw, "catc_update_site_settings", {"site": PATH, "domain_name": "d39-before.lab"})

        scoped_args = {"scope": PATH, "sections": ["sites", "settings"]}
        scoped = await call(lab_rw, "catc_export_config", scoped_args)
        full = await call(lab_rw, "catc_export_config", {})
        for text in (scoped, full):
            assert dump_export(load_export(text)) == text  # byte-identical round trip on live data
        doc = load_export(scoped)
        assert doc["sites"] == [{"path": PATH, "type": "area"}]
        assert doc["settings"][PATH]["dns"]["dns"]["domainName"] == "d39-before.lab"

        # Nothing changed yet: the scoped diff against live is empty.
        same = await call(lab_rw, "catc_diff_config", {"before": scoped})
        assert same["identical"], same

        await apply(lab_rw, "catc_update_site_settings", {"site": PATH, "domain_name": "d39-after.lab"})

        expected = [("settings", PATH, "changed", "dns.dns.domainName", "d39-before.lab", "d39-after.lab")]
        out = await call(lab_rw, "catc_diff_config", {"before": scoped})
        got = [
            (c["section"], c["item"], c["change"], c.get("field"), c.get("before"), c.get("after"))
            for c in out["changes"]
        ]
        assert got == expected, out
        assert out["after"] == "live"

        # Whole-lab export: other sessions' objects may change meanwhile, so look only at this site.
        out = await call(lab_rw, "catc_diff_config", {"before": full, "limit": 2000})
        mine = [
            (c["section"], c["item"], c["change"], c.get("field"), c.get("before"), c.get("after"))
            for c in out["changes"]
            if SITE in json.dumps(c)
        ]
        assert mine == expected, out

        # Two exports compared with each other give the same answer.
        later = await call(lab_rw, "catc_export_config", scoped_args)
        out = await call(lab_rw, "catc_diff_config", {"before": scoped, "after": later})
        assert [(c["item"], c["field"], c["after"]) for c in out["changes"]] == [
            (PATH, "dns.dns.domainName", "d39-after.lab")
        ]
    finally:
        if site_id:
            with contextlib.suppress(Exception):
                await raw.run_job("DELETE", f"/dna/intent/api/v1/areas/{site_id}")
