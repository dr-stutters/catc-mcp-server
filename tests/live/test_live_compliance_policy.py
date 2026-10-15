"""D4 live: a "no ip http server" compliance policy on mcp-test-lab gives r1 a violation; a template
fix makes it compliant; the http server is put back and everything mcp-test-* is removed."""

import asyncio
import contextlib
from typing import Any

import pytest
from fastmcp import Client

from .test_live_phase2 import R1, RUN, routers  # noqa: F401 - fixture
from .test_live_writes import apply, call

pytestmark = pytest.mark.live
SITE = "Global/mcp-test-lab"


async def _violations(c: Client, policy: str) -> list[dict[str, Any]]:  # type: ignore[type-arg]
    await apply(c, "catc_run_compliance", {"devices": [R1]})
    out: dict[str, Any] = {}
    for _ in range(12):
        out = await call(
            c, "catc_list_compliance_violations", {"device": R1, "policy": policy, "response_format": "json"}
        )
        if out["results"]:
            break
        await asyncio.sleep(10)
    rows: list[dict[str, Any]] = out["results"]
    return rows


async def _deploy(c: Client, proj: str, name: str, content: str) -> None:  # type: ignore[type-arg]
    await apply(
        c,
        "catc_create_template",
        {"project": proj, "name": name, "device_families": ["Routers"], "content": content},
    )
    await apply(c, "catc_commit_template", {"template": f"{proj}/{name}", "comment": "d4"})
    done = await apply(c, "catc_deploy_template", {"template": f"{proj}/{name}", "devices": [R1]})
    assert done["deployment"]["status"] == "SUCCESS", done


async def test_policy_violation_and_fix(lab_rw: Client, routers: dict[str, Any]) -> None:  # type: ignore[type-arg]  # noqa: F811
    policy, proj = f"mcp-test-no-http-{RUN}", f"mcp-test-d4-{RUN}"
    rules = [
        {
            "name": "no-http-server",
            "description": "The HTTP server must be off",
            "device_families": ["Routers", "Switches and Hubs"],
            "suggested_fix": "no ip http server",
            "conditions": [
                {
                    "operator": "MATCHES_EXPRESSION",
                    "value": "^ip http server",
                    "violation_when": "matches",
                    "severity": "MAJOR",
                }
            ],
        }
    ]
    created = await apply(
        lab_rw, "catc_create_compliance_policy", {"name": policy, "rules": rules, "sites": [SITE]}
    )
    assert created["status"] == "ACTIVE", created
    dup = await call(lab_rw, "catc_create_compliance_policy", {"name": policy, "rules": rules})
    assert dup["status"] == "blocked"
    await apply(lab_rw, "catc_create_template_project", {"name": proj})
    try:
        got = await call(lab_rw, "catc_get_compliance_policy", {"policy": policy})
        assert got["rules"][0]["conditions"][0]["violation_when"] == "matches"
        assert SITE in got["sites"]
        # Make sure the router has the http server on, then expect a violation.
        await _deploy(lab_rw, proj, "mcp-test-http-on", "ip http server\n")
        bad = await _violations(lab_rw, policy)
        assert bad, "no violation for ip http server on r1"
        assert bad[0]["severity"] == "MAJOR" and "ip http server" in bad[0]["message"], bad
        at_site = await call(
            lab_rw,
            "catc_list_compliance_violations",
            {"policy": policy, "site": SITE + "/mcp-test-bldg", "response_format": "json"},
        )
        assert any(r.get("device") == "r1.mcp.lab" for r in at_site["results"]), at_site
        # The fix: turn it off and re-run compliance.
        await _deploy(lab_rw, proj, "mcp-test-http-off", "no ip http server\n")
        await apply(lab_rw, "catc_run_compliance", {"devices": [R1]})
        await asyncio.sleep(20)
        good = await call(
            lab_rw,
            "catc_list_compliance_violations",
            {"device": R1, "policy": policy, "response_format": "json"},
        )
        assert not good["results"], good
        moved = await apply(
            lab_rw, "catc_assign_compliance_policy", {"policy": policy, "sites": [SITE], "mode": "remove"}
        )
        assert moved["sites"] == []
    finally:
        with contextlib.suppress(Exception):
            await _deploy(lab_rw, proj, "mcp-test-http-restore", "ip http server\n")
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_template_project", {"project": proj})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_compliance_policy", {"policy": policy})
