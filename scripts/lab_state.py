"""Seed or clean up the Catalyst Center lab objects the live tests rely on.

    uv run python scripts/lab_state.py status
    uv run python scripts/lab_state.py seed [--no-devices]
    uv run python scripts/lab_state.py cleanup [--keep-devices]

Seed creates (skipping whatever already exists): global credentials mcp-test-cli / -snmp-ro /
-snmp-rw, sites Global/mcp-test-lab/mcp-test-bldg/mcp-test-floor1 with network settings and site
credentials at mcp-test-lab, template project mcp-test-dayn (mcp-test-loopback, mcp-test-cdp,
mcp-test-port-open, committed), switching profile mcp-test-sw-profile, and, unless --no-devices,
discovers r1/r2 of the CML `catc-routers` recipe (198.18.128.152-153), waits for them to be Managed,
assigns and provisions them at mcp-test-bldg. Cleanup removes all of it (devices first).

Everything goes through this server's own MCP tools (preview, then confirm), in-process, with the
appliance in .env and every tier enabled for this process only. Device credentials come from
LAB_CLI_USERNAME / LAB_CLI_PASSWORD / LAB_SNMP_RO / LAB_SNMP_RW in .env; they are never printed.
"""

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.config import Settings
from catc_mcp.server import create_server

AREA, BLDG, FLOOR = (
    "Global/mcp-test-lab",
    "Global/mcp-test-lab/mcp-test-bldg",
    "Global/mcp-test-lab/mcp-test-bldg/mcp-test-floor1",
)
CREDS = ("mcp-test-cli", "mcp-test-snmp-ro", "mcp-test-snmp-rw")
PROJECT, PROFILE, DISCOVERY = "mcp-test-dayn", "mcp-test-sw-profile", "mcp-test-disc-routers"
ROUTERS = ("198.18.128.152", "198.18.128.153")
TEMPLATES = {
    "mcp-test-loopback": (
        "Routers",
        "interface Loopback{{ loop_id }}\n description {{ desc }}\n ip address {{ ip }} 255.255.255.255",
    ),
    "mcp-test-cdp": ("Routers", "cdp run\ninterface GigabitEthernet2\n cdp enable"),
    "mcp-test-port-open": ("Switches and Hubs", "interface {{ port }}\n authentication open"),
}


ROOT = Path(__file__).resolve().parent.parent
SECRET_VARS = ("LAB_CLI_PASSWORD", "LAB_SNMP_RO", "LAB_SNMP_RW")
ABSENT = re.compile(
    r"\bNo (network device|site|network profile|discovery|template project|global credential|project)"
    r"|not found",
    re.I,
)


def lab_env() -> dict[str, str]:
    values = {k: v for k, v in dotenv_values(ROOT / ".env").items() if v is not None}
    return {**values, **{k: v for k, v in os.environ.items() if k.startswith("LAB_")}}


def scrub(text: str) -> str:
    """Error text with the lab secrets replaced, trimmed."""
    env = lab_env()
    for var in SECRET_VARS:
        if env.get(var):
            text = text.replace(env[var], "***")
    return text[:300]


def say(msg: str) -> None:
    print(scrub(msg) if len(msg) < 2000 else scrub(msg[:2000]), flush=True)


def absent(err: Exception) -> bool:
    return bool(ABSENT.search(str(err)))


async def call(c: Client, tool: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    res = await c.call_tool(tool, args, raise_on_error=False)
    data = res.structured_content
    if data is None:
        text = "\n".join(getattr(x, "text", "") for x in res.content)
        try:
            data = json.loads(text)
        except ValueError:
            data = text
    if res.is_error:
        raise ToolError(scrub(f"{tool}: {data}"))
    return data


async def write(c: Client, tool: str, args: dict[str, Any]) -> str:  # type: ignore[type-arg]
    """Preview, then confirm. Returns 'applied' or 'skipped: <blockers>'."""
    preview = await call(c, tool, args)
    if preview.get("status") == "blocked":
        return "skipped: " + "; ".join(preview.get("blockers") or [])
    await call(c, tool, {**args, "confirm": preview["confirm"]})
    return "applied"


async def exists(c: Client, tool: str, args: dict[str, Any]) -> bool:  # type: ignore[type-arg]
    """True/False for present/absent; any other error (auth, timeout...) is raised."""
    try:
        await call(c, tool, args)
        return True
    except ToolError as e:
        if absent(e):
            return False
        raise


async def project_templates(c: Client) -> list[str]:  # type: ignore[type-arg]
    """Template names in the mcp-test project ([] when it doesn't exist)."""
    try:
        out = await call(c, "catc_list_templates", {"project": PROJECT, "response_format": "json"})
    except ToolError:
        return []
    return sorted(t["name"] for t in out["results"])


async def status(c: Client) -> dict[str, Any]:  # type: ignore[type-arg]
    creds = await call(c, "catc_list_global_credentials", {"response_format": "json"})
    names = {r.get("description") for r in creds["results"]}
    out: dict[str, Any] = {"credentials": {n: n in names for n in CREDS}}
    out["sites"] = {s: await exists(c, "catc_get_site", {"site": s}) for s in (AREA, BLDG, FLOOR)}
    out["template_project"] = await project_templates(c)
    out["profile"] = await exists(c, "catc_get_network_profile", {"profile": PROFILE})
    devs = {}
    for ip in ROUTERS:
        try:
            d = await call(c, "catc_get_device", {"device": ip})
            devs[ip] = f"{d.get('hostname')} {d.get('reachabilityStatus')}/{d.get('collectionStatus')}"
        except ToolError:
            devs[ip] = "absent"
    out["devices"] = devs
    return out


async def seed(c: Client, devices: bool) -> None:  # type: ignore[type-arg]
    env = lab_env()
    missing = [
        k for k in ("LAB_CLI_USERNAME", "LAB_CLI_PASSWORD", "LAB_SNMP_RO", "LAB_SNMP_RW") if not env.get(k)
    ]
    if missing:
        sys.exit(f"Set {', '.join(missing)} in .env")
    have = {
        r.get("description")
        for r in (await call(c, "catc_list_global_credentials", {"response_format": "json"}))["results"]
    }
    cred_args = {
        "mcp-test-cli": {
            "credential_type": "CLI",
            "username": env["LAB_CLI_USERNAME"],
            "password": env["LAB_CLI_PASSWORD"],
            "enable_password": env["LAB_CLI_PASSWORD"],
        },
        "mcp-test-snmp-ro": {"credential_type": "SNMPV2_READ_COMMUNITY", "community": env["LAB_SNMP_RO"]},
        "mcp-test-snmp-rw": {"credential_type": "SNMPV2_WRITE_COMMUNITY", "community": env["LAB_SNMP_RW"]},
    }
    for name, args in cred_args.items():
        say(
            f"credential {name}: "
            + (
                "exists"
                if name in have
                else await write(c, "catc_create_global_credential", {**args, "description": name})
            )
        )
    sites = [
        ({"site_type": "area", "name": "mcp-test-lab"}, AREA),
        (
            {
                "site_type": "building",
                "name": "mcp-test-bldg",
                "parent": AREA,
                "address": "1 Lab St, Sydney NSW",
                "latitude": -33.86,
                "longitude": 151.2,
                "country": "Australia",
            },
            BLDG,
        ),
        ({"site_type": "floor", "name": "mcp-test-floor1", "parent": BLDG}, FLOOR),
    ]
    for args, path in sites:
        say(
            f"site {path}: "
            + (
                "exists"
                if await exists(c, "catc_get_site", {"site": path})
                else await write(c, "catc_create_site", args)
            )
        )
    settings = {
        "site": AREA,
        "dns_servers": ["198.18.133.1"],
        "domain_name": "mcp.lab",
        "ntp_servers": ["198.18.128.1"],
        "banner": "mcp-test banner: authorised use only",
        "timezone": "Australia/Sydney",
        "wired_data_collection": True,
    }
    say("site settings: " + await write(c, "catc_update_site_settings", settings))
    say(
        "site credentials: "
        + await write(c, "catc_assign_site_credentials", {"site": AREA, "credentials": list(CREDS)})
    )
    say("template project: " + await write(c, "catc_create_template_project", {"name": PROJECT}))
    present = set(await project_templates(c))
    for name, (family, content) in TEMPLATES.items():
        if name in present:
            say(f"template {name}: exists")
            continue
        say(
            f"template {name}: "
            + await write(
                c,
                "catc_create_template",
                {"project": PROJECT, "name": name, "device_families": [family], "content": content},
            )
        )
        say(
            "  commit: "
            + await write(c, "catc_commit_template", {"template": f"{PROJECT}/{name}", "comment": "seed"})
        )
    say(
        f"profile {PROFILE}: "
        + (
            "exists"
            if await exists(c, "catc_get_network_profile", {"profile": PROFILE})
            else await write(c, "catc_create_switching_profile", {"name": PROFILE})
        )
    )
    if not devices:
        return
    absent = [ip for ip in ROUTERS if not await exists(c, "catc_get_device", {"device": ip})]
    if absent:
        say(f"discovery {DISCOVERY} ({', '.join(absent)}), waiting...")
        say(
            "  "
            + await write(
                c,
                "catc_create_discovery",
                {
                    "name": DISCOVERY,
                    "ip_ranges": [f"{ROUTERS[0]}-{ROUTERS[-1]}"],
                    "global_credentials": list(CREDS),
                    "netconf_port": 830,
                    "wait": True,
                },
            )
        )
    for _ in range(60):
        states = [
            await call(c, "catc_get_device", {"device": ip})
            for ip in ROUTERS
            if await exists(c, "catc_get_device", {"device": ip})
        ]
        if len(states) == len(ROUTERS) and all(d.get("collectionStatus") == "Managed" for d in states):
            break
        await asyncio.sleep(20)
    else:
        sys.exit("The routers did not become Managed; is the catc-routers CML lab running?")
    say("assign: " + await write(c, "catc_assign_devices_to_site", {"devices": list(ROUTERS), "site": BLDG}))
    say("provision: " + await write(c, "catc_provision_devices", {"devices": list(ROUTERS), "site": BLDG}))


async def cleanup(c: Client, keep_devices: bool) -> None:  # type: ignore[type-arg]
    if not keep_devices:
        for ip in ROUTERS:
            if await exists(c, "catc_get_device", {"device": ip}):
                say(f"device {ip}: " + await write(c, "catc_delete_device", {"device": ip}))
    for tool, args in (
        ("catc_delete_discovery", {"discovery": DISCOVERY}),
        ("catc_delete_template_project", {"project": PROJECT}),
    ):
        try:
            say(f"{tool} {args}: " + await write(c, tool, args))
        except ToolError as e:
            if not absent(e):
                raise
            say(f"{tool} {args}: not present")
    if await exists(c, "catc_get_network_profile", {"profile": PROFILE}):
        prof = await call(c, "catc_get_network_profile", {"profile": PROFILE})
        if prof.get("sites"):
            try:
                say(
                    "profile sites: "
                    + await write(
                        c, "catc_unassign_profile_from_sites", {"profile": PROFILE, "sites": prof["sites"]}
                    )
                )
            except ToolError as e:
                say(f"profile sites: {e} (deleting the profile anyway)")
        # No delete tool for profiles: the raw API call, preview-first like everything else.
        path = f"/dna/intent/api/v1/networkProfilesForSites/{prof['id']}"
        say(f"profile {PROFILE}: " + await write(c, "catc_api_call", {"method": "DELETE", "path": path}))
    else:
        say(f"profile {PROFILE}: not present")
    if await exists(c, "catc_get_site", {"site": AREA}):
        say(f"site {AREA}: " + await write(c, "catc_delete_site", {"site": AREA, "recursive": True}))
    for name in CREDS:
        try:
            say(
                f"credential {name}: " + await write(c, "catc_delete_global_credential", {"credential": name})
            )
        except ToolError as e:
            if not absent(e):
                raise
            say(f"credential {name}: not present")


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["status", "seed", "cleanup"])
    ap.add_argument("--no-devices", action="store_true", help="seed: skip discovering/provisioning r1/r2")
    ap.add_argument("--keep-devices", action="store_true", help="cleanup: leave r1/r2 in the inventory")
    args = ap.parse_args()
    os.chdir(ROOT)  # .env is read from the repo root
    settings = Settings(mcp_enable_writes=True, mcp_enable_dangerous=True, mcp_task_timeout=1800)
    async with Client(create_server(settings)) as c:
        if args.action == "seed":
            await seed(c, devices=not args.no_devices)
        elif args.action == "cleanup":
            await cleanup(c, keep_devices=args.keep_devices)
        print(json.dumps(await status(c), indent=1))


if __name__ == "__main__":
    asyncio.run(main())
