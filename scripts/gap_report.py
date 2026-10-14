"""Coverage of the bundled Catalyst Center API spec by the curated tools, per functional area.

    uv run python scripts/gap_report.py            # markdown table (used in docs/GAP-ANALYSIS.md)
    uv run python scripts/gap_report.py --uncovered "Software Image"   # list an area's uncovered ops

An operation counts as covered when a curated tool calls its path (path match; a tool that uses GET
on a path is counted for the other methods on that path only if it calls them too, see METHODS).
Everything else is reachable through catc_api_call (GET in the read tier, any method with the
dangerous tier), so "not reachable" is empty except for multipart uploads.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "src/catc_mcp/specs/catc-3.2.2.json.gz"
SRC = ROOT / "src/catc_mcp"

# (area, regex on "METHOD path tag") - first match wins. Order matters.
AREAS: list[tuple[str, str]] = [
    (
        "Auth, tasks, files, platform",
        r" /dna/(system/api/v1/auth|intent/api/v1/(task|file|dnac-|nodes-config|executionStatus))|"
        r"business-api|\[Task\]|\[File\]|\[Platform\]",
    ),
    ("Credentials", r"credential|Credential"),
    ("Discovery", r"/discovery|\[Discovery\]"),
    ("PnP / device onboarding", r"onboarding/pnp|pnp|\[Device Onboarding|Claim PnP|PnP devices"),
    ("LAN automation", r"lan-automation|LAN Automation"),
    ("Device replacement / RMA", r"[Rr]eplacement"),
    ("Config archive", r"network-device-config|ConfigFiles|network-device-archive|Configuration Archive"),
    ("Command runner", r"network-device-poller|Command Runner"),
    ("Path trace", r"flow-analysis|Path Trace|thousandEyesPathTrace"),
    ("Topology", r"/topology|\[Topology\]"),
    ("Compliance & config drift", r"compliance|Compliance"),
    (
        "SWIM (images)",
        r"/image|/images|networkDeviceImage|productNames|productSeries|siteWise|Software Image|"
        r"imageTransferProtocol|Software Management",
    ),
    ("Licensing", r"licen[sc]e|Licen[sc]e|smartAccount"),
    ("Templates", r"template|Template|/projects|preview-deploy|direct-deploy"),
    ("Provisioning", r"provision|Provision"),
    (
        "SDA fabric",
        r"/sda/|\[SDA\]|Fabric|Anycast|Virtual Networks|Transit|Port Assignments|Port Channel|"
        r"Extranet|Multicast|Layer 2 Handoffs|Layer 3 Handoffs|Authentication Profile",
    ),
    (
        "Wireless",
        r"wireless|Wireless|ssid|SSID|/wlc|accesspoint|access-point|Access [Pp]oint|AnchorGroup|"
        r"802.11|Rf|rf-profile|dot11|ApJoin|wlcRedundancy|Client Exclusion|Steering|Pre-Auth",
    ),
    ("Sensors", r"[Ss]ensor|icap"),
    (
        "Assurance: issues & events",
        r"assuranceIssues|/issues|Issues|assuranceEvents|/event/event|Fabric Events|"
        r"issueTrigger|systemIssueDefinitions|customIssueDefinitions",
    ),
    ("Assurance: clients", r"client|Client|user-enrichment|userEnrichment|\[Users\]"),
    (
        "Assurance: device & network health",
        r"health|Health|networkDevices/.*trend|interfaces/query|"
        r"/data/api/v1/networkDevices|/dna/data/api/v1/interfaces|processKpis|wirelessControllersStats|"
        r"thousandEyes|Know Your Network|Applications|application|Application",
    ),
    (
        "Event management / notifications",
        r"/event/|Event Management|/dna/system/api/v1/event|ITSM|itsm|"
        r"Destination|webhook|syslog-config|snmp-config|email-config",
    ),
    ("Reports", r"/data/reports|Reports"),
    ("Audit logs", r"audit"),
    ("Backup & restore", r"backup|Backup|Restore"),
    ("Users & roles", r"/user|/role|accessGroups|User and Roles|external-authentication|external-servers"),
    (
        "System settings & integration",
        r"System Settings|authentication-policy-servers|integrate-ise|"
        r"ise-integration|provisioningSettings|custom-prompt|Cisco Trusted|certificate|ipam/serverSetting|"
        r"\[Servers\] .*(Spaces|CMX|location)|locationServers|Cisco IMC|SFTP|"
        r"securityAdvisories|Security Advisories",
    ),
    ("IP pools (IPAM)", r"ipam|global-pool|reserve-ip-subpool|IpAddressPool"),
    (
        "Network settings",
        r"/sites/\{id\}/(aaa|banner|dhcp|dns|ntp|telemetry|timeZone|imageDistribution)|"
        r"Network Settings|\[Servers\]|\[Banner\]|\[Time Zone\]|/network( |/)|service-provider|"
        r"networkProfilesForSites/.*/templates",
    ),
    ("Network profiles", r"networkProfiles|network-profile|Switch Network Profiles"),
    ("Sites", r"/site|/area|/building|/floor|Sites|Site Design|Network Hierarchy|/maps"),
    ("Tags", r"/tag|\[Tag\]"),
    (
        "Inventory (devices, interfaces, modules)",
        r"network-device|networkDevice|/interface|Devices|"
        r"inventoryManagement|EoX|eox|filterGroup|Industrial|REP Rings|networkDevicesSshKeyChanges|"
        r"Wired|Health and Performance",
    ),
]


def load_ops() -> list[tuple[str, str, str]]:
    with gzip.open(SPEC) as f:
        spec = json.loads(f.read())
    ops = []
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method in ("get", "post", "put", "delete", "patch"):
                tag = (op.get("tags") or ["?"])[0]
                ops.append((method.upper(), path.replace("//", "/"), tag))
    return ops


def area_of(method: str, path: str, tag: str) -> str:
    key = f"{method} {path} [{tag}]"
    for name, rx in AREAS:
        if re.search(rx, key):
            return name
    return "Other"


def norm(path: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", path.rstrip("/"))


def used_paths(src: Path = SRC) -> set[str]:
    """Normalised API paths the curated tools call (string literals and f-strings in src/)."""
    out: set[str] = set()
    consts: dict[str, str] = {}
    for py in src.rglob("*.py"):
        text = py.read_text()
        for name, val in re.findall(r'^([A-Z_]+)\s*=\s*"(/dna/[^"]+)"', text, re.M):
            consts[name] = val
    for py in src.rglob("*.py"):
        text = py.read_text()
        for lit in re.findall(r'f?"(/dna/[^"]*)"', text):
            out.add(norm(lit))
        for name, rest in re.findall(r'f"\{([A-Z_]+)\}(/[^"]*)"', text):
            if name in consts:
                out.add(norm(consts[name] + rest))
        for name in consts:
            if re.search(rf"\b{name}\b", text):
                out.add(norm(consts[name]))
    # Paths built from a dict of suffixes (site settings, site detail endpoints).
    for suffix in (
        "aaaSettings",
        "bannerSettings",
        "dhcpSettings",
        "dnsSettings",
        "ntpSettings",
        "telemetrySettings",
        "timeZoneSettings",
        "imageDistributionSettings",
        "deviceCredentials",
    ):
        out.add(norm(f"/dna/intent/api/v1/sites/{{id}}/{suffix}"))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uncovered", help="list the uncovered operations of areas matching this text")
    ap.add_argument("--src", type=Path, default=SRC, help="package source to measure (default: this one)")
    args = ap.parse_args()
    ops = load_ops()
    used = used_paths(args.src)
    by_area: dict[str, list[tuple[str, str, str, bool]]] = defaultdict(list)
    for method, path, tag in ops:
        by_area[area_of(method, path, tag)].append((method, path, tag, norm(path) in used))
    if args.uncovered:
        for area, items in sorted(by_area.items()):
            if args.uncovered.lower() in area.lower():
                for m, p, t, c in items:
                    if not c:
                        print(f"{m:6} {p}  [{t}]")
        return
    total = len(ops)
    covered = sum(c for items in by_area.values() for *_, c in items)
    print(f"Operations: {total}; behind curated tools: {covered} ({100 * covered / total:.0f} %)\n")
    print("| Area | Operations | Curated | % |")
    print("|---|---:|---:|---:|")
    for area, items in sorted(by_area.items(), key=lambda kv: -len(kv[1])):
        n, c = len(items), sum(x[3] for x in items)
        print(f"| {area} | {n} | {c} | {100 * c / n:.0f} |")


if __name__ == "__main__":
    main()
