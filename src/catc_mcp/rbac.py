"""Catalyst Center RBAC: the least-privilege role definitions (roadmap D17) and the account check in
catc_status.

The three custom roles are tested in the lab (tests/live/test_least_privilege.py); docs/least-privilege.md
explains every permission and the API calls that create them. Permission ids are the leaf ids of
GET /dna/system/api/v2/roles/permissions (Catalyst Center 3.2.2). Anything a role doesn't list is Deny.
"""

from __future__ import annotations

from typing import Any

# Everything the read tier calls.
READ: dict[str, str] = {
    "Assurance.Monitoring": "Read",  # health, issues, events, clients, 360s, topology
    "Assurance.Troubleshooting": "Read",  # path trace
    "Assurance.Settings": "Read",  # issue settings behind catc_get_issue
    "Extensions.Event Subscription": "Read",  # event notifications (event-series)
    "Extensions.Intent API": "Read",
    "Network Design.Profiles & Settings": "Read",  # site settings, credentials, IP pools, profiles, templates
    "Network Management.Discovery": "Read",
    "Network Management.Hierarchy": "Read",  # (minimum Read)
    "Network Management.Inventory": "Read",  # devices, interfaces, modules, config, archive, tags
    "Network Management.License": "Read",  # catc_get_device_hardware licence records
    "Network Management.Network-wide Settings": "Read",  # (fixed at Read)
    "Network Operations.Compliance": "Read",
    "Network Operations.Device Replacement & Refresh": "Read",  # RMA list
    "Network Operations.PnP": "Read",
    "Network Operations.SWIM": "Read",  # images, golden tags
    "Network Provision.Device Provision": "Read",  # provisioning status in device_360
    "Network Provision.Network-wide Config": "Read",  # (fixed at Read)
    "Network Provision.SD-Access": "Read",  # catc_get_sda_fabric
    # The next two exist only once the Access Control Application / SD Access packages are deployed
    # (seed_access.py skips permissions an appliance doesn't have). SD-Access depends on Group-Based
    # Policy Read.
    "Policy.Group-Based Policy": "Read",
    "Network Operations.LAN Automation": "Read",  # LAN automation sessions and status
    "Security.Audit Log": "Read",  # audit logs, recent activity
    "Security.SSI": "Read",  # catc_get_ssi_readiness (Security Service Insertion readiness)
    "System.System Settings": "Read",  # catc_get_policy_servers (ISE)
    # catc_get_system_health, catc_list_backups / catc_get_backup_status, the account check in catc_status.
    # Its maximum is Read on 3.2.2, so catc_create_backup needs SUPER-ADMIN-ROLE (docs/least-privilege.md).
    "System.System Administration": "Read",
    "Utilities.Command Runner": "Read",  # catc_run_show_commands (Read is enough for show commands)
    "Utilities.Event Viewer": "Read",
    "Utilities.Scheduler": "Read",  # (minimum Read)
    "Utilities.Machine Reasoner": "Read",  # dependency of Assurance.Monitoring
    "Utilities.Reports": "Read",  # dependency of Assurance.Monitoring
    "Utilities.App Hosting": "Read",  # dependency of Assurance.Monitoring
}
# The write tier on top of READ.
WRITE: dict[str, str] = {
    **READ,
    "Assurance.Monitoring": "Write",  # catc_update_issue_status
    "Network Design.Profiles & Settings": "Write",  # settings, creds, pools, profiles, templates, preview
    "Network Design.Wireless Maps": "Write",  # floors (POST/PUT/DELETE /v2/floors are map operations)
    "Network Management.Discovery": "Write",
    "Network Management.Hierarchy": "Write",  # sites, assign devices to sites
    "Network Management.Inventory": "Write",  # resync, tags
    "Network Operations.Compliance": "Write",  # compliance runs and policies
    "Network Operations.Device Replacement & Refresh": "Write",  # mark for replacement
    "Network Operations.SWIM": "Write",  # golden tagging (distribute/activate are MCP-dangerous)
}
# The dangerous tier: provisioning, PnP claims, SDA, ISE integration (System Settings).
DANGEROUS: dict[str, str] = {
    **WRITE,
    "Network Operations.PnP": "Write",
    "Network Provision.Device Provision": "Write",
    "Network Provision.SD-Access": "Write",
    # A dependency of Device Provision and SD-Access Write (GET /dna/system/api/v2/roles/permissions).
    "Utilities.Scheduler": "Write",
    # The ISE integration writes (catc_add_ise_server / update / accept / delete policy server) need
    # SUPER-ADMIN-ROLE: 3.2.2 refuses them (403) to custom roles even with every System permission at Write.
    "System.System Settings": "Write",
}
ROLES: dict[str, tuple[str, dict[str, str]]] = {
    "mcp-catc-ro": ("catc-mcp-server read tier. Managed by the suite's seed step.", READ),
    "mcp-catc-rw": ("catc-mcp-server read + write tiers. Managed by the suite's seed step.", WRITE),
    "mcp-catc-dangerous": ("catc-mcp-server every tier. Managed by the suite's seed step.", DANGEROUS),
}
# Built-in roles (roleList names and v2 ids) and the server tier they amount to.
BUILTIN_TIERS = {
    "SUPER-ADMIN": "admin",
    "SUPER-ADMIN-ROLE": "admin",
    "NW-ADMIN": "dangerous",
    "NETWORK-ADMIN-ROLE": "dangerous",
    "OBSERVER": "ro",
    "OBSERVER-ROLE": "ro",
}
TIER_ORDER = {"unknown": -1, "ro": 0, "rw": 1, "dangerous": 2, "admin": 3}
_WRITE_GRANTS = {k for k, v in WRITE.items() if v == "Write"}
_DANGEROUS_GRANTS = {k for k, v in DANGEROUS.items() if v == "Write"}


def permissions_tier(permissions: list[dict[str, Any]]) -> str:
    """The server tier a custom role's permission list amounts to: `ro` (no Write), `rw` (Write only where
    the write role has it), `dangerous` (Write only where the dangerous role has it) or `admin` (Write
    anywhere else, e.g. System Administration)."""
    writes = {str(p.get("id")) for p in permissions if str(p.get("privilege", "")).lower() == "write"}
    if not writes:
        return "ro"
    if writes <= _WRITE_GRANTS:
        return "rw"
    return "dangerous" if writes <= _DANGEROUS_GRANTS else "admin"


def enabled_tier(writes: bool, dangerous: bool) -> str:
    return "dangerous" if writes and dangerous else "rw" if writes else "ro"


def account_check(role_tiers: dict[str, str], enabled: str) -> dict[str, Any]:
    """Status block: the account's roles, the tier they amount to, and a warning when it exceeds what the
    server has enabled (least privilege) or falls short of it (tools Catalyst Center will refuse)."""
    tier = max(role_tiers.values(), key=lambda t: TIER_ORDER.get(t, -1)) if role_tiers else "unknown"
    out: dict[str, Any] = {"roles": sorted(role_tiers), "role_tier": tier, "enabled_tier": enabled}
    if tier == "unknown":
        return out
    if TIER_ORDER[tier] > TIER_ORDER[enabled]:
        out["warning"] = (
            f"The Catalyst Center account has {tier} permissions but this server only enables {enabled} "
            "tools: "
            "use a least-privilege account (role mcp-catc-ro / mcp-catc-rw / mcp-catc-dangerous, "
            "docs/least-privilege.md)."
        )
    elif TIER_ORDER[tier] < TIER_ORDER[enabled]:
        out["note"] = (
            f"The account's role amounts to {tier}, below the enabled {enabled} tier: Catalyst Center will "
            "refuse some write tools (403)."
        )
    return out
