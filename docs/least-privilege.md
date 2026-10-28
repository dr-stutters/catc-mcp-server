# Least-privilege accounts for `catc-mcp-server`

The server needs one Catalyst Center account. Give it the smallest role that covers the tiers you enable:

| Server tiers enabled | Account (lab) | Role |
|---|---|---|
| read only (default) | `mcp-catc-ro` | custom `mcp-catc-ro` |
| read + write (`MCP_ENABLE_WRITES=true`) | `mcp-catc-rw` | custom `mcp-catc-rw` |
| + dangerous (`MCP_ENABLE_DANGEROUS=true`) | `mcp-catc-admin` | custom `mcp-catc-dangerous` |

Never use SUPER-ADMIN-ROLE (or NETWORK-ADMIN-ROLE) for a hosted server. `catc_status` shows the account's
roles, the tier they amount to and a **warning when the role allows more than the enabled tiers**
(`catc.account`). MCP-side roles (`MCP_ROLES`, core docs/PRODUCTION.md) restrict *callers*; this guide
restricts *the server itself*. Use both.

The three roles are defined in code (`src/catc_mcp/rbac.py`), created through the API calls in section 4, and
checked by `tests/live/test_least_privilege.py`. Tested on Catalyst Center **3.2.2-75131** (lab), 2026-10-15.

## How Catalyst Center RBAC works (what we found)

- A role is a list of leaf permissions (`GET /dna/system/api/v2/roles/permissions`: 40 on 3.2.2, e.g.
  `Network Management.Inventory`), each `Deny`, `Read` or `Write`. Catalyst Center stores only the non-Deny
  ones. Some have a floor or a ceiling (`Network Management.Hierarchy` minimum Read, `Network Provision.Network-wide
  Config` maximum Read). Send **every** leaf permission when you create or update a role (unlisted ones as Deny), so an
  upgrade that adds a permission with a Read default doesn't silently widen the role.
- A user needs an **access group** binding its role to a scope (`/dna/system/api/v1/accessGroups`, scope = the
  Global site here). A user created through the API with only `roleList` gets `accessGroups: [""]`: it logs in and
  reads fine, but some writes fail *inside* Catalyst Center (tag creation: `Failed to add members based on the rules.
  java.lang.NullPointerException`), for custom and built-in roles alike. Create a
  `<role>_GLOBAL` access group per role and assign it to the user.
- Password policy: no more than two consecutive characters of the user name or full name.
- A denied API call returns HTTP 403 "Role does not have valid permissions to access the API"; the server reports
  it as "Catalyst Center denied access (403) on <METHOD> <path>".

## 1. Read-only role: `mcp-catc-ro`

| Permission (Catalyst Center id) | Privilege | Needed by |
|---|---|---|
| Assurance.Monitoring | Read | health, issues, events, clients, `catc_device_360` / `catc_client_360`, topology |
| Assurance.Troubleshooting | Read | `catc_path_trace` (Read is enough to run a path trace) |
| Assurance.Settings | Read | issue settings behind `catc_get_issue` |
| Extensions.Event Subscription | Read | `catc_list_event_notifications`, `catc_recent_activity` |
| Extensions.Intent API | Read | the Intent API itself |
| Network Design.Profiles & Settings | Read | site settings, credentials list, IP pools, network profiles, templates |
| Network Management.Discovery | Read | `catc_list_discoveries`, `catc_list_discovery_devices` |
| Network Management.Hierarchy | Read | sites (minimum Read) |
| Network Management.Inventory | Read | devices, interfaces, modules, config, config archive, tags |
| Network Management.License | Read | licence records in `catc_get_device_hardware` |
| Network Management.Network-wide Settings | Read | (fixed at Read) |
| Network Operations.Compliance | Read | compliance summary/detail, policies, violations |
| Network Operations.Device Replacement & Refresh | Read | `catc_list_device_replacements` |
| Network Operations.PnP | Read | `catc_list_pnp_devices` |
| Network Operations.SWIM | Read | images, golden tags |
| Network Provision.Device Provision | Read | provisioning status in `catc_device_360` |
| Network Provision.Network-wide Config | Read | (fixed at Read) |
| Network Provision.SD-Access | Read | `catc_get_sda_fabric` and the other SD-Access reads |
| Policy.Group-Based Policy | Read | a dependency of Network Provision.SD-Access (exists once the `aca` package is deployed) |
| Network Operations.LAN Automation | Read | LAN automation sessions and status (exists once `sda` is deployed; 403 without it) |
| Security.Audit Log | Read | `catc_list_audit_logs`, `catc_recent_activity` |
| Security.SSI | Read | `catc_get_ssi_readiness` (Security Service Insertion readiness). On 3.2.2 custom roles get 403 on the SSI API even with this (Read is its maximum); only a SUPER-ADMIN-ROLE account read it in the live test |
| Security.Security Advisory | Read | `catc_security_advisories` and the PSIRT part of `catc_lifecycle_signals` (403 without it) |
| System.System Settings | Read | `catc_get_policy_servers` (ISE integration) |
| System.System Administration | Read | `catc_get_system_health`, `catc_list_backups`, `catc_get_backup_status`, the account check in `catc_status` |
| Utilities.Command Runner | Read | `catc_run_show_commands` (Read is enough for show commands) |
| Utilities.Event Viewer, Scheduler, Machine Reasoner, Reports, App Hosting | Read | dependencies of Assurance.Monitoring |

**Denied** (not used by any read tool): Extensions.ITSM, Network Design.Wireless Maps (floor writes only), Policy.Application
Policy, Policy.IP Based Access Control, Security.Rogue and aWIPS,
Stealthwatch, Umbrella, Utilities.Bonjour, Utilities.Remote Support Authorization.

**Expected denial in the read tier:** `catc_preview_template`. The template preview API is a `PUT` that needs
*Network Design.Profiles & Settings* **Write**; the read-only role doesn't get it. Use the rw account to preview
templates (the write-tier template tools preview anyway).

## 2. Write role: `mcp-catc-rw`

Everything in `mcp-catc-ro`, plus Write on:

| Permission | Write tools it enables |
|---|---|
| Assurance.Monitoring | `catc_update_issue_status` |
| Network Design.Profiles & Settings | site settings and AAA, global credentials, IP pools, network profiles and template attachment, template projects/templates/commit, `catc_preview_template` |
| Network Design.Wireless Maps | creating, updating and deleting **floors** (`/v2/floors`) |
| Network Management.Discovery | `catc_create_discovery` |
| Network Management.Hierarchy | `catc_create_site`, `catc_update_site`, `catc_assign_devices_to_site` |
| Network Management.Inventory | `catc_resync_devices`, `catc_set_device_role` (`PUT network-device/brief`), tags and tag members |
| Network Operations.Compliance | `catc_run_compliance`, compliance policies, the field notice scan of `catc_trigger_lifecycle_scan` |
| Security.Security Advisory | the security advisory scan of `catc_trigger_lifecycle_scan` |
| Utilities.Machine Reasoner | the network bug scan of `catc_trigger_lifecycle_scan` (the permission that scans for Cisco bugs) |
| Network Operations.Device Replacement & Refresh | `catc_mark_device_for_replacement` |
| Network Operations.SWIM | `catc_tag_golden_image` |

**Stays Read (dangerous-only):** Network Provision.Device Provision, Network Operations.PnP, Network Provision.SD-Access,
System.System Settings. So Catalyst Center itself refuses provisioning, PnP claims and ISE integration changes to this
account (tested: re-provisioning a router as `mcp-catc-rw` → 403).

Catalyst Center's permissions don't line up exactly with the server's tiers: Hierarchy Write also allows deleting
sites, and Inventory Write allows deleting devices. Those tools are in the server's dangerous tier, so with
`MCP_ENABLE_DANGEROUS=false` they aren't registered; the role alone doesn't stop them.

## 3. Dangerous role: `mcp-catc-dangerous`

Everything in `mcp-catc-rw`, plus Write on Network Operations.PnP (`catc_claim_pnp_device`, reset, delete),
Network Provision.Device Provision (`catc_provision_devices`, `catc_delete_device` of a provisioned device,
`catc_replace_device`; template deploys also need this role: tested, rw gets 403 on the deploy API), Network Provision.SD-Access, Utilities.Scheduler (a dependency of Device Provision and SD-Access Write) and System.System Settings.

**After deploying the SD-Access packages, re-run the seed step.** Installing `aca` + `sda` adds Policy.Group-Based
Policy and Network Operations.LAN Automation to the permission list, and SD-Access Write then depends on Group-Based
Policy Read; roles created before the install have them at Deny (seen on the 3.2.2 lab appliance, 2026-10-21:
LAN automation reads answered 403 to `mcp-catc-rw`).

**The ISE integration writes need SUPER-ADMIN-ROLE.** `catc_add_ise_server`, `catc_update_policy_server`,
`catc_accept_ise_certificate` and `catc_delete_policy_server` are refused to every custom role on 3.2.2: tested
2026-10-21, `mcp-catc-dangerous` with every System permission at Write still gets 403 "Role does not have valid
permissions to access the API" on `PUT authentication-policy-servers/{id}` and `PUT integrate-ise/{id}`, while the
reads (`GET authentication-policy-servers`, `GET ise-integration-status`) work with System Settings Read. Run those
four tools from an instance whose account has SUPER-ADMIN-ROLE (only while you need them), or make the change in the
GUI.

**Backups need SUPER-ADMIN-ROLE too.** `catc_create_backup` is a write under System.System Administration, the
permission whose description covers "HA, Disaster Recovery, System Health, Backup and Restore", and on 3.2.2 its
`maximumPrivilege` is **Read** (`GET /dna/system/api/v2/roles/permissions`, 2026-10-22): no custom role can take a
backup, so the dangerous role does not change for it. The reads (`catc_list_backups`, `catc_get_backup_status`) work
with System Administration Read (checked live as `mcp-catc-rw`, 2026-10-22). The create itself is unit-tested only:
the lab appliance has no backup target. When the account's roles are not SUPER-ADMIN-ROLE the preview says so, and a
403 names this section. Take the backup from a SUPER-ADMIN-ROLE instance while you need it, or in the GUI
(*System > Backup & Restore*). SWIM distribute/activate use
SWIM Write (already in rw). Prefer a separate server instance (token, container) for this tier.

## 4. Create them

GUI: *System > Users & Roles > Role Based Access Control > Create a New Role* (set each permission as in the
tables; everything else Deny), then *User Management > Add* with that role.

API, as a SUPER-ADMIN (create each object only if it is missing, so the steps can be re-run):

```bash
POST /dna/system/api/v2/roles          {"name": "mcp-catc-ro", "description": "...", "permissions": [{"id": "Assurance.Monitoring", "privilege": "Read"}, ...]}
PUT  /dna/system/api/v2/roles/{id}     (same body, to update)
POST /dna/system/api/v1/accessGroups   {"name": "mcp-catc-ro_GLOBAL", "role": ["mcp-catc-ro"], "resourceGroups": [{"name": "Global", "srcResourceId": "*", "type": "site"}]}
POST /dna/system/api/v1/user           {"username": "mcp-catc-ro", "password": "...", "firstName": "mcp", "lastName": "mcp-catc-ro", "roleList": ["mcp-catc-ro"], "accessGroups": ["<group id>"]}
```

1. `GET /dna/system/api/v2/roles/permissions` for the leaf permission ids, then build each role's body from
   `ROLES` in `src/catc_mcp/rbac.py`: the listed privilege, every other leaf permission `Deny` (clamped to the
   permission's `minimumPrivilege` / `maximumPrivilege`).
2. `GET /dna/system/api/v2/roles`: POST the roles that are missing; for an existing one, compare its permissions
   (`GET /dna/system/api/v2/roles/{id}`; Catalyst Center omits Deny entries) and PUT when they differ.
3. `GET /dna/system/api/v1/accessGroups`: POST the missing `<role>_GLOBAL` groups, then read them back for their ids.
4. `GET /dna/system/api/v1/user`: POST missing users with their role and access group; PUT existing ones whose
   `roleList` / `accessGroups` differ (the user PUT can't change a password: delete and re-create the user to
   reset it). Never change the admin you run as, or an account with a built-in role.

Removing them is the reverse: DELETE the users, then the access groups, then the roles. On hosted servers store
the server's password as a Docker secret (`CATC_PASSWORD_FILE`), not in `.env`. The live test reads the accounts
as `CATC_RO_USERNAME`/`CATC_RO_PASSWORD` and `CATC_RW_USERNAME`/`CATC_RW_PASSWORD` ([live-tests.md](live-tests.md)).

## 5. Verify

```bash
uv run pytest -m live tests/live/test_least_privilege.py -v -s
```

- `test_read_tier_as_readonly_user`: logs in as `mcp-catc-ro`, calls every read tool as an MCP `ro` caller
  (core `assert_read_tier_works`) and checks that write tools are hidden; `catc_preview_template` must be the only
  403. Result on 3.2.2-75131: **ok 53, denied 0, errors 0, skipped 6** (5 need ids from earlier calls, plus the
  expected preview denial, asserted separately).
- `test_write_tier_as_rw_user`: as `mcp-catc-rw`, creates and deletes a tag and an area; re-provisioning
  `CATC_LIVE_ROUTER1` is refused by Catalyst Center (403).
- Whole live suite per account: `CATC_USERNAME=mcp-catc-rw CATC_PASSWORD=... uv run pytest tests/live -m live`
  (results below).

| Live suite run as (2026-10-15, 3.2.2-75131) | Result |
|---|---|
| `mcp-catc-rw` | everything passes except the **5 tests that deploy templates** (change window, compliance policy, link-down activity, Day-N deploy, onboarding): `POST /v2/template-programmer/template/deploy` → 403, as intended (template deploys are dangerous tier) |
| `mcp-catc-admin` (`mcp-catc-dangerous`) | **all pass** (39 tests; PnP/RMA and sw2 tests skip when their CML labs are stopped) |
| `mcp-catc-ro` | read tier: ok 53, denied 0 (`test_read_tier_as_readonly_user`) |

The first rw run also found that **floors** need *Network Design.Wireless Maps* Write (`POST /v2/floors` → 403
with only Hierarchy Write): Catalyst Center treats floors as wireless maps. Both write roles include it.

## 6. Lab rebuild

Recreate the roles, access groups and users (section 4) whenever the Catalyst Center is rebuilt. The suite's own
seed script for this, part of its lab rebuild, lives in the private lab repo (stutters-mcp-lab).
