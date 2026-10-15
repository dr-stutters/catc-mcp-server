# Changelog

## 0.8.2 (2026-10-15)

### Fixed
- Core v0.12.3: the bundled spec's 12 `//dna/...` paths are normalized, so `catc_search_spec` results can be used
  directly with `catc_api_call` (before, the double slash was rejected).

## 0.8.1 (2026-10-15)

### Changed
- Core bumped to stutters-mcp-core 0.12.2: `<prefix>_status` reports `server.server_version`; a list's
  "output truncated" warning is kept next to a tool's own `note`.
- `catc_search_spec` / `catc_get_definition` descriptions use Catalyst Center examples ('network device',
  '/dna/intent/api/v1/network-device/{id}') via the new `ServerSpec` options.

## 0.8.0 (2026-10-15)

Operator-eyes quality pass (D25-D30): 12 operator tasks run against the live lab through the tools only;
wrong answers and dead ends fixed. 126 tools (65 read, 40 write, 21 dangerous), 4 prompts.

### Fixed
- **Ghost devices and stale issues (D25)**: `catc_list_device_health` left in health records of devices deleted
  from the inventory ('which devices are unhealthy' named 3 deleted switches); they are now left out and named.
  Issue rows name their device, show `last_seen` and mark devices no longer in the inventory;
  `catc_device_360` groups repeated issues and warns that an old issue may already have cleared (OSPF_Down was
  reported 'active' while the adjacency was FULL).
- **Template deploys target only applicable devices (D26)**: by site/tag, devices outside the template's device
  families are skipped and listed (a Routers template by site previewed the WLC, which CatC then refuses).
- **Audit log (D27)**: readable UTC times, device column, severity, `changes_only=true`; `catc_recent_activity`
  lists changes only (before: 118 of 120 rows were internal provisioning chatter).

### Added
- **`catc_list_clients` (D29)**: wired/wireless clients by device/WLC, site, SSID, type, MAC, IP, connected_only.
- **Guidance (D28)**: instructions for settings vs templates, stale issues, what changed / who did it,
  template rollback, clients, health; onboarding prompt fixes; archive age note in `catc_compare_device_configs`.
- **Outputs (D30)**: `catc_get_issue` without internal attributes (3.7 -> 2.2 KB); deployments keep the realized
  CLI; readable times (templates, WLC, 360 compliance); site settings `inherited_from`; `catc_path_trace` takes
  device names.

## 0.7.0 (2026-10-15)

Roadmap items found during overnight 2 (D21-D24). 125 tools, 4 prompts.

### Added
- **Background tasks (D21)**: depends on `stutters-mcp-core[tasks]`; with `MCP_TASKS=true` the ten long tools
  (discovery, provisioning, template deploy, SWIM, WLC provisioning, PnP claim, RMA, fabric device, anycast
  gateway) run as MCP background tasks. Live: a discovery as a task.
- **Prompt `catc_decommission_device` (D22)** (dangerous tier, with ise): config copy, the un-provision = delete
  effects, untagging, delete with explicit clean_config, then the ISE NAD Catalyst Center leaves behind.
- **PnP lab rebuild (D23)**: `scripts/pnp_dhcp.py` (udhcpd + option 43 on mcp-catc-pnp, wired into the suite
  rebuild) and docs/pnp.md (option 43, CML autoinstall suppression, NCOB02066 claim hang, RMA needs SWIM).
- **Discovery explains missing devices (D24)**: `not_found` addresses and a note on serial collisions (CML
  cat9000v CMLUADP), reachability and credentials.

## 0.6.0 (2026-10-15)

Later items D13 (first slice), D14 and D16: 125 tools (64 read, 40 write, 21 dangerous), 3 prompts.

### Added
- **SD-Access writes (D13, first slice)**: `catc_create_fabric_site`, `catc_create_virtual_network` (write);
  `catc_add_fabric_device` (border/control plane/edge, border ASN), `catc_add_anycast_gateway`,
  `catc_assign_fabric_port`, `catc_delete_sda_object` (dangerous, reverse-order blockers). `catc_get_sda_fabric`
  returns ids and port assignments. Previews are live-checked; applying is refused by the dCloud 3.2.2 image
  (NCSP11008: no SD-Access application), which the tools now explain. `labs/mcp-catc-fabric.yaml`.
- **Wireless (D14)**: `catc_get_wireless_controller`; `catc_create_ssid` / `catc_delete_ssid` /
  `catc_create_wireless_profile` / `catc_delete_wireless_profile` (write; passphrases masked, bound by a keyed
  digest); `catc_provision_wireless_controller` (dangerous). Live on a 9800-CL (`labs/mcp-catc-wlc.yaml`).
- **Reports (D16)**: `catc_list_report_views`, `catc_get_report_view`, `catc_list_reports`,
  `catc_get_report_content` (CSV/JSON), `catc_create_report`, `catc_delete_report`; `catc_list_itsm_instances`.
  Live: Inventory report filtered to Routers.
- `scripts/lab_state.py seed` discovers the WLC when CML lab `mcp-catc-wlc` runs.

### Found live (3.2.2-75131)
- Every CML cat9000v reports serial CMLUADP: Catalyst Center merges them into one device. Give each a unique
  `conf/vswitch.xml` serial.
- Non-open SSIDs need an AKM and an RSN cipher (NCND10090); AP locations without a wireless profile are refused;
  the WLANs stay on the WLC when the design objects are deleted.
- Reports: viewGroupVersion isn't exposed (Inventory wants 2.0.0); `GET /data/reports` is 404 when empty; the
  download needs `Accept: application/octet-stream`; executions take ~7 minutes on dCloud.

### Changed
- The cortex container logs in as the least-privilege `mcp-catc-rw` account; `MCP_METRICS=true`.

## 0.5.0 (2026-10-15)

Production gate (D17, D19, D20) on core v0.12.0. D18 (version matrix) skipped overnight: it needs older
Catalyst Center releases.

### Added
- **Least-privilege roles (D17)**: `src/catc_mcp/rbac.py` defines three custom Catalyst Center roles
  (`mcp-catc-ro`, `mcp-catc-rw`, `mcp-catc-dangerous`); `scripts/seed_access.py` creates them with
  Global access groups and users from `.env` (idempotent, `--check`, `--delete`); docs/least-privilege.md lists
  every permission. Tested live on 3.2.2: read tier ok 53/denied 0 as `mcp-catc-ro`; the whole live suite as
  `mcp-catc-rw` (only template deploys get 403, as designed) and as `mcp-catc-admin` (all pass).
  `tests/live/test_least_privilege.py`.
- `catc_status` reports the account's roles and the tier they amount to (`catc.account`), with a warning when
  the role allows more than the enabled tiers.
- **Safety rails (D19)**: `CATC_MAX_DEVICES_PER_CHANGE` (default 10, 0 = off) blocks template deploys,
  provisioning, SWIM, PnP claims, device replacement and deletion that touch more devices; those tools plus
  resync and compliance runs report `blast_radius` for core's `MCP_MAX_BLAST_RADIUS`. Change windows, dry run
  and two-person approval (core G7) are covered by unit and live tests.
- `catc_deploy_template` targets a `site` (all devices below it, Global = whole inventory) or a `tag` as well as a
  device list; the preview shows the targets and the template version (number, commit time, comment); the
  confirm token is bound to the resolved devices.

### Changed
- **`catc_delete_device` (D20)**: `clean_config` is required; title "Delete device (un-provision)"; the
  description and preview say plainly that un-provisioning deletes the device (unmanaged, assurance history
  and config archive lost, the ISE NAD stays) and show the archived config versions that go.
  Live: r2 un-provisioned with clean_config=false (config stays on the device), then re-onboarded.
- Core pinned to v0.12.0 (safety rails, roles, secrets, metrics, OAuth, multi-instance, tasks, `config`).
- Live tests that need sw2 (`mcp-catc-onboard`) skip when it is unreachable.

### Found live (3.2.2-75131)
- Users created through the API without an access group get `accessGroups: [""]`; tag creation then fails
  inside Catalyst Center with a NullPointerException, whatever the role.
- Floors need *Network Design.Wireless Maps* Write; the template preview API needs *Network Design.Profiles &
  Settings* Write; template deploys need the dangerous role; Command Runner Read is enough for show commands.

## 0.4.0 (2026-10-15)

Roadmap "Next" (D8-D11): ISE integration and site AAA, PnP claim and RMA, and the
`catc_change_window` and `catc_onboard_switch_with_nac` prompts. 106 tools (58 read, 32 write, 16
dangerous) and 3 prompts. Core v0.4.0 (prompt test kit: cross-server references checked against the
ise manifest, prompt snapshots). D12 (SWIM live) moved to Later: no SWIM-importable image available.

### Added
- Prompt `catc_change_window(template, targets, window_end, params, rollback)` (D10): baseline ->
  preview -> safety rails -> deploy -> status -> verify -> diff -> compliance -> issue diff -> rollback
  plan. Live-tested on r1 + r2 (`tests/live/test_live_change_window.py`, deploy and negation rollback).
- ISE integration and site AAA (D8): `catc_get_policy_servers` (AAA/ISE servers, ISE node roles and
  trust, integration steps and the certificate waiting to be accepted; secrets never returned),
  `catc_update_site_aaa_settings` (write: network/client AAA as ISE or plain AAA, RADIUS/TACACS,
  inherit), and dangerous `catc_add_ise_server`, `catc_accept_ise_certificate` (preview shows the ISE
  certificate fingerprints), `catc_delete_policy_server`. Live: ISE 3.5 integrated (pxGrid), client
  AAA at a building, cat9000v provisioned there gets `radius server` -> ISE and a NAD in ISE.
- Prompt `catc_onboard_switch_with_nac(switch_ip, site_path, access_port, test_mac, auth_mode)` (D9,
  uses the ise server: `ise_get_nad`, `ise_create_nad`, `ise_find_session`, `ise_get_auth_history`,
  `ise_why_auth_failed`, `ise_endpoint_360`, `ise_set_endpoint`, `ise_create_authz_rule`). Live: closed-mode MAB on a cat9000v
  port, rejected (15039) until the endpoint was registered in ISE, then Authorized/PermitAccess.
- PnP and RMA (D11): dangerous `catc_claim_pnp_device` (site claim with a day-0 onboarding template
  and variables, optional image; waits for Provisioned), `catc_reset_pnp_device`,
  `catc_delete_pnp_device`; `catc_list_device_replacements`, `catc_mark_device_for_replacement`
  (write; blocks reachable devices and images missing from the repository, NCRM11042) and dangerous
  `catc_replace_device` (preview: both serials/PIDs and the config archive version restored). Live:
  a blank cat8000v claimed from PnP to mcp-test-floor1 with a day-0 template, Managed afterwards;
  RMA is mock-only (needs the faulty device's image imported, i.e. D12's image).

### Fixed
- `catc_list_pnp_devices`: the `state` filter now filters the device state (Unclaimed, Provisioned,
  Error...) instead of the onboarding sub-state, and the table shows both (`state`, `onboarding`).

### Changed
- Core pinned to v0.4.0 (via v0.3.1: `catc_get_definition(examples=True)`); `tests/manifests`
  (this server's and the ise server's tool manifests) and `tests/snapshots/prompts-rw`.

## 0.3.0 (2026-10-15)

Roadmap "Now" (D1-D6): pull-only activity lookups, network profiles, compliance policy authoring,
hardening, the lab seed/cleanup script and the `catc_onboard_device` prompt. 95 tools (56 read, 30
write, 9 dangerous) and 1 prompt. Core v0.3.0.

### Added
- `catc_list_event_notifications`: platform event notifications (`event/event-series`: device
  unreachable, link/OSPF alerts, config drift, reboots, licensing, system health), newest first, with
  type/category/domain/severity and device/site filters; audit records hidden unless asked for.
- `catc_recent_activity(device, site, hours, sources)`: issues, assurance events, notifications and
  the audit log for one window and scope, merged newest first with a `source` column; a failing source
  is reported under `errors` and the rest still returned. Pull-only (ADR-003): queried when called.
- Network profiles (D3): `catc_get_network_profile` (templates, sites incl. inherited),
  `catc_create_switching_profile` (SDA API, or the UI's `/api/v1/siteprofile` where the SDA package
  is absent), `catc_attach_template_to_profile` / `catc_detach_template_from_profile`,
  `catc_assign_profile_to_sites` / `catc_unassign_profile_from_sites`. Only switching and wireless
  profiles take templates. The provisioning API does not apply profile templates on 3.2.2 (checked
  live): deploy them with `catc_deploy_template`.
- Prompt `catc_onboard_device` (D6): credentials, discovery, inventory sync, site, settings and
  profile check, assign, provision, template deploy, verification (360, compliance, show commands,
  recent activity). Exercised live on a fresh cat9000v.

- `scripts/lab_state.py seed|cleanup|status` (D5): seeds or removes the mcp-test-* lab objects the
  live tests use (credentials, site hierarchy and settings, template project, switching profile, and
  the discovered + provisioned CML routers), through the server's own tools.

### Changed
- `catc_tag_golden_image` preview shows the image's current golden state per role at the site (and
  where it is inherited from) and refuses a no-op tag/untag.
- `catc_deploy_template` results and previews say Catalyst Center doesn't save the configuration and
  point to `catc_compare_device_configs(compare='startup')`.
- `catc_get_device_hardware` asks for the licence records of the device's family only.
- `gather_sections` moved from tools/smart.py to common.py.
- Core pinned to stutters-mcp-core **v0.3.0** (pull-only; no event APIs). Lists from APIs without a
  total (PnP devices, audit log) now report `next_offset` when the page was full (core 0.1.2 fix).
- Pagers: one per response shape on the client (`pager`, `data_pager`, `audit_pager`); the
  endpoint page-size caps (issues 25, events 20, audit 25, device health 500) are passed per call
  with `fetch_page(max_page=...)`. The module-level `DATA_PAGER`, `EVENTS_PAGER`, `AUDIT_PAGER` and
  `DEVICE_HEALTH_PAGER` are gone.
- Compliance policies (D4): `catc_list_compliance_policies`, `catc_get_compliance_policy` (rules,
  conditions, sites), `catc_list_compliance_violations` (per device or per site),
  `catc_create_compliance_policy` (policy + rules + regex/string conditions + sites in one preview,
  rolled back if a step fails), `catc_assign_compliance_policy` (add/remove/replace sites),
  `catc_delete_compliance_policy` (dangerous). Remediation stays on `catc_api_call`.
- `catc_create_discovery`: a bare address in a Range/Multi Range is sent as `ip-ip` (3.2.2 rejected
  it with "IPAddress for Range Discovery is invalid").
- `catc_list_audit_logs` takes `device` (hostname, IP, serial or id) and `site`. Catalyst Center tags
  few audit records with a device or site, so these filters also match the record text.
  `device_id` still works.

## 0.2.0 (2026-10-15)

Phase 2: gap analysis against the full 3.2.2 API (`docs/GAP-ANALYSIS.md`) and the first live tests
against real devices (CML cat8000v routers and a cat9000v switch with a client).

### Added
- Credentials: `catc_list_global_credentials`, `catc_create_global_credential` (CLI, SNMPv2c RO/RW,
  SNMPv3, NETCONF, HTTP(S); secrets never echoed), `catc_delete_global_credential`,
  `catc_assign_site_credentials`; `catc_get_site_settings` shows the site's credentials by name.
- Network settings writes: `catc_update_site_settings` (DNS, NTP, DHCP, banner, time zone, syslog/SNMP
  trap collectors, wired data collection) with a current-vs-new preview.
- IP pools: `catc_list_ip_pools`, `catc_create_ip_pool` (global pool or site reservation, overlap and
  containment checks), `catc_delete_ip_pool`.
- Config archive and drift: `catc_list_config_archive`, `catc_compare_device_configs` (vs previous
  version, running vs startup, or any two files; masked unified diff).
- `catc_get_device_hardware` (stack, PoE budget and ports, module count, smart-licensing state).
- `catc_get_template_deployment` (per-device deployment result).
- SWIM: `catc_list_device_images` (running image and golden-image compliance per device),
  `catc_tag_golden_image` (tag/untag).
- Platform reads: `catc_get_system_health` (service health, backups, licence, AAA/ISE servers),
  `catc_list_network_profiles`, `catc_list_pnp_devices`, `catc_get_sda_fabric`, `catc_list_ssids`.
- `scripts/gap_report.py` (API coverage per area); live tests against the CML routers
  (`tests/live/test_live_phase2.py`).

### Changed
- `catc_create_discovery`: pick global credentials by name, SNMP RW community, NETCONF port; with
  `wait=true` the result lists what was found; `Single` is sent as a one-address Range.
- `catc_provision_devices` re-provisions devices already provisioned at the site and refuses moves.
- `catc_delete_device` deletes provisioned devices through the provisioning API (Catalyst Center
  un-provisions and deletes in one step) instead of refusing them.
- `catc_delete_tag` refuses tags in use unless `remove_members=true`.
- `catc_assign_devices_to_site` shows each device's current site and skips devices already there.
- `catc_device_360`: health from `metricsDetails`, tags, provisioning state; `catc_client_360`:
  wired/wireless-specific fields, health per type, onboarding root causes.
- `catc_get_network_health`, `catc_list_events` (family inferred from the device; readable rows),
  `catc_list_issues` (readable times, compact columns) and `catc_get_compliance_detail`
  (non-compliant first) return compact, useful output.
- `catc_run_show_commands` accepts regex alternation (`| include up|down`), strips the echoed
  command and prompt, and shows empty output as "(no output)".

### Fixed
- Issue ids were missing from issue lists (the API calls them `issueId`), so issues couldn't be
  opened or resolved; `catc_get_issue` failed on every call (invalid `view`) and now includes the
  suggested actions and their commands.
- `catc_create_template` returned a JSON string as the template id when Catalyst Center had remarks;
  warnings are now reported separately.
- `catc_get_device_config(match=...)` matched anywhere in a section header.

## 0.1.1 (2026-10-15)

- Core pinned to stutters-mcp-core v0.1.1: nested secrets masked in the audit log, flag-like values
  ("true"/"false"/...) under secret-looking keys no longer masked, server starts even when the
  status probe fails with a configuration error.
- Removed the local missing-credentials workaround (core's `require_credentials` raises `AuthError`).
- `.dockerignore` follows the core template (keeps `.env` out of the build context).

## 0.1.0 (2026-10-15)

First release, built on stutters-mcp-core 0.1.0 and tested against Catalyst Center 3.2.2-75131.

- Login with `X-Auth-Token` (auto-renewed), optional static `CATC_TOKEN`, 1-based paging, 429 retries,
  task and business-API execution polling, readable errors from Catalyst Center's error bodies.
- 38 read tools: status, sites, inventory (devices, interfaces, masked running config, modules),
  assurance (network/device/client health, clients, issues, events), audit log, topology (physical,
  L3, VLAN), compliance, templates (list/get/preview), SWIM images, discoveries, tags, tasks, spec
  search/definitions; smart tools `catc_device_360`, `catc_client_360`, `catc_path_trace` and
  `catc_run_show_commands` (show-only). `catc_api_call` is GET-only unless the dangerous tier is on.
- Bundled 3.2.2 OpenAPI spec (exported from the appliance's Developer Toolkit).
- 16 preview-first write tools: sites, tags, template projects/templates (create, update, commit,
  delete), discovery, device site assignment, resync, compliance runs, issue resolve/ignore.
- 8 dangerous tools: template deploy, provisioning, SWIM distribute/activate, delete
  site/device/discovery, raw non-GET `catc_api_call`.
- Dockerfile and compose file for the HTTP transport (port 8034 on cortex).
