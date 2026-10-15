# Changelog

## Unreleased

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
  `ise_why_auth_failed`, `ise_endpoint_360`, `ise_set_endpoint`, `ise_create_authz_rule`).

### Changed
- Core pinned to v0.3.1 (`catc_get_definition(examples=True)`).

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
