# catc-mcp-server roadmap
_Last updated 2026-10-15: logs and events are pull-only ([ADR-003](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/adr/003-no-event-ingestion.md)); D7 (webhooks) dropped, D2 reframed as on-demand activity lookups. Current release v0.2.0. Suite roadmap: [stutters-mcp-core/ROADMAP.md](https://github.com/dr-stutters/stutters-mcp-core/blob/main/ROADMAP.md). Gap analysis: [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)._

## Summary
- v0.2.0 covers onboarding, day-N change and troubleshooting against Catalyst Center 3.2.2: 81 tools, 34 of 38 operator workflows curated, and live tests on real CML devices (r1/r2 cat8000v, sw1 cat9000v). Everything else is reachable through `catc_api_call`, except 12 multipart/binary operations.
- Biggest gaps: issues, assurance events and the audit log are each queryable, but platform event notifications aren't curated and there is no merged "what happened here recently" view; four workflows still on api_call (AAA/ISE site settings, PnP claim, LAN automation, template-to-profile attach); SWIM distribute/activate is mock-only (no `.bin` image); SDA and wireless are read-only; compliance policy authoring, reports, ITSM and RMA aren't curated.
- **Now** gives the server on-demand activity lookups that need no appliance setup (issues, assurance events, event notifications and audit log, merged by time; pull-only per ADR-003), template-to-profile attach, compliance policy authoring, hardening of known rough edges plus a lab seed/cleanup script, the core v0.3.0 bump and pager clean-up (C1/C5) and the `catc_onboard_device` prompt.
- **Next** brings ISE integration and AAA, the NAC and change-window prompts, PnP/RMA and live SWIM. SWIM is blocked on a cisco.com image. Webhooks (D7) were dropped: the servers never receive pushed data.
- **Later** is SDA writes, wireless, LAN automation, and reports/ITSM. These are bounded by the 5-node CML EVAL cap and missing AP/ServiceNow resources.

## Now
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| D1 | **Core v0.3.0 bump and per-endpoint page caps**: pin core v0.3.0 (pull-only; includes the 0.1.2 fix for core C1) so lists without a total (PnP, audit log) keep `Page.more`. Replace the four per-cap pagers (data 25, events 20, audit 25 with 0-based offsets, device health 500) with `fetch_page(max_page=...)` (core C5) | Lists that silently look complete lead the model to wrong conclusions | none | Unit (respx: no totals, caps); live read suite on dCloud CatC | S | [#8](https://github.com/dr-stutters/catc-mcp-server/issues/8) |
| D2 | **On-demand activity lookups**: new `catc_list_event_notifications` (platform notifications, `event/event-series`) and `catc_recent_activity(since, device, site)`, which queries issues, assurance events, notifications and the audit log for one window and merges them by time; `catc_list_audit_logs` accepts a device name/IP. Existing `catc_list_issues`, `catc_list_events` and `catc_list_audit_logs` stay (`catc_list_events` keeps its name). Queried when called; no poller or buffer | "What happened on this device or site recently?" in one call, with zero appliance setup; feeds `ise_incident_timeline` | none (server → CatC :443, already in place) | Live `catc-routers`: shut r2 Gi2, then `catc_recent_activity(device=r2)` shows the issue and events; a settings change shows from the audit log. Unit: merge order, one source failing | M | [#9](https://github.com/dr-stutters/catc-mcp-server/issues/9) |
| D3 | **Template ↔ network profile ↔ site**: `catc_attach/detach_template_to_profile`, `catc_assign_profile_to_sites` (preview-first) | Day-N templates on a profile are what provisioning applies. Closes an uncovered workflow | A network profile created once in the UI (the 3.2.2 API has no create call) | Live `catc-routers`: attach `mcp-test-loopback`, assign to mcp-test-lab, re-provision r1, check the CLI | S | [#10](https://github.com/dr-stutters/catc-mcp-server/issues/10) |
| D4 | **Compliance policy authoring**: list/get policies with rules, conditions and violations; create and assign policies (write); delete (dangerous). Remediation stays on api_call | Compliance against *our* standard, not only "in sync" | none (3.2.x API, version-gated per D18) | Live `catc-routers`: a "no ip http server" policy gives an r1 violation; a template fix makes it compliant | M | [#11](https://github.com/dr-stutters/catc-mcp-server/issues/11) |
| D5 | **Hardening**: the Phase 2 review deferrals (golden-tag preview state, `_gather_sections` location, licence fetch by IP); `/discoverys` alongside the deprecated `/discovery`; a deploy warning that CatC doesn't save config; `scripts/lab_state.py seed\|cleanup` for the hand-left lab objects | Fix known rough edges and make the live suite repeatable | none | Live `catc-routers`: seed → suite → cleanup → seed. Unit per fix | M | [#12](https://github.com/dr-stutters/catc-mcp-server/issues/12) |
| D6 | **Prompt `catc_onboard_device`**: credentials → discovery (wait) → site → settings check → provision → verify (360, compliance, show commands) | The most common CatC task, done end to end in the order learned in the lab | none | Live `catc-routers`: delete r2, re-onboard it through the prompt; core C9 snapshot | S | [#13](https://github.com/dr-stutters/catc-mcp-server/issues/13) |

## Next
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| ❌ D7 | ~~Event Management webhooks~~: **dropped (ADR-003)**. Servers never receive pushed data; CatC events are queried on demand (D2) | — | — | — | — | [#14](https://github.com/dr-stutters/catc-mcp-server/issues/14) (closed) |
| D8 | **ISE integration and per-site AAA**: `catc_list_policy_servers`, `catc_get/update_site_aaa_settings`, and `catc_add_ise_server` (dangerous) | The start of 802.1X/MAB and SDA; provisioning pushes AAA and creates the ISE NAD | ISE 198.18.134.35 with ERS and the **pxGrid persona** on; ISE GUI and CLI credentials for CatC; **CatC → ISE** :443, :8910, :22 | Live `ise-access`: AAA at mcp-test-lab, provision sw1, check the CLI and the NAD in ISE | M | [#15](https://github.com/dr-stutters/catc-mcp-server/issues/15) |
| D9 | **Prompt `catc_onboard_switch_with_nac`** (with ise): D6 onboarding, then AAA (D8), ISE NAD check, an access-port 802.1X/MAB template, first-auth check (`ise_session_by_mac`) and `catc_client_360` | The most frequent cross-product NAC job | As D8; the ise server available to the client | Live `ise-access`: Alpine MAB, including an ISE rule for its MAC | S | [#16](https://github.com/dr-stutters/catc-mcp-server/issues/16) |
| D10 | **Prompt `catc_change_window`**: baseline → preview → rails check (D19/G7) → deploy → verify → compliance → diff → issue diff → rollback plan | Every change gets a baseline, a verification and a rollback | none | Live `catc-routers`: `mcp-test-loopback` on r1+r2, then roll back | S | [#17](https://github.com/dr-stutters/catc-mcp-server/issues/17) |
| D11 | **PnP claim and RMA**: `catc_claim/reset/delete_pnp_device` (dangerous) and `catc_list_device_replacements`, `catc_mark_device_for_replacement`, `catc_replace_device` (dangerous). Closes the PnP workflow | Zero-touch day-0 and like-for-like replacement | CML recipe `catc-pnp`: a blank cat8000v plus dnsmasq with option 43 → 198.18.128.11. **Device → CatC** :80/:443. RMA needs a same-PID replacement that arrives unclaimed | Live: claim to mcp-test-floor1 with a day-0 template; RMA r2 → new cat8000v | L | [#18](https://github.com/dr-stutters/catc-mcp-server/issues/18) |
| D12 | **SWIM live**: `catc_import_image_url`, plus live distribute/activate (mock-only today), with long-job handling (core C12) | Upgrades are high-risk and still mocked | **Blocked**: a `c8000v-universalk9.<ver>.SPA.bin` (~1 GB, a different version from the running one), a CCO account entitled to download it, an HTTP server CatC can reach (e.g. a CML `nginx` node), and bootflash space on r1 | Live `catc-routers` r1: import → golden → distribute → activate → verify; r2 as control | M | [#19](https://github.com/dr-stutters/catc-mcp-server/issues/19) |

## Later
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| D13 | **SDA writes**: fabric sites, fabric device roles, L3 VNs, anycast gateways and port assignments, preview-first; deletes are dangerous | CatC's intent model pays off in SDA (169 ops, read-only today) | ISE with pxGrid (D8); cat9000v fabric-role support to confirm on 17.18; a `catc-sda` recipe of 2 × cat9000v + Alpine (3 nodes, so `catc-routers` is stopped) | Live `catc-sda`: fabric site, VN and gateway, edge port; Alpine gets DHCP in the VN | L | [#20](https://github.com/dr-stutters/catc-mcp-server/issues/20) |
| D14 | **Wireless**: provision a cat9800-CL as WLC, SSIDs and wireless profiles, WLC/AP reads | Half of a campus; only SSIDs are readable today | cat9800 is in CML. **CML has no AP node**, so AP join, RF and wireless clients need a physical AP through an external connector (not available) | Live `catc-wlc`: discover, provision, SSID + profile, check the 9800 CLI; AP parts mock-only | L | [#21](https://github.com/dr-stutters/catc-mcp-server/issues/21) |
| D15 | **LAN automation**: start (v2, dangerous), status, log, stop | Greenfield underlay; rare but very error-prone | A seed plus 1–2 blank cat9000v (18 GB each, most of the EVAL cap), a LAN-automation IP pool, PnP (D11) | Live: the underlay is built and the devices land at the site | L | [#22](https://github.com/dr-stutters/catc-mcp-server/issues/22) |
| D16 | **Reports and ITSM**: report templates, create (JSON/CSV only), executions and text content; ITSM instances, integration events and issue→ITSM subscriptions | Scheduled reports and ticket hand-off | Reports: none. ITSM: a ServiceNow PDI with the CatC app, the ITSM bundle, and **CatC → ServiceNow** :443 (dCloud egress unverified) | Live: an inventory report on the `catc-routers` devices; ITSM mock-only | M | [#23](https://github.com/dr-stutters/catc-mcp-server/issues/23) |

## Logs and events (pull-only, ADR-003)
Every tool queries Catalyst Center when called ([ADR-003](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/adr/003-no-event-ingestion.md)). No webhooks, syslog subscriptions, pollers or buffers; the history available is what CatC keeps.

| Tool | What it reads | Status |
|---|---|---|
| `catc_list_issues`, `catc_get_issue` | Assurance issues (priority, status, site, device, client MAC) and their suggested actions | ✅ v0.2.0 |
| `catc_list_events` | Assurance events: device syslog, SNMP traps, client onboarding (up to 7 days) | ✅ v0.2.0 |
| `catc_list_audit_logs` | Who changed what, including changes made outside MCP (up to 30 days) | ✅ v0.2.0 |
| `catc_list_event_notifications` (D2) | Platform event notifications (device unreachable, provisioning, SWIM, system) | Now |
| `catc_recent_activity` (D2) | Issues + assurance events + notifications + audit log for a device or site, merged by time | Now |

## Workflow prompts owned by this server
| Prompt | What it does | Other servers used | Bucket |
|---|---|---|---|
| `catc_onboard_device` | Credentials → discovery → site → settings → provision → verify (D6) | none | Now |
| `catc_onboard_switch_with_nac` | CatC onboarding, ISE integration and site AAA, ISE NAD check, 802.1X/MAB port template, first auth check (D9) | ise | Next |
| `catc_change_window` | Template preview → deploy → verify → compliance → rollback plan, inside the rails (D10) | none | Next |

CatC is also a data source for prompts owned by other servers: `ise_troubleshoot_endpoint_access` (device CLI and client 360), `ise_incident_timeline` (CatC issues, events and audit log, queried on demand through D2) and `cml_replicate_site` (site, settings and templates).

## Production gate (server-specific)
- [ ] **D17 Custom RBAC roles** ([#24](https://github.com/dr-stutters/catc-mcp-server/issues/24)): `ro`, `rw` and `dangerous` CatC roles defined through `/dna/system/api/v2/roles`, and tested with one user each. `catc_status` warns when the role exceeds the enabled tier. Feeds core [G3](https://github.com/dr-stutters/stutters-mcp-core/issues/20).
- [ ] **D18 Version matrix 2.3.7.x / 3.1 / 3.2** ([#25](https://github.com/dr-stutters/catc-mcp-server/issues/25)): one bundled spec per minor version, exported from that version's Developer Toolkit. The spec is picked from `installedVersion` (nearest lower, with a warning) or set with `CATC_SPEC_VERSION`. Tools declare a minimum version and refuse cleanly below it: SWIM `networkDeviceImages` 3.1.3+, compliancePolicys, `aaaSettings`, `/discoverys` 3.2.1. The live suite runs per version. Feeds core [G6](https://github.com/dr-stutters/stutters-mcp-core/issues/23).
- [ ] **D19 Safety rails** ([#26](https://github.com/dr-stutters/catc-mcp-server/issues/26)): `CATC_MAX_DEVICES_PER_CHANGE` (default 10) for deploy, provision, SWIM and claim. A change-window guard on every dangerous tool. Confirm tokens bind the resolved device ids; this is done for provisioning and is extended to deploy, SWIM and remediation. Dry-run mode is honoured. Builds on core [G7](https://github.com/dr-stutters/stutters-mcp-core/issues/24).
- [ ] **D20 Un-provision deletes the device** ([#27](https://github.com/dr-stutters/catc-mcp-server/issues/27)): `DELETE /sda/provisionDevices/{id}` un-provisions **and** removes the device, and 3.x has no un-provision-only call. `catc_delete_device` must require `clean_config` explicitly, state both effects and the config archive version that will be lost, be blocked in dry-run mode and count towards D19's limit.
- Core items that apply unchanged: [G1](https://github.com/dr-stutters/stutters-mcp-core/issues/18) OAuth, [G2](https://github.com/dr-stutters/stutters-mcp-core/issues/19) per-user roles, [G4](https://github.com/dr-stutters/stutters-mcp-core/issues/21) secrets (`CATC_PASSWORD_FILE`), [G5](https://github.com/dr-stutters/stutters-mcp-core/issues/22) observability, [G8](https://github.com/dr-stutters/stutters-mcp-core/issues/25) scanning, [G9](https://github.com/dr-stutters/stutters-mcp-core/issues/26) public release (scrub the lab IPs and the `mcp.lab` objects from docs and tests), [G10](https://github.com/dr-stutters/stutters-mcp-core/issues/27) multi-instance (several CatC clusters).

## External services and prerequisites
| Service / prerequisite | Needed for (items) | Provided by | Network path | Status |
|---|---|---|---|---|
| Catalyst Center 3.2.2-75131 (dCloud, 198.18.128.11, self-signed) | all | dCloud | server → CatC :443 via cortex tun0 (VPN) | ✅ in place |
| CML 2.10 controller, **EVAL cap 5 running nodes** | all live device tests | Lab | cortex → 198.18.128.10 | ✅ in place. `catc-routers` (2) + `ise-access` (2) already use 4 of 5 |
| Lab state in CatC: r1.mcp.lab / r2.mcp.lab provisioned at Global/mcp-test-lab/mcp-test-bldg, the mcp-test-* creds, discovery and template project | live suite (D5 seeds and cleans this) | left by Phase 2 | — | ✅ present; CML labs stopped, so the devices show as Unreachable |
| ISE 198.18.134.35 integrated with CatC: ERS on, pxGrid persona on, CatC client approved, GUI and CLI credentials | D8, D9, D13 | ISE node (CatC ↔ ISE integration, appliance to appliance; our servers never subscribe to pxGrid) | **CatC → ISE** :443, :8910, :22 | ⏳ to set up (CatC has no policy servers today) |
| A network profile in CatC | D3 | one-time UI step | — | ⏳ to set up |
| CML recipe `catc-pnp` (blank cat8000v + dnsmasq option 43) | D11 | cml roadmap | **device → CatC** :80/:443 | ⏳ to build |
| IOS XE `.bin` for cat8000v + CCO download entitlement | D12 | cisco.com | — | ❌ missing |
| HTTP image server reachable from CatC (e.g. CML `nginx` node) | D12 | CML | **CatC → server** HTTP | ⏳ to set up |
| CML recipe `catc-sda` (2 × cat9000v + Alpine); cat9000v fabric-role support | D13 | cml roadmap; to confirm on 17.18 | — | ⏳ to build/confirm |
| cat9800-CL image | D14 | CML image library | CatC ↔ 9800 SSH/NETCONF | ✅ present |
| Physical Catalyst AP via a CML external connector | D14 (AP parts) | — | — | ❌ unavailable |
| ServiceNow PDI with the CatC app; CatC internet egress | D16 (ITSM) | ServiceNow developer program | **CatC → ServiceNow** :443 | ❌ unavailable |
| CatC 2.3.7.x and 3.1.x instances | D18 | dCloud catalog / customer lab | server → CatC :443 | ❌ not available yet |

## Not planned
- **Per-feature wireless controller models** (~560 ops: AP join/RF/flex/mDNS/policy profiles, intended and deployed): they change rarely, are model-heavy, and are reachable through `catc_search_spec` + `catc_api_call`. D14 covers only WLC provisioning, SSIDs and profiles.
- **Multipart uploads and binary downloads** (12 ops: image file upload, certificate import, maps import/export, unmasked config ZIP, PDF reports). MCP can't carry them sensibly. D12 uses URL import and D16 keeps reports to text formats.
- **Users/roles management, backups (create/restore), sensors, smart-account licensing, email/SNMP/SFTP/PagerDuty event destinations**: one-off admin work or not in the lab. Roles are read only for the D17 check.
- **A separate un-provision tool**: CatC 3.x has none. Un-provisioning is deletion, so it stays in `catc_delete_device` (D20).
- **Receiving events in this server** (Event Management webhooks or syslog subscriptions, device syslog/traps): out of scope suite-wide (ADR-003); D7 was dropped. CatC already collects device syslog and traps, and `catc_list_events` / D2 query them on demand.
