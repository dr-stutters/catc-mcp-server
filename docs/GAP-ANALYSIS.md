# Catalyst Center API gap analysis (Phase 2)

Against **Catalyst Center 3.2.2-75131**, using the Intent/System/Data API spec the server bundles
(`src/catc_mcp/specs/catc-3.2.2.json.gz`, exported from that appliance's Developer Toolkit: 1,421
paths, **1,914 operations**, 256 tags). Live work used real devices built in CML: two cat8000v
routers (lab `mcp-cml-catc`, recipe `catc-routers`) and a cat9000v switch with an Alpine client
(lab `mcp-cml-ise`, recipe `ise-access`). `scripts/gap_report.py` regenerates the numbers below.

## 1. Headline

| | v0.1.1 | v0.2.0 |
|---|---:|---:|
| Operations behind curated tools | 115 (6 %) | 163 (9 %) |
| Reachable through `catc_api_call` (spec-guided) | all but 12 | all but 12 |
| Not usable through MCP (multipart uploads, binary downloads) | 12 | 12 |
| Operator workflows (section 3) covered by curated tools | 22 of 38 | 34 of 38 |
| Tools (read / write / dangerous incl. `catc_api_call`) | 38 / 16 / 8 | 50 / 23 / 8 |

The operation count is dominated by breadth, not by what operators do every day: **575 operations
(30 %) are wireless controller feature models** (per-feature CRUD for WLAN/policy/RF/AP-join/mDNS/...
profiles plus "deployed" variants), 169 are SD-Access, and most of compliance (111) is the new
compliance-policy authoring model. Measured by operator workflows, the day-to-day work (onboard,
day-N change, troubleshoot) is covered by curated tools; the rest stays on `catc_api_call`, which
`catc_search_spec` + `catc_get_definition` make usable.

Not usable through MCP (12): multipart uploads (`POST /image/importation/source/file`,
`/certificate`, `/certificate-p12`, `/trustedCertificates/import`, `/file/{nameSpace}`,
`/maps/import/start`, `/v2/floors/{id}/uploadImage`) and binary downloads (unmasked config ZIP
`networkDeviceConfigFiles/{id}/downloadUnmasked`, `network-device-archive/cleartext` exports,
report downloads, maps export). The masked configuration is available as text (catc_compare_device_configs).

## 2. Operations per area

Counting is per path: an operation counts as curated when a tool calls its path (so a tool that only
reads a settings path also credits the PUT on it; the table is a guide, section 3 is the real measure).

| Area | Operations | Curated v0.1.1 | Curated v0.2.0 | Decision |
|---|---:|---:|---:|---|
| Wireless (feature models, SSIDs, profiles, APs) | 575 | 0 | 2 | Read SSIDs per site; rest api_call (no WLC in the lab; huge config-model surface) |
| SDA fabric | 169 | 0 | 14 | One aggregated read (`catc_get_sda_fabric`); writes api_call |
| Inventory (devices, interfaces, modules, stack, PoE) | 156 | 11 | 15 | + hardware/licence tool |
| Compliance & config drift | 111 | 4 | 4 | Run + detail kept; drift via config archive; policy authoring api_call |
| Assurance: device & network health | 105 | 3 | 4 | Kept; trend/KPI analytics api_call |
| Templates | 91 | 14 | 15 | + deployment status; import/export, clone, profile attach api_call |
| Sites | 74 | 18 | 19 | Already covered |
| SWIM | 68 | 3 | 6 | + per-device image status, golden tagging |
| Event management / notifications | 48 | 0 | 0 | api_call (rarely changed; webhook setup is one-off) |
| Credentials | 40 | 5 | 7 | + list/create/delete global, site assignment |
| System settings & integration | 39 | 0 | 2 | Read (AAA/ISE servers in system health); ISE integration api_call |
| Assurance: issues & events | 37 | 4 | 4 | Fixed issue ids, suggested actions, readable events |
| PnP | 34 | 0 | 2 | Read list; claim api_call (lab has no PnP devices) |
| Users & roles | 33 | 0 | 0 | api_call (admin, rare) |
| Provisioning | 31 | 4 | 5 | + re-provision; delete of provisioned devices |
| Network settings | 31 | 14 | 14 | + writes (DNS/NTP/DHCP/banner/time zone/telemetry) |
| Discovery | 29 | 8 | 9 | Named credentials, SNMP RW, NETCONF, Single fix, result summary |
| Licensing | 28 | 0 | 2 | Device licences in the hardware tool; smart-account ops api_call |
| Auth, tasks, files, platform | 26 | 6 | 6 | Covered |
| Sensors | 26 | 0 | 0 | api_call (no sensors) |
| Assurance: clients | 25 | 2 | 2 | client 360 reworked |
| IP pools (IPAM) | 22 | 0 | 4 | + list/create/reserve/release |
| Tags | 20 | 9 | 8 | Delete with members fixed |
| LAN automation | 19 | 0 | 0 | api_call (needs PnP seed/underlay design; not in the lab) |
| Reports | 15 | 0 | 0 | api_call (report scheduling is UI-driven; downloads are binary) |
| Backup & restore | 13 | 0 | 4 | Read (in system health); create/restore api_call (needs NFS target) |
| Path trace | 12 | 4 | 4 | Covered |
| Network profiles | 10 | 0 | 3 | Read with sites and templates |
| Config archive | 9 | 0 | 2 | + list versions, unified diffs |
| Device replacement / RMA | 8 | 0 | 0 | api_call |
| Topology | 6 | 5 | 5 | Covered |
| Command runner | 2 | 1 | 1 | Covered (allow-list improved) |

## 3. Operator workflows

Scored by operator value: **H** = daily/weekly and error-prone through raw calls (multi-step, id
lookups, async tasks), **M** = regular, **L** = rare/admin. "Live" = exercised against the CML devices.

### Onboard a device (discover → site → provision)

| Workflow | Value | v0.1.1 | v0.2.0 | Live |
|---|---|---|---|---|
| Create global CLI/SNMP/NETCONF credentials | H | api_call | `catc_create_global_credential` | yes |
| List credentials (no secrets) | H | api_call | `catc_list_global_credentials` | yes |
| Assign credentials to a site | M | api_call | `catc_assign_site_credentials` | yes |
| Discover devices with named credentials, SNMP RW, NETCONF | H | partial (all global creds, RO only) | `catc_create_discovery` | yes (routers and switch) |
| See what a discovery found and why not | H | yes | + summary in the discovery result | yes |
| Build the site hierarchy | H | yes | yes | yes |
| Network settings (DNS, NTP, DHCP, banner, time zone, syslog/trap collectors, wired data collection) | H | read only | `catc_update_site_settings` | yes, pushed by provisioning and verified on the router CLI |
| IP pools and site reservations | M | api_call | `catc_list/create/delete_ip_pool` | yes |
| Assign devices to a site | H | yes | shows current site, skips no-ops | yes |
| Provision / re-provision wired devices | H | provision (mock only) | provision + re-provision | yes (r1, r2, sw1) |
| AAA/ISE settings per site | M | read | api_call (needs an ISE integration first) | no |
| PnP claim | M | api_call | list read; claim api_call | no PnP devices |
| LAN automation | L | api_call | api_call | no |

### Day-N change (template → preview → deploy → verify → compliance)

| Workflow | Value | v0.1.1 | v0.2.0 | Live |
|---|---|---|---|---|
| Template project/template CRUD, commit | H | yes | + Catalyst Center's template warnings surfaced | yes |
| Preview against a device | H | yes | yes | yes |
| Deploy to one or many devices and wait | H | mock only | per-device result via deployment status | yes (r1, r1+r2, sw1) |
| Re-check a deployment later | M | api_call | `catc_get_template_deployment` | yes |
| Verify on the device | H | command runner | command runner (echo/prompt stripped, `a\|b` regex allowed) | yes, plus the CML console |
| Compliance run + detail | H | mock only | compact detail, non-compliant first | yes (drift detected) |
| What exactly drifted (running vs startup, vs previous) | H | no | `catc_compare_device_configs` | yes |
| Config archive versions | M | api_call | `catc_list_config_archive` | yes |
| Tag devices for targeting | M | yes | delete of tags in use fixed | yes |
| Attach templates to network profiles | L | api_call | profiles listed with templates; attach api_call | no profiles |
| SWIM: per-device image status | M | api_call | `catc_list_device_images` | yes |
| SWIM: golden tag | M | api_call | `catc_tag_golden_image` | refused cleanly (no imported image) |
| SWIM: distribute / activate | M | mock | mock | not feasible: no image in the repository (section 5) |

### Troubleshoot

| Workflow | Value | v0.1.1 | v0.2.0 | Live |
|---|---|---|---|---|
| Device 360 | H | yes | health from metricsDetails, tags, provisioned, EoX 404 as "no data" | yes |
| Client 360 | H | yes | wired/wireless fields, health map, onboarding root causes | yes (Alpine on sw1) |
| Issues list → detail → suggested commands → resolve/ignore | H | broken (no ids) | fixed ids, suggested actions with commands | yes (OSPF/link-down issues) |
| Events for a device/client | H | needed `device_family` | family inferred, readable rows | yes |
| Path trace | H | mock | yes | yes (with and without CDP) |
| Command runner | H | yes | output cleaned, `a\|b` regex | yes |
| Interfaces, modules, hardware (stack/PoE/licences) | M | partial | `catc_get_device_hardware` | yes |
| Topology (physical/L3/VLAN) | M | yes | yes | yes |
| Network/device/client health | H | raw body | compact | yes |
| Appliance health, backups, licence | M | api_call | `catc_get_system_health` | yes |
| Audit log | M | yes | yes | yes |
| Device resync / delete | M | mock | delete handles provisioned devices | yes |

Not covered by a curated tool (api_call): AAA/ISE site settings, PnP claim, LAN automation, attaching
templates to network profiles.

## 4. Review of the existing tools (bugs and fixes)

Found by running the v0.1.1 tools against real devices for the first time:

- **Issue ids were missing**: the data API returns `issueId`, the tools picked `id`, so
  `catc_list_issues` / `catc_device_360` showed no id and `catc_get_issue` /
  `catc_update_issue_status` couldn't be chained. Fixed (`issue_row`).
- **`catc_get_issue` failed** on every call (`view=impactedHosts` isn't valid on 3.2.2). The default
  view also is the only one carrying `suggestedActions`; they are now returned with their commands.
- **`catc_device_360` health was empty**: health lives under `metricsDetails`; -1/null mean "not
  computed" and are dropped. EoX 404 is reported as "no EoX data", not an error.
- **`catc_delete_tag`** said members are untagged; Catalyst Center refuses instead. Now blocked in the
  preview with `remove_members=true` to untag first.
- **`catc_create_template`** returned a JSON string as the template id when Catalyst Center had
  remarks; the id and the warnings ("POTENTIAL_CONFLICT ... reserved") are now separated.
- **Un-provisioning deletes the device**: `DELETE /sda/provisionDevices/{id}` un-provisions *and*
  removes the device (and cleans config by default). A separate un-provision tool would have been
  misleading, so `catc_delete_device` uses that API for provisioned devices (with `clean_config`
  passed explicitly) instead of refusing them.
- **`catc_provision_devices`** only did first-time provisioning; it now re-provisions devices already
  provisioned at the site and refuses moves (Catalyst Center can't move a provisioned device).
- **Discovery `Single`** finishes in seconds with nothing found on 3.2.2; it is sent as a one-address
  Range (verified live: Single found nothing, Range found the switch).
- **Discovery used every global credential** and only an SNMP RO community; now named credentials,
  SNMP RW and the NETCONF port, and `wait=true` returns what was found.
- **Command runner** refused `show ... | include a|b` (regex alternation, which Catalyst Center's own
  suggested actions use); now allowed, with `redirect/tee/append/...` still refused even when glued.
  Output no longer repeats the command and the prompt; empty output shows as "(no output)".
- **`catc_get_device_config(match=...)`** matched anywhere in the header line
  (`interface Loopback` returned `ip domain lookup source-interface Loopback0`); now a prefix match
  where an exact header wins (`interface Gi1/0/2` no longer returns Gi1/0/20-24).
- **`catc_list_events`** needed `device_family` even when a device was given; inferred now. Rows are
  readable (UTC time, name, device, details).
- **`catc_get_network_health`** returned the raw body; now the score, counts and per-category health.
- **`catc_assign_devices_to_site`** now shows each device's current site and skips devices already there.
- **`catc_client_360`** showed RSSI/SNR/channel zeros for wired clients and a verbose onboarding block.

## 5. Left to `catc_api_call`, and why

- **Wireless feature models (≈560 ops)**: per-feature WLC configuration objects; changing them is
  rare, model-heavy and needs a WLC to test. SSIDs per site are readable.
- **SDA writes** (fabric sites, devices, VNs, anycast gateways, transits, port assignments): big
  structured payloads and design decisions; needs ISE and a fabric-capable lab. The fabric is
  readable in one call.
- **Compliance policy authoring, sensors, LAN automation, device replacement, ITSM, reports,
  users/roles, backups (create/restore), ISE integration**: one-off admin or lab-incompatible.
- **SWIM import / distribute / activate**: the tools exist (distribute/activate mocked), but the lab
  can't exercise them: there is no cisco.com connectivity and the CML images boot in install mode
  from `packages.conf`, so no `.bin` exists anywhere to import. Golden tagging is refused cleanly
  ("no imported image").

## 6. Lab quirks found (3.2.2-75131)

- Global credential create (`POST /globalCredentials`) returns a task whose `progress` holds the new
  id; SNMP types are `SNMPV2_READ_COMMUNITY` / `SNMPV2_WRITE_COMMUNITY` (not `SNMPV2C_*`). IP pool
  creates do the same.
- Discovery of two routers took ~13 min; a single switch ~3 min.
- Provisioning a router took ~90 s; it pushed DNS, NTP, banner, syslog/trap hosts, the assurance
  telemetry subscriptions and a SCEP trustpoint (visible in the config archive diff).
- Template deploys don't save the configuration: after a deploy, RUNNING_CONFIG compliance turns
  NON_COMPLIANT until `write memory` (the diff shows the deployed lines as unsaved).
- The config archive gets a new version on config-change syslog (once provisioning set the logging
  host) and on resync.
- Path trace needs CDP links: without CDP it fails with "no link ... Make sure CDP is enabled"; after
  deploying `cdp run` via a template and a resync, it completes.
- Assurance issues (OSPF adjacency down, link down) appeared about 1 minute after shutting a link.
- Device licence records (`/networkDeviceLicenses`) have their own ids and a different
  `networkDeviceId`; match them on the management address.
