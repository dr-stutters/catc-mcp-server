# catc-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Catalyst Center** (formerly DNA Center).
It gives an AI assistant curated, task-oriented tools for the operator workflows: onboarding (credentials,
discovery, sites, network settings, IP pools, provisioning), day-N changes (templates, deploy, compliance
and config drift) and troubleshooting (device/client 360, issues with suggested commands, events, path
trace, read-only CLI), plus SWIM, topology and appliance health, and a spec-driven escape hatch for the
rest of the Intent API. `docs/GAP-ANALYSIS.md` maps the whole 3.2.2 API to the tools. Built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core).

> Not affiliated with, endorsed by or supported by Cisco Systems, Inc. "Cisco" and "Catalyst Center"
> are trademarks of Cisco Systems, Inc.

- **Supported version:** Catalyst Center **3.2.2** (tested against 3.2.2-75131). Most tools use
  long-standing Intent API endpoints and should work on 2.3.7.x and 3.1.x; SWIM distribute/activate use
  the `networkDeviceImages` API added in 3.1.3.
- **Safety:** read-only by default. Writes and the dangerous tier are opt-in, and every change is
  **preview-first**: the first call returns a preview and a single-use confirm token; nothing changes
  until the identical call is repeated with that token (refused if the arguments, the caller or the
  target objects changed in between).

## Quick start

```bash
git clone https://github.com/dr-stutters/catc-mcp-server && cd catc-mcp-server
uv sync
cp .env.example .env && chmod 600 .env   # set CATC_URL, CATC_USERNAME, CATC_PASSWORD
uv run catc-mcp-server check             # logs in and prints catc_status as JSON
```

### Claude Code (stdio)

```bash
claude mcp add catc -- uv --directory /path/to/catc-mcp-server run catc-mcp-server
```

or in `.mcp.json` / `~/.claude.json`:

```json
{
  "mcpServers": {
    "catc": {
      "command": "uv",
      "args": ["--directory", "/path/to/catc-mcp-server", "run", "catc-mcp-server"],
      "env": {"MCP_ENABLE_WRITES": "false"}
    }
  }
}
```

Credentials come from the repo's `.env` (or pass `CATC_URL`, `CATC_USERNAME`, `CATC_PASSWORD` in `env`).

### Claude Code (HTTP)

Run the container (below), create a token with `catc-mcp-server token <name>`, then:

```bash
claude mcp add --transport http catc http://cortex:8034/mcp --header "Authorization: Bearer <token>"
```

```json
{
  "mcpServers": {
    "catc": {
      "type": "http",
      "url": "http://cortex:8034/mcp",
      "headers": {"Authorization": "Bearer <token>"}
    }
  }
}
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CATC_URL` | (required) | Catalyst Center base URL, e.g. `https://catc.example.com` |
| `CATC_USERNAME` / `CATC_PASSWORD` | | API account (Basic auth → `X-Auth-Token`, renewed before its 1 h expiry and on 401) |
| `CATC_TOKEN` | | A pre-issued `X-Auth-Token` instead of username/password (expires after about an hour) |
| `CATC_VERIFY_SSL` | `true` | TLS verification; `false` for self-signed labs (logged as a warning, shown in `catc_status`) |
| `CATC_CA_BUNDLE` | | CA bundle for the appliance certificate |
| `CATC_TIMEOUT` / `CATC_RETRIES` | `30` / `2` | Per-request timeout (s) and retries (429 always retried, honouring `Retry-After`) |
| `CATC_RATE_LIMIT` / `CATC_MAX_CONCURRENCY` | none / `8` | Client-side pacing (requests/min) and concurrent requests |
| `CATC_COMMAND_RUNNER_TIMEOUT` | `120` | Seconds `catc_run_show_commands` waits for output |
| `CATC_MAX_DEVICES_PER_CHANGE` | `10` | Most devices one deploy/provision/SWIM/PnP/delete may touch (`0` = off; see Safety rails) |
| `MCP_ROLES` / `MCP_DEFAULT_ROLE` | off / `ro` | Per-caller roles `ro`/`rw`/`admin` (core docs/PRODUCTION.md) |
| `MCP_DRY_RUN`, `MCP_CHANGE_WINDOW`, `MCP_MAX_BLAST_RADIUS`, `MCP_TWO_PERSON_TOOLS`, `MCP_DENY_TOOLS` | off | Safety rails (core G7; see Safety rails) |
| `CATC_INSTANCES` | | Several Catalyst Centers in one server (`CATC_<NAME>_URL`, ...): every tool gets `instance` |
| `MCP_METRICS` | `false` | Prometheus `/metrics` on the HTTP port |
| `MCP_TASKS` / `MCP_TASKS_URL` | `false` / `memory://` | Run the long tools as MCP background tasks: `catc_create_discovery`, `catc_provision_devices`, `catc_deploy_template`, `catc_distribute_image`, `catc_activate_image`, `catc_provision_wireless_controller`, `catc_claim_pnp_device`, `catc_replace_device`, `catc_add_fabric_device`, `catc_add_anycast_gateway` (clients without task support call them normally) |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST` / `MCP_PORT` / `MCP_PATH` | `0.0.0.0` / `8000` / `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | `name:sha256:<hex>` entries; **required** for HTTP |
| `MCP_ENABLE_WRITES` | `false` | Register the write tools |
| `MCP_ENABLE_DANGEROUS` | `false` | Register the dangerous tools (needs writes too) |
| `MCP_CONFIRM_TTL` | `600` | Confirm token lifetime (s) |
| `MCP_TASK_TIMEOUT` | `600` | How long tools wait for Catalyst Center tasks (s) |
| `MCP_CACHE_DIR` | `~/.cache/catc-mcp-server` | Spec index cache (`""` disables) |
| `MCP_MAX_RESPONSE_CHARS` | `40000` | Response size budget; lists are trimmed with a note |
| `MCP_AUDIT_LOG` | `stderr` | One JSON line per tool call: `stderr`, a file path, or `off` |
| `LOG_LEVEL` | `INFO` | |

## Least-privilege account

Don't run the server as an admin. Three custom Catalyst Center roles, tested live on 3.2.2, match the
server's tiers: **mcp-catc-ro** (read tier), **mcp-catc-rw** (+ write tier; Catalyst Center itself refuses
provisioning, PnP claims and ISE changes) and **mcp-catc-dangerous**. [docs/least-privilege.md](docs/least-privilege.md)
lists every permission, the access-group requirement and the API calls; `scripts/seed_access.py` creates the roles,
access groups and users. `catc_status` shows the account's roles under `catc.account` and warns when they allow
more than the enabled tiers.

Every tool call is written to the audit log with the caller's token name, so give each person their own
token (`catc-mcp-server token alice`).

## Safety rails

Every write is preview-first. On top of that (core G7, `docs/PRODUCTION.md` in stutters-mcp-core):

- **`CATC_MAX_DEVICES_PER_CHANGE`** (default **10**, `0` = off): template deploys, provisioning, SWIM
  distribute/activate, PnP claims, device replacement and device deletion that touch more devices are blocked
  in the preview. `catc_deploy_template` targets an explicit device list, every device under a `site`
  (child sites included; `Global` = the whole inventory) or a `tag`; the limit applies after expansion.
- **Blast radius**: those tools plus `catc_resync_devices` and `catc_run_compliance` report `blast_radius`
  (devices touched), limited by `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES` (e.g.
  `catc_deploy_template=5`).
- **Change windows** (`MCP_CHANGE_WINDOW="Sat 22:00-04:00 Australia/Sydney"`), **dry run** (`MCP_DRY_RUN=true`),
  **two-person approval** (`MCP_TWO_PERSON_TOOLS="@dangerous"`) and per-tool deny lists (`MCP_DENY_TOOLS`) apply
  to every write tool.
- Confirm tokens are bound to the resolved targets: if a tag's or site's members, a template's versions or a
  device's provisioning change between preview and confirm, the confirm is refused.
- **Un-provisioning deletes the device.** Catalyst Center 3.x has no separate un-provision call;
  `catc_delete_device` is the only way, requires `clean_config` explicitly and its preview lists every effect
  (unmanaged, assurance history and config archive lost, ISE NAD left behind). To keep managing a device,
  re-provision it instead.

## Tools

Start with `catc_status`, then `catc_list_devices` / `catc_get_site_hierarchy`. The smart tools do the
most work per call: `catc_device_360`, `catc_client_360`, `catc_path_trace`, `catc_run_show_commands`.
Names, IPs, serial numbers, site paths and credential descriptions are accepted wherever an id is
expected.

Typical flows:

- **Onboard:** `catc_create_global_credential` → `catc_create_discovery` (wait=true) →
  `catc_create_site` → `catc_update_site_settings` / `catc_assign_site_credentials` →
  `catc_assign_devices_to_site` → `catc_provision_devices`.
- **Day-N change:** `catc_create_template` → `catc_commit_template` → `catc_preview_template` →
  `catc_deploy_template` → verify with `catc_run_show_commands` → `catc_run_compliance` /
  `catc_compare_device_configs` (template deploys don't `write memory`, so running-vs-startup
  compliance goes non-compliant until the config is saved).
- **Troubleshoot:** `catc_device_360` / `catc_client_360` → `catc_list_issues` → `catc_get_issue`
  (Catalyst Center's suggested commands) → `catc_run_show_commands`; `catc_path_trace` (needs CDP or
  LLDP between devices); `catc_list_events`.
- **What happened here?** `catc_recent_activity(device=..., site=..., hours=...)` merges issues,
  assurance events, event notifications and the audit log for one window (pull-only: queried when
  called); drill down with `catc_list_event_notifications` / `catc_list_audit_logs`.
- **Standards:** `catc_create_compliance_policy` (regex/string rules on the running config) →
  `catc_run_compliance` → `catc_list_compliance_violations`.
- **Profiles:** `catc_attach_template_to_profile` / `catc_assign_profile_to_sites` record which Day-N
  templates belong to a site; the provisioning API doesn't push them (3.2.2), so deploy them with
  `catc_deploy_template`.

Prompts: `catc_onboard_device` (write tier) walks credentials → discovery → site → settings →
assign → provision → template deploy → verification, preview-first at every write.
`catc_change_window` (write tier) runs a Day-N template change: baseline (issues, compliance, config
archive) → per-device preview → rails (≤ 10 devices, window end) → deploy → deployment status → CLI
check → config diff → compliance → issue diff → a written rollback plan (negation template or the
pre-change archive). Without the dangerous tier it stops after the rails with a reviewed change plan.
`catc_onboard_switch_with_nac` (write tier, uses the **ise** server too) checks the ISE integration
(`catc_get_policy_servers`), sets the site's client AAA to ISE, onboards and provisions the switch,
confirms its NAD in ISE (`ise_get_nad`), deploys an IBNS 2.0 MAB/802.1X port template and verifies
the first authentication (`ise_find_session`, `ise_get_auth_history`, `ise_why_auth_failed`,
`ise_endpoint_360`, `catc_client_360`).
`catc_decommission_device` (dangerous tier, uses **ise**) keeps a copy of the config, shows what
un-provisioning loses (it deletes the device), untags it, deletes it with an explicit `clean_config`, and
removes the NAD Catalyst Center leaves in ISE (`ise_get_nad`, `ise_delete_nad`).

- **ISE / AAA:** `catc_add_ise_server` → `catc_accept_ise_certificate` (check the fingerprints) →
  `catc_update_site_aaa_settings` → `catc_provision_devices` (pushes RADIUS config and creates the
  NAD in ISE; deleting the device later does **not** remove that NAD).
- **Zero-touch / RMA:** `catc_list_pnp_devices(state='Unclaimed')` → `catc_claim_pnp_device` (day-0
  template from the *Onboarding Configuration* project; `hostname` is a blocked template command, pass
  it to the claim). RMA: `catc_mark_device_for_replacement` (the faulty device must be unreachable and
  its image imported in SWIM) → `catc_replace_device`.

- `catc_run_show_commands` is **read tier** but only accepts `show ...` commands; after a `|` only
  include/exclude/begin/section/count filters are allowed (regex alternatives such as
  `| include up|down` are fine; no redirect/tee/append, no `;`, `&`, `<`, `>`).
- Global credential secrets (passwords, communities, SNMPv3 keys) are write-only: they are masked in
  previews and never returned.
- Running configs, template bodies and command output have passwords, secrets, keys and SNMP
  communities masked.
- `catc_api_call` does GETs in the read tier; with the dangerous tier on, it also does preview-first
  POST/PUT/PATCH/DELETE. Find endpoints with `catc_search_spec` and bodies with `catc_get_definition`.

### Read (65)

| Tool | What it does |
|---|---|
| `catc_client_360` | Everything about one client in one call: identity (IP, user, host type/OS), health score, where it connects (switch and port, or AP, SSID, band and RSSI/SNR), VLAN, onboarding state, its active issues and recent onboarding events. |
| `catc_compare_device_configs` | Unified diff between two archived configurations of one device: what changed since the previous running config, what is unsaved (running vs startup), or any two archive files. |
| `catc_device_360` | Everything about one network device in one call: inventory record, site, assurance health (overall, CPU, memory), tags, whether it is provisioned, active issues (last 24h, repeats grouped, with how long ago each last occurred), interface counts and the ports that are down while admin-up, compliance status and end-of-life (EoX) alerts. |
| `catc_get_client` | Details for one wired or wireless client: IP, user, host type/OS, health score, connected switch/port or AP/SSID/band, VLAN, RSSI/SNR, and onboarding state. |
| `catc_get_client_health` | Client health summary: overall, wired and wireless client scores and how many clients are in each health band (poor/fair/good/idle/no data). |
| `catc_get_compliance_detail` | Compliance report for one device per category (startup vs running config, image, PSIRT, EoX, network settings, network profile, fabric): status, message, last check time, whether Catalyst Center can remediate it and, with include_diff, what differs. |
| `catc_get_compliance_policy` | One compliance policy: its rules (device families, software type, suggested fix) with their conditions (what is tested, whether a match or a non-match is the violation, severity) and the sites it is assigned to, by name (including the sites below the assigned ones). |
| `catc_get_compliance_summary` | Fleet compliance at a glance: how many devices are compliant, non-compliant, in progress, not available or in error, and which devices are non-compliant (with hostname). |
| `catc_get_definition` | Describe a Cisco Catalyst Center API operation (parameters, request fields, required fields) or a schema (fields with types and enums). |
| `catc_get_device` | Full inventory record for one network device: platform, serial, software, role, uptime, reachability and collection status (with failure reason), management IP, MAC, location. |
| `catc_get_device_config` | The device's running configuration as last collected by Catalyst Center (not live: run catc_run_show_commands for that). |
| `catc_get_device_hardware` | Hardware and licensing of one device in one call: stack members (role, state, priority, serial, platform, software) and StackWise Virtual links, PoE budget (allocated / consumed / remaining watts) and the PoE ports drawing power, module count, and smart-licensing state with the licences in use. |
| `catc_get_issue` | One assurance issue in full: description, affected device/client/site, timeline, additional attributes and Catalyst Center's suggested actions with the show commands it proposes (run them with catc_run_show_commands). |
| `catc_get_l3_topology` | Layer 3 topology for one routing protocol: routers and the adjacencies between them with interface names and addresses. |
| `catc_get_network_health` | Overall network health score and the healthy/unhealthy device counts per category (access, distribution, core, router, wireless), plus a per-site health summary. |
| `catc_get_network_profile` | One network profile: its type, the Day-N CLI templates attached to it and the sites it is assigned to (by name, including inherited child sites). |
| `catc_get_physical_topology` | Physical (CDP/LLDP-derived) topology: devices and the links between them with port names, link status and addresses. |
| `catc_get_policy_servers` | Authentication and policy servers known to Catalyst Center (System > Settings > Authentication and Policy Servers): plain RADIUS/TACACS servers and integrated Cisco ISE, with protocol, ports, state, pxGrid, and per ISE node its role (PRIMARY/SECONDARY/PXGRID), FQDN and certificate trust state; plus the ISE integration status (each step, and the certificate waiting to be accepted, if any). |
| `catc_get_report_content` | Download a report execution's content (CSV or JSON reports only; PDF/TDE are binary). |
| `catc_get_report_view` | A report view's formats, filters (name, type) and field groups, i.e. |
| `catc_get_sda_fabric` | SD-Access fabric overview in one call: fabric sites (authentication profile, pub/sub), the fabric devices at each with their roles (control plane, border, edge) and border settings, layer 3 virtual networks, anycast gateways (VN, IP pool, VLAN) and edge port assignments, with the ids catc_delete_sda_object takes. |
| `catc_get_site` | One site: id, type, name hierarchy, address/coordinates (buildings), dimensions and RF model (floors), its direct child sites and how many network devices are assigned to it. |
| `catc_get_site_hierarchy` | The site hierarchy (Global > areas > buildings > floors) as an indented tree with each site's type and id. |
| `catc_get_site_settings` | Network settings for a site (Design > Network Settings): AAA servers, banner, DHCP, DNS, NTP, telemetry (syslog/SNMP/NetFlow collectors), time zone, image distribution servers and the device credentials the site uses (shown as 'TYPE:description', never secrets). |
| `catc_get_system_health` | Health of the Catalyst Center appliance itself: service health events (counts by state and the ones that are not healthy), last backups and the backup target, system licence (registration/evaluation), ISE/AAA server integration status, and release version. |
| `catc_get_task` | Status of an asynchronous Catalyst Center operation: progress, whether it finished or failed, the failure reason and any result data. |
| `catc_get_template` | One template in full: content (CLI body), language, variables (name, type, required, default, choices), target device families/software, project and version history. |
| `catc_get_template_deployment` | Status of one template deployment: overall status and, per device, whether the push succeeded, the CLI actually pushed (realizedClis: what a rollback has to undo) and Catalyst Center's detailed message (e.g. the CLI line the device rejected). |
| `catc_get_vlan_topology` | Without `vlan`: the VLAN names Catalyst Center knows about. |
| `catc_get_wireless_controller` | A Catalyst 9800 WLC as Catalyst Center sees it: provisioning status, primary managed AP locations and the SSIDs deployed on it (admin status, managed by Catalyst Center or not). |
| `catc_list_audit_logs` | Catalyst Center audit log, newest first: who did what and when (logins, provisioning, template deploys, configuration changes, API calls) with the device it concerns. |
| `catc_list_clients` | Wired and wireless clients Catalyst Center Assurance saw in the window, newest first: MAC, IP, user, type, connection status, health, the switch and port or WLC/SSID/band, VLAN, last onboarding failure and when it was last seen. |
| `catc_list_compliance_policies` | User-defined compliance policies (Provision > Compliance > Policies) with their status (ACTIVE, NO_RULES_CONFIGURED, NO_SITES_ASSIGNED...), rule and site counts. |
| `catc_list_compliance_violations` | Compliance policy violations from the last compliance run (catc_run_compliance), per device (every violating policy, or one) or per site for one policy: rule, condition, severity and message. |
| `catc_list_config_archive` | Configuration versions Catalyst Center has archived for a device (running and startup config, VLAN database), newest first, with when and why each was taken (first collection, scheduled, config-change syslog, user request) and the file ids. |
| `catc_list_device_health` | Assurance health per network device: overall score, CPU/memory, interface/link errors, reachability, and the issue count. |
| `catc_list_device_images` | Software image status per network device: the image it runs, whether that matches the golden image for its site and role (COMPLIANT / NON_COMPLIANT / UNKNOWN when no golden image is set), compatibility, and the status of the last image update. |
| `catc_list_device_interfaces` | Interfaces of one device with oper/admin status, description, IPv4 address, VLAN, port mode, speed/duplex and MAC. |
| `catc_list_device_modules` | Hardware modules of one device (line cards, supervisors, power supplies, fans, transceivers) with part number, serial number and operational state. |
| `catc_list_device_replacements` | Devices marked for replacement (RMA) and replacement workflows: faulty device name, serial and platform, the replacement serial, status (MARKED_FOR_REPLACEMENT -> READY_FOR_REPLACEMENT -> REPLACEMENT_IN_PROGRESS -> REPLACED or ERROR) and times. |
| `catc_list_devices` | List network devices in the Catalyst Center inventory with hostname, management IP, platform, software version, role, reachability and serial. |
| `catc_list_discoveries` | Discovery jobs with their type (range/CDP/LLDP/single), IP ranges, status, condition and number of devices found. |
| `catc_list_discovery_devices` | Devices found by one discovery with reachability, the failure reason when unreachable, and CLI/SNMP/NETCONF credential status: the place to look when a discovery 'found nothing'. |
| `catc_list_event_notifications` | Catalyst Center platform event notifications, newest first: device unreachable, link and OSPF/BGP alerts raised as notifications, config-change (drift) events, provisioning, SWIM, licensing and system/service health. |
| `catc_list_events` | Assurance events (syslog, SNMP traps, client onboarding events) for network devices or clients, newest first. |
| `catc_list_global_credentials` | Global device credentials (CLI, SNMPv2c read/write, SNMPv3, NETCONF port, HTTP(S)) that discovery and sites use: description, type, username/port and id. |
| `catc_list_images` | Software images known to Catalyst Center (imported into the repository, or suggested from cisco.com): name, version, product families, golden tag, integrity status and id. |
| `catc_list_ip_pools` | IP address pools: global pools and the subpools reserved from them for sites, with subnet, gateway, DHCP/DNS servers, type (Generic/LAN/Management/Service/WAN) and usage (assigned/total addresses). |
| `catc_list_issues` | Assurance issues (problems Catalyst Center detected) with priority, the device they are about, summary, status, site and how long ago each last occurred, newest first. |
| `catc_list_itsm_instances` | ITSM (ServiceNow) integration instances configured in Catalyst Center: name, type, URL, status (credentials are never shown). |
| `catc_list_network_profiles` | Network profiles (Design > Network Profiles) with their type, the sites they are assigned to and the Day-N CLI templates attached to them. |
| `catc_list_pnp_devices` | Plug and Play (PnP) devices waiting for or going through zero-touch onboarding: serial, platform, state, the site and workflow they're claimed to, first/last contact, and any error. |
| `catc_list_report_views` | Report view groups (Inventory, Compliance, SWIM, Licensing, EoX, Access Point, ...) or, with group, that group's views. |
| `catc_list_reports` | Reports defined in Catalyst Center with their view, format and executions (newest first: id, status, start/end), for catc_get_report_content. |
| `catc_list_ssids` | Wireless SSIDs defined at a site (Design > Network Settings > Wireless): name, security (auth type), radio bands, whether it's enabled and broadcast, AAA servers and id. |
| `catc_list_tag_members` | Members of one tag: network devices (hostname, IP, platform) or interfaces, whether added statically or by a dynamic rule. |
| `catc_list_tags` | Tags used to group devices and interfaces (for templates, provisioning and filtering): name, description, whether it is a system tag, dynamic membership rules and id. |
| `catc_list_template_projects` | Template projects (folders of templates) with description, id and template count. |
| `catc_list_templates` | Configuration templates (Template Editor) with project, language (Jinja/Velocity), software type, device families, committed version count and id. |
| `catc_path_trace` | Trace the network path between two IPs as Catalyst Center sees it: each hop (device, ingress/egress interfaces, how the link was learned), ACL verdicts when statistics are requested, and the failure reason if the trace can't be built (e.g. the source isn't known to Catalyst Center). |
| `catc_preview_template` | Render a template with the given variable values and show the resulting CLI, without deploying anything. |
| `catc_recent_activity` | What happened on this device or site recently? Queries Catalyst Center's assurance issues, assurance events (syslog, traps), platform event notifications and the audit log for the same window and scope, and merges them newest first with a `source` column. |
| `catc_run_show_commands` | Run read-only `show` commands live on managed devices through Catalyst Center's command runner and return each device's output. |
| `catc_search_spec` | Search the Cisco Catalyst Center OpenAPI spec for operations (method + path) and schemas. |
| `catc_status` | Check the connection to Cisco Catalyst Center: product version and API user, which API surfaces answer, and this MCP server's configuration (writes enabled?, TLS verification). |

### Write (40)

| Tool | What it does |
|---|---|
| `catc_assign_compliance_policy` | Change which sites a compliance policy applies to (each site includes the sites below it). |
| `catc_assign_devices_to_site` | Assign (or move) unprovisioned network devices to a building or floor. |
| `catc_assign_profile_to_sites` | Assign a network profile to sites (areas, buildings or floors; child sites inherit it). |
| `catc_assign_site_credentials` | Set which global credentials (CLI, SNMPv2c read/write, SNMPv3, HTTP read/write) a site uses (Design > Network Settings > Device Credentials). |
| `catc_attach_template_to_profile` | Attach a Day-N CLI template to switching or wireless network profiles, so it belongs to the profiles' sites (the UI's provisioning flow offers it there). |
| `catc_commit_template` | Commit a template's current content as a new version (required before deploying it). |
| `catc_create_compliance_policy` | Create a compliance policy that checks devices against your own standard, e.g. "no ip http server" (a MATCHES_EXPRESSION '^ip http server' condition with violation_when='matches') or "a login banner is set" ('^banner login' with violation_when='does_not_match'). |
| `catc_create_discovery` | Start a device discovery (IP range, CIDR, single IP, or CDP/LLDP from a seed) that adds what it finds to the inventory. |
| `catc_create_fabric_site` | Make a site an SD-Access fabric site. |
| `catc_create_global_credential` | Create a global device credential that discovery and site assignment can use. |
| `catc_create_ip_pool` | Create a global IP pool, or reserve a subpool of one for a site (pass site + global_pool). |
| `catc_create_report` | Create a report from a view and run it now (delivery: download). |
| `catc_create_site` | Create an area, building or floor in the site hierarchy. |
| `catc_create_ssid` | Define an SSID (WLAN) in network design. |
| `catc_create_switching_profile` | Create an empty switching network profile, to attach Day-N templates to and assign to sites. |
| `catc_create_tag` | Create a (static) tag for grouping devices or interfaces. |
| `catc_create_template` | Create a (not yet committed) configuration template in a project. |
| `catc_create_template_project` | Create a template project (a folder for configuration templates). |
| `catc_create_virtual_network` | Create a layer 3 virtual network (VRF) or add an existing one to more fabric sites. |
| `catc_create_wireless_profile` | Create a wireless network profile that carries SSIDs. |
| `catc_delete_global_credential` | Delete a global device credential. |
| `catc_delete_ip_pool` | Release a site's reserved subpool, or delete a global pool (refused while it still has reservations). |
| `catc_delete_report` | Delete a report and its executions. |
| `catc_delete_ssid` | Delete an SSID from network design. |
| `catc_delete_tag` | Delete a user-defined tag. |
| `catc_delete_template` | Delete a configuration template and all its versions. |
| `catc_delete_template_project` | Delete a template project together with every template in it. |
| `catc_delete_wireless_profile` | Delete a wireless network profile. |
| `catc_detach_template_from_profile` | Detach a Day-N CLI template from network profiles. |
| `catc_mark_device_for_replacement` | Mark a faulty device for replacement (RMA), the first step before catc_replace_device; or unmark it. |
| `catc_resync_devices` | Re-collect inventory (config, interfaces, modules) from devices now instead of waiting for the next polling cycle. |
| `catc_run_compliance` | Run a compliance check now for devices (all categories unless given). |
| `catc_tag_golden_image` | Mark an imported software image as golden (the target version) for a device product at a site and its children, or remove the tag. |
| `catc_unassign_profile_from_sites` | Remove a network profile's assignment from sites. |
| `catc_update_issue_status` | Mark assurance issues as resolved, or ignore them for some hours. |
| `catc_update_site` | Rename a site or change a building's address/coordinates or a floor's number, RF model and dimensions. |
| `catc_update_site_aaa_settings` | Set a site's AAA network settings (Design > Network Settings > AAA): which server devices use for administrator login (network) and for 802.1X/MAB endpoints (client), as ISE or plain AAA, RADIUS or TACACS. |
| `catc_update_site_settings` | Change a site's network settings (Design > Network Settings): DNS servers and domain, NTP, DHCP servers, banner, time zone, and telemetry (external syslog/SNMP trap servers, Catalyst Center as collector, wired client data collection). |
| `catc_update_tag_members` | Add network devices to, or remove them from, a static tag. |
| `catc_update_template` | Change a template's content or description (creates uncommitted changes; commit with catc_commit_template). |

### Dangerous (21)

| Tool | What it does |
|---|---|
| `catc_accept_ise_certificate` | Answer Catalyst Center's 'trust this ISE certificate?' step of the ISE integration (or retry a failed integration). |
| `catc_activate_image` | Install and activate a software image on a device (distributing it first if needed). |
| `catc_add_anycast_gateway` | Add an anycast gateway (the client subnet's default gateway, the same IP on every edge) for an IP pool in a virtual network at a fabric site. |
| `catc_add_fabric_device` | Give a provisioned device a fabric role (control plane, border, edge) at a fabric site. |
| `catc_add_ise_server` | Integrate Cisco ISE with Catalyst Center as the AAA and policy server: CatC connects to ISE (ERS over 443, pxGrid 8910), discovers its nodes and, after you accept ISE's certificate, trusts it. |
| `catc_api_call` | Call any Cisco Catalyst Center REST endpoint (escape hatch for things no other tool covers). |
| `catc_assign_fabric_port` | Assign an edge port to a fabric VLAN (host onboarding): Catalyst Center configures the access port (VLAN, authentication template) on the edge. |
| `catc_claim_pnp_device` | Claim an Unclaimed Plug and Play device to a site: Catalyst Center pushes the day-0 onboarding template (with its variables), optionally an image, then adds the device to the inventory at that site. |
| `catc_delete_compliance_policy` | Delete a user compliance policy with its rules, conditions and site assignments; its violations disappear from the compliance results. |
| `catc_delete_device` | Remove a device from Catalyst Center. |
| `catc_delete_discovery` | Delete a discovery job and its results (devices it added stay in the inventory). |
| `catc_delete_pnp_device` | Remove a device from the Plug and Play list (not from the inventory). |
| `catc_delete_policy_server` | Remove an authentication and policy server (plain AAA or the integrated ISE) from Catalyst Center. |
| `catc_delete_sda_object` | Remove an SD-Access object: a port assignment, an anycast gateway, a layer 3 virtual network, a device's fabric role or a fabric site. |
| `catc_delete_site` | Delete a site from the hierarchy. |
| `catc_deploy_template` | Deploy (push) a committed configuration template to devices: an explicit list, every device under a site, or every device with a tag. |
| `catc_distribute_image` | Copy an imported software image to a device's flash (SWIM distribution) without activating it. |
| `catc_provision_devices` | Provision wired network devices to the site they are assigned to: Catalyst Center pushes the site's network settings (AAA, DNS, NTP, banner, syslog/SNMP trap/telemetry, etc.) to them. |
| `catc_provision_wireless_controller` | Provision a Catalyst 9800 WLC: set its primary managed AP locations, then push the WLANs, policy profiles and tags of the wireless profiles assigned to those sites (plus the site's AAA, DNS, NTP and telemetry settings). |
| `catc_replace_device` | Replace a faulty device with a new one of the same model (RMA): Catalyst Center pushes the faulty device's archived running config (and licences) to the replacement through PnP and moves the inventory entry, site and history to the new serial. |
| `catc_reset_pnp_device` | Reset a PnP device that is in Error so it retries onboarding (it becomes Unclaimed again and can be claimed with catc_claim_pnp_device). |

## API spec

Catalyst Center does not serve its OpenAPI document over the API, so the server ships one:
`src/catc_mcp/specs/catc-3.2.2.json.gz` is the Intent/System/Data API spec (OpenAPI 3.0.3, 1,421
paths / 1,914 operations) **exported from the Developer Toolkit of a Catalyst Center 3.2.2-75131
appliance**, with examples stripped (`scripts/bundle_spec.py`). Cisco's public
[catalyst-center-api-specs](https://github.com/cisco-en-programmability/catalyst-center-api-specs)
repository only covers the Assurance APIs. To refresh it for another release, export the spec from
*Platform > Developer Toolkit > APIs* and run
`uv run python scripts/bundle_spec.py swagger.json <version>`.

## Deploying (Docker)

```bash
uv run catc-mcp-server token reptar        # put the sha256 line in .env as MCP_AUTH_TOKENS=...
CORE_READ_TOKEN=$(gh auth token) docker compose up -d --build
curl -s http://localhost:8034/health
```

The compose file runs the container read-only, non-root, with all capabilities dropped; writes are on
and the dangerous tier is off. `CORE_READ_TOKEN` is only needed while stutters-mcp-core is private.

## Development

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest   # unit (respx)
uv run pytest tests/live -m live     # against the lab in .env; creates and removes mcp-test-* objects
uv run python scripts/tool_table.py  # regenerate the tool tables above
uv run python scripts/gap_report.py  # API coverage per area (docs/GAP-ANALYSIS.md)
```

Troubleshooting configuration: `uv run catc-mcp-server config` prints the effective settings and where each
came from (secrets only as set/unset), without contacting Catalyst Center.

Live tests skip themselves when `CATC_URL` is unset or unreachable. The device workflow tests in
`tests/live/test_live_phase2.py` need the two CML routers of the cml-mcp-server `catc-routers`
recipe (198.18.128.152/.153) discovered and reachable, and skip otherwise. SWIM distribute/activate
are covered by mocked unit tests only (no importable image in the lab).

## License

MIT. See [LICENSE](LICENSE).
