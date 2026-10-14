# catc-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Catalyst Center** (formerly DNA Center).
It gives an AI assistant curated, task-oriented tools for inventory, sites, assurance health and issues,
topology, compliance, configuration templates, software images, discovery, path trace and read-only CLI,
plus a spec-driven escape hatch for the rest of the Intent API. Built on
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

Create a dedicated local user (System > Users & Roles > User Management) instead of using an admin:

- **Read-only use:** assign the built-in **OBSERVER-ROLE**. Everything in the read tier works except
  `catc_run_show_commands` and `catc_path_trace`, which start jobs on the appliance (see the next item).
- **Read + troubleshooting:** a custom role (System > Users & Roles > Role Based Access Control) with
  Read on everything, plus Write on *Assurance > Path Trace* and *Network Analytics > Data Access /
  Command Runner*.
- **Writes:** add Write on *Network Design* (sites, network settings), *Network Provisioning >
  Inventory Management* (tags, discovery, device site assignment, resync, compliance) and *Network
  Provisioning > Templates*.
- **Dangerous tier:** additionally *Network Provisioning > Provision* and *Image Update*; or use
  NETWORK-ADMIN-ROLE. Keep this on a separate token/instance with `MCP_ENABLE_DANGEROUS=true`.

Every tool call is written to the audit log with the caller's token name, so give each person their own
token (`catc-mcp-server token alice`).

## Tools

Start with `catc_status`, then `catc_list_devices` / `catc_get_site_hierarchy`. The smart tools do the
most work per call: `catc_device_360`, `catc_client_360`, `catc_path_trace`, `catc_run_show_commands`.
Names, IPs, serial numbers and site paths are accepted wherever an id is expected.

- `catc_run_show_commands` is **read tier** but only accepts `show ...` commands; after a `|` only
  include/exclude/begin/section/count filters are allowed (no redirects, no `;`, `&`, `<`, `>`).
- Running configs, template bodies and command output have passwords, secrets, keys and SNMP
  communities masked.
- `catc_api_call` does GETs in the read tier; with the dangerous tier on, it also does preview-first
  POST/PUT/PATCH/DELETE. Find endpoints with `catc_search_spec` and bodies with `catc_get_definition`.

### Read (38)

| Tool | What it does |
|---|---|
| `catc_client_360` | Everything about one client in one call: identity (IP, user, host type/OS), health score, where it connects (switch and port, or AP, SSID, band and RSSI/SNR), VLAN, onboarding state, its active issues and recent onboarding events. |
| `catc_device_360` | Everything about one network device in one call: inventory record, site, assurance health (overall, CPU, memory), active issues (last 24h), interface counts and the ports that are down while admin-up, compliance status and end-of-life (EoX) alerts. |
| `catc_get_client` | Details for one wired or wireless client: IP, user, host type/OS, health score, connected switch/port or AP/SSID/band, VLAN, RSSI/SNR, and onboarding state. |
| `catc_get_client_health` | Client health summary: overall, wired and wireless client scores and how many clients are in each health band (poor/fair/good/idle/no data). |
| `catc_get_compliance_detail` | Compliance report for one device per category (startup vs running config, image, PSIRT, EoX, network settings, network profile, fabric): status, last check time and, with include_diff, what differs. |
| `catc_get_compliance_summary` | Fleet compliance at a glance: how many devices are compliant, non-compliant, in progress, not available or in error, and which devices are non-compliant (with hostname). |
| `catc_get_definition` | Describe a Cisco Catalyst Center API operation (parameters, request fields, required fields) or a schema (fields with types and enums). |
| `catc_get_device` | Full inventory record for one network device: platform, serial, software, role, uptime, reachability and collection status (with failure reason), management IP, MAC, location. |
| `catc_get_device_config` | The device's running configuration as last collected by Catalyst Center (not live: run catc_run_show_commands for that). |
| `catc_get_issue` | One assurance issue in full: description, affected device/client/site, timeline, additional attributes and Catalyst Center's suggested actions (troubleshooting steps). |
| `catc_get_l3_topology` | Layer 3 topology for one routing protocol: routers and the adjacencies between them with interface names and addresses. |
| `catc_get_network_health` | Overall network health score and the healthy/unhealthy device counts per category (access, distribution, core, router, wireless), plus a per-site health summary. |
| `catc_get_physical_topology` | Physical (CDP/LLDP-derived) topology: devices and the links between them with port names, link status and addresses. |
| `catc_get_site` | One site: id, type, name hierarchy, address/coordinates (buildings), dimensions and RF model (floors), its direct child sites and how many network devices are assigned to it. |
| `catc_get_site_hierarchy` | The site hierarchy (Global > areas > buildings > floors) as an indented tree with each site's type and id. |
| `catc_get_site_settings` | Network settings for a site (Design > Network Settings): AAA servers, banner, DHCP, DNS, NTP, telemetry (syslog/SNMP/NetFlow collectors), time zone and image distribution servers. |
| `catc_get_task` | Status of an asynchronous Catalyst Center operation: progress, whether it finished or failed, the failure reason and any result data. |
| `catc_get_template` | One template in full: content (CLI body), language, variables (name, type, required, default, choices), target device families/software, project and version history. |
| `catc_get_vlan_topology` | Without `vlan`: the VLAN names Catalyst Center knows about. |
| `catc_list_audit_logs` | Catalyst Center audit log, newest first: who did what and when (logins, provisioning, template deploys, configuration changes, API calls), with category and severity. |
| `catc_list_device_health` | Assurance health per network device: overall score, CPU/memory, interface/link errors, reachability, and the issue count. |
| `catc_list_device_interfaces` | Interfaces of one device with oper/admin status, description, IPv4 address, VLAN, port mode, speed/duplex and MAC. |
| `catc_list_device_modules` | Hardware modules of one device (line cards, supervisors, power supplies, fans, transceivers) with part number, serial number and operational state. |
| `catc_list_devices` | List network devices in the Catalyst Center inventory with hostname, management IP, platform, software version, role, reachability and serial. |
| `catc_list_discoveries` | Discovery jobs with their type (range/CDP/LLDP/single), IP ranges, status, condition and number of devices found. |
| `catc_list_discovery_devices` | Devices found by one discovery with reachability, the failure reason when unreachable, and CLI/SNMP/NETCONF credential status: the place to look when a discovery 'found nothing'. |
| `catc_list_events` | Assurance events (syslog, SNMP traps, client onboarding events) for network devices or clients, newest first. |
| `catc_list_images` | Software images known to Catalyst Center (imported into the repository, or suggested from cisco.com): name, version, product families, golden tag, integrity status and id. |
| `catc_list_issues` | Assurance issues (problems Catalyst Center detected) with priority, severity, status, category, affected entity and site, newest first. |
| `catc_list_tag_members` | Members of one tag: network devices (hostname, IP, platform) or interfaces, whether added statically or by a dynamic rule. |
| `catc_list_tags` | Tags used to group devices and interfaces (for templates, provisioning and filtering): name, description, whether it is a system tag, dynamic membership rules and id. |
| `catc_list_template_projects` | Template projects (folders of templates) with description, id and template count. |
| `catc_list_templates` | Configuration templates (Template Editor) with project, language (Jinja/Velocity), software type, device families, committed version count and id. |
| `catc_path_trace` | Trace the network path between two IPs as Catalyst Center sees it: each hop (device, ingress/egress interfaces, how the link was learned), ACL verdicts when statistics are requested, and the failure reason if the trace can't be built (e.g. the source isn't known to Catalyst Center). |
| `catc_preview_template` | Render a template with the given variable values and show the resulting CLI, without deploying anything. |
| `catc_run_show_commands` | Run read-only `show` commands live on managed devices through Catalyst Center's command runner and return each device's output. |
| `catc_search_spec` | Search the Cisco Catalyst Center OpenAPI spec for operations (method + path) and schemas. |
| `catc_status` | Check the connection to Cisco Catalyst Center: product version and API user, which API surfaces answer, and this MCP server's configuration (writes enabled?, TLS verification). |

### Write (16)

| Tool | What it does |
|---|---|
| `catc_assign_devices_to_site` | Assign (or move) unprovisioned network devices to a building or floor. |
| `catc_commit_template` | Commit a template's current content as a new version (required before deploying it). |
| `catc_create_discovery` | Start a device discovery (IP range, CIDR, or CDP/LLDP from a seed) that adds what it finds to the inventory. |
| `catc_create_site` | Create an area, building or floor in the site hierarchy. |
| `catc_create_tag` | Create a (static) tag for grouping devices or interfaces. |
| `catc_create_template` | Create a (not yet committed) configuration template in a project. |
| `catc_create_template_project` | Create a template project (a folder for configuration templates). |
| `catc_delete_tag` | Delete a user-defined tag (its members are untagged, not deleted). |
| `catc_delete_template` | Delete a configuration template and all its versions. |
| `catc_delete_template_project` | Delete a template project together with every template in it. |
| `catc_resync_devices` | Re-collect inventory (config, interfaces, modules) from devices now instead of waiting for the next polling cycle. |
| `catc_run_compliance` | Run a compliance check now for devices (all categories unless given). |
| `catc_update_issue_status` | Mark assurance issues as resolved, or ignore them for some hours. |
| `catc_update_site` | Rename a site or change a building's address/coordinates or a floor's number, RF model and dimensions. |
| `catc_update_tag_members` | Add network devices to, or remove them from, a static tag. |
| `catc_update_template` | Change a template's content or description (creates uncommitted changes; commit with catc_commit_template). |

### Dangerous (8)

| Tool | What it does |
|---|---|
| `catc_activate_image` | Install and activate a software image on a device (distributing it first if needed). |
| `catc_api_call` | Call any Cisco Catalyst Center REST endpoint (escape hatch for things no other tool covers). |
| `catc_delete_device` | Remove a (non-provisioned) device from the Catalyst Center inventory; with clean_config also remove the settings Catalyst Center configured on it. |
| `catc_delete_discovery` | Delete a discovery job and its results (devices it added stay in the inventory). |
| `catc_delete_site` | Delete a site from the hierarchy. |
| `catc_deploy_template` | Deploy (push) a committed configuration template to devices. |
| `catc_distribute_image` | Copy an imported software image to a device's flash (SWIM distribution) without activating it. |
| `catc_provision_devices` | Provision wired network devices to a site: Catalyst Center pushes the site's network settings (AAA, DNS, NTP, syslog/SNMP/telemetry, etc.) to them. |

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
```

Live tests skip themselves when `CATC_URL` is unset or unreachable. With an empty inventory the
device/client tools are only checked for clean empty or not-found answers; deploy, provisioning and
SWIM are covered by mocked unit tests.

## License

MIT. See [LICENSE](LICENSE).
