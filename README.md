# catc-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Catalyst Center** (formerly DNA Center).
It gives an AI assistant curated, task-oriented tools for the operator workflows: onboarding (credentials,
discovery, sites, network settings, IP pools, provisioning), day-N changes (templates, deploy, compliance
and config drift) and troubleshooting (device/client 360, issues with suggested commands, events, path
trace, read-only CLI), plus SWIM, topology and appliance health, and a spec-driven escape hatch for the
rest of the Intent API. `docs/GAP-ANALYSIS.md` maps the whole 3.2.2 API to the tools. Built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core).

> **Disclaimer.** This is not an official Cisco product or repository, and it isn't supported or endorsed by
> Cisco. It's a personal project by [@dr-stutters](https://github.com/dr-stutters), for lab and learning use
> only: don't point it at production systems. It's provided as is, with no warranty (see the
> [license](LICENSE)). Cisco and Catalyst Center are trademarks of Cisco Systems, Inc.

- **Supported version:** Catalyst Center **3.2.2** (tested against 3.2.2-75131). Most tools use
  long-standing Intent API endpoints and should work on 2.3.7.x and 3.1.x; SWIM distribute/activate use
  the `networkDeviceImages` API added in 3.1.3.
- **Safety:** read-only by default. Writes and the dangerous tier are opt-in, and every change is
  **preview-first**: the first call returns a preview and a single-use confirm token; nothing changes
  until the identical call is repeated with that token (refused if the arguments, the caller or the
  target objects changed in between).

## Quickstart (5 minutes)

You need: a Catalyst Center API user for the server (read-only is enough to start: the custom role
**mcp-catc-ro**, see [docs/least-privilege.md](docs/least-privilege.md); never SUPER-ADMIN-ROLE on a shared server).

**A. On your laptop (stdio), from a release wheel.** Every [GitHub release](https://github.com/dr-stutters/catc-mcp-server/releases)
has a wheel with stutters-mcp-core bundled in; it needs only PyPI dependencies.

```bash
WHEEL=https://github.com/dr-stutters/catc-mcp-server/releases/download/v0.20.1/catc_mcp_server-0.20.1-py3-none-any.whl
export CATC_URL=https://catalyst-center.example.com CATC_USERNAME=mcp-catc-ro CATC_PASSWORD='...'
uvx --from "$WHEEL" catc-mcp-server check           # preflight: login, TLS, role, version, ISE integration
claude mcp add catc -e CATC_URL=$CATC_URL -e CATC_USERNAME=$CATC_USERNAME -e CATC_PASSWORD="$CATC_PASSWORD" \
  -- uvx --from "$WHEEL" catc-mcp-server             # stdio is the default transport
```

Claude Desktop (`claude_desktop_config.json`), same idea:

```json
{
  "mcpServers": {
    "catc": {
      "command": "uvx",
      "args": ["--from", "https://github.com/dr-stutters/catc-mcp-server/releases/download/v0.20.1/catc_mcp_server-0.20.1-py3-none-any.whl", "catc-mcp-server"],
      "env": {"CATC_URL": "https://catalyst-center.example.com", "CATC_USERNAME": "mcp-catc-ro", "CATC_PASSWORD": "..."}
    }
  }
}
```

**B. On a shared host (HTTP), from the image.** Multi-arch (amd64/arm64), signed, with an SBOM:
`ghcr.io/dr-stutters/catc-mcp-server:<version>` (or `:latest`).

```bash
docker run --rm -e CATC_URL=https://catalyst-center.example.com -e CATC_USERNAME=mcp-catc-ro -e CATC_PASSWORD='...' \
  ghcr.io/dr-stutters/catc-mcp-server catc-mcp-server check
docker run --rm ghcr.io/dr-stutters/catc-mcp-server catc-mcp-server token alice   # one token per person
cp .env.example .env && chmod 600 .env    # CATC_*, MCP_AUTH_TOKENS=alice:sha256:...
docker compose up -d                      # pulls the image; http://localhost:8034/mcp
claude mcp add --transport http catc http://localhost:8034/mcp --header "Authorization: Bearer <token>"
```

For a team, use [docs/deploying.md](docs/deploying.md): read-only by default, per-user tokens in the audit
log, several Catalyst Centers, the shared token and API limits, the change rails, TLS with Caddy, upgrades.

**`check`** runs without an MCP client and exits 1 on a failure (`--json` for scripts, `--strict` to fail on
warnings, `--instance lab` for one Catalyst Center). It reports the token login
(`POST /dna/system/api/v1/auth/token`) and the Intent API, TLS trust, the credentials, the API user's roles
against the enabled tiers, the Catalyst Center release against the bundled API spec (3.2.2 tested; older than
2.3.7 fails), and whether Cisco ISE is integrated (informational, never a failure):

```text
  OK    reachability[login]    POST /dna/system/api/v1/auth/token issued an X-Auth-Token (210 ms)
  OK    reachability[intent]   Intent API answered (release 3.2.2-75131) (95 ms)
  OK    tls                    certificate verified against the system trust store
  OK    auth                   credentials accepted; the token lasts 60 min and is renewed after 55 min, ...
  FAIL  role                   role 'mcp-catc-ro (ro)' cannot use the write tier(s) this server enables
                               -> Give the account a role that allows them (docs/least-privilege.md), or ...
  OK    version                Catalyst Center 3.2.2-75131: tested (bundled API spec 3.2.2-75131)
  OK    ise                    Cisco ISE integrated: 192.0.2.10 ACTIVE
```

`catc-mcp-server serve --http` serves HTTP (needs `MCP_AUTH_TOKENS`); `catc-mcp-server config` shows the
effective settings and where each came from, without contacting Catalyst Center.

### From source

```bash
git clone https://github.com/dr-stutters/catc-mcp-server && cd catc-mcp-server
python3 scripts/bundle_core.py vendor    # bundles the pinned stutters-mcp-core as catc_mcp._core (needs git)
uv sync
cp .env.example .env && chmod 600 .env   # set CATC_URL, CATC_USERNAME, CATC_PASSWORD
uv run catc-mcp-server check
```

The shared [stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) library (with its `tasks` extra) is
**bundled** into the package as `catc_mcp._core` (core ADR-005): the wheel, the sdist and the Docker image need
nothing but their PyPI dependencies, with no git dependency and no token. `uv build` writes a wheel that installs on
its own (`pip install dist/catc_mcp_server-*.whl`), with the Catalyst Center spec bundle included as before; every
GitHub release has one attached. The pinned core tag is `[tool.bundle-core]` in `pyproject.toml` and `catc_status`
reports it as `core_version`. The vendored copy is generated, not committed: `scripts/bundle_core.py vendor` writes
it, `check` reports drift, and `update --tag vX.Y.Z` moves the pin (then `uv lock`). A plain git checkout has no
`catc_mcp/_core`, so install from a release wheel rather than `git+https://...`.

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
| `MCP_TASKS` / `MCP_TASKS_URL` | `false` / `memory://` | Run the long tools as MCP background tasks: `catc_create_discovery`, `catc_provision_devices`, `catc_provision_site`, `catc_deploy_template`, `catc_distribute_image`, `catc_activate_image`, `catc_provision_wireless_controller`, `catc_claim_pnp_device`, `catc_replace_device`, `catc_add_fabric_device`, `catc_add_anycast_gateway` (clients without task support call them normally) |
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
lists every permission, the access-group requirement and the API calls that create the roles, access groups and
users. `catc_status` shows the account's roles under `catc.account` and warns when they allow
more than the enabled tiers.

Every tool call is written to the audit log with the caller's token name, so give each person their own
token (`catc-mcp-server token alice`).

## Safety rails

Every write is preview-first. On top of that (core G7, `docs/PRODUCTION.md` in stutters-mcp-core):

- **`CATC_MAX_DEVICES_PER_CHANGE`** (default **10**, `0` = off): template deploys, provisioning, SWIM
  distribute/activate, PnP claims, device replacement, device deletion and `catc_write_memory` that touch more
  devices are blocked in the preview. `catc_deploy_template` targets an explicit device list, every device under
  a `site` (child sites included; `Global` = the whole inventory) or a `tag`; the limit applies after expansion.
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
- **One port** (contain or fix a client port; dangerous tier): `catc_set_interface(device, interface,
  action=shut|no_shut|access_vlan|voice_vlan|description)` through Catalyst Center's interface API. Uplinks
  (physical topology), trunks, port channels and virtual interfaces are refused unless `allow_uplink`; the
  management port is never shut. The preview shows the port row, Catalyst Center's dry run
  (`deploymentMode=Preview`) and the undo call; one device for `CATC_MAX_DEVICES_PER_CHANGE`.
- **What happened here?** `catc_recent_activity(device=..., site=..., hours=...)` merges issues,
  assurance events, event notifications and the audit log for one window (pull-only: queried when
  called); drill down with `catc_list_event_notifications` / `catc_list_audit_logs`.
- **What happened to this client?** `catc_client_timeline(mac=..., hours=... or since=...)` merges its
  onboarding steps, assurance events (ISE authentications, roams, failures) and issues by time.
- **Template versions:** `catc_list_template_versions` → `catc_diff_template_versions`;
  `catc_template_usage` / `catc_template_drift` show which devices run an older version (roll back with
  `catc_deploy_template(version=...)`); move templates with their history between projects or Catalyst
  Centers with `catc_export_templates` → `catc_import_templates` (`name=` imports a copy).
- **Standards:** `catc_create_compliance_policy` (regex/string rules on the running config) →
  `catc_run_compliance` → `catc_list_compliance_violations`.
- **Baseline and drift:** `catc_export_config` (sites, settings, credentials by name, templates, profiles,
  pools, SSIDs, tags, compliance policies as stable YAML; [format](docs/config-export.md)) →
  later `catc_diff_config(before=<export>)` lists what changed against live Catalyst Center (or against a
  second export); `catc_list_audit_logs` says who.
- **Rebuild or promote a design:** `catc_import_config(export=<export>, secrets=...)` (dangerous tier) plans
  the export onto a Catalyst Center by name, in dependency order (sites, credentials, settings, pools,
  reservations, templates, profiles, tags), creates what is missing, updates sites and site settings that
  differ, never deletes or overwrites the rest, and stops at the first failure
  ([docs](docs/config-export.md#import)). Provision afterwards.
- **Wireless config audit:** `catc_get_wlc_config(wlc)` summarizes the feature models Catalyst Center keeps
  for a 9800 WLC (WLAN, policy and RLAN profiles, policy and site tags, RF, AP join, flex, mDNS, mesh,
  calendar, Dot11be) with counts and names; `feature=` returns one family in full (`children=true` adds the
  sub-collections, e.g. a policy tag's WLAN-to-policy mappings); `state='deployed'` reads what the WLC
  reported back, and `diff=true` lists per feature the profiles only on one side and the fields that differ.
  PSKs, MPSK keys and AP passwords are masked and never compared. AP tag and location mappings stay empty
  until APs join. The models exist only for WLCs with Per-Device Configuration enabled (D71);
  a WLC provisioned through site-based network profiles (`catc_provision_wireless_controller`) has none, and
  the tool says so.
- **Wireless change (per-device):** on a 9800 with Per-Device Configuration enabled (not provisioned through
  site-based profiles), `catc_set_wlan_security`, `catc_set_wlan_vlan` and `catc_set_rf_profile` stage a
  change in the intended model; `catc_get_wlc_config(diff=true)` shows what is pending and
  `catc_deploy_wlc_config` (dangerous) pushes it and reports each config group's status
  (`catc_get_wlc_deployments`). Needs the provisioning settings without "require preview"
  ([docs](docs/wireless-per-device.md)).
- **AP join and power profiles:** `catc_list_ap_profiles` shows each AP profile (SSH/Telnet and management
  user, the AP's 802.1X supplicant, CDP, rogue detection, country, time zone, power profile; passwords masked)
  with the wireless profile site tags that use it, plus the AP power profiles. `catc_set_ap_profile` and
  `catc_set_ap_power_profile` create, update or delete them (write tier, preview-first). They are design
  objects: a wireless profile site tag names the AP profile and a WLC re-provision pushes it.
- **SD-Access:** prerequisites (the `aca` + `sda` packages, re-seeded roles, ISE), the build order
  (`catc_build_fabric_site`), the way out of the fabric, day-N changes, checks, group-based policy and teardown
  are in [docs/sd-access.md](docs/sd-access.md), with the 3.2.2 quirks found live.
- **Backups (before the group-based policy migration or an upgrade):** `catc_get_backup_status` says whether a
  backup target (NFS or physical disk) is configured, whether a backup can run now and how the last ones went;
  `catc_create_backup` (dangerous, needs a SUPER-ADMIN-ROLE account) takes one, refusing in the preview when there
  is no target, no encryption passphrase, an unhealthy NFS server, a running backup/restore or a duplicate name;
  follow it with `catc_get_backup_status(execution=...)` and `catc_list_backups`. Restores stay in the GUI.
- **Profiles:** `catc_attach_template_to_profile` / `catc_assign_profile_to_sites` record which Day-N
  templates belong to a site; the provisioning API doesn't push them (3.2.2), so deploy them with
  `catc_deploy_template`.

Prompts: `catc_onboard_device` (write tier) walks credentials → discovery → site → settings →
assign → provision → template deploy → verification, preview-first at every write.
`catc_change_window` (write tier) runs a Day-N template change: baseline (issues, compliance, config
archive) → per-device preview → rails (≤ 10 devices, window end) → deploy → deployment status → CLI
check → config diff → compliance → issue diff → a written rollback plan (negation template or the
pre-change archive). It offers a maintenance window (`catc_schedule_maintenance`) so the change's own
alerts stay quiet; a started window can't be cancelled or given a new end time (Catalyst Center
refuses it), so after verification it is ended with `catc_update_maintenance_window(end_now=true)`.
Without the dangerous tier it stops after the rails with a reviewed change plan.
`catc_onboard_switch_with_nac` (write tier, uses the **ise** server too) checks the ISE integration
(`catc_get_policy_servers`), sets the site's client AAA to ISE, onboards and provisions the switch,
confirms its NAD in ISE (`ise_get_nad`), deploys an IBNS 2.0 MAB/802.1X port template and verifies
the first authentication (`ise_find_session`, `ise_get_auth_history`, `ise_why_auth_failed`,
`ise_endpoint_360`, `catc_client_360`), then checks that every device at the site is a NAD in ISE
(`ise_audit_nads` with the site's `catc_list_devices` rows, matched by IP).
`catc_admin_access_via_ise` (dangerous tier, uses **ise** and **Windows_Server**) moves Catalyst Center admin
logins onto an AD group through ISE: AD group and user, ISE NAD for Catalyst Center, an authorization profile
returning `cisco-av-pair = Role=<role>`, a policy set for Catalyst Center's RADIUS logins (with ISE mirror users
for the local accounts as a break-glass path), external authentication on, a local and an AD test login, the ISE
auth record and an undo list; by default it switches external authentication off again at the end.
`catc_client_troubleshoot` (read tier, uses **ise**) takes a client by MAC, IP or username through Catalyst
Center (360, issues, live CLI, path trace), ISE (auth history, failure reason, NAD) and the switch's AAA health to a
diagnosis and a previewed-only fix.
`catc_site_health_review` (read tier) is the weekly review of one site as a single ranked report: maintenance
windows first (`catc_list_maintenance_windows`: devices under maintenance are listed apart, never as findings),
health now and over the window (`catc_site_health_report`, `catc_health_trend`, network, device and client
health), open and recurring issues, compliance (`catc_compliance_report`), image currency against the golden image
(`catc_list_device_images`) and template drift (`catc_template_drift`), ranked most severe first and ending with
next steps that name the tools to run.
`catc_build_fabric_site` (dangerous tier, uses **ise** for the AAA check) builds an SD-Access fabric site from
switches to a client in the fabric: SD-Access availability and the account's tier, devices onboarded and provisioned
at the building, the client pool, the fabric site, border and control plane before the edges, the VN, the anycast
gateway, the edge ports, then the checks (fabric read-back, CLI on the edges, pending fabric events,
`catc_fabric_health`), and the teardown (`catc_delete_fabric_site` with cascade) as a preview. An authentication
template other than No Authentication comes last, after an AAA check: RADIUS to ISE from every fabric device's
RLOC, and the NADs and their location in ISE.

`catc_group_policy_rollout` (write tier, uses **ise**) changes one cell of ISE's TrustSec matrix and proves a
Catalyst Center-managed edge enforces it: the groups and the cell in ISE and on the edge, the previewed
`ise_set_egress_policy` and `ise_push_trustsec_matrix`, the clients' SGTs (`ise_find_session`), the edge's
downloaded cell and bindings (`catc_get_group_policy_enforcement`), a test flow and the counters, and an undo
preview. ISE stays the policy owner; the prompt never starts Catalyst Center's group-based policy migration.
`catc_guest_wireless_with_ise` (dangerous tier, uses **ise**) builds guest Wi-Fi with ISE central web auth
the validated way: guest type, sponsor group and portal in ISE, a CWA redirect authorization profile and the
Wireless MAB redirect / Guest Flow permit rules scoped to the SSID, then a Guest web-auth SSID
(`catc_create_ssid` with `l3_auth='web_auth'`, `auth_server='auth_ise'`, the ISE PSN as `auth_servers`, MAC
filtering and AAA override; no `pre_auth_acl`, since ISE returns the redirect ACL), a wireless profile at the AP
location, the redirect ACL on the 9800, WLC
provisioning, the read-back and 9800 CLI check (`show wlan name`, the policy profile's AAA override and NAC,
CoA), `ise_policy_explain` for the redirect and permit hits, and an undo list (applied at the end with
`keep=false`).
`catc_decommission_device` (dangerous tier, uses **ise**) keeps a copy of the config, shows what
un-provisioning loses (it deletes the device), untags it, deletes it with an explicit `clean_config`, and
removes the NAD Catalyst Center leaves in ISE (`ise_get_nad`, `ise_delete_nad`).

`suite_change_check` (read tier, from the stutters-mcp-core suite pack) is the pre/post change check across
SD-WAN, ISE, Catalyst Center and FMC. The Catalyst Center leg is `catc_snapshot(site)` before the change and
`catc_compare_snapshot(before)` after it. The snapshot covers device reachability, health score and version, health per site,
compliance per device and type, and open P1/P2 issues. The blob stays in the conversation, and the compare names what
got unhealthy.

The rest of the suite pack: `suite_access_review` (read tier) lists who can change what on every connected
platform (admin accounts, roles and the external groups that grant them, resolved to people through Active
Directory); `suite_asbuilt_drift` (read tier, uses **netbox**) checks whether the documentation has drifted from
the wiring; `suite_decommission_site` (dangerous tier) removes one site everywhere it exists without leaving
orphans (here: the site with its devices, fabric site and pool reservations); `suite_maintenance_window`
(dangerous tier) runs one maintenance window at a site across products (here: SWIM distribute, then activate one
device at a time). Legs whose tools a server does not ship yet are marked pending in the prompt.

- **ISE / AAA:** `catc_add_ise_server` → `catc_accept_ise_certificate` (check the fingerprints) →
  `catc_update_site_aaa_settings` → `catc_provision_devices` (pushes RADIUS config and creates the
  NAD in ISE; deleting the device later does **not** remove that NAD). `catc_get_policy_servers`
  gives each server a `next_action`; an entry that FAILED (ISE renamed, certificate renewed, FQDN not
  matching its CN) is fixed in place with `catc_update_policy_server` (ISE password re-entered), then
  the certificate is accepted again; `include_sites=true` lists the sites whose AAA uses each server.
  When the enterprise CA is renewed or replaced, `catc_import_trusted_certificate` puts the new CA chain in
  Catalyst Center's trust store (root first; leaf, expired and key-carrying PEMs refused in the preview)
  before ISE's leaves are re-issued.
- **SD-Access fabric AAA:** `catc_check_fabric_aaa(fabric_site)` reads every fabric device live (one command
  runner request): the RLOC its RADIUS comes from (Loopback0), each RADIUS server's state (DEAD, dead count,
  automate-tester), TrustSec environment data and PAC, with a verdict and the fix per device. Pass the ise
  server's `ise_list_nads(response_format='json')` results as `ise_nads` (and `expected_location`) to check
  the NAD covering each RLOC and its location group too; without them the result gives the `ise_audit_nads`
  arguments.
- **Admin login through ISE:** `catc_get_external_authentication` (on/off, AAA attribute, servers, roles) →
  ISE side (Catalyst Center as a NAD with the policy-server shared secret, an authorization profile returning
  `cisco-av-pair = Role=<role>`) → `catc_set_external_authentication(enable=true)` (dangerous; lockout risk named
  in the preview) → `catc_test_login` with a local admin first, then the external user (pass/fail and the roles
  granted; the password and token are never stored or returned).
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

### Read (112)

| Tool | What it does |
|---|---|
| `catc_ai_insights` | AI-driven issues from Cisco AI Network Analytics (baseline deviations Catalyst Center learns in the cloud) for the network or a site. |
| `catc_check_fabric_aaa` | Whether every fabric device at an SD-Access fabric site can do AAA with ISE, with a verdict and the fix per device. |
| `catc_client_360` | Everything about one client in one call: identity (IP, user, host type/OS), health score, where it connects (switch and port, or AP, SSID, band and RSSI/SNR), VLAN, onboarding state, its active issues and recent onboarding events. |
| `catc_client_timeline` | What happened to this client? One timeline, newest first, for one MAC: the onboarding steps Catalyst Center timestamps for it (association, authentication, DHCP, onboarded), its assurance events (ISE authentications, onboarding attempts with each step, roams, disconnects, with the result and failure reason) and its issues, merged by time with a `source` column. |
| `catc_compare_device_configs` | Unified diff between two archived configurations of one device: what changed since the previous running config, what is unsaved (running vs startup), or any two archive files. |
| `catc_compare_snapshot` | Compare a catc_snapshot blob from before a change with one from after it (or, when `after` is empty, a fresh snapshot of the same scope taken now) and name what changed, most severe first: major = got unhealthy (session down, metric past its limit, healthy item gone), minor = changed but not clearly bad, info = recovered or improved. |
| `catc_compliance_report` | Which devices are out of standard: compliance at a site (and below) from the last compliance runs, counted by site, category (startup vs running config, image, PSIRT, EoX, network settings, your compliance policies as NETWORK_RULES...) and severity, with the non-compliant devices and their failing categories and policy rule violations (worst first). |
| `catc_config_drift` | Config drift across sites: which devices' running configuration differs from a golden device (lines missing compared with it, and extra lines) or no longer contains what a template renders to (lines missing; a 'no X' template line counts as present when X is absent). |
| `catc_device_360` | Everything about one network device in one call: inventory record, site, assurance health (overall, CPU, memory), tags, whether it is provisioned, active issues (last 24h, repeats grouped, with how long ago each last occurred), interface counts and the ports that are down while admin-up, compliance status and end-of-life (EoX) alerts, and a maintenance note when the device is in a running maintenance window (no issues or health while it runs) or one starts within 24h. |
| `catc_diff_config` | Compare two config exports, or an export with live Catalyst Center: items added or removed and, for changed items, each field that differs (before and after values). |
| `catc_diff_template_versions` | Unified diff between two versions of a template (or a version and the uncommitted draft), with lines added and removed. |
| `catc_eox_report` | End-of-life (EoX) report from Catalyst Center: the network summary (hardware, software and module alerts), each device's scan status, alert count and alert types, and the bulletins behind them (end of sale, end of software maintenance and vulnerability support, last date of support, flagged when already past, with the Cisco link). |
| `catc_export_config` | Export Catalyst Center design intent as YAML, by name and in a stable order: the site hierarchy, network settings set at each site (not inherited), credentials (type, description and username only: secrets are never exported), template projects and templates (secrets in template bodies masked), network profiles with their templates and sites, global IP pools and site reservations, SSIDs (passphrases masked), wireless profiles, tags with their dynamic rules, and compliance policies with their rules and sites. |
| `catc_export_templates` | Export a template project, or one template, as a JSON document: content, variables, device types and every committed version with its comment, author and time. |
| `catc_fabric_health` | SD-Access health as Catalyst Center Assurance scores it. |
| `catc_find_host` | Where is this host plugged in: from a MAC, IP, hostname or username, each matching client Assurance saw in the window, newest first, with its switch (name, management IP) and port or AP/WLC/SSID, VLAN, SGT, site, status, health, last seen and a one-line `where`, plus a live lookup on given switches. |
| `catc_get_activity` | One Catalyst Center activity: description, status, type, recurring, start/end (ISO 8601 UTC) and the jobs it triggered (each run of a recurring schedule, or the job a one-off activity started), with each job's status, failure reason and task id (catc_get_task(task_id) for the task's own detail). |
| `catc_get_backup_status` | Whether Catalyst Center can take a backup now, and how the last ones went: the backup target (NFS server or physical disk, mount path, backups kept, encryption passphrase set, the NFS server's health and the disk use), `ready` with the blockers (no target, no passphrase, NFS unhealthy, a backup or restore already running), the last backup, and the recent backup/restore executions (job, status, percent done, errors). |
| `catc_get_client` | Details for one wired or wireless client: IP, user, host type/OS, health score, connected switch/port or AP/SSID/band, VLAN, RSSI/SNR, and onboarding state. |
| `catc_get_client_health` | Client health summary: overall, wired and wireless client scores and how many clients are in each health band (poor/fair/good/idle/no data). |
| `catc_get_compliance_detail` | Compliance report for one device per category (startup vs running config, image, PSIRT, EoX, network settings, network profile, fabric): status, message, last check time, whether Catalyst Center can remediate it and, with include_diff, what differs. |
| `catc_get_compliance_policy` | One compliance policy: its rules (device families, software type, suggested fix) with their conditions (what is tested, whether a match or a non-match is the violation, severity) and the sites it is assigned to, by name (including the sites below the assigned ones). |
| `catc_get_compliance_summary` | Fleet compliance at a glance: how many devices are compliant, non-compliant, in progress, not available or in error, and which devices are non-compliant (with hostname). |
| `catc_get_definition` | Describe a Cisco Catalyst Center API operation (parameters, request fields, required fields) or a schema (fields with types and enums). |
| `catc_get_device` | Full inventory record for one network device: platform, serial, software, role, uptime, reachability and collection status (with failure reason), management IP, MAC, location. |
| `catc_get_device_config` | The device's running configuration as last collected by Catalyst Center (not live: run catc_run_show_commands for that). |
| `catc_get_device_hardware` | Hardware and licensing of one device in one call: stack members (role, state, priority, serial, platform, software) and StackWise Virtual links, PoE budget (allocated / consumed / remaining watts) and the PoE ports drawing power, module count, and smart-licensing state with the licences in use. |
| `catc_get_external_authentication` | How Catalyst Center admins log in: whether external authentication (System > Users & Roles > External Authentication) is on, the AAA attribute it reads the role from (empty = the default, Cisco-AVPair for RADIUS / cisco-av-pair for TACACS+), the AAA servers it asks (from the authentication and policy servers, e.g. the integrated ISE), the roles an external user can be given (the value the AAA server must return: 'Role=<name>'), and the external users that have logged in so far. |
| `catc_get_fabric_authentication_profile` | The host onboarding (authentication template) posture of an SD-Access fabric site. |
| `catc_get_fabric_multicast` | Multicast at an SD-Access fabric site. |
| `catc_get_fabric_wireless` | SD-Access fabric wireless: the VLAN-to-SSID mappings of each fabric site (fabric-enabled WLANs and the SGT they carry), and for one fabric site the switch-side wireless settings (which fabric devices carry wireless roles, rolling AP upgrade) and wireless multicast. |
| `catc_get_group_policy_enforcement` | What a switch actually enforces for group-based access control (TrustSec / SD-Access), read live through the command runner: the environment data it downloaded from ISE (state, servers, the security group name table), every source -> destination cell with its SGACLs and the default policy, the enforcement counters (SW/HW denied and permitted per cell) and the IP-to-SGT bindings, global and per VRF (on an SD-Access edge the clients' bindings are in their VN's VRF). |
| `catc_get_issue` | One assurance issue in full: description, affected device/client/site, timeline, additional attributes and Catalyst Center's suggested actions with the show commands it proposes (run them with catc_run_show_commands). |
| `catc_get_l3_topology` | Layer 3 topology for one routing protocol: routers and the adjacencies between them with interface names and addresses. |
| `catc_get_lan_automation` | LAN automation (underlay automation) on Catalyst Center: active sessions and their limit, each session's status (seed devices, discovered devices and their site, IP pools, discovery level, multicast, hostname prefix) and optionally the latest log entries. |
| `catc_get_network_health` | Overall network health score and the healthy/unhealthy device counts per category (access, distribution, core, router, wireless), plus a per-site health summary. |
| `catc_get_network_profile` | One network profile: its type, the Day-N CLI templates attached to it and the sites it is assigned to (by name, including inherited child sites). |
| `catc_get_physical_topology` | Physical (CDP/LLDP-derived) topology: devices and the links between them with port names, link status and addresses. |
| `catc_get_policy_servers` | Authentication and policy servers known to Catalyst Center (System > Settings > Authentication and Policy Servers): plain RADIUS/TACACS servers and integrated Cisco ISE, with protocol, ports, state, pxGrid, and per ISE node its role (PRIMARY/SECONDARY/PXGRID), FQDN and certificate trust state; plus the ISE integration status (each step, and the certificate waiting to be accepted, if any). |
| `catc_get_provisioning_settings` | Catalyst Center's global provisioning settings (System > Settings > Visibility and Control of Configurations): require_preview (every provision/deploy must produce a configuration preview that is reviewed before it runs) and require_itsm_approval (that preview also needs ITSM/ServiceNow approval; implies require_preview), what that means for this server's provision, template deploy, wireless deploy and SWIM tools, and the ITSM integrations configured. |
| `catc_get_report_content` | Download a report execution's content (CSV or JSON reports only; PDF/TDE are binary). |
| `catc_get_report_view` | A report view's formats, filters (name, type) and field groups, i.e. |
| `catc_get_sda_fabric` | SD-Access fabric overview in one call: fabric sites (authentication profile, pub/sub), the fabric devices at each with their roles (control plane, border, edge), and per border its BGP AS and handoff counts (IP transit, SD-Access transit, layer 2; detail in catc_list_l3_handoffs), layer 3 virtual networks, anycast gateways (VN, IP pool, VLAN) and edge port assignments, with the ids catc_delete_sda_object takes; when present also fabric zones, port channels, layer 2 VNs, border handoffs (IP transit, SD-Access transit, layer 2), multicast, transit networks and extranet policies. |
| `catc_get_site` | One site: id, type, name hierarchy, address/coordinates (buildings), dimensions and RF model (floors), its direct child sites and how many network devices are assigned to it. |
| `catc_get_site_hierarchy` | The site hierarchy (Global > areas > buildings > floors) as an indented tree with each site's type and id. |
| `catc_get_site_settings` | Network settings for a site (Design > Network Settings): AAA servers, banner, DHCP, DNS, NTP, telemetry (syslog/SNMP/NetFlow collectors), time zone, image distribution servers and the device credentials the site uses (shown as 'TYPE:description', never secrets). |
| `catc_get_ssi_readiness` | Security Service Insertion (SSI) readiness of the SD-Access fabric. |
| `catc_get_system_health` | Health of the Catalyst Center appliance itself: service health events (counts by state and the ones that are not healthy), last backups and the backup target, system licence (registration/evaluation), ISE/AAA server integration status, and release version. |
| `catc_get_task` | Status of an asynchronous Catalyst Center operation: progress, whether it finished or failed, the failure reason and any result data. |
| `catc_get_template` | One template in full: content (CLI body), language, variables (name, type, required, default, choices), target device families/software, project and version history. |
| `catc_get_template_deployment` | Status of one template deployment: overall status and, per device, whether the push succeeded, the CLI actually pushed (realizedClis: what a rollback has to undo) and Catalyst Center's detailed message (e.g. the CLI line the device rejected). |
| `catc_get_vlan_topology` | Without `vlan`: the VLAN names Catalyst Center knows about. |
| `catc_get_wireless_controller` | A Catalyst 9800 WLC as Catalyst Center sees it: provisioning status, primary managed AP locations and the SSIDs deployed on it (admin status, managed by Catalyst Center or not). |
| `catc_get_wlc_config` | Wireless feature configuration Catalyst Center keeps for a Catalyst 9800 WLC (the /dna/campus feature models): WLAN, policy and RLAN profiles, policy and site tags, RF/radio profiles and RF tags, AP join, power, mesh and calendar profiles, flex, mDNS, Dot11be and AP tag mappings. |
| `catc_get_wlc_deployments` | Configuration deployments Catalyst Center ran on a Catalyst 9800 WLC, newest first: per config group (WLAN, policy and RF groups, or the site settings of a site-based provision), its status, when it ran and Catalyst Center's error and remedy when it failed. |
| `catc_health_trend` | Health over a time window: min, average, latest, the worst moment and the dips (when each started, how long it lasted, how low it went), whether it is getting worse, and a short series of points. |
| `catc_issue_recurrence` | What keeps breaking: the same issue (name and device or client) opening and closing again in the window. |
| `catc_lifecycle_signals` | Every lifecycle and security signal Catalyst Center has for one device or the devices under a site, in one read: EoX alerts, Cisco security advisories (PSIRT), field notices, network bugs and insecure configurations (deprecated or weak CLI such as telnet, SNMPv1/v2c communities, HTTP), with one verdict line per signal and a row per device. |
| `catc_link_mismatch` | Links whose two ends disagree, from Catalyst Center's Inventory Insight: speed/duplex mismatches and native VLAN / allowed VLAN mismatches at a site (and the sites below it). |
| `catc_list_activities` | Catalyst Center activities (the scheduler's jobs), split into upcoming (scheduled, not started yet), in progress (running, or a work item waiting for action), recurring (the schedules, e.g. the weekly config-archive backup and the security-advisory scan) and finished (failed first, then newest first). |
| `catc_list_ap_profiles` | AP join profiles (Design > Network Settings > Wireless > AP Profiles): per profile the AP management access (SSH/Telnet, user; passwords masked), the AP's 802.1X supplicant (EAP-FAST/TLS/PEAP, user), CDP, rogue detection and minimum RSSI, country, time zone, power profile and client limit, with the wireless profile site tags that carry it to a WLC. |
| `catc_list_audit_logs` | Catalyst Center audit log, newest first: who did what and when (logins, provisioning, template deploys, configuration changes, API calls) with the device it concerns. |
| `catc_list_backups` | Catalyst Center system backups on the configured backup target, newest first: name, status (SUCCESS, FAILED, IN_PROGRESS), scope (with or without Assurance data), start/end, duration, size, whether it is still on the target and compatible to restore, the release it was taken on, who took it and whether it was on-demand or scheduled. |
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
| `catc_list_health_score_definitions` | Assurance health score settings: per device family (router, switch, WLC, AP, wired and wireless client) each KPI behind the health score, its threshold (e.g. router CPU 95%), whether it counts towards overall health, whether it follows the issue threshold, and DEFAULT or changed (CUSTOM, with the factory threshold beside a changed one). |
| `catc_list_images` | Software images known to Catalyst Center (imported into the repository, or suggested from cisco.com): name, version, product families, golden tag, integrity status and id. |
| `catc_list_ip_pools` | IP address pools: global pools and the subpools reserved from them for sites, with subnet, gateway, DHCP/DNS servers, type (Generic/LAN/Management/Service/WAN) and usage (assigned/total addresses). |
| `catc_list_issue_definitions` | Assurance issue definitions: for each built-in (system) one its name and display name, whether it is enabled, its priority next to the factory default, the threshold where it has one (e.g. minutes BGP may be down), device type and category; for custom ones the syslog rule in words (severity, %FACILITY-SEV-MNEMONIC, text regex, N times in M minutes), priority and whether it notifies. |
| `catc_list_issues` | Assurance issues (problems Catalyst Center detected) with priority, the device they are about, summary, status, site and how long ago each last occurred, newest first. |
| `catc_list_itsm_instances` | ITSM (ServiceNow) integration instances configured in Catalyst Center: name, type, URL, status (credentials are never shown). |
| `catc_list_l3_handoffs` | Layer 3 handoffs of a fabric site's borders: how each VN leaves the fabric. |
| `catc_list_maintenance_windows` | Catalyst Center device maintenance windows: description, status (UPCOMING, IN_PROGRESS, COMPLETED, FAILED), start and end in ISO 8601 UTC, duration, recurrence (every N days until a date), and the devices by hostname. |
| `catc_list_network_profiles` | Network profiles (Design > Network Profiles) with their type, the sites they are assigned to and the Day-N CLI templates attached to them. |
| `catc_list_pending_fabric_events` | SD-Access fabric intent still to push: the pending fabric events Catalyst Center has queued, per fabric site. |
| `catc_list_pnp_devices` | Plug and Play (PnP) devices waiting for or going through zero-touch onboarding: serial, platform, state, the site and workflow they're claimed to, first/last contact, and any error. |
| `catc_list_report_views` | Report view groups (Inventory, Compliance, SWIM, Licensing, EoX, Access Point, ...) or, with group, that group's views. |
| `catc_list_reports` | Reports defined in Catalyst Center with their view, format and executions (newest first: id, status, start/end), for catc_get_report_content. |
| `catc_list_ssids` | Wireless SSIDs defined at a site (Design > Network Settings > Wireless): name, security (auth type), radio bands, whether it's enabled and broadcast, AAA servers and id. |
| `catc_list_tag_members` | Members of one tag: network devices (hostname, IP, platform) or interfaces, whether added statically or by a dynamic rule. |
| `catc_list_tags` | Tags used to group devices and interfaces (for templates, provisioning and filtering): name, description, whether it is a system tag, dynamic membership rules and id. |
| `catc_list_template_projects` | Template projects (folders of templates) with description, id and template count. |
| `catc_list_template_versions` | Version history of a template: every committed version with its number, commit time, author, comment, size and lines added/removed against the version before, and whether the template has uncommitted changes. |
| `catc_list_templates` | Configuration templates (Template Editor) with project, language (Jinja/Velocity), software type, device families, committed version count and id. |
| `catc_list_transit_networks` | SD-Access transit networks, with ids. |
| `catc_network_services_health` | How the AAA (RADIUS), DHCP and DNS servers answered the network, as Catalyst Center Assurance measured it: per server the transactions, successful and failed ones, success %, average latency (AAA: EAP vs MAB split; DHCP: discover-offer and request-ack), one verdict line ("ISE 198.18.134.35 answered 97% of 212 AAA requests, average latency 180 ms; 6 MAB failures on sw1"), the devices (NADs) behind it with their own counts, the top failing devices and the trend. AAA also folds in the Assurance issues saying a device marked its AAA server DEAD or not responding (open or resolved in the window): the data API counts only requests a device sent, so a dead-server window shows no failures. |
| `catc_path_trace` | Trace the network path between two IPs as Catalyst Center sees it: each hop (device, ingress/egress interfaces, how the link was learned), ACL verdicts when statistics are requested, and the failure reason if the trace can't be built (e.g. the source isn't known to Catalyst Center). |
| `catc_preview_template` | Render a template with the given variable values and show the resulting CLI, without deploying anything. |
| `catc_recent_activity` | What happened on this device or site recently? Queries Catalyst Center's assurance issues, assurance events (syslog, traps), platform event notifications and the audit log for the same window and scope, and merges them newest first with a `source` column. |
| `catc_run_show_commands` | Run read-only `show` commands live on managed devices through Catalyst Center's command runner and return each device's output. |
| `catc_search_spec` | Search the Cisco Catalyst Center OpenAPI spec for operations (method + path) and schemas. |
| `catc_security_advisories` | Cisco security advisories (PSIRTs) Catalyst Center matched against the devices: per device the scan status, scan mode and advisory count, and the advisories themselves (id, impact rating, CVSS, CVEs, first fixed releases per vulnerable version, Cisco link, affected devices), highest CVSS first. |
| `catc_site_health_report` | One report on a site over a window: health now, the device and client trends with their dips and direction, when issues were raised, the worst devices and clients with the issue behind each, issues that keep coming back, AI-driven insights where available, and a one-line verdict. |
| `catc_snapshot` | Take a compact, versioned snapshot of Cisco Catalyst Center health for a pre/post change check: device reachability, health score and software version, health per site, compliance per device and type, open P1/P2 Assurance issues. |
| `catc_status` | Check the connection to Cisco Catalyst Center: product version and API user, which API surfaces answer, and this MCP server's configuration (writes enabled?, TLS verification). |
| `catc_template_drift` | Template drift per device: for every device a template was deployed to, the version it last received against the template's latest committed version. |
| `catc_template_usage` | Where a template is used: the network profiles it is attached to, the sites those profiles are assigned to, and the devices it was deployed to with the version each one runs against the latest committed version (current / behind / failed). |
| `catc_test_login` | Prove that a user can log in to Catalyst Center (a local account, or an external one through ISE when external authentication is on): one token request with these credentials, nothing else. |
| `catc_top_problems` | The worst devices or clients over the window, each with the issue behind it. |

### Write (61)

| Tool | What it does |
|---|---|
| `catc_assign_compliance_policy` | Change which sites a compliance policy applies to (each site includes the sites below it). |
| `catc_assign_devices_to_site` | Assign (or move) unprovisioned network devices to a building or floor. |
| `catc_assign_profile_to_sites` | Assign a network profile to sites (areas, buildings or floors; child sites inherit it). |
| `catc_assign_site_credentials` | Set which global credentials (CLI, SNMPv2c read/write, SNMPv3, HTTP read/write) a site uses (Design > Network Settings > Device Credentials). |
| `catc_attach_template_to_profile` | Attach a Day-N CLI template to switching or wireless network profiles, so it belongs to the profiles' sites (the UI's provisioning flow offers it there). |
| `catc_cancel_maintenance` | Delete a maintenance window (and every future occurrence of a recurring one). |
| `catc_clone_template` | Copy a template under a new name, in the same or another project. |
| `catc_commit_template` | Commit a template's current content as a new version (required before deploying it). |
| `catc_create_compliance_policy` | Create a compliance policy that checks devices against your own standard, e.g. "no ip http server" (a MATCHES_EXPRESSION '^ip http server' condition with violation_when='matches') or "a login banner is set" ('^banner login' with violation_when='does_not_match'), or straight from CLI lines with require_lines=['service password-encryption'] / forbid_lines=['ip http server']. |
| `catc_create_custom_issue` | Create a custom (syslog-based) Assurance issue: "alert when this syslog appears". |
| `catc_create_discovery` | Start a device discovery (IP range, CIDR, single IP, or CDP/LLDP from a seed) that adds what it finds to the inventory. |
| `catc_create_fabric_site` | Make a site an SD-Access fabric site. |
| `catc_create_fabric_zone` | Make a building or floor inside an SD-Access fabric site a fabric zone. |
| `catc_create_global_credential` | Create a global device credential that discovery and site assignment can use. |
| `catc_create_ip_pool` | Create a global IP pool, or reserve a subpool of one for a site (pass site + global_pool). |
| `catc_create_report` | Create a report from a view and run it now (delivery: download). |
| `catc_create_site` | Create an area, building or floor in the site hierarchy. |
| `catc_create_ssid` | Define an SSID (WLAN) in network design. |
| `catc_create_switching_profile` | Create an empty switching network profile, to attach Day-N templates to and assign to sites. |
| `catc_create_tag` | Create a (static) tag for grouping devices or interfaces. |
| `catc_create_template` | Create a (not yet committed) configuration template in a project. |
| `catc_create_template_project` | Create a template project (a folder for configuration templates). |
| `catc_create_transit_network` | Define an SD-Access transit network. |
| `catc_create_virtual_network` | Create a layer 3 virtual network (VRF) or add an existing one to more fabric sites. |
| `catc_create_wireless_profile` | Create a wireless network profile that carries SSIDs. |
| `catc_delete_custom_issue` | Delete a custom (syslog-based) issue definition. |
| `catc_delete_global_credential` | Delete a global device credential. |
| `catc_delete_ip_pool` | Release a site's reserved subpool, or delete a global pool (refused while it still has reservations). |
| `catc_delete_report` | Delete a report and its executions. |
| `catc_delete_ssid` | Delete an SSID from network design. |
| `catc_delete_tag` | Delete a user-defined tag. |
| `catc_delete_template` | Delete a configuration template and all its versions. |
| `catc_delete_template_project` | Delete a template project together with every template in it. |
| `catc_delete_wireless_profile` | Delete a wireless network profile. |
| `catc_detach_template_from_profile` | Detach a Day-N CLI template from network profiles. |
| `catc_import_templates` | Import templates from a catc_export_templates document: creates missing projects, then each template with its committed versions replayed in order (version comments kept; numbers start at 1 on this Catalyst Center) and the uncommitted draft on top. |
| `catc_import_trusted_certificate` | Add an enterprise CA certificate, or a CA chain, to Catalyst Center's trusted certificates, so it trusts the servers and clients that CA issued (ISE's admin and pxGrid certificates, a syslog or proxy server). |
| `catc_mark_device_for_replacement` | Mark a faulty device for replacement (RMA), the first step before catc_replace_device; or unmark it. |
| `catc_resync_devices` | Re-collect inventory (config, interfaces, modules) from devices now instead of waiting for the next polling cycle. |
| `catc_run_compliance` | Run a compliance check now for devices (all categories unless given). |
| `catc_schedule_maintenance` | Schedule a Catalyst Center maintenance window for devices (a list, every device under a site, or a tag), optionally repeating every N days, so a planned change doesn't raise an alert storm. |
| `catc_set_ap_power_profile` | Create, update or delete an AP power profile: ordered rules that turn an Ethernet port down to a speed, a radio down to fewer spatial streams, or a radio or the USB port off when the switch gives the AP too little PoE. |
| `catc_set_ap_profile` | Create, update or delete an AP join profile: SSH/Telnet with the AP management credentials, the AP's 802.1X supplicant (EAP-FAST, EAP-TLS or EAP-PEAP) for closed-auth switch ports, CDP, rogue detection (minimum RSSI, report and transient intervals), country, time zone and power profile. Management credentials go as a set (user, password, enable password), and an update of a profile with them, or with an EAP-FAST/PEAP supplicant, takes the passwords again (Catalyst Center never returns them). |
| `catc_set_device_role` | Set the inventory role of network devices (ACCESS, CORE, DISTRIBUTION, BORDER ROUTER) and pin it (role source MANUAL) so Catalyst Center's automatic classification no longer changes it. |
| `catc_set_rf_profile` | Stage RF profile settings in the WLC's per-device intended configuration: state, TX power range, DCA channel width, client limit, description (only the ones given change). |
| `catc_set_wlan_security` | Stage a WLAN's security in the WLC's per-device intended configuration: open, WPA2/WPA3 personal (PSK/SAE) or enterprise (802.1X with an AAA method list); PMF follows the mode. |
| `catc_set_wlan_vlan` | Stage the VLAN of a WLAN's policy profile in the WLC's per-device intended configuration (the policy profile's interfaceName). |
| `catc_tag_golden_image` | Mark an imported software image as golden (the target version) for a device product at a site and its children, or remove the tag. |
| `catc_trigger_lifecycle_scan` | Start Catalyst Center's field notice, network bug and/or security advisory scans now instead of waiting for the scheduled run (EoX has no on-demand scan). |
| `catc_unassign_profile_from_sites` | Remove a network profile's assignment from sites. |
| `catc_update_compliance_policy` | Change an existing compliance policy: add rules (conditions, or CLI lines with require_lines/forbid_lines), delete rules by name, rename it or change its description. |
| `catc_update_health_score_definition` | Tune Assurance health scores to the customer's standard: change a KPI's threshold per device family (router CPU 95% -> 85%), leave a KPI out of overall health, or tie it to the issue threshold; reset_to_default puts KPIs back. |
| `catc_update_issue_definition` | Enable or disable a built-in Assurance issue, or change its priority (P1..P4, or back to the default) or threshold: "stop paging me about X". |
| `catc_update_issue_status` | Mark assurance issues as resolved, or ignore them for some hours. |
| `catc_update_maintenance_window` | Change a maintenance window's start, end, description or recurrence (times ISO 8601 with an offset), or end a running window now (end_now=true). |
| `catc_update_site` | Rename a site or change a building's address/coordinates or a floor's number, RF model and dimensions. |
| `catc_update_site_aaa_settings` | Set a site's AAA network settings (Design > Network Settings > AAA): which server devices use for administrator login (network) and for 802.1X/MAB endpoints (client), as ISE or plain AAA, RADIUS or TACACS. |
| `catc_update_site_settings` | Change a site's network settings (Design > Network Settings): DNS servers and domain, NTP, DHCP servers, banner, time zone, and telemetry (external syslog/SNMP trap servers, Catalyst Center as collector, wired client data collection). |
| `catc_update_tag_members` | Add network devices to, or remove them from, a static tag. |
| `catc_update_template` | Change a template's content or description (creates uncommitted changes; commit with catc_commit_template). |
| `catc_write_memory` | Save the running configuration to the startup configuration (write memory) on devices, so a template deploy or other change survives a reload. |

### Dangerous (46)

| Tool | What it does |
|---|---|
| `catc_accept_ise_certificate` | Answer Catalyst Center's 'trust this ISE certificate?' step of the ISE integration (or retry a failed integration). |
| `catc_activate_image` | Install and activate a software image on a device (distributing it first if needed). |
| `catc_add_anycast_gateway` | Add an anycast gateway (the client subnet's default gateway, the same IP on every edge) for an IP pool in a virtual network at a fabric site. |
| `catc_add_fabric_device` | Give a provisioned device a fabric role (control plane, border, edge) at a fabric site. |
| `catc_add_ise_server` | Integrate Cisco ISE with Catalyst Center as the AAA and policy server: CatC connects to ISE (ERS over 443, pxGrid 8910), discovers its nodes and, after you accept ISE's certificate, trusts it. |
| `catc_add_l3_handoff` | Hand a border off onto a transit network. |
| `catc_anchor_virtual_network` | Create a layer 3 virtual network anchored at one fabric site and extend it to others (multi-site SD-Access), extend an anchored VN to more sites, or stop anchoring one (remove_anchor). |
| `catc_api_call` | Call any Cisco Catalyst Center REST endpoint (escape hatch for things no other tool covers). |
| `catc_apply_pending_fabric_events` | Apply a fabric site's pending fabric events. |
| `catc_assign_fabric_port` | Assign an edge port to a fabric VLAN (host onboarding): Catalyst Center configures the access port (VLAN, authentication template) on the edge. |
| `catc_claim_pnp_device` | Claim an Unclaimed Plug and Play device to a site: Catalyst Center pushes the day-0 onboarding template (with its variables), optionally an image, then adds the device to the inventory at that site. |
| `catc_create_backup` | Take an on-demand Catalyst Center system backup to the configured backup target (NFS server or physical disk), e.g. before the group-based policy migration or an upgrade. |
| `catc_delete_compliance_policy` | Delete a user compliance policy with its rules, conditions and site assignments; its violations disappear from the compliance results. |
| `catc_delete_device` | Remove a device from Catalyst Center. |
| `catc_delete_discovery` | Delete a discovery job and its results (devices it added stay in the inventory). |
| `catc_delete_fabric_device` | Take a device out of its SD-Access fabric site (all its fabric roles). |
| `catc_delete_fabric_site` | Remove an SD-Access fabric site; the site itself stays in the hierarchy. |
| `catc_delete_l3_handoff` | Remove a border's layer 3 handoff onto a transit. |
| `catc_delete_pnp_device` | Remove a device from the Plug and Play list (not from the inventory). |
| `catc_delete_policy_server` | Remove an authentication and policy server (plain AAA or the integrated ISE) from Catalyst Center. |
| `catc_delete_sda_object` | Remove an SD-Access object: a port assignment, an anycast gateway, a layer 3 virtual network, a device's fabric role, a fabric zone or a fabric site. |
| `catc_delete_site` | Delete a site from the hierarchy. |
| `catc_delete_transit_network` | Delete a transit network. |
| `catc_deploy_template` | Deploy (push) a committed configuration template to devices: an explicit list, every device under a site, or every device with a tag. |
| `catc_deploy_wlc_config` | Deploy a Catalyst 9800 WLC's per-device intended configuration to the WLC (what catc_set_wlan_security, catc_set_wlan_vlan and catc_set_rf_profile staged, and any other intended change). |
| `catc_distribute_image` | Copy an imported software image to a device's flash (SWIM distribution) without activating it. |
| `catc_import_config` | Build Catalyst Center design intent from a catc_export_config document: a PoC's design on a production Catalyst Center, or a rebuilt lab. |
| `catc_provision_devices` | Provision wired network devices to the site they are assigned to: Catalyst Center pushes the site's network settings (AAA, DNS, NTP, banner, syslog/SNMP trap/telemetry, etc.) to them. |
| `catc_provision_site` | Zero-touch for a site: provision every wired device assigned to the site (or a floor below it) that isn't provisioned yet, in one change, to the building or floor it is assigned to. |
| `catc_provision_wireless_controller` | Provision a Catalyst 9800 WLC: set its primary managed AP locations, then push the WLANs, policy profiles and tags of the wireless profiles assigned to those sites (plus the site's AAA, DNS, NTP and telemetry settings). |
| `catc_replace_device` | Replace a faulty device with a new one of the same model (RMA): Catalyst Center pushes the faulty device's archived running config (and licences) to the replacement through PnP and moves the inventory entry, site and history to the new serial. |
| `catc_reset_pnp_device` | Reset a PnP device that is in Error so it retries onboarding (it becomes Unclaimed again and can be claimed with catc_claim_pnp_device). |
| `catc_set_external_authentication` | Turn Catalyst Center's external authentication on or off (System > Users & Roles > External Authentication), optionally setting the AAA attribute first. |
| `catc_set_extranet_policy` | Create, update or delete an SD-Access extranet policy. |
| `catc_set_fabric_authentication_profile` | Set an SD-Access fabric site's authentication template and/or edit that template's settings. |
| `catc_set_fabric_multicast` | Set multicast at an SD-Access fabric site. |
| `catc_set_fabric_port_channel` | Create, change or delete a port channel on an SD-Access fabric device. |
| `catc_set_interface` | Change one switch port through Catalyst Center: shut / no shut, the access VLAN, the voice VLAN or the description (containment or remediation without writing a template). |
| `catc_set_l2_handoff` | Set or remove a layer 2 handoff: a fabric VLAN extended out of a border port into a VLAN of a traditional network. |
| `catc_set_l2_virtual_network` | Create, change or delete a layer 2 virtual network at an SD-Access fabric site. |
| `catc_set_provisioning_settings` | Turn Catalyst Center's 'Visibility and Control of Configurations' on or off (System > Settings): require_preview and/or require_itsm_approval, with PUT provisioningSettings. |
| `catc_update_anycast_gateway` | Change an anycast gateway in place instead of deleting and re-adding it (which drops every client in the subnet). |
| `catc_update_fabric_device` | Change a fabric border's updatable settings in place: border priority (1-9), AS-path prepends (1-10), a custom BGP router id, and the layer 2 border type. |
| `catc_update_fabric_site` | Change an SD-Access fabric site's control plane mode (LISP pub/sub or LISP/BGP) or underlay transport (IPv4, IPv6, dual stack). |
| `catc_update_policy_server` | Edit an authentication and policy server (System > Settings > Authentication and Policy Servers > Edit): the ISE FQDN and login, ports, protocol, pxGrid, retries and timeout. |
| `catc_update_port_assignment` | Change an edge port's fabric assignment in place. |

## API spec

Catalyst Center does not serve its OpenAPI document over the API, so the server ships one:
`src/catc_mcp/specs/catc-3.2.2.json.gz` is the Intent/System/Data API spec (OpenAPI 3.0.3, 1,421
paths / 1,914 operations) **exported from the Developer Toolkit of a Catalyst Center 3.2.2-75131
appliance**, with examples stripped (`scripts/bundle_spec.py`). Cisco's public
[catalyst-center-api-specs](https://github.com/cisco-en-programmability/catalyst-center-api-specs)
repository only covers the Assurance APIs. To refresh it for another release, export the spec from
*Platform > Developer Toolkit > APIs* and run
`uv run python scripts/bundle_spec.py swagger.json <version>`.

**Spec conformance (contract test).** Every request the unit suite sends to the fake appliance (method,
path, query keys, top-level JSON body keys) is recorded and checked against the bundled spec when the
session ends; `pytest tests/unit` fails on a path, method, query key or body key the spec doesn't
declare. Deliberate exceptions (the business-API execution-status poll, the UI's `/api/v1/siteprofile`
fallback, the `tag/{id}/member` body whose spec schema is wrong, ...) are listed with a reason in
`tests/unit/spec_allowlist.py`. After a spec refresh, `uv run python scripts/spec_audit.py` prints the full
report: mismatches, allowlisted findings and allowlist entries nothing uses any more.

## Docker

```bash
uv run catc-mcp-server token alice          # put the sha256 line in .env as MCP_AUTH_TOKENS=...
docker compose up -d                        # pulls ghcr.io/dr-stutters/catc-mcp-server (MCP_IMAGE_TAG, default latest)
docker compose up -d --build                # or build from this checkout (no token: core is bundled)
curl -s http://localhost:8034/health
```

The container runs as non-root with a read-only root filesystem, no capabilities and a named volume for
the spec cache. The compose file is **read-only**: set `MCP_ENABLE_WRITES=true` (and `MCP_ENABLE_DANGEROUS=true`)
in `.env` to opt in. Shared hosts (TLS, several Catalyst Centers, per-user tokens, upgrades):
[docs/deploying.md](docs/deploying.md).

## Development

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest   # unit (respx)
uv run pytest tests/live -m live     # against the CatC in .env; creates and removes mcp-test-* objects
uv run python scripts/tool_table.py  # regenerate the tool tables above
uv run python scripts/gap_report.py  # API coverage per area (docs/GAP-ANALYSIS.md)
```

Troubleshooting configuration: `uv run catc-mcp-server config` prints the effective settings and where each
came from (secrets only as set/unset), without contacting Catalyst Center.

Live tests skip themselves when `CATC_URL` is unset or unreachable. Lab devices, sites, ISE, WLC, fabric and
PnP inputs come from `CATC_LIVE_*` variables; a test whose variables are unset skips and names them.
[docs/live-tests.md](docs/live-tests.md) lists every variable and the objects the device tests expect.

## License

MIT. See [LICENSE](LICENSE).
