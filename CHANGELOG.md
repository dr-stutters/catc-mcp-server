# Changelog

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
