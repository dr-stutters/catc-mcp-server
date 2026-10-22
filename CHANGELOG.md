# Changelog

## Unreleased

### Added
- **SD-Access guide (D109, #194, Wave 6 part G).** docs/sd-access.md: prerequisites (installing the `aca` +
  `sda` packages over the API, re-seeding the roles, ISE, devices), the build order and the
  `catc_build_fabric_site` prompt, the way out (transits and handoffs), day-N changes, checks, group-based
  policy as ISE-owned and edge-verified, teardown with the cascades, and the 3.2.2 quirks found live; a unit test
  keeps every tool it names real. Linked from the README.
- **SD-Access fabric site settings (D104, #189, Wave 6 part G).** `catc_update_fabric_site(fabric_site,
  pub_sub?, underlay_transport?)` (dangerous): move a fabric site's control plane between LISP/BGP and LISP
  pub/sub, or set its underlay transport (IPv4, IPv6, dual stack), over `PUT sda/fabricSites` with the rest of
  the record (the authentication template) kept; the preview shows current -> new and counts the fabric
  devices Catalyst Center re-provisions, and warns that going back to LISP/BGP may be refused.
- **SD-Access extended nodes (D106, #191, Wave 6 part G).** `catc_assign_fabric_port` takes the extended-node
  port types `AUTHENTICATOR_SWITCH` and `SUPPLICANT_BASED_EXTENDED_NODE` (no data/voice VLAN: they onboard over
  INFRA_VN), and `catc_add_anycast_gateway` takes `pool_type` (EXTENDED_NODE or FABRIC_AP, required for INFRA_VN)
  and `supplicant_based_onboarding` for the INFRA_VN pool. A USER_DEVICE port on Closed Authentication (its own
  template or the fabric site's) no longer needs a VLAN: ISE assigns it (the 3.2.2 spec requires a VLAN only for
  the other templates).
- **SD-Access Security Service Insertion readiness (D107, #192, Wave 6 part G).** `catc_get_ssi_readiness(
  fabric_site?, virtual_network?)` (read): per fabric site its SSI readiness and message, per VN its readiness,
  gateways, extranet role and ready/total devices, per device its role, reachability, licence and readiness
  (`securityServiceInsertion/fabricSitesReadiness`); the first step before steering a VN through a firewall at
  the border (fmc). The read-only role gains Security.SSI Read; without it 3.2.2 answers 403 (live-checked).
- **SD-Access anchored virtual networks (D105, #190, Wave 6 part G).** `catc_anchor_virtual_network(
  virtual_network, anchor_site?, fabric_sites?, remove_anchor=false)` (dangerous): anchor a layer 3 VN at one
  fabric site and extend it to others over an SD-Access transit (`PUT sda/layer3VirtualNetworks` with
  `anchoredSiteId`), or stop anchoring it; refuses without an SD-Access transit, with fewer than two sites or a
  no-op. The result reads the VN back (`anchored_at`, `anchor_verified`) and warns when the anchor did not
  change: the PUT reports success even when only the site assignment applied, and whether leaving
  `anchoredSiteId` out clears an anchor is unproven. `catc_create_virtual_network` now carries a VN's anchor
  when it adds sites (a PUT without it could unanchor the VN). Unit-tested only: the live proof needs a second
  fabric site.
- **SD-Access fabric device changes (D103, #188, Wave 6 part G).** `catc_update_fabric_device(device, roles?,
  border_asn?, default_exit?, import_external_routes?, border_priority?, prepend_as_count?, layer2_border?,
  bgp_router_id?)` (dangerous): roles and border settings in place over `PUT sda/fabricDevices` (an edge that
  becomes a border, a second control plane, a border's priority, default exit, route import, AS-path prepends,
  layer 2 border type), instead of removing the device from the fabric and adding it back. A new border needs
  its AS; an existing border's AS can't change; refuses dropping the last control plane while edges remain and
  dropping EDGE_NODE while ports are assigned.
- **SD-Access fabric border changes (D103, #188, Wave 6 part G).** `catc_update_fabric_device(device,
  border_priority?, prepend_as_count?, layer2_border?, bgp_router_id?)` (dangerous): a border's priority (1-9),
  AS-path prepends (1-10), custom BGP router id and layer 2 border type in place over `PUT sda/fabricDevices`.
  The 3.2.2 spec marks roles, the local AS, default exit and route import not updatable, so they are re-sent as
  read and not offered (remove and re-add the device for those); read-back values outside the PUT ranges (the
  unset priority 10, prepend 0) are left out of the request.
- **SD-Access extranet policies (D95, #166, Wave 6 part F).** `catc_set_extranet_policy(name, provider_vn?,
  subscriber_vns?, fabric_sites?, delete=false)` (dangerous): create, update (unset fields keep their value)
  or delete a policy over `sda/extranetPolicies`, so subscriber VNs reach a provider VN's shared services
  through LISP route leaking inside the fabric; refuses unknown VNs, a provider that is also a subscriber,
  and a no-op; blast radius = the fabric devices of the sites concerned.
- **SD-Access fabric zones (D97, #168, Wave 6 part F).** `catc_create_fabric_zone(site,
  authentication_profile?)` (write: no device change) makes a building or floor inside a fabric site a zone
  (`POST sda/fabricZones`; the template defaults to the fabric site's), so anycast gateways can be limited to
  it. `catc_delete_sda_object` gains kind `fabric_zone` (refused while the zone still has gateways or ports);
  the `catc_delete_fabric_site` cascade already removes zones.
- **SD-Access port channels (D98, #169, Wave 6 part F).** `catc_set_fabric_port_channel(device,
  port_channel?, interfaces?, connected_device_type=TRUNK|EXTENDED_NODE, protocol=LACP|PAGP|ON, description?,
  native_vlan?, allowed_vlans?, delete=false)` (dangerous) creates a port channel on a fabric device (Catalyst
  Center names it), changes its members, description or trunk VLANs, or deletes it (`sda/portChannels`);
  refuses member ports that have a port assignment or sit in another port channel, PAgP-less extended nodes
  and more than 8 ports for PAgP/ON. The `catc_delete_fabric_*` cascades already remove port channels.
- **SD-Access multicast (D96, #167, Wave 6 part F).** `catc_get_fabric_multicast(fabric_site)` (read): the
  replication mode and per-VN multicast (pool, fabric or external RPs with ASM ranges, SSM ranges).
  `catc_set_fabric_multicast(fabric_site, replication?, virtual_network?, ip_pool?, rp?, rp_devices?,
  external_rp_ip?, asm_ranges?, ssm_ranges?, remove_vn=false)` (dangerous): native or head-end replication
  (`PUT sda/multicast`) and/or a VN's multicast (`POST`/`PUT`/`DELETE sda/multicast/virtualNetworks`, one
  request at a time; unset settings keep their value), with current -> new in the preview.
- **SD-Access transits and layer 3 handoffs (D93, #164, Wave 6 part F).** `catc_list_transit_networks`
  (read), `catc_create_transit_network(name, transit_type=ip|sda_pubsub|sda_bgp, asn?, control_plane_devices?,
  site?)` (write: no device change), `catc_add_l3_handoff(border, transit, ...)` (dangerous): an IP transit
  hands each VN off on its own VLAN/SVI over `interface` with point-to-point addresses (or an external
  connectivity pool) and eBGP; an SD-Access transit registers the border with the transit control plane.
  `catc_delete_l3_handoff` (by VN) and `catc_delete_transit_network` (refused while a border uses it). The
  3.2.2 spec types the transit `type` as an array with an `IP_BASED_TRANSIT,` typo; the tools send the plain
  string the API answers with. Live-read on the 3.2.2 lab appliance (no transits yet).
- **SD-Access layer 2 (D94, #165, Wave 6 part F).** `catc_set_l2_virtual_network(fabric_site, vlan_name,
  vlan_id?, traffic_type?, layer3_vn?, flooding_address?, multiple_ip_to_mac?, resource_guard?, delete=false)`
  (dangerous): create, change or delete a layer 2 VN (a fabric VLAN without an anycast gateway) over
  `sda/layer2VirtualNetworks`; delete is refused while edge ports or a layer 2 handoff use it.
  `catc_set_l2_handoff(border, interface, vlan, external_vlan?, delete=false)` (dangerous): extend a layer 2
  VN's or a gateway's VLAN out of a border port into an external VLAN (`sda/fabricDevices/layer2Handoffs`).
- **SD-Access LAN automation and fabric wireless, read-only (D102, #173, Wave 6 part F).**
  `catc_get_lan_automation(include_log?)`: active sessions and their limit, each session's status (seed
  devices, discovered devices, IP pools, discovery level, multicast) and optionally the log; 3.2.2 pages
  `lan-automation/status` and `/log` 10 at a time (limit > 10 answers 400), and a 403 names the missing
  Network Operations.LAN Automation permission. `catc_get_fabric_wireless(fabric_site?)`: VLAN-to-SSID
  mappings, the switch-side wireless settings and wireless multicast. Both live-read on the 3.2.2 lab
  appliance (nothing configured); writes wait for a lab that can host PnP switches behind a seed or a fabric
  WLC with APs.
- **Prompt `catc_build_fabric_site` (D101, #172, Wave 6 part F).** Builds an SD-Access fabric site from
  switches to a client in the fabric with a check after each step: SD-Access availability and the account's
  tier (a role seeded before the packages may lack Group-Based Policy Read), onboarding, site settings and
  client AAA for an authenticated template, the client pool, assign + provision, fabric site, border and
  control plane before the edges, VN, anycast gateway, edge ports, then the fabric read-back, edge CLI,
  pending fabric events and `catc_fabric_health`; the teardown (`catc_delete_fabric_site`, cascade) stays a
  preview. Written from the D13 flow before its live run; the live findings refine it.
- **SD-Access teardown (D13, #20, Wave 6 part E).** `catc_delete_fabric_site(fabric_site, cascade=false)`
  (dangerous): without `cascade` it refuses while the fabric still holds anything and lists it; with
  `cascade=true` the preview lists every object and the apply removes them in reverse order: edge port
  assignments, port channels, multicast VNs, anycast gateways, layer 2 VNs, border handoffs (IP transit, SD-Access
  transit, layer 2), the site from each layer 3 VN (the VN stays; `INFRA_VN` goes with the site), fabric zones,
  fabric devices (edges before the control plane and border), then the fabric site. A failed step stops the run
  and names what was removed; running it again continues from what is left. `catc_delete_fabric_device(device,
  cascade=false)` (dangerous) takes a device out of its fabric by hostname, IP or serial, optionally removing
  its port assignments, port channels and handoffs first, and refuses the last control plane node while edges
  remain. `catc_delete_sda_object` stays for single objects by id.
- **SD-Access health (D92, #163, Wave 6 part F).** `catc_fabric_health(fabric_site?, include?, hours?,
  trend_interval?)` (read) over the Data API's `fabricSummary`, `fabricSiteHealthSummaries`,
  `virtualNetworkHealthSummaries` and `transitNetworkHealthSummaries`: the fabric summary (sites, L3/L2 VNs,
  transits, fabric devices, P1-P3 issues), each fabric site's good-health percentage and device counts, the
  dimensions with fair or poor devices (control plane, LISP sessions, border to control plane, pub/sub, BGP,
  AAA, CTS environment data, port channels, VN exit, ...; grouped generically from the
  `<dim>{Good,Fair,Poor,No,Total}Health...` keys), the same per VN and transit, an optional per-site trend
  and a one-line verdict. Live-read on the 3.2.2 lab appliance (no fabric yet: the empty verdict).
- **SD-Access day-N edits (D99, #170, Wave 6 part F).** `catc_update_anycast_gateway(fabric_site, ip_pool,
  ...)` and `catc_update_port_assignment(device, interface, ...)` (dangerous) change a gateway or an edge port
  in place (`PUT sda/anycastGateways`, `PUT sda/portAssignments`) instead of a delete and re-add that drops
  every client: layer 2 flooding and its address, IP-directed broadcast, multiple IP-to-MAC, traffic type, a
  static security group, group-based policy enforcement, TCP MSS and resource guard on a gateway; data/voice
  VLAN (VLAN or pool name), authentication template, static security group, description, a trunk's native
  and allowed VLANs on a port. The PUT carries the current record with only the changed fields replaced; the
  preview shows current -> new per field; fields the API won't change are not offered.
- **SD-Access drift (D100, #171, Wave 6 part F).** `catc_list_pending_fabric_events(fabric_site?)` (read):
  the pending fabric events Catalyst Center has queued per fabric site (configuration it wants to push again
  after an RMA, a reload, a failed provision or a device-side change), with id and detail; live-read on the
  3.2.2 lab appliance. `catc_apply_pending_fabric_events(fabric_site, event_ids?)` (dangerous) applies them
  (`POST sda/pendingFabricEvents/apply`, one event per request as the API asks), stopping at the first
  failure with what was applied and returning what is still pending.

### Changed
- Least-privilege roles after the SD-Access packages (Wave 6 part E): `mcp-catc-ro` gains Policy.Group-Based
  Policy Read (a dependency of Network Provision.SD-Access) and Network Operations.LAN Automation Read;
  `mcp-catc-dangerous` gains Utilities.Scheduler Write (a dependency of Device Provision and SD-Access Write).
  Both Policy and LAN automation permissions only exist once `aca` + `sda` are deployed; roles seeded before
  the install have them at Deny (LAN automation reads answered 403 on the lab appliance). Re-run the seed step
  after installing the packages (docs/least-privilege.md).
- `catc_get_sda_fabric` also shows the Wave 6 part F objects when present: per fabric site its fabric zones,
  layer 2 VNs, port channels, border handoffs (IP transit, SD-Access transit, layer 2) and multicast
  (replication mode, per-VN settings); at the top the transit networks and extranet policies. Each section
  fails on its own (`unavailable`).
- The `catc_onboard_switch_with_nac` prompt ends with the site's NAD coverage check (D9, Wave 6 part D):
  `ise_audit_nads(expected=<catc_list_devices(site) rows>, check_stale=false)` (ise I67) and its
  `coverage.verdict`. Devices match NADs by IP, so a NAD Catalyst Center reused under another name
  (`nad_name_differs`) is fine; missing_nad, wrong_ndg, ip_mismatch and aaa_elsewhere are red, each with its
  fix offered as a preview only.

### Fixed
- **SD-Access live run (Wave 6 parts E-G, 2026-10-21).** The previews of `catc_add_anycast_gateway`,
  `catc_update_anycast_gateway` and `catc_set_l2_virtual_network` name the edges ('hostname (IP)') instead of
  device ids; `catc_create_ip_pool`'s preview shows the DHCP and DNS servers it sends. `catc_get_ssi_readiness`'s
  403 says that on 3.2.2 custom roles get 403 even with Security.SSI Read (SUPER-ADMIN-ROLE reads it).
  docs/sd-access.md gains the quirks found live (RADIUS from the RLOC loopback, border defaults read back out of
  range, the SSI 403).
- `catc_add_fabric_device` sent `borderPriority: 10` and `prependAutonomousSystemCount: 0` for every border;
  the 3.2.2 spec allows 1-9 and 1-10 (unset = Catalyst Center's defaults), so the request could be refused.
  Both are now left out unless the new optional `border_priority` (1-9) or `prepend_as_count` (1-10) is
  given. Found while planning D103.
- `catc_set_fabric_multicast`: `asm_ranges` given without `rp` on a VN that already has multicast were dropped
  (the current RP was kept as it was). They now go to the VN's default IPv4 RP, or its only one; several RPs
  with no default, or no RP at all, are refused with a blocker.

## 0.12.0 (2026-10-21)

Catalyst Center ↔ ISE (Wave 6 part D, proven live on Catalyst Center 3.2.2 with ISE 3.5 and the CML `ise-access` lab): `catc_update_policy_server` repairs a FAILED ISE integration in place and `catc_get_policy_servers` names the next step (`next_action`); Catalyst Center admin logins through ISE (`catc_get_external_authentication`, `catc_set_external_authentication`, `catc_test_login`, prompt `catc_admin_access_via_ise`); `catc_network_services_health` (AAA/DHCP/DNS as Assurance measures them); `catc_find_host` and `catc_list_clients(user=)`; prompt `catc_client_troubleshoot`; the NAC onboarding prompt follows `next_action` and handles brownfield AAA. The ISE integration writes and external authentication need a SUPER-ADMIN account (docs/least-privilege.md). Wave 6's other items and part E (SD-Access) are not in this release.

### Added
- **Find a host (D47, #93).** `catc_find_host(mac|ip|hostname|user, search_devices?, hours=24)` (read): each
  matching client Assurance saw in the window, newest first, with its switch (name, management IP) and port or
  AP/WLC/SSID, VLAN, SGT, the AAA server, site, status, health, last seen and a one-line `where`; a switch no
  longer in the inventory is marked. `search_devices` (up to 10 switches) also looks the host up live through
  the command runner (`show mac address-table address`, `show device-tracking database mac|address`,
  `show ip arp`; an IP that only ARP knows is followed to the MAC table for its port). A hostname that is a
  network device, not a client, returns the device. Live on 3.2.2: `user='mcp-eaptls-client'` resolves to
  `52:54:00:62:C6:B2` on sw1 Gi1/0/3, VLAN 10, SGT 7, `Global/mcp-test-lab/mcp-test-nac`; `ip='10.10.10.50'`
  had no Assurance record (the switch's device-tracking table had lost the IPv4 binding) and the live lookup
  found it through ARP and the MAC table.
- `catc_list_clients(user=)`: clients by the username they logged in with (part of the name, case-insensitive,
  `*` wildcards) through `POST clients/query` with a `username` filter; the other filters apply to the matched
  rows, and a release that rejects the filter key is scanned and matched client-side (`user_match` says
  which). 3.2.2 accepts the key: `like` is case-insensitive with `*` as the wildcard, `eq` is case-sensitive.
- **Edit an authentication and policy server (D75, #130).** `catc_update_policy_server(server, fqdn?,
  ise_password?, ise_username?, protocol?, authentication_port?, accounting_port?, tacacs_port?, pxgrid?,
  use_catc_cert_for_pxgrid?, retries?, timeout_seconds?, wait=true)` (dangerous tier: it resets trust and the
  pxGrid client) over `PUT authentication-policy-servers/{id}`. Only what you pass changes; the ISE entry is
  resent whole, so an ISE edit needs the ISE password (masked in previews and results, bound to the confirm
  token by a digest); the RADIUS/TACACS shared secret and the server IP have no API field and stay as they
  are. A protocol can only be widened to RADIUS_TACACS (as the API documents). The preview lists the field
  changes and the consequences (re-run integration, certificate to accept again on an FQDN change, pxGrid
  client to approve or pxGrid off). After the PUT the tool waits for the integration to re-run (a status left
  over from before the edit is ignored by its step times) and returns the certificate chain when Catalyst
  Center asks for it, with `next_action: accept_certificate`.
  Live on 3.2.2: the lab's FAILED entry repaired (FQDN `ise.demo.mitchcloud.lab` → `ise.mitchcloud.lab`, ISE's
  admin certificate accepted after comparing fingerprints, pxGrid client auto-approved on ISE): COMPLETE,
  both nodes TRUSTED. The four ISE integration writes need SUPER-ADMIN-ROLE: 3.2.2 refuses them (403) to
  custom roles even with every System permission at Write (docs/least-privilege.md).
- `catc_get_policy_servers` gives every server a `next_action`: `update_entry` with the field Catalyst
  Center's failure message names (`fqdn` for a CN mismatch or a name the appliance can't resolve,
  `ise_password` for a login/ERS failure), `accept_certificate`, `approve_pxgrid_on_ise` (the pxGrid step
  waits or failed: names the Catalyst Center subscriber to approve on ISE), `wait` or `none`.
  `include_sites=true` adds the sites whose own network or client AAA points at each server (reads every
  site's AAA settings; off by default).
- **Prompt `catc_admin_access_via_ise` (D89, #145).** Dangerous tier, uses ise and Windows_Server: preconditions
  (a COMPLETE ISE entry, the external-auth servers and roles), AD group and user, ISE AD groups, ISE NAD for
  Catalyst Center with the policy-server shared secret, an authorization profile with
  `av_pairs=["Cisco:cisco-av-pair=Role=<role>"]` (ise-mcp-server's new `av_pairs`), optional break-glass mirror
  users for the local accounts, a policy set on `Radius:NAS-IP-Address`, a local test login before and right after
  enabling (disable at once if it fails), the AD test login with the role granted, the ISE auth record and the
  local-account fallback finding, then (keep_enabled=false) external authentication off and the undo.
- **Catalyst Center admin login through ISE (D88, #144).** `catc_get_external_authentication()` (read: whether
  external authentication is on, the AAA attribute the role is read from, empty meaning the default
  Cisco-AVPair / cisco-av-pair, the AAA servers Catalyst Center asks from `users/external-servers` without
  their shared secrets, the roles a server can return, and the external users seen so far);
  `catc_set_external_authentication(enable, aaa_attribute?)` (dangerous tier: the preview lists the servers,
  the attribute and the lockout risk, and refuses to enable with no AAA server or to repeat the current state;
  a custom attribute is posted before the flag); `catc_test_login(username, password)` (read tier: one token
  request with those credentials; pass/fail with Catalyst Center's reason, or the token's claims and the
  user's roles and auth source from the user list; the password and the token are registered as secrets and
  never stored, logged or returned).
  Live on 3.2.2 (2026-10-21, ISE 3.5): an AD user in `mcp-catc-admins` logged in with OBSERVER-ROLE through ISE
  and external authentication was switched off again. Findings in the tools' text: logins go to ISE first (a local
  account only works while ISE accepts it with a role), and a custom role in the reply is refused with 400
  'Invalid user profile' (built-in roles only); `catc_test_login` now returns Catalyst Center's own failure text.
- **Prompt `catc_client_troubleshoot` (D45, #81).** Read tier, uses ise: find the client by MAC, IP or username
  (Assurance's user column, or ISE's session) → client 360 and issues → live CLI on the switch (access session,
  port, running config, device tracking, RADIUS server state) and the VLAN check → path trace → ISE auth history
  and failure reason, NAD check → `catc_network_services_health` verdict for the switch → a diagnosis (auth
  failure, ISE not reached or wrong secret, wrong VLAN/authorization, port/DHCP, path, healthy) → a fix shown as
  a preview only. Notes the 3.2.2 lab finding that a wrong shared secret is silent in ISE and a MAB lookup can
  still pass with it.
- **Network services health (D68, #115).** `catc_network_services_health(service='aaa'|'dhcp'|'dns'|'all', site?,
  hours=24, server?, device?, trend=true)` (read) over the data API's `aaaServices` / `dhcpServices` /
  `dnsServices`: per server the transactions, successful/failed, success %, average latency weighted by
  transactions (AAA: EAP vs MAB; DHCP: discover-offer and request-ack), the devices (NADs) behind it, the top
  failing devices, the trend (`trendAnalytics`, empty buckets dropped) and one verdict line per server ("ISE
  198.18.134.35 answered 97.2% of 212 AAA requests, average latency 117 ms; 6 MAB failures on sw1"), named ISE/AAA
  from the policy servers. An empty window says why (telemetry from managed devices, minutes of lag); a service
  or trend that fails is reported in its section instead of failing the call.

### Changed
- The `catc_client_troubleshoot` prompt finds a client given by IP or username with `catc_find_host` (D47).
- The `catc_onboard_switch_with_nac` prompt's first step follows `next_action` (an entry that FAILED is
  fixed with `catc_update_policy_server` instead of stopping), and `check`'s ISE warning names the update
  tool.
- The prompt also carries the lab window's provisioning findings (3.2.2): Catalyst Center refuses a switch that already
  has AAA config (it names the lines; remove them with approval, resync, provision, restore what must stay), an
  existing ISE NAD with the switch's IP is reused, and a discovery that finds nothing may be a stale ARP entry on
  the appliance or a TACACS+ VTY login that rejects the CLI user.

## 0.11.0 (2026-10-18)

Wireless feature models on a Catalyst 9800 (Wave 6 D70 and D71, proven live on two 9800-CLs in CML against Catalyst Center 3.2.2): `catc_get_wlc_config` reads the intended and deployed per-device models and diffs them; `catc_set_wlan_security`, `catc_set_wlan_vlan`, `catc_set_rf_profile` stage changes and `catc_deploy_wlc_config` pushes them with a preview. Also the core v0.14.3 bundle (secret masking in raw `catc_api_call` previews, HMAC-keyed confirm tokens) and a WLC provisioning fix. Wave 5's D46/D42/D41 and Wave 6's other items are not in this release.

### Added
- **Wireless feature config reads (D70, #117).** `catc_get_wlc_config(wlc, feature=None, state="intended")`
  (read tier) reads the `/dna/campus/api/v1/wirelessControllers/{id}/{intended|deployed}/...` feature models
  for a Catalyst 9800 WLC, resolved by hostname, IP, serial or id. Without `feature`: a count and up to 20
  names for each of 27 families (WLAN, policy and RLAN profiles, policy and site tags, RF and radio profiles,
  RF tags, multi-BSSID, URWB, AP join, power, mesh and calendar profiles, flex, five mDNS models, Dot11be,
  AP tag, priming and location mappings; AP trace and packet-capture profiles in `deployed` only), the empty
  ones under `no_data`, and per-family errors under `unavailable` instead of failing the call. With
  `feature`: that family's records, with `deviceVersion` hoisted, `configType` dropped and false flags
  omitted unless `all_fields=true`; `name` picks one record and `children=true` adds each record's
  sub-collections (a policy tag's WLAN-to-policy mappings, MPSK keys, RF DCA channels, flex VLANs...).
  `diff=true` compares intended with deployed per feature, matched by name: profiles only on one side, the
  fields the intent sets that differ on the WLC, and (with `children`) sub-collection rows only on one side.
  PSKs, MPSK keys, AP management and dot1x passwords, NTP trust keys, FTP passwords and URWB passphrases are
  masked and never compared (the WLC returns them encrypted). AP-dependent families say "no data" cleanly on
  a WLC without APs. Live on Catalyst Center 3.2.2 the models exist only for WLCs with Per-Device
  Configuration enabled (see D71): a WLC provisioned through site-based network profiles (D14's
  `catc_provision_wireless_controller`) answers every model read with 404 NCWS70003 "provisioned via
  Site-based Network profiles". One probe detects that and the tool returns `provisioning: site-based network
  profiles` with Catalyst Center's reason and where to look instead (`catc_get_wireless_controller`), not 27
  errors. The models page at most 100 records (3.2.2 refuses `limit` > 100; the spec says 500).

- **Wireless per-device writes and intended deploy (D71, #118).** Three write-tier tools stage a change in a
  Catalyst 9800 WLC's per-device intended configuration with `POST .../intended/<group>/update` (op `MERGE`:
  only the given fields change), and nothing reaches the WLC until the deploy:
  `catc_set_wlan_security(wlc, wlan, security, passphrase?, auth_list?)` (open, WPA2/WPA3 personal or
  enterprise, WPA2/WPA3 transition; every AKM flag set explicitly so a mode change clears the old one; PMF
  required for WPA3-only, optional for transition; the PSK is masked in previews and results and bound to the
  confirm token by a keyed digest), `catc_set_wlan_vlan(wlc, vlan, wlan | policy_profile)` (the policy
  profile's `interfaceName`, found from the WLAN through the policy tags; the preview lists every WLAN that
  uses that policy profile) and `catc_set_rf_profile(wlc, rf_profile, ...)` (state, TX power range, DCA
  channel width, client limit, description; the preview names the RF tags using it). The dangerous-tier
  `catc_deploy_wlc_config(wlc)` previews the intended-vs-deployed diff per feature (D70's diff, now shared)
  with a blast radius of one WLC, posts `.../intended/deploy`, then reports each config group's status from
  `.../intended/deviceDeployments` for the deploy's activity; `catc_get_wlc_deployments(wlc, activity_id?)`
  (read) lists them later, with Catalyst Center's error and remedy. Both are refused with the reason on a WLC
  without writable per-device configuration (404 NCWS70003 on a site-based WLC), and the deploy preview is
  blocked while the global provisioning settings require preview or ITSM approval (Catalyst Center refuses
  the deploy then). Research in [docs/wireless-per-device.md](docs/wireless-per-device.md): SSID security,
  VLAN and RF profile exist only in the per-device models, not in `featureTemplates/wireless/*` (design
  templates that ride on site-based profiles), and per-device mode is enabled per WLC in the GUI only, with
  no revert. Live on a second 9800-CL (`mcp-catc-wlc2`, never provisioned, Per-Device Configuration enabled):
  SSID `mcp-d71` moved from VLAN 1 to 20 through its policy tag (`vlan 20` on the WLC; intended, deployed and
  the diff agree), a learned `default-policy-profile` moved to VLAN 30 with its other settings kept, and the
  WLAN went from WPA2 to WPA2/WPA3 (`[WPA2 + WPA3][PSK][SAE][AES]`). What that run taught the tools: enabling
  per-device configuration learns the WLC's config into the deployed model only, so the set tools also find
  records there and stage them whole (secrets aside, so a learned PERSONAL WLAN needs its passphrase); the
  9800's pre-configured RF profiles are refused (the WLC rolls back any change); WPA3 modes turn adaptive
  802.11r off (17.18 refuses it with WPA3); the deploy preview lists records only on the WLC as kept (deploy
  doesn't remove them) and says that a deleted intended record is deleted on the WLC; the deploy's activity
  is its task id (`deployActivityId`), and a rolled-back group gives `outcome: failed` with the WLC's message.
  Details in [docs/wireless-per-device.md](docs/wireless-per-device.md#live-results-2026-10-18-second-9800-cl).

### Fixed
- **`catc_get_wlc_config` on per-device WLCs (D70, found in D71's live run).** A WLC before "Enable
  Per-Device Configuration" answers 400 NCWS70003 "Per-device configuration is not enabled": reported as
  `provisioning: per-device configuration not enabled` with what to do, like the site-based case. Once a WLC
  has anything staged, Catalyst Center 3.2.2 answers an intended family without records with 500 NCND00050
  instead of an empty list: that now reads as no records (deployed reads keep the error). URWB models answer
  403 while URWB is beta: listed under `not_enabled`, not `unavailable`.
- **`catc_provision_wireless_controller` on a WLC that was never provisioned.** Catalyst Center answers its
  `primaryManagedApLocations` read with 400 NCWS51004 ("No locations were discovered") instead of an empty
  list, so the preview failed on a freshly discovered 9800. That now counts as no current locations (in
  `catc_get_wireless_controller` too). Found in the D70 live run.

### Changed
- ROADMAP: the owner reopened the per-feature wireless models on 2026-10-18. D70 and D71 moved from Later to
  Next; the "Not planned" entry now covers only the feature writes outside D71's curated subset.
- Bundled stutters-mcp-core v0.14.0 -> v0.14.2: raw `catc_api_call` writes mask secret fields (`passphrase`,
  shared secrets, communities, keys), nested dicts and lists included, in the preview and the result. The request
  sent to Catalyst Center is unchanged. Before this, a POST to `.../intended/ssids/update` showed the PSK in the preview.
- Bundled stutters-mcp-core v0.14.2 -> v0.14.3: confirm tokens bind their arguments with an HMAC-keyed digest
  (a low-entropy PSK can no longer be brute-forced from the stored hash), and the WLC-only secret names
  (`key`, `wepKey`, `ntpServerTrustKey`, `spacesConnCfgToken`) are registered with the core's `EXTRA_SECRET_KEYS`,
  so raw `catc_api_call` previews and the audit log mask them as well.

## 0.10.0 (2026-10-17)

Wave 4 Phase B, against Catalyst Center 3.2.2: templates depth (D36), compliance depth (D37), assurance analytics
(D38), config export and diff (D39) and config import (D40), plus `catc_status` reporting SD-Access availability
(D13 stays blocked: the lab's SD Access package is not deployed). Also ships Phase A (the 0.9.0 notes below), which
was never released on its own.

### Added
- **Config import (D40, #76).** `catc_import_config` (dangerous tier, preview-first) builds Catalyst Center
  design intent from a `catc_export_config` document: a PoC's design on a production Catalyst Center, or a
  rebuilt lab. It reads a live export of the document's scope (the nearest existing ancestor when the scope
  doesn't exist yet), matches every item by name and plans steps in dependency order: sites (create, or update
  building/floor attributes) → credentials (created with `secrets`, by `TYPE:description`; never overwritten) →
  network settings per site (a category PUT whole when it differs; credential slots by name) → global pools →
  reservations → template projects → templates (created and committed as version 1; never overwritten) →
  switching profiles (create, attach missing templates, assign sites not already covered by an assigned
  parent) → tags. Nothing is deleted or unassigned; existing credentials, pools, reservations, templates and
  tags that differ are listed as `skip` with what differs. SSIDs, wireless profiles and compliance policies
  are counted as not imported. The preview blocks a new credential without its secrets, any value still
  masked in the export (an AAA shared secret, a template line), references to sites, credentials, pools or
  templates that exist neither on Catalyst Center nor in the export, and a building without a country and
  location. Applying runs the steps one by one and stops at the first failure with `applied`, `failed` and
  `not_applied`; running the import again plans only what is still missing. Template and switching-profile
  creation are now shared helpers (`create_imported_template`, `create_switching_profile`).
- **`catc_status` reports whether SD-Access is deployed (D13, #20).** A new `catc.sda` block reads
  `/dna/system/api/v1/installedRelease` and gives the state of the optional `sda` (SD Access) and `aca` (Access
  Control Application) packages, `available`, and the reason when they aren't deployed. `/dnac-packages` lists
  both even when they were skipped at install, which is why the first D13 slice found 'sda' listed yet fabric
  site creation failing with NCSP11008 ('Package required ... No application found for type
  ConnectivityDomain'). The refusal message from the SDA write tools now points there and to the install
  (System > Software Management, or `POST /dna/system/api/v1/installOptionalPackages`). SDA apply stays
  mock-tested only: the lab 3.2.2 image ships both packages SKIPPED, and D13 is blocked until there's a
  Catalyst Center with SD Access deployed.
- **Compliance depth (D37, #73).** Policy authoring beyond D4: rules straight from CLI lines
  (`require_lines` / `forbid_lines` become exact-line regex conditions with a generated message, per rule
  device families and software type) and `catc_update_compliance_policy` (write: add rules, delete rules by
  name, replace a rule by removing and adding it in one call, rename, description; removals run first and a
  failure reports what was done). `catc_compliance_report` (read): devices at a site and below from the last
  compliance runs, counted by status, site, category (your policies as NETWORK_RULES) and severity, the
  non-compliant devices worst first with their failing categories and policy rule violations, a per-rule
  count, and the trend between runs (`in_last_run`: new vs persisting non-compliance; `since_previous_report`:
  new and fixed items against the previous report at an earlier run, kept in the cache directory).
  `catc_config_drift` (read): devices whose latest archived running config differs from a golden device
  (missing and extra lines as `parent > child`) or lacks what a template renders to per device (`no X` lines
  honoured), with `only` / `ignore` regexes applied to both sides; hostname, version, certificates and
  similar lines are ignored. Site membership is read per site (or per device when that is fewer calls); the
  report details 25 devices and drift checks 50 by default (`max_devices`), saying when it cut the list.
  Live: a policy requiring `service password-encryption`, r1 compliant and r2 not; the report and both drift
  modes show r2.
- **Assurance analytics (D38, #74).** Five read tools in `tools/assurance_analytics.py`:
  `catc_health_trend` (network, site, device or client over a window: min/avg/latest, the worst moment, each dip
  with start, length and depth, worse/better/steady, a trimmed series; site trends also give when issues were
  raised, device/client trends the issues open in the window), `catc_top_problems` (worst devices or clients in the
  window with the issue behind each), `catc_issue_recurrence` (the same issue opening again: times opened,
  occurrences, gap between openings, each opening with when it closed), `catc_ai_insights` (AI-driven issues,
  filtered server-side; `no_ai_issues` when there are none, `unavailable` with the reason when the query fails)
  and `catc_site_health_report` (all of it for one site, with a one-line verdict). Site trends are asynchronous on
  3.2.2 (an assurance task is polled); network/device trends over a day use 1-hour buckets in 7-day chunks (the
  API's limits); site filters match the site and below, not siblings; a per-device trend 404 (e.g. during a
  resync) is reported as no data. Found live: a cat8000v's health score ignores a down link, so the outage shows as issues and issue bursts, not a dip.
- **Config export and diff (D39, #75).** `catc_export_config(scope, sections)` writes the site hierarchy, the
  network settings set at each site, credentials (type, description, username: never secrets), template projects
  and templates, network profiles with their templates and sites, IP pools and reservations, SSIDs (passphrases
  masked), wireless profiles, tags and compliance policies as YAML, by name and in a stable order, with a
  `format`/`version` header (version 1) for config import (D40). `catc_diff_config(before, after?)` compares two
  exports, or an export with live Catalyst Center, by item identity: added/removed items and each changed field.
  Secrets are masked by a final pass over the whole document (secret-looking key names, template `#set`/`{% set %}`
  assignments, secret variable defaults). Reads are bounded (8 in flight); a site or item that fails is skipped
  and listed in `meta.warnings`; built-in (SYSTEM) compliance policies are left out. Diff values over 400
  characters are cut and the rows held under the response limit.
  Both run as MCP background tasks. Format: [docs/config-export.md](docs/config-export.md). New dependency:
  PyYAML. The templates section uses its own minimal serializer until D36's lands.
- **Templates depth (D36, #72).** Read: `catc_list_template_versions` (every committed version with time,
  author, comment and +/- lines against the one before; flags uncommitted changes),
  `catc_diff_template_versions` (unified diff of two versions, or a version and the draft; secrets masked),
  `catc_export_templates` (a project or one template as JSON, format `catc-mcp-templates` v1: content,
  variables, device types and every version with its comment; secrets masked and listed: IOS secret lines,
  Velocity/Jinja set-assignments of secret-named variables, and defaults of variables that are sensitive, typed as
  secrets or named like one (`redact_template()` / `secret_name()` are shared with config export); the document
  comes from the pure `serialize_templates()`, which config export (D39) reuses), `catc_template_usage` (network
  profiles, their sites, and the devices it was deployed to with the version each runs) and
  `catc_template_drift` (per device: last version deployed vs latest committed: current / behind / failed).
  Write: `catc_import_templates` (preview-first; creates missing projects, replays the versions in order with
  their comments and leaves the draft on top; import as a copy with `name` / `project`; refuses existing names,
  composite templates and any mask token still in the content) and `catc_clone_template` (Catalyst Center's clone: content and
  variables, no versions). `catc_deploy_template` takes `version` to push an older committed version (a
  rollback). Drift comes from the deploy tasks Catalyst Center keeps (their deployment status names the
  version; `GET /task` pages from offset 0 on 3.2.2, not 1 as its spec says), and Day-N templates pushed by the
  provisioning flow leave no such record. Config export (D39) now masks templates with the same shared rules: a
  value that is only a template variable (`#set($secret = $x)`) stays, and `sensitiveField` variables are masked.

## 0.9.0 (not released on its own; included in 0.10.0)

### Added
- **`catc-mcp-server check` preflight (D32, #68; core C21).** Runs without an MCP client: the token login
  (`POST /dna/system/api/v1/auth/token`) and the Intent API, TLS trust, credentials (a static `CATC_TOKEN` warns:
  it is never renewed), the API user's roles against the enabled tiers (built-in roles by name, custom roles by
  their permissions, as in `catc_status`; fails when writes/dangerous are on without them, warns on an
  administrator role or when the roles can't be read), the Catalyst Center release against the bundled API spec
  (3.2.2 tested; 2.3.7 minimum) and the ISE integration (ok when ACTIVE, otherwise a warning; never a failure).
  Text or `--json`, `--strict`, `--instance`; exit 1 on a failure; every `CATC_INSTANCES` Catalyst Center.
  `serve --http` / `serve --stdio`. README quickstart for a release wheel (`uvx --from`) and for the image, with
  Claude Code / Claude Desktop config. PyPI publishing stays open (deferred).
- **Published image (D33, #69; core C22).** `release.yml` calls core `publish-image.yml`:
  `ghcr.io/dr-stutters/catc-mcp-server` for amd64 and arm64, cosign keyless signature, SPDX SBOM attestation;
  `<version>` + `latest` on releases, `<version>-rcN` + `rc` on pre-release tags. `docker-compose.yml` pulls it
  (`MCP_IMAGE_TAG`; `--build` still builds locally).
- **Shared-host guide and example (D34, #70).** `docs/deploying.md` (read-only defaults, per-user tokens and the
  audit log, the token and API rate limits every caller shares, the D19 rails for teams, several Catalyst Centers
  with `CATC_INSTANCES`, Caddy TLS, the least-privilege account step by step, upgrades and verifying signatures)
  and `examples/shared-host/` (server + Caddy, and a test override with two mocked Catalyst Centers). Contract
  tests pin the tier defaults (`tests/unit/test_tier_defaults.py`).

### Changed
- Bundled core v0.14.0.
- **`docker-compose.yml` no longer enables writes.** It used to set `MCP_ENABLE_WRITES=true`; the server it starts
  is now read-only. Operators who want the write tier set `MCP_ENABLE_WRITES=true` (and
  `MCP_ENABLE_DANGEROUS=true` for the dangerous tier) in `.env`.

### Changed
- **stutters-mcp-core is bundled into the package (D31, #67; core C20 / ADR-005).** The wheel, sdist and image
  carry core v0.13.0 (with the `tasks` extra's dependencies) as `catc_mcp._core`, so installing needs no git
  dependency and Docker needs no `CORE_READ_TOKEN`. The pin is `[tool.bundle-core]` (tag + commit + extras) in
  `pyproject.toml`; core's runtime dependencies are listed in the server's own. `scripts/bundle_core.py` vendors it
  (`vendor`, after a clone), checks for drift (`check`) and moves the pin (`update --tag`). Code and tests import
  `catc_mcp._core`; importing the package without the bundle says how to fix it. The bundled Catalyst Center spec
  (`scripts/bundle_spec.py`) still ships in the wheel.
- `catc_status` reports the bundled core version (`server.core_version`).
- CI: the core `bundle-core.yml` job vendors, fails on drift, builds the wheel and sdist, installs the wheel
  with `pip install --no-index` in a clean venv and runs the unit + contract suite against it. The release
  builds the image from the bundled wheel.

- **Live tests take their lab inputs from `CATC_LIVE_*` variables (D35, #71).** Device addresses, site paths,
  ISE, WLC, SD-Access fabric and PnP inputs are no longer hard-coded: each test reads documented variables and
  skips naming the unset ones. New: `CATC_LIVE_ROUTER1`/`2`, `CATC_LIVE_PATH_TRACE`, `CATC_LIVE_BUILDING`,
  `CATC_LIVE_FLOOR`, `CATC_LIVE_CLIENT_MAC`, `CATC_LIVE_ONBOARD_SWITCH`, `CATC_LIVE_ISE_IP`/`_FQDN`/`_USERNAME`/
  `_PASSWORD`, `CATC_LIVE_RADIUS_SECRET`, `CATC_LIVE_WLC`, `CATC_LIVE_FABRIC_BUILDING`/`_BORDER`/`_EDGE`/`_POOL`/
  `_PORT`, `CATC_LIVE_PNP_SERIAL`, `CATC_LIVE_DEVICE_USERNAME`/`_PASSWORD`, `CATC_LIVE_SNMP_RO`/`_RW` and
  `CATC_LIVE_RMA_DEVICE` (with the existing `CATC_LIVE_ISE_CYCLE` and `CATC_LIVE_RMA`). They replace the
  `LAB_ISE_*`, `LAB_RADIUS_SECRET` and `LAB_CLI_*`/`LAB_SNMP_*` keys the tests read. All listed in the new
  [docs/live-tests.md](docs/live-tests.md) and in `.env.example`.
- `docs/least-privilege.md` describes the API steps that create the roles, access groups and users; `docs/pnp.md`
  describes the PnP DHCP server and option 43 without lab addresses. The roles' descriptions in `rbac.py` say
  "Managed by the suite's seed step".

### Removed
- The git source for stutters-mcp-core and `CORE_READ_TOKEN` (Dockerfile build secret, compose, workflows).
- **Lab tooling moved to the suite's private lab repo (stutters-mcp-lab) (D35, #71):** `scripts/lab_state.py`,
  `scripts/seed_access.py`, `scripts/pnp_dhcp.py`, their unit test (`tests/unit/test_lab_state.py`) and the CML
  lab exports `labs/mcp-catc-fabric.yaml` / `labs/mcp-catc-wlc.yaml`. The `LAB_*` keys are gone from
  `.env.example`.

## 0.8.3 (2026-10-15)

### Fixed
- **Write previews show what a PUT removes** (core 0.12.4 `field_changes(..., replace=True)`):
  `catc_update_site_aaa_settings` sends each given role whole, so a dropped secondary server is now listed as
  `"removed": true` (a read-back shared secret is never shown); `catc_update_template` and `catc_update_site` diff
  the whole body they PUT (both start from the current object, so this is a guard: nothing is dropped today).
- `catc_update_site_settings`: the category PUT now sends back the site's other local sub-settings (e.g. telemetry
  SNMP trap servers when only syslog servers change) instead of leaving them out. Its preview stays a partial
  diff, as each given part is merged into the site's values.

### Changed
- Core bumped to stutters-mcp-core 0.12.4; `tests/manifests/ise.json` refreshed from ise-mcp-server 0.7.2.

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
  returns ids and port assignments. Previews are live-checked; applying is refused by the lab 3.2.2 image
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
  download needs `Accept: application/octet-stream`; executions take ~7 minutes on the lab.

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
