# SD-Access with catc-mcp-server

How to build, change, check and tear down a Cisco SD-Access fabric through this server, and what Catalyst
Center 3.2.2 does that the API reference doesn't say. Every write is preview-first; the dangerous tier (anything
that pushes configuration to fabric devices) needs `MCP_ENABLE_DANGEROUS=true`.

## 1. Prerequisites

**The SD-Access application.** Catalyst Center needs the optional packages *Access Control Application* (`aca`)
and *SD Access* (`sda`, which depends on `aca`) DEPLOYED. Some images ship them SKIPPED (the lab 3.2.2 image
does): fabric site creation then fails with `NCSP11008` ("Package required ... No application found for type
ConnectivityDomain"). `catc_status` reports it under `catc.sda` (packages, `available`, the reason).

Installing them is a 30–60 minute appliance change with service restarts (on the lab appliance: 41 minutes;
inventory, credential and site-settings reads answered 502 for a few minutes while it ran, and the ISE
integration stayed COMPLETE). Over the API, as a SUPER-ADMIN or a role that may change software:

1. `GET /dna/system/api/v1/installedRelease` gives the package ids (e.g. `aca::2.739.65146`, `sda::2.739.65146`).
2. `POST /dna/system/api/v1/installOptionalPackages` with `{"optionalPackages": ["aca::…", "sda::…"]}`
   (`catc_api_call`, dangerous, preview-first) returns a task id.
3. `GET /dna/system/api/v1/softwareManagementExecutions/{taskId}` until `status` is SUCCESS;
   `installedRelease` shows the packages DEPLOYED a few minutes before the job ends.

**Roles.** The packages add permissions (Policy.Group-Based Policy, Network Operations.LAN Automation), and
Network Provision.SD-Access Write depends on Group-Based Policy Read and Utilities.Scheduler Write. Roles created
before the install have them at Deny: re-run the seed step after installing (docs/least-privilege.md). Without it
LAN automation, SSI readiness and possibly SD-Access writes answer 403.

**ISE.** An ISE integrated with pxGrid (`catc_get_policy_servers` shows it COMPLETE and TRUSTED) for
authenticated host onboarding and group-based policy.

**Devices.** Switches discovered, assigned to the fabric site's building (or a floor under it) and provisioned
(`catc_provision_devices`): fabric roles need provisioned devices. Cloned virtual switches need unique serial
numbers, or Catalyst Center merges them into one inventory record.

## 2. Build a fabric site

The prompt `catc_build_fabric_site` walks all of this with a check after each step. By hand:

1. Client pool: a global pool, then a reservation at the building (`catc_create_ip_pool`) with its gateway and
   DHCP server.
2. `catc_create_fabric_site` (an area or building; the authentication template and pub/sub). Build on No
   Authentication and set any other template last, after the AAA check below.
3. `catc_add_fabric_device`: control plane and border first, then the edges. A border needs its BGP AS; its
   priority (1–9) and AS-path prepends (1–10) are optional (leaving them out keeps Catalyst Center's defaults).
   A priority, once set, can't go back to the default (section 3).
4. `catc_create_virtual_network` (a layer 3 VN at the fabric site).
5. `catc_add_anycast_gateway`: the pool in the VN; Catalyst Center pushes the SVI to every edge. In INFRA_VN the
   pool is for extended nodes or fabric APs (`pool_type`).
6. `catc_assign_fabric_port`: edge ports to a gateway's VLAN (by VLAN or pool name). A port on Closed
   Authentication needs no VLAN: ISE assigns it. Extended nodes: `AUTHENTICATOR_SWITCH` /
   `SUPPLICANT_BASED_EXTENDED_NODE` ports.
7. Read it back: `catc_get_sda_fabric` (devices, VNs, gateways, ports, and zones, layer 2 VNs, port channels,
   handoffs, multicast, transits and extranet policies when present).

**The way out.** A custom VN has no route out of the fabric until a border hands it off: an IP transit
(`catc_create_transit_network`, then `catc_add_l3_handoff` with one VLAN/SVI and point-to-point addresses per VN,
eBGP to the fusion router or WAN) or an SD-Access transit between fabric sites. Until then DHCP from a server
outside the fabric fails; prove the gateway with a static address. Shared services between VNs:
`catc_set_extranet_policy`.

**AAA before an authentication template.** Prove a client in the VN on No Authentication first, then set
Closed Authentication, Low Impact or Open Authentication with `catc_set_fabric_authentication_profile` (its
preview names every edge it is pushed to). Closed Authentication blocks every client on the edge ports until ISE
authorizes it, so a fabric that can't reach ISE blocks everyone. Fabric provisioning sends RADIUS from each
fabric device's Loopback0 (its RLOC), and the NADs Catalyst Center creates in ISE carry the RLOC /32 in
`Location#All Locations` (section 7). Before you switch, check every fabric device with `catc_run_show_commands`:

- `show aaa servers`: the ISE server is `current UP`, not `DEAD`;
- `show running-config | include radius source-interface` and `show ip interface brief | include Loopback0`:
  the address ISE sees;
- `show cts environment-data`: the download is COMPLETE and lists the ISE server.

DEAD, or environment data that never completes, means ISE has no route back to the RLOC subnet or no NAD for
the RLOC. The route is fixed on ISE or its gateway, not in Catalyst Center (the lab added one for
10.255.255.0/24 on the ISE CLI); moving the RADIUS source by CLI drifts from Catalyst Center's intent. After the
fix a switch keeps the server DEAD until its automate-tester probe gets an answer, minutes later (section 7).
In ISE (ise-mcp-server): `ise_get_nad` with each RLOC finds its NAD; `ise_policy_explain` with `nad=<RLOC>` and
`flow='wired-mab'` (or `wired-dot1x`) must select the policy set and rule meant for the fabric's clients; a NAD
left in All Locations when that set matches a location moves with `ise_update_nad` (`groups`). The clients
need a rule that authorizes them (for MAB, their MACs in an endpoint group the rule permits). The prompt
`catc_build_fabric_site` runs these checks before it sets the template. An AAA readiness check is planned
(D110, #207).

**More of the fabric.** Layer 2 VNs and layer 2 handoffs (`catc_set_l2_virtual_network`, `catc_set_l2_handoff`),
fabric zones (`catc_create_fabric_zone`), port channels (`catc_set_fabric_port_channel`), multicast
(`catc_get_fabric_multicast`, `catc_set_fabric_multicast`), anchored VNs across sites
(`catc_anchor_virtual_network`, needs an SD-Access transit).

## 3. Change it

- Authentication template of the site and its profiles (Closed, Open, Low Impact, No Authentication;
  MAB/802.1X order, fallback timer, hosts, BPDU guard, pre-auth ACL): `catc_get_fabric_authentication_profile`
  and `catc_set_fabric_authentication_profile`. ISE's policy only works when it matches: Closed Authentication
  with MAB first gives each edge port `PMAP_DefaultWiredDot1xClosedAuth_MAB_1X`, and a client stays blocked
  until ISE authorizes its MAC (live: SGT and dACL from the ISE rule). The edges need RADIUS to ISE from their
  Loopback0 first: check it before switching (section 2, *AAA before an authentication template*).
- A gateway or an edge port in place, instead of delete + re-add (which drops the clients):
  `catc_update_anycast_gateway`, `catc_update_port_assignment` (including a static security group).
- A border's priority, prepends, BGP router id and layer 2 type: `catc_update_fabric_device`. Roles, the local
  AS, default exit and route import can't be updated on 3.2.2: remove the device and add it back. A priority is
  one way: a border added without one reads back as 10, but 3.2.2 refuses 10 on a write (`NCHS20769`), so once
  set it only moves within 1–9 (9 is the closest to unset); the tool's preview warns when it sets the first one.
- The site's control plane (LISP/BGP or pub/sub) and underlay transport: `catc_update_fabric_site`.

## 4. Check it

- `catc_fabric_health`: fabric sites, VNs and transits as Assurance scores them, the dimensions with fair or
  poor devices, a verdict; lags a change by minutes.
- `catc_list_pending_fabric_events` and `catc_apply_pending_fabric_events`: drift Catalyst Center wants to push
  again (after an RMA, a reload, a failed provision).
- `catc_run_show_commands` on the edges: `show lisp session`, `show vlan brief`, `show running-config interface
  <port>`, `show access-session`, `show aaa servers`, and with SGTs `show cts role-based sgt-map vrf <VN> all`
  (the clients' IP-to-SGT bindings; the global table only lists the switch's own addresses). It takes up to 10
  commands per call. Catalyst Center 3.2.2's command runner takes at most 5 per request, so the tool sends
  them 5 at a time, one request after another, and merges each device's output; a raw `catc_api_call` to
  `network-device-poller/cli/read-request` has to split them itself.
- `catc_get_ssi_readiness`: Security Service Insertion readiness (a firewall at the border, with fmc).
- `catc_get_lan_automation`, `catc_get_fabric_wireless`: LAN automation sessions and fabric wireless, read-only.

## 5. Group-based access control

ISE stays the policy owner: security groups, SGACLs and the egress matrix are written with ise-mcp-server
(`ise_set_sgt`, `ise_set_egress_policy`, `ise_push_trustsec_matrix`), and Catalyst Center proves what the edge
enforces: `catc_get_group_policy_enforcement` reads the downloaded environment data, cells, counters and IP-to-SGT
bindings (an SD-Access edge keeps the clients' bindings in their VN's VRF and the global table only has the
switch's own addresses, section 7; the tool reads the switch's VRFs, the first 4 or the ones in `vrfs`, and each
binding shows its `vrf`), and the
prompt `catc_group_policy_rollout` pairs the ISE change with the edge check and a test flow. The clients get
their SGT from ISE's authorization result (or a static one: `catc_update_port_assignment` `security_group`).
Catalyst Center 3.2.2 has no public intent API for security
groups, contracts or group-based policy; its internal UI API holds seeded defaults, not ISE's matrix, until its
*policy migration*, which hands the matrix to Catalyst Center and makes ISE's TrustSec objects read-only. Don't
start the migration on a shared lab: ise-mcp-server's TrustSec writes stop working.

## 6. Tear it down

`catc_delete_fabric_site` with `cascade=true` removes, in reverse order, edge ports, port channels, multicast
VNs, gateways, layer 2 VNs, border handoffs, the site's VN memberships (INFRA_VN goes with the site), zones and
fabric devices (edges first), then the fabric site; the devices stay provisioned and the pool and site stay.
`catc_delete_fabric_device` takes one device out (with `cascade=true`, its ports, port channels and handoffs
first); `catc_delete_sda_object` removes a single object by id; `catc_delete_l3_handoff` and
`catc_delete_transit_network` remove the way out.

## 7. 3.2.2 quirks

- `NCSP11008` on fabric site creation: the SD Access application isn't deployed (section 1).
- A border's `borderPriority` must be 1–9 and `prependAutonomousSystemCount` 1–10 (unset = Catalyst Center's
  defaults: priority 10, no prepends); sending 10 or 0 is out of range.
- The spec types a transit network's `type` as an array whose enum has an `IP_BASED_TRANSIT,` typo; the API
  takes the plain string.
- `lan-automation/status` and `/log` accept `limit` 1–10 only.
- A USER_DEVICE port needs a VLAN unless its template is Closed Authentication.
- `PUT sda/layer3VirtualNetworks` assigns sites and anchors in two steps; if anchoring fails the site assignment
  still applies (read the VN back).
- The group-based policy objects under `/api/v2/data/customer-facing-service/` answer only once the package
  install job has finished (502 before), and hold seeded defaults until the policy migration.
- Fabric provisioning sends RADIUS from Loopback0 (`ip radius source-interface Loopback0`, global and in
  `dnac-client-radius-group`), and the NADs Catalyst Center creates in ISE carry the RLOC /32, not the management
  IP. ISE needs a route back to the RLOCs (in a lab whose underlay isn't routed, the switch's RADIUS server stays
  DEAD and the edge's TrustSec environment data never completes). The NADs also land in `Location#All Locations`:
  move them into the location your policy set matches.
- A border added without priority or prepends reads back `borderPriority: 10` and
  `prependAutonomousSystemCount: 0`, outside the 1–9 / 1–10 the API takes on a write; `catc_update_fabric_device`
  sets them (priority 2 shows as `priority 2` on the border's LISP locators). There is no way back to the unset
  default: a `PUT sda/fabricDevices` with `borderPriority: 10` answers 400 `NCHS20769` ("The borderPriority
  entered is invalid. Please make sure it is a number between 1 and 9."), so the closest is 9. Prepends take
  1–10 only as well, so 0 (none) can't be sent back either (by the spec; not tried live).
- The command runner (`POST network-device-poller/cli/read-request`) refuses more than 5 commands per request:
  400 "Maximum of 5 commands allowed per request". `catc_run_show_commands` and the tools built on it split
  longer lists into requests of 5.
- On the lab's cat9000v (17.18), a RADIUS server marked DEAD stays DEAD after the path to ISE is fixed, until
  the automate-tester probe (Catalyst Center's AAA provisioning sets `automate-tester username dummy probe-on`
  on the server) gets an answer, minutes later; `show aaa servers` and the TrustSec environment data catch up
  then. Re-read before deciding a fix didn't work.
- An SD-Access edge keeps the clients' IP-to-SGT bindings in their VN's VRF (`show cts role-based sgt-map vrf
  <VN> all`); `show cts role-based sgt-map all` only has the switch's own addresses.
- `securityServiceInsertion/*` answers 403 to custom roles even with Security.SSI Read (the permission's
  maximum); a SUPER-ADMIN-ROLE account reads it.
