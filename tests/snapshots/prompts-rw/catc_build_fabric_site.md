# catc_build_fabric_site

title: Build an SD-Access fabric site
arguments: {"authentication": "Closed Authentication", "border": "198.18.128.176", "border_asn": "65001", "building": "Global/mcp-test-lab/mcp-test-fabric", "client_pool": "10.10.40.0/24", "client_ports": "198.18.128.175:GigabitEthernet1/0/3, 198.18.128.175:GigabitEthernet1/0/4", "dhcp_server": "10.255.40.14", "edges": "198.18.128.175", "virtual_network": "MCP_VN"}

Build an SD-Access fabric site from switches to a client in the fabric: SD-Access availability,
the devices onboarded and provisioned at the building, the client IP pool, the fabric site, border
and control plane before the edges, the virtual network, the anycast gateway, the edge ports, and
the checks between the steps (fabric read-back, CLI on the edges, pending fabric events, fabric
health). An authentication template other than No Authentication is set last, after an AAA check:
RADIUS to ISE from every fabric device's RLOC, and (with the ise tools) the NADs and their location.
Ends with the teardown as a preview (catc_delete_fabric_site with cascade). Every write is
preview-first.

## user

Build the SD-Access fabric site Global/mcp-test-lab/mcp-test-fabric: border + control plane 198.18.128.176, edges
198.18.128.175, clients in MCP_VN on 10.10.40.0/24 (gateway 10.10.40.1, DHCP 10.255.40.14),
authentication "Closed Authentication". Every write is preview-first: show the preview, wait for
the user's approval, then repeat the call with the confirm token. Stop and report at the
first failure; never skip a check.

1. SD-Access available: `catc_status`: catc.sda.available must be true (the Access Control
   Application and SD Access packages DEPLOYED; otherwise fabric creation fails with NCSP11008) and the
   account's role_tier "dangerous" or above. A custom role seeded before the packages were installed lacks
   Policy.Group-Based Policy Read and may get 403 on SD-Access writes: re-run the seed step
   (docs/least-privilege.md).
2. Devices: `catc_get_device` for each of 198.18.128.176, 198.18.128.175. Missing ones: onboard them as in
   the catc_onboard_device prompt (`catc_list_global_credentials`,
   `catc_create_discovery` with wait=true), until each is Reachable and Managed. Each switch needs
   a unique serial number (cloned virtual switches that share one get merged into a single inventory record).
3. Site and settings: `catc_get_site_hierarchy`; create Global/mcp-test-lab/mcp-test-fabric with
   `catc_create_site` if missing. `catc_update_site_settings` at the building: DHCP
   server 10.255.40.14 and the DNS the clients use.
   Closed Authentication needs ISE for the clients: `catc_get_policy_servers` must show the ISE
   integration COMPLETE, and the building's client AAA must point at ISE
   (`catc_update_site_aaa_settings` client server_type ISE). Leave network (device admin) AAA
   alone.
4. Client pool: `catc_list_ip_pools`. A global pool covering 10.10.40.0/24 must exist; then reserve 10.10.40.0/24
   at Global/mcp-test-lab/mcp-test-fabric with `catc_create_ip_pool` (gateway 10.10.40.1, DHCP server 10.255.40.14). Note the
   reserved pool's name: the anycast gateway and the ports use it.
5. Assign and provision: `catc_assign_devices_to_site` for all of 198.18.128.176, 198.18.128.175 at
   Global/mcp-test-lab/mcp-test-fabric (or a floor under it), then `catc_provision_devices`. Fabric roles need provisioned
   devices.
6. Fabric site: `catc_create_fabric_site` site "Global/mcp-test-lab/mcp-test-fabric", authentication_profile
   "No Authentication" (step 13 sets "Closed Authentication" once step 12 has proven AAA).
   Read back with `catc_get_sda_fabric`.
7. Border and control plane first: `catc_add_fabric_device` device "198.18.128.176", fabric_site
   "Global/mcp-test-lab/mcp-test-fabric", roles ["CONTROL_PLANE_NODE", "BORDER_NODE"], border_asn "65001". Leave the
   border priority and AS-path prepends unset unless the design needs them: once set, a priority can't go
   back to the unset default (3.2.2 refuses 10 with NCHS20769; `catc_update_fabric_device` moves
   it within 1-9 only). Then each edge: `catc_add_fabric_device` with fabric_site "Global/mcp-test-lab/mcp-test-fabric" and
   roles ["EDGE_NODE"]. After each, `catc_get_sda_fabric` shows the device with its roles.
8. Virtual network: `catc_create_virtual_network` name "MCP_VN", fabric_sites ["Global/mcp-test-lab/mcp-test-fabric"].
9. Anycast gateway: `catc_add_anycast_gateway` fabric_site "Global/mcp-test-lab/mcp-test-fabric", virtual_network "MCP_VN",
   ip_pool "<pool name from step 4>". The preview names every edge that gets the SVI.
10. Edge ports:
   - `catc_assign_fabric_port` device "198.18.128.175", interface "GigabitEthernet1/0/3", data_vlan "<pool name>"
   - `catc_assign_fabric_port` device "198.18.128.175", interface "GigabitEthernet1/0/4", data_vlan "<pool name>"
11. Checks:
   - `catc_get_sda_fabric` for Global/mcp-test-lab/mcp-test-fabric: devices and roles, MCP_VN, the gateway and the ports.
   - `catc_run_show_commands` on the edges: "show vlan brief", "show ip interface brief | include
     Vlan", "show running-config interface <port>" (the access VLAN and template), "show lisp session" (the
     session to the control plane is Up); on the border "show lisp session" and "show ip route vrf MCP_VN".
   - `catc_list_pending_fabric_events` for Global/mcp-test-lab/mcp-test-fabric: none pending.
   - Clients: `catc_list_clients` by edge device (Assurance lags minutes) or the client itself: an
     address in 10.10.40.0/24 and a ping to 10.10.40.1. DHCP from 10.255.40.14 works only when the VN can reach it: a server
     outside the fabric needs a border layer 3 handoff for MCP_VN (an IP transit to a fusion router); until then
     prove the gateway with a static address.
   - `catc_fabric_health` for Global/mcp-test-lab/mcp-test-fabric (scores lag provisioning by minutes; empty right after is
     not a failure).
12. AAA before "Closed Authentication": fabric provisioning sends RADIUS from each fabric device's Loopback0 (its
   RLOC), and Catalyst Center creates the ISE NADs on the RLOC /32 in Location#All Locations, not on the
   management IP. "Closed Authentication" blocks every client on the edge ports until ISE authorizes it,
   so prove every fabric device reaches ISE first:
   - `catc_run_show_commands` on 198.18.128.176, 198.18.128.175: "show aaa servers" (the ISE server's state
     must be current UP, not DEAD), "show running-config | include radius source-interface", "show ip
     interface brief | include Loopback0" (the RLOC: the address ISE sees) and "show cts environment-data"
     (download COMPLETE, the ISE server listed).
   - DEAD, or the environment data not COMPLETE: ISE has no route back to the RLOC subnet, or no NAD for the
     RLOC. The route is fixed on ISE or its gateway, outside Catalyst Center: tell the user and wait. Don't
     move the switches' RADIUS source by CLI (Catalyst Center's intent is Loopback0; the change would drift).
     After the fix a switch keeps the server DEAD until its automate-tester probe gets an answer (minutes):
     read "show aaa servers" again before calling the fix failed.
   - ISE (with the ise tools; without them, ask the user to check this in ISE): `ise_get_nad` with
     each RLOC finds its NAD. `ise_policy_explain` nad "<RLOC>", flow "wired-mab" ("wired-dot1x"
     for 802.1X clients) must select the policy set and the rule meant for the fabric's clients. A NAD left in
     Location#All Locations when that set matches a location: preview `ise_update_nad` with groups
     = the NAD's groups with the location replaced, and apply it on approval. The test clients need a rule
     that authorizes them (for MAB, their MACs in an endpoint group the rule permits).
   Go on only when every fabric device shows the ISE server UP.
13. Authentication template: `catc_set_fabric_authentication_profile` fabric_site "Global/mcp-test-lab/mcp-test-fabric",
   template "Closed Authentication", make_default true (authentication_order "mac" for MAB-first clients). The
   preview names every edge Catalyst Center pushes it to and counts the ports that follow the default. Then
   on the edges with `catc_run_show_commands`: "show access-session" (each client port
   Authorized), "show running-config interface <port>" (its source template), and with SGTs from ISE "show
   cts role-based sgt-map vrf MCP_VN all" (an edge keeps the clients' IP-to-SGT bindings in the VN's VRF; the
   global table only has the switch's own addresses). `ise_find_session` with a client's MAC
   shows its authorization; a client that stays unauthorized: `ise_why_auth_failed` with its
   MAC.
14. Summary: what was created (site, pool, fabric site, roles, MCP_VN, gateway, ports), each check's
   result, the AAA check per fabric device,
   the authentication template, and the undo as a preview only (do not confirm unless the user
   asks): `catc_delete_fabric_site` fabric_site "Global/mcp-test-lab/mcp-test-fabric", cascade true (ports, gateways, the
   site's VN membership, fabric devices, then the fabric site; the devices stay provisioned, the pool and the
   site stay).
