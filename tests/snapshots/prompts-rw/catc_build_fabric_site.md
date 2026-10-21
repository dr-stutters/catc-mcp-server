# catc_build_fabric_site

title: Build an SD-Access fabric site
arguments: {"authentication": "Closed Authentication", "border": "198.18.128.176", "border_asn": "65001", "building": "Global/mcp-test-lab/mcp-test-fabric", "client_pool": "10.10.40.0/24", "client_ports": "198.18.128.175:GigabitEthernet1/0/3, 198.18.128.175:GigabitEthernet1/0/4", "dhcp_server": "10.255.40.14", "edges": "198.18.128.175", "virtual_network": "MCP_VN"}

Build an SD-Access fabric site from switches to a client in the fabric: SD-Access availability,
the devices onboarded and provisioned at the building, the client IP pool, the fabric site, border
and control plane before the edges, the virtual network, the anycast gateway, the edge ports, and
the checks between the steps (fabric read-back, CLI on the edges, pending fabric events, fabric
health). Ends with the teardown as a preview (catc_delete_fabric_site with cascade). Every write is
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
   "Closed Authentication". Read back with `catc_get_sda_fabric`.
7. Border and control plane first: `catc_add_fabric_device` device "198.18.128.176", fabric_site
   "Global/mcp-test-lab/mcp-test-fabric", roles ["CONTROL_PLANE_NODE", "BORDER_NODE"], border_asn "65001". Then each
   edge: `catc_add_fabric_device` with fabric_site "Global/mcp-test-lab/mcp-test-fabric" and roles ["EDGE_NODE"]. After
   each, `catc_get_sda_fabric` shows the device with its roles.
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
12. Summary: what was created (site, pool, fabric site, roles, MCP_VN, gateway, ports), each check's result, and
   the undo as a preview only (do not confirm unless the user asks): `catc_delete_fabric_site`
   fabric_site "Global/mcp-test-lab/mcp-test-fabric", cascade true (ports, gateways, the site's VN membership, fabric devices, then the
   fabric site; the devices stay provisioned, the pool and the site stay).
