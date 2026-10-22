# catc_onboard_switch_with_nac

title: Onboard an access switch with 802.1X/MAB (Catalyst Center + ISE)
arguments: {"access_port": "GigabitEthernet1/0/2", "auth_mode": "monitor", "cli_credential": "mcp-test-cli", "site_path": "Global/mcp-test-lab/mcp-test-nac", "snmp_credential": "mcp-test-snmp-ro", "switch_ip": "198.18.128.170", "test_mac": "5254.0012.3456"}

Onboard an access switch with network access control: check the Catalyst Center <-> ISE
integration, set the site's client AAA to ISE, discover/assign/provision the switch, confirm
its NAD in ISE, deploy an 802.1X/MAB access-port template, verify the first
authentication in ISE and Catalyst Center, then check that every device at the site is a
NAD in ISE. Needs the ise MCP server too. Every write is preview-first.

## user

Onboard switch 198.18.128.170 at Global/mcp-test-lab/mcp-test-nac with 802.1X/MAB (monitor mode) on GigabitEthernet1/0/2, and
prove it with test endpoint 52:54:00:12:34:56. This needs both the catc and the ise MCP servers; if the ise
tools are missing, say so and stop after step 5. Every write is preview-first: show the preview,
wait for approval, then repeat the call with the confirm token. Stop and report on any failure.

1. ISE integration: `catc_get_policy_servers`. An ISE entry must exist with its nodes
   TRUSTED and the integration COMPLETE (next_action "none"). If none, it has to be added with
   `catc_add_ise_server` (ISE PAN IP/FQDN, a super-admin login, a RADIUS shared secret;
   suggest the user enters the secrets themselves rather than pasting them into the chat). If the
   entry exists but FAILED, next_action names the fix: "update_entry" ->
   `catc_update_policy_server` with the field it names (an ISE edit needs the ISE
   password re-entered; a name-resolution failure needs the appliance's DNS fixed by an admin, not
   an edit); "approve_pxgrid_on_ise" -> approve the Catalyst Center pxGrid client on ISE. When
   the integration stops at WAITING_USER_INPUT ("accept_certificate"), show the certificate
   fingerprints and, after the user confirms them, `catc_accept_ise_certificate`. ISE
   needs ERS and the pxGrid persona. These tools are dangerous tier: if they are missing here,
   stop and say the ISE integration must be fixed first.
2. Site AAA: `catc_get_site_settings` with categories ["aaa"] for "Global/mcp-test-lab/mcp-test-nac". Set
   client (endpoint) AAA to ISE with `catc_update_site_aaa_settings`:
   client={"server_type": "ISE", "protocol": "RADIUS", "primary": "<ISE PSN IP from step 1>"}.
   Leave network (device admin) AAA alone unless the user asks: pointing device logins at ISE
   without an ISE device-admin policy for Catalyst Center's CLI user locks Catalyst Center out.
3. Onboard (as in the catc_onboard_device prompt): `catc_get_device` "198.18.128.170";
   if absent, credentials (mcp-test-cli, mcp-test-snmp-ro) via `catc_list_global_credentials`, then
   `catc_create_discovery` with ip_ranges ["198.18.128.170"], discovery_type "Range", wait=true;
   poll `catc_get_device` until Reachable + Managed (2-5 minutes); create missing site
   levels with `catc_create_site`; `catc_assign_devices_to_site`.
   A discovery that finds nothing at all, although the switch answers ping: the appliance may hold a
   stale ARP entry for the IP (a re-created lab switch); a ping from the switch to the appliance
   refreshes it. "CLI validation failed": check the switch's VTY login (a TACACS+ server that rejects
   the CLI credential's user is not a fallback to local).
4. Provision: `catc_provision_devices` with devices ["198.18.128.170"] and site
   "Global/mcp-test-lab/mcp-test-nac". This pushes the AAA/RADIUS config pointing at ISE; an existing NAD in ISE with the
   switch's IP is reused (not duplicated), otherwise one is created. (Dangerous tier; if it isn't
   available, stop and say so.) Catalyst Center refuses a switch that already has AAA config
   ("AAA CLI(s) are already present ...", or "Unable to push ... address ipv4 <ISE> auth-port 1812"
   for a RADIUS server on the same address and ports): show the user the lines it names, keep a copy
   of the running config, and only with their approval remove them on the switch, resync
   (`catc_resync_devices`) and provision again; restore anything that must stay (e.g.
   device-admin TACACS+) afterwards.
5. Check the switch: `catc_run_show_commands` with
   "show running-config | section aaa|radius", "show running-config | include dot1x|device-tracking" and
   "show aaa servers": the radius server must be the ISE PSN, aaa authentication dot1x / authorization
   network must use that group, and the ISE server must not be DEAD. Note the RADIUS source ("ip radius
   source-interface", if set): ISE sees that address, not necessarily 198.18.128.170. DEAD means ISE doesn't
   answer: no NAD for the source address (step 6) or no route back to it from ISE. After the fix the switch
   keeps the server DEAD until its automate-tester probe gets an answer (minutes): check again before
   calling the fix failed.
6. NAD in ISE: `ise_get_nad` with "198.18.128.170" (and with the RADIUS source address from step 5
   when it differs). Catalyst Center normally creates it during provisioning. Only if it's missing, offer
   `ise_create_nad` (name = the switch hostname, ips ["198.18.128.170"] plus the RADIUS source
   address when it differs, the same RADIUS shared secret as step 1).
7. Access-port template (IBNS 2.0 style: Catalyst Center's provisioning leaves the switch in the
   new-style identity mode, where legacy "authentication ..." interface commands are dropped):
   create it in a project of the user's choice with `catc_create_template`
   (device_families ["Switches and Hubs"]), content:
       dot1x system-auth-control
       policy-map type control subscriber MCP-NAC
        event session-started match-all
         10 class always do-until-failure
          10 authenticate using mab priority 20
        event agent-found match-all
         10 class always do-until-failure
          10 terminate mab
          20 authenticate using dot1x priority 10
        event authentication-failure match-first
         10 class always do-until-failure
          10 terminate mab
          20 terminate dot1x
          30 authentication-restart 60
       interface GigabitEthernet1/0/2
        switchport mode access
        access-session host-mode multi-auth
        access-session port-control auto
        mab
        dot1x pae authenticator
        spanning-tree portfast
        service-policy type control subscriber MCP-NAC
   then `catc_commit_template`, `catc_preview_template` against the switch,
   and `catc_deploy_template` to ["198.18.128.170"]. If the deploy fails because the switch
   asks "This operation will permanently convert all relevant authentication commands ... Do you
   wish to continue?" (it is still in legacy mode), tell the user, and with their approval add these
   lines right after "dot1x system-auth-control", commit and deploy again (a switch already in
   new-style mode rejects the convert command, so only add it when asked):
       #INTERACTIVE
       authentication convert-to new-style<IQ>Do you wish to continue<R>yes
       #ENDS_INTERACTIVE
   Check with "show running-config interface GigabitEthernet1/0/2" that the access-session lines are there.
8. First authentication: have the endpoint 52:54:00:12:34:56 send traffic on GigabitEthernet1/0/2 (MAB starts on the first
   frame). Then:
   - `catc_run_show_commands` "show access-session interface GigabitEthernet1/0/2 details";
   - `ise_find_session` with mac "52:54:00:12:34:56" (live session, authz profile, NAD);
   - `ise_get_auth_history` with mac "52:54:00:12:34:56" (every attempt, pass/fail, rule hit);
   - on failure `ise_why_auth_failed` with mac "52:54:00:12:34:56". A MAB endpoint ISE doesn't
     know is usually rejected: offer to register it (`ise_set_endpoint` with a group
     the MAB rule permits) or a rule for it (`ise_create_authz_rule`), then bounce the
     port by re-triggering traffic and check again;
   - `ise_endpoint_360` with mac "52:54:00:12:34:56" (profile, group, history);
   - `catc_client_360` with mac "52:54:00:12:34:56" (Catalyst Center's view: switch, port, VLAN,
     health; it can take ~5 minutes to show up).
9. NAD coverage for the site: `catc_list_devices` with site "Global/mcp-test-lab/mcp-test-nac",
   response_format "json" and limit 500, then `ise_audit_nads` with expected = its rows as
   they are (hostname and managementIpAddress are accepted; leave out access points, family
   "Unified AP": their WLC is the NAD) and check_stale=false (one site is only part of the
   inventory, so every other NAD would look stale). Add aaa_server = the RADIUS server address seen
   in step 5 to this switch's row so aaa_elsewhere is checked too. Read coverage.verdict, then
   coverage.devices. Devices are matched to NADs by IP, never by name: a row with nad_name_differs
   (Catalyst Center reused an existing NAD under another name) is fine. These are red; each row's
   `fix` names the fix, which is offered as a preview only (nothing is applied without approval):
   - missing_nad: no NAD covers the device's IP, so ISE drops its RADIUS silently (11007):
     `ise_create_nad`, or provision it again (`catc_provision_devices`), which
     creates the NAD;
   - wrong_ndg (only for a row given an ndg): the NAD is not in that device group:
     `ise_update_nad` with the group paths;
   - ip_mismatch: a NAD has the device's name but another IP (a re-addressed device or a stale
     entry): `ise_update_nad` with ips ["<the device's IP>/32"] if it is this device;
   - aaa_elsewhere: the switch's RADIUS server is not an ISE node: fix the site's client AAA
     (`catc_update_site_aaa_settings`, step 2) and provision again (step 4).
10. Summary: switch onboarded (site, provisioning), AAA/ISE config on the switch, NAD in ISE,
   the port template, the endpoint's authentication result in both products, and the coverage
   verdict with any red rows and their fixes. In monitor mode remind the user that failures don't
   block traffic yet, and that "closed" mode enforces it.
