# catc_onboard_switch_with_nac

title: Onboard an access switch with 802.1X/MAB (Catalyst Center + ISE)
arguments: {"access_port": "GigabitEthernet1/0/2", "auth_mode": "monitor", "cli_credential": "mcp-test-cli", "site_path": "Global/mcp-test-lab/mcp-test-nac", "snmp_credential": "mcp-test-snmp-ro", "switch_ip": "198.18.128.170", "test_mac": "5254.0012.3456"}

Onboard an access switch with network access control: check the Catalyst Center <-> ISE
integration, set the site's client AAA to ISE, discover/assign/provision the switch, confirm
its NAD in ISE, deploy an 802.1X/MAB access-port template, then verify the first
authentication in ISE and Catalyst Center. Needs the ise MCP server too. Every write is
preview-first.

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
4. Provision: `catc_provision_devices` with devices ["198.18.128.170"] and site
   "Global/mcp-test-lab/mcp-test-nac". This pushes the AAA/RADIUS config pointing at ISE and creates the switch as a
   NAD in ISE. (Dangerous tier; if it isn't available, stop and say so.)
5. Check the switch: `catc_run_show_commands` with
   "show running-config | section aaa|radius" and "show running-config | include dot1x|device-tracking":
   the radius server must be the ISE PSN and aaa authentication dot1x / authorization network must
   use that group.
6. NAD in ISE: `ise_get_nad` with "198.18.128.170". Catalyst Center normally creates it
   during provisioning. Only if it's missing, offer `ise_create_nad` (name = the
   switch hostname, ips ["198.18.128.170"], the same RADIUS shared secret as step 1).
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
9. Summary: switch onboarded (site, provisioning), AAA/ISE config on the switch, NAD in ISE,
   the port template, and the endpoint's authentication result in both products. In monitor mode
   remind the user that failures don't block traffic yet, and that "closed" mode enforces it.
