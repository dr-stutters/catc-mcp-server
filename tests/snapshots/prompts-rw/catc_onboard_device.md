# catc_onboard_device

title: Onboard a device into Catalyst Center
arguments: {"cli_credential": "mcp-test-cli", "ip_or_range": "198.18.128.170", "provision": "true", "site_path": "Global/mcp-test-lab/mcp-test-bldg", "snmp_credential": "mcp-test-snmp-ro"}

Onboard a network device end to end: check or create global credentials, discover it
(waiting for the job), put it at a site (creating the hierarchy if needed), check the site's
network settings, provision it, then verify with a device 360, a compliance run and show
commands. Every write is preview-first and waits for the user's approval.

## user

Onboard 198.18.128.170 into Catalyst Center at Global/mcp-test-lab/mcp-test-bldg. Credentials requested: mcp-test-cli, mcp-test-snmp-ro.
Work through the steps in order. Every write tool is preview-first: show the preview, wait for the
user's approval, then repeat the call with the confirm token. Stop and report if a step fails.


1. Is it already managed? Call `catc_get_device` with "198.18.128.170". A device that exists and is Reachable/Managed skips to
   step 5; one that exists but is unreachable is reported instead of rediscovered.
2. Credentials: call `catc_list_global_credentials`. Use the CLI credential "mcp-test-cli" and the SNMPv2c read credential "mcp-test-snmp-ro". If one is missing,
   ask the user for the values and create it with `catc_create_global_credential`
   (secrets are never echoed back).
3. Discover: call `catc_create_discovery` with name "onboard-198.18.128.170",
   ip_ranges=["198.18.128.170"], discovery_type "Range" (a single address is sent as a
   one-address range; the "Single" type finds nothing on 3.2.x), global_credentials naming the
   credentials from step 2, and wait=true. One switch takes about 3 minutes, two routers about 13.
   If it times out, follow it with `catc_list_discoveries` and
   `catc_list_discovery_devices`.
4. Check the result: every address must show reachable with CLI and SNMP "Success". Explain any
   failure (wrong credentials, no SSH/SNMP, unreachable) and stop. The discovery ends before the
   inventory sync: poll `catc_get_device` every 30 s or so until reachabilityStatus is
   Reachable and collectionStatus is Managed (2-5 minutes; "Unknown"/"In Progress" until then).
   Don't move on with a device that is not Managed.
5. Site: call `catc_get_site` for "Global/mcp-test-lab/mcp-test-bldg". If it doesn't exist, show the user the
   missing levels and create them with `catc_create_site` (area, then building with an
   address or coordinates, then floor) after approval. Devices are provisioned to a building or
   floor, not an area.
6. Settings: call `catc_get_site_settings` for "Global/mcp-test-lab/mcp-test-bldg" (inherited values
   included) and show DNS, NTP, banner, syslog/SNMP servers, time zone and the site's device
   credentials. If something the user expects is missing, offer
   `catc_update_site_settings` and `catc_assign_site_credentials` at the
   right level. Also show any network profile on the site and its templates with
   `catc_list_network_profiles` / `catc_get_network_profile`: those are the
   Day-N templates meant for this site (deployed in step 8).
7. Assign: call `catc_assign_devices_to_site` with devices=["198.18.128.170"] and
   site="Global/mcp-test-lab/mcp-test-bldg".
8. Provision: call `catc_provision_devices` with devices=["198.18.128.170"] and
   site="Global/mcp-test-lab/mcp-test-bldg". Show the preview (it pushes the site's network settings: DNS, NTP, banner,
   syslog/SNMP trap/telemetry collectors) and wait for approval. Provisioning takes about 90
   seconds. It does not apply the Day-N templates of the site's network profile: if step 6 found
   any, offer `catc_deploy_template` for each afterwards. If the tool isn't available
   (the dangerous tier is off on this server), stop here and tell the user provisioning is the
   remaining step.
9. Verify:
   - `catc_device_360` for each of ["198.18.128.170"]: reachability, site, provisioning state, health
     (health can take ~5 minutes to appear for a new device);
   - `catc_run_compliance` for the device, then `catc_get_compliance_detail`
     for it; NETWORK_SETTINGS should be compliant after provisioning;
   - `catc_run_show_commands` with
     "show running-config | include ntp|logging host|ip domain|banner" to see what was pushed.
     Catalyst Center doesn't save the config: suggest "write memory" or a template if the user
     wants it to survive a reload;
   - `catc_recent_activity` for the device over the last hour, for anything that went
     wrong (issues, events, audit).
10. Summarise: device name, IP, site, provisioning result, what was pushed, compliance, and anything
    left to do.
