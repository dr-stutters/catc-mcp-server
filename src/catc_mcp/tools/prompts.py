"""Workflow prompts owned by this server (core `@reg.prompt`, BUILDING-A-SERVER §5a)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field
from stutters_mcp_core import Tier, ToolRegistrar, tool_ref


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(title="Onboard a device into Catalyst Center", uses=["catc"], tier=Tier.WRITE)
    def catc_onboard_device(
        ip_or_range: Annotated[
            str,
            Field(description="Management IP, or a range 'first-last' (e.g. 198.18.128.170-198.18.128.171)"),
        ],
        site_path: Annotated[
            str, Field(description="Building or floor to put it at, e.g. 'Global/Area/Building/Floor 1'")
        ],
        cli_credential: Annotated[
            str, Field(description="Name (description) of the global CLI credential to discover with")
        ] = "",
        snmp_credential: Annotated[
            str, Field(description="Name of the global SNMPv2c read credential (optional)")
        ] = "",
        provision: Annotated[
            bool, Field(description="Provision after assigning to the site (pushes the site's settings)")
        ] = True,
    ) -> str:
        """Onboard a network device end to end: check or create global credentials, discover it
        (waiting for the job), put it at a site (creating the hierarchy if needed), check the site's
        network settings, provision it, then verify with a device 360, a compliance run and show
        commands. Every write is preview-first and waits for the user's approval."""
        target = ip_or_range.strip()
        first = target.split("-")[0].strip()
        if "-" in target:
            devs = "DEVICES"
            devs_note = (
                f"DEVICES below means the management IPs of every device the discovery of {target} "
                "found and that is Managed (step 4); act on all of them, not just the first."
            )
            check = f"Call {tool_ref('catc_list_devices')} and look for addresses in {target}."
        else:
            devs = f'["{first}"]'
            devs_note = ""
            check = f'Call {tool_ref("catc_get_device")} with "{first}".'
        creds = ", ".join(c for c in (cli_credential, snmp_credential) if c) or "(none named)"
        provision_step = (
            f"""8. Provision: call {tool_ref("catc_provision_devices")} with devices={devs} and
   site="{site_path}". Show the preview (it pushes the site's network settings: DNS, NTP, banner,
   syslog/SNMP trap/telemetry collectors) and wait for approval. Provisioning takes about 90
   seconds. It does not apply the Day-N templates of the site's network profile: if step 6 found
   any, offer {tool_ref("catc_deploy_template")} for each afterwards. If the tool isn't available
   (the dangerous tier is off on this server), stop here and tell the user provisioning is the
   remaining step."""
            if provision
            else "8. Provisioning was not requested: skip it; say the device is assigned, not provisioned."
        )
        return f"""Onboard {target} into Catalyst Center at {site_path}. Credentials requested: {creds}.
Work through the steps in order. Every write tool is preview-first: show the preview, wait for the
user's approval, then repeat the call with the confirm token. Stop and report if a step fails.

{devs_note}
1. Is it already managed? {check} A device that exists and is Reachable/Managed skips to
   step 5; one that exists but is unreachable is reported instead of rediscovered.
2. Credentials: call {tool_ref("catc_list_global_credentials")}. Use the CLI credential
   "{cli_credential or "<ask the user which one>"}" and SNMP credential
   "{snmp_credential or "<optional>"}". If one is missing, ask the user for the values and create
   it with {tool_ref("catc_create_global_credential")} (secrets are never echoed back).
3. Discover: call {tool_ref("catc_create_discovery")} with name "onboard-{first}",
   ip_ranges=["{target}"], discovery_type "Range" (a single address is sent as a
   one-address range; the "Single" type finds nothing on 3.2.x), global_credentials naming the
   credentials from step 2, and wait=true. One switch takes about 3 minutes, two routers about 13.
   If it times out, follow it with {tool_ref("catc_list_discoveries")} and
   {tool_ref("catc_list_discovery_devices")}.
4. Check the result: every address must show reachable with CLI and SNMP "Success". Explain any
   failure (wrong credentials, no SSH/SNMP, unreachable) and stop. The discovery ends before the
   inventory sync: poll {tool_ref("catc_get_device")} every 30 s or so until reachabilityStatus is
   Reachable and collectionStatus is Managed (2-5 minutes; "Unknown"/"In Progress" until then).
   Don't move on with a device that is not Managed.
5. Site: call {tool_ref("catc_get_site")} for "{site_path}". If it doesn't exist, show the user the
   missing levels and create them with {tool_ref("catc_create_site")} (area, then building with an
   address or coordinates, then floor) after approval. Devices are provisioned to a building or
   floor, not an area.
6. Settings: call {tool_ref("catc_get_site_settings")} for "{site_path}" (inherited values
   included) and show DNS, NTP, banner, syslog/SNMP servers, time zone and the site's device
   credentials. If something the user expects is missing, offer
   {tool_ref("catc_update_site_settings")} and {tool_ref("catc_assign_site_credentials")} at the
   right level. Also show any network profile on the site and its templates with
   {tool_ref("catc_list_network_profiles")} / {tool_ref("catc_get_network_profile")}: those are the
   Day-N templates meant for this site (deployed in step 8).
7. Assign: call {tool_ref("catc_assign_devices_to_site")} with devices={devs} and
   site="{site_path}".
{provision_step}
9. Verify:
   - {tool_ref("catc_device_360")} for each of {devs}: reachability, site, provisioning state, health
     (health can take ~5 minutes to appear for a new device);
   - {tool_ref("catc_run_compliance")} for the device, then {tool_ref("catc_get_compliance_summary")};
     NETWORK_SETTINGS should be compliant after provisioning;
   - {tool_ref("catc_run_show_commands")} with
     "show running-config | include ntp|logging host|ip domain|banner" to see what was pushed.
     Catalyst Center doesn't save the config: suggest "write memory" or a template if the user
     wants it to survive a reload;
   - {tool_ref("catc_recent_activity")} for the device over the last hour, for anything that went
     wrong (issues, events, audit).
10. Summarise: device name, IP, site, provisioning result, what was pushed, compliance, and anything
    left to do."""
