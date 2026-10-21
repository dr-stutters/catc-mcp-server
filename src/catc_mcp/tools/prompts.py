"""Workflow prompts owned by this server (core `@reg.prompt`, BUILDING-A-SERVER §5a)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import Field

from catc_mcp._core import InvalidRequest, Tier, ToolRegistrar, tool_ref
from catc_mcp.common import norm_mac

# Devices per change (roadmap D19's CATC_MAX_DEVICES_PER_CHANGE default).
MAX_DEVICES_PER_CHANGE = 10
PORT_RE = re.compile(r"[A-Za-z][A-Za-z\-]*\d+(/\d+){0,3}(\.\d+)?")


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
        cli_part = (
            f'Use the CLI credential "{cli_credential}"'
            if cli_credential
            else "Ask the user which CLI credential to use (or list them and let them pick)"
        )
        snmp_part = (
            f'Use the SNMPv2c read credential "{snmp_credential}".'
            if snmp_credential
            else "No SNMP credential was named: ask the user, or name every global SNMPv2c read "
            "credential in global_credentials."
        )
        cred_line = f"{cli_part}. {snmp_part}"
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
2. Credentials: call {tool_ref("catc_list_global_credentials")}. {cred_line} If one is missing,
   ask the user for the values and create it with {tool_ref("catc_create_global_credential")}
   (secrets are never echoed back).
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
   - {tool_ref("catc_run_compliance")} for the device, then {tool_ref("catc_get_compliance_detail")}
     for it; NETWORK_SETTINGS should be compliant after provisioning;
   - {tool_ref("catc_run_show_commands")} with
     "show running-config | include ntp|logging host|ip domain|banner" to see what was pushed.
     Catalyst Center doesn't save the config: suggest "write memory" or a template if the user
     wants it to survive a reload;
   - {tool_ref("catc_recent_activity")} for the device over the last hour, for anything that went
     wrong (issues, events, audit).
10. Summarise: device name, IP, site, provisioning result, what was pushed, compliance, and anything
    left to do."""

    @reg.prompt(title="Run a Day-N template change window", uses=["catc"], tier=Tier.WRITE)
    def catc_change_window(
        template: Annotated[
            str, Field(description="Template to deploy: 'Project/Template name', a unique name or its id")
        ],
        targets: Annotated[
            str,
            Field(
                description="Comma-separated devices (hostname, management IP, serial or id), e.g. 'r1,r2'"
            ),
        ],
        window_end: Annotated[
            str,
            Field(
                description="When the change window closes (ISO 8601 with offset, e.g. "
                "2026-10-15T23:00+11:00); nothing is deployed after it"
            ),
        ],
        params: Annotated[
            str, Field(description='Template variable values as JSON, e.g. {"loopback_id": 77} (optional)')
        ] = "",
        rollback: Annotated[
            Literal["negation", "archive"],
            Field(
                description="How to roll back: 'negation' = a template that removes what was added; "
                "'archive' = restore lines from the pre-change running config in the archive"
            ),
        ] = "negation",
    ) -> str:
        """Run a safe Day-N change with Catalyst Center: baseline (issues, compliance, config archive),
        per-device preview, safety-rail checks (device limit, window end), deploy, deployment status,
        CLI verification, a compliance run, the config diff, a post-change issue diff, and a written
        rollback plan. Deploying is dangerous-tier; without it the prompt stops at a reviewed plan."""
        devices = [t.strip() for t in targets.split(",") if t.strip()]
        if any(ord(ch) < 32 for ch in template + targets + window_end + params):
            raise ValueError("Arguments must not contain control characters (newlines, tabs).")
        devs = json.dumps(devices)
        try:
            parsed = json.loads(params) if params.strip() else {}
        except ValueError as exc:
            raise ValueError(f"params must be a JSON object: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError('params must be a JSON object, e.g. {"loopback_id": 77}')
        params_arg = json.dumps(parsed)
        try:
            end = datetime.fromisoformat(window_end.strip())
        except ValueError as exc:
            raise ValueError(f"window_end must be ISO 8601, e.g. 2026-10-15T23:00+11:00: {exc}") from exc
        if end.tzinfo is None:
            raise ValueError("window_end needs a UTC offset, e.g. 2026-10-15T23:00+11:00")
        too_many = (
            f"\n   STOP: {len(devices)} devices is over the limit of {MAX_DEVICES_PER_CHANGE} per change. "
            "Ask the user to split the change into batches."
            if len(devices) > MAX_DEVICES_PER_CHANGE
            else ""
        )
        left = (end - datetime.now(UTC)).total_seconds() / 60
        if left < 15:
            too_many += (
                f"\n   STOP: when this prompt was rendered the window had {max(left, 0):.0f} minutes left "
                "(under 15). Don't deploy; offer to plan the change for the next window."
            )
        if rollback == "negation":
            rollback_plan = f"""   - Write the negation: for every line the template added (step 7's diff, '+'
     lines; if the deploy failed before step 7, use the rendered CLI from step 3), the
     'no ...' form, in dependency order (children before parents, e.g. 'no interface Loopback77'
     removes its sub-commands too). Offer to create it as "<template>-rollback" in the same project
     with {tool_ref("catc_create_template")} + {tool_ref("catc_commit_template")}, preview it with
     {tool_ref("catc_preview_template")}, and (only if the user asks to roll back now)
     deploy it with {tool_ref("catc_deploy_template")}."""
        else:
            rollback_plan = f"""   - Name the pre-change running-config archive version from step 1 per device
     (file id and time) and list the lines that differ (step 7). Catalyst Center has no "restore archive"
     call: the rollback is a template that puts back the '-' lines and removes the '+' lines.
     Offer to build it with {tool_ref("catc_create_template")} + {tool_ref("catc_commit_template")}
     and deploy it with {tool_ref("catc_deploy_template")} if the user asks to roll back now."""
        return f"""Change window: deploy template "{template}" to {devs} with params {params_arg}.
The window closes at {window_end}. Work through the steps in order and stop on any failure.
Every write is preview-first: show the preview, wait for the user's approval, then repeat the call
with the confirm token. Keep a short log of each step's result for the summary.

1. Baseline, before touching anything (save the results; steps 8-9 compare against them):
   - {tool_ref("catc_get_device")} for each device: it must be Reachable and Managed;
   - {tool_ref("catc_list_issues")} with device=<each device>: the open issues now;
   - {tool_ref("catc_get_compliance_detail")} for each device: per-category status now;
   - {tool_ref("catc_list_config_archive")} for each device: the newest RUNNINGCONFIG file id and
     time (the pre-change version). If it is older than the device's last change, run
     {tool_ref("catc_resync_devices")} first so the archive is current.
2. Template: {tool_ref("catc_get_template")} for "{template}". It must be committed (a
   draft can't be deployed; offer {tool_ref("catc_commit_template")}), and its device types must
   match the targets. List its variables and check {params_arg} supplies the required ones.
3. Preview per device: {tool_ref("catc_preview_template")} with params {params_arg} and device=<each
   device>. Show the rendered CLI for each device and point out anything risky (interfaces shut,
   routing, AAA, ACLs on the management path).
4. Safety rails, all must pass before deploying:
   - at most {MAX_DEVICES_PER_CHANGE} devices in one change (this one: {len(devices)});{too_many}
   - the current time is before {window_end}, with enough time left for deploy + verification +
     a rollback (allow 15 minutes); otherwise stop and say the window is too short;
   - no P1/P2 issue open on a target in step 1 (or the user accepts it explicitly);
   - the user has approved the rendered CLI from step 3.
5. Deploy: {tool_ref("catc_deploy_template")} with template "{template}", devices={devs},
   params {params_arg}. Show the preview and wait for approval. If the tool isn't available (the
   dangerous tier is off on this server), stop here: hand the user steps 1-4 and the rollback
   plan (step 10) as the reviewed change plan.
6. Deployment status: {tool_ref("catc_get_template_deployment")} with the deployment id until
   every device is SUCCESS (or one fails: then go to step 10 for that device).
   Verify on the devices: {tool_ref("catc_run_show_commands")} with the show commands that prove
   the change (e.g. "show running-config | section <what the template touches>").
7. Config diff: {tool_ref("catc_resync_devices")}, wait ~2 minutes, then
   {tool_ref("catc_compare_device_configs")} with compare="previous" for each device. The '+'
   lines must be what the template rendered in step 3 and nothing else. If the result is
   identical or misses the change (the archive got no new version, or more than one), compare
   with compare="files", from_file=<step 1's file id> and to_file=<the newest RUNNINGCONFIG>.
8. Compliance: {tool_ref("catc_run_compliance")} for {devs}, then
   {tool_ref("catc_get_compliance_detail")} again. Compare with the baseline: RUNNING_CONFIG
   (startup vs running) usually turns NON_COMPLIANT because Catalyst Center doesn't save the
   config; anything else that changed is a finding.
9. Issue diff: {tool_ref("catc_list_issues")} per device again (and
   {tool_ref("catc_recent_activity")} for the window) and report new issues since step 1.
10. Rollback plan (always write it, even when everything passed):
{rollback_plan}
   - Say when it must be started to finish before {window_end}.
11. Summary: what was deployed where, deployment result, verification output, config diff,
    compliance before/after, new issues, and the rollback plan. Suggest "write memory" (or a
    template) if the change should survive a reload."""

    @reg.prompt(
        title="Onboard an access switch with 802.1X/MAB (Catalyst Center + ISE)",
        uses=["catc", "ise"],
        tier=Tier.WRITE,
    )
    def catc_onboard_switch_with_nac(
        switch_ip: Annotated[str, Field(description="Management IP of the switch to onboard")],
        site_path: Annotated[
            str, Field(description="Building or floor for the switch, e.g. 'Global/Area/Building'")
        ],
        access_port: Annotated[
            str, Field(description="Access port to enable 802.1X/MAB on, e.g. GigabitEthernet1/0/2")
        ],
        test_mac: Annotated[
            str, Field(description="MAC of a test endpoint on that port, e.g. 52:54:00:12:34:56")
        ],
        auth_mode: Annotated[
            Literal["monitor", "closed"],
            Field(
                description="monitor: open authentication (traffic allowed, results logged); closed: enforced"
            ),
        ] = "monitor",
        cli_credential: Annotated[
            str, Field(description="Global CLI credential (description) to discover with")
        ] = "",
        snmp_credential: Annotated[str, Field(description="Global SNMPv2c read credential (optional)")] = "",
    ) -> str:
        """Onboard an access switch with network access control: check the Catalyst Center <-> ISE
        integration, set the site's client AAA to ISE, discover/assign/provision the switch, confirm
        its NAD in ISE, deploy an 802.1X/MAB access-port template, then verify the first
        authentication in ISE and Catalyst Center. Needs the ise MCP server too. Every write is
        preview-first."""
        texts = (switch_ip, site_path, access_port, test_mac, cli_credential, snmp_credential)
        if any(not ch.isprintable() or ch in '"`' for t in texts for ch in t):
            raise ValueError("Arguments must be printable text without quotes or backticks.")
        try:
            ip = str(ipaddress.ip_address(switch_ip.strip()))
        except ValueError as exc:
            raise ValueError(f"switch_ip must be an IP address: {exc}") from exc
        port = access_port.strip()
        if not PORT_RE.fullmatch(port):
            raise ValueError(
                f"access_port must be an interface name such as GigabitEthernet1/0/2, not {port!r}."
            )
        mac = norm_mac(test_mac)
        switch_ip = ip
        closed_line = "\n        access-session closed" if auth_mode == "closed" else ""
        creds = ", ".join(c for c in (cli_credential, snmp_credential) if c) or "(ask the user)"
        return f"""Onboard switch {switch_ip} at {site_path} with 802.1X/MAB ({auth_mode} mode) on {port}, and
prove it with test endpoint {mac}. This needs both the catc and the ise MCP servers; if the ise
tools are missing, say so and stop after step 5. Every write is preview-first: show the preview,
wait for approval, then repeat the call with the confirm token. Stop and report on any failure.

1. ISE integration: {tool_ref("catc_get_policy_servers")}. An ISE entry must exist with its nodes
   TRUSTED and the integration COMPLETE (next_action "none"). If none, it has to be added with
   {tool_ref("catc_add_ise_server")} (ISE PAN IP/FQDN, a super-admin login, a RADIUS shared secret;
   suggest the user enters the secrets themselves rather than pasting them into the chat). If the
   entry exists but FAILED, next_action names the fix: "update_entry" ->
   {tool_ref("catc_update_policy_server")} with the field it names (an ISE edit needs the ISE
   password re-entered; a name-resolution failure needs the appliance's DNS fixed by an admin, not
   an edit); "approve_pxgrid_on_ise" -> approve the Catalyst Center pxGrid client on ISE. When
   the integration stops at WAITING_USER_INPUT ("accept_certificate"), show the certificate
   fingerprints and, after the user confirms them, {tool_ref("catc_accept_ise_certificate")}. ISE
   needs ERS and the pxGrid persona. These tools are dangerous tier: if they are missing here,
   stop and say the ISE integration must be fixed first.
2. Site AAA: {tool_ref("catc_get_site_settings")} with categories ["aaa"] for "{site_path}". Set
   client (endpoint) AAA to ISE with {tool_ref("catc_update_site_aaa_settings")}:
   client={{"server_type": "ISE", "protocol": "RADIUS", "primary": "<ISE PSN IP from step 1>"}}.
   Leave network (device admin) AAA alone unless the user asks: pointing device logins at ISE
   without an ISE device-admin policy for Catalyst Center's CLI user locks Catalyst Center out.
3. Onboard (as in the catc_onboard_device prompt): {tool_ref("catc_get_device")} "{switch_ip}";
   if absent, credentials ({creds}) via {tool_ref("catc_list_global_credentials")}, then
   {tool_ref("catc_create_discovery")} with ip_ranges ["{switch_ip}"], discovery_type "Range", wait=true;
   poll {tool_ref("catc_get_device")} until Reachable + Managed (2-5 minutes); create missing site
   levels with {tool_ref("catc_create_site")}; {tool_ref("catc_assign_devices_to_site")}.
   A discovery that finds nothing at all, although the switch answers ping: the appliance may hold a
   stale ARP entry for the IP (a re-created lab switch); a ping from the switch to the appliance
   refreshes it. "CLI validation failed": check the switch's VTY login (a TACACS+ server that rejects
   the CLI credential's user is not a fallback to local).
4. Provision: {tool_ref("catc_provision_devices")} with devices ["{switch_ip}"] and site
   "{site_path}". This pushes the AAA/RADIUS config pointing at ISE; an existing NAD in ISE with the
   switch's IP is reused (not duplicated), otherwise one is created. (Dangerous tier; if it isn't
   available, stop and say so.) Catalyst Center refuses a switch that already has AAA config
   ("AAA CLI(s) are already present ...", or "Unable to push ... address ipv4 <ISE> auth-port 1812"
   for a RADIUS server on the same address and ports): show the user the lines it names, keep a copy
   of the running config, and only with their approval remove them on the switch, resync
   ({tool_ref("catc_resync_devices")}) and provision again; restore anything that must stay (e.g.
   device-admin TACACS+) afterwards.
5. Check the switch: {tool_ref("catc_run_show_commands")} with
   "show running-config | section aaa|radius" and "show running-config | include dot1x|device-tracking":
   the radius server must be the ISE PSN and aaa authentication dot1x / authorization network must
   use that group.
6. NAD in ISE: {tool_ref("ise_get_nad")} with "{switch_ip}". Catalyst Center normally creates it
   during provisioning. Only if it's missing, offer {tool_ref("ise_create_nad")} (name = the
   switch hostname, ips ["{switch_ip}"], the same RADIUS shared secret as step 1).
7. Access-port template (IBNS 2.0 style: Catalyst Center's provisioning leaves the switch in the
   new-style identity mode, where legacy "authentication ..." interface commands are dropped):
   create it in a project of the user's choice with {tool_ref("catc_create_template")}
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
       interface {port}
        switchport mode access
        access-session host-mode multi-auth{closed_line}
        access-session port-control auto
        mab
        dot1x pae authenticator
        spanning-tree portfast
        service-policy type control subscriber MCP-NAC
   then {tool_ref("catc_commit_template")}, {tool_ref("catc_preview_template")} against the switch,
   and {tool_ref("catc_deploy_template")} to ["{switch_ip}"]. If the deploy fails because the switch
   asks "This operation will permanently convert all relevant authentication commands ... Do you
   wish to continue?" (it is still in legacy mode), tell the user, and with their approval add these
   lines right after "dot1x system-auth-control", commit and deploy again (a switch already in
   new-style mode rejects the convert command, so only add it when asked):
       #INTERACTIVE
       authentication convert-to new-style<IQ>Do you wish to continue<R>yes
       #ENDS_INTERACTIVE
   Check with "show running-config interface {port}" that the access-session lines are there.
8. First authentication: have the endpoint {mac} send traffic on {port} (MAB starts on the first
   frame). Then:
   - {tool_ref("catc_run_show_commands")} "show access-session interface {port} details";
   - {tool_ref("ise_find_session")} with mac "{mac}" (live session, authz profile, NAD);
   - {tool_ref("ise_get_auth_history")} with mac "{mac}" (every attempt, pass/fail, rule hit);
   - on failure {tool_ref("ise_why_auth_failed")} with mac "{mac}". A MAB endpoint ISE doesn't
     know is usually rejected: offer to register it ({tool_ref("ise_set_endpoint")} with a group
     the MAB rule permits) or a rule for it ({tool_ref("ise_create_authz_rule")}), then bounce the
     port by re-triggering traffic and check again;
   - {tool_ref("ise_endpoint_360")} with mac "{mac}" (profile, group, history);
   - {tool_ref("catc_client_360")} with mac "{mac}" (Catalyst Center's view: switch, port, VLAN,
     health; it can take ~5 minutes to show up).
9. Summary: switch onboarded (site, provisioning), AAA/ISE config on the switch, NAD in ISE,
   the port template, and the endpoint's authentication result in both products. In monitor mode
   remind the user that failures don't block traffic yet, and that "closed" mode enforces it."""

    @reg.prompt(title="Decommission a device", uses=["catc", "ise"], tier=Tier.DANGEROUS)
    def catc_decommission_device(
        device: Annotated[str, Field(description="Device hostname, management IP or serial")],
        clean_config: Annotated[
            Literal["true", "false"],
            Field(
                description="true: also remove the configuration Catalyst Center pushed (AAA, syslog, "
                "SNMP, telemetry, banner); false: leave the device's configuration as it is"
            ),
        ],
        remove_ise_nad: Annotated[
            Literal["true", "false"], Field(description="Also delete the device's network device in ISE")
        ] = "true",
    ) -> str:
        """Take a device out of Catalyst Center cleanly: keep a copy of its configuration, show what
        un-provisioning loses (it DELETES the device: unmanaged, assurance history and config archive
        gone), untag it, delete it with an explicit clean_config, then remove the network device
        Catalyst Center leaves behind in ISE. Every write is preview-first; needs the ise server for
        the last step."""
        if any(not ch.isprintable() or ch in '"`' for ch in device):
            raise ValueError("device must be printable text without quotes or backticks.")
        dev = device.strip()
        if not dev:
            raise ValueError("Give the device's hostname, management IP or serial.")
        ise = (
            f"""6. ISE: Catalyst Center does not delete the network device it created in ISE when it
   provisioned this device (with AAA = ISE). Call {tool_ref("ise_get_nad")} with the device's
   management IP (from step 1); if one exists and its name is the device's hostname (CatC names it
   so, group DNAC#DNAC Devices), preview {tool_ref("ise_delete_nad")} for it, show the preview and
   delete it once the user approves. If the NAD has another name or other IPs, show it and ask
   first: it may be shared or hand-made. Afterwards {tool_ref("ise_list_nads")} filtered by the
   name confirms it is gone."""
            if remove_ise_nad == "true"
            else "6. ISE: skipped (remove_ise_nad=false). Mention that ISE still has the device's NAD."
        )
        return f"""Decommission "{dev}" from Catalyst Center (clean_config={clean_config}). Show every
preview to the user and confirm only after they approve. Stop if a step fails and report what was done.

1. Identify: call {tool_ref("catc_device_360")} for "{dev}" and note hostname, management IP,
   serial, site, provisioning state and health. If it isn't found, stop: nothing to decommission.
2. Keep a copy: call {tool_ref("catc_get_device_config")} for "{dev}" (running config, secrets
   masked) and {tool_ref("catc_list_config_archive")}; give the user the configuration or tell them
   where the archive versions are, because deleting the device deletes its archive in Catalyst
   Center.
3. Impact: call {tool_ref("catc_delete_device")} with device "{dev}" and clean_config={clean_config}
   WITHOUT confirm. Show the preview's side effects verbatim: un-provisioning in Catalyst Center 3.x
   deletes the device (no longer managed: no assurance, compliance, templates or provisioning until
   it is rediscovered), its archived configuration versions go, and with clean_config=true the
   AAA/syslog/SNMP/telemetry/banner configuration Catalyst Center pushed is removed from the device
   (it may lose RADIUS/TACACS+ logins that relied on it). If the user only wanted to stop managing
   some settings, suggest re-provisioning instead and stop here.
4. Tags: call {tool_ref("catc_list_tags")}; for any static tag that has the device
   ({tool_ref("catc_list_tag_members")}), remove it with {tool_ref("catc_update_tag_members")}
   (remove=["{dev}"]), so automation keyed on the tag doesn't target a ghost.
5. Delete: repeat {tool_ref("catc_delete_device")} with the same arguments and the confirm token
   from step 3 (after the user approved it). Then {tool_ref("catc_get_device")} for "{dev}" must say
   no such device; {tool_ref("catc_get_task")} if it is still running.
{ise}
7. Summary: what was saved (config), what was removed (inventory entry, tags, ISE NAD), whether the
   device's configuration was cleaned, and how to bring it back: the {tool_ref("catc_onboard_device")}
   prompt (discovery, site, provisioning)."""

    @reg.prompt(
        title="Catalyst Center admin login through ISE",
        uses=["catc", "ise", "win"],
        tier=Tier.DANGEROUS,
    )
    def catc_admin_access_via_ise(
        catc_ip: Annotated[
            str, Field(description="The IP Catalyst Center sends RADIUS from (its enterprise interface)")
        ],
        ad_group: Annotated[
            str, Field(description="AD group whose members get the role, e.g. mcp-catc-admins")
        ] = "mcp-catc-admins",
        ad_user: Annotated[
            str, Field(description="AD user to prove the login with (created if missing)")
        ] = "",
        role: Annotated[
            str,
            Field(
                description="Catalyst Center role the group gets: SUPER-ADMIN-ROLE, NETWORK-ADMIN-ROLE, "
                "OBSERVER-ROLE or a custom role name"
            ),
        ] = "OBSERVER-ROLE",
        mirror_local_accounts: Annotated[
            Literal["true", "false"],
            Field(
                description="true: first mirror every local Catalyst Center account in use as an ISE "
                "internal user with its current role (break-glass while ISE answers)"
            ),
        ] = "true",
        keep_enabled: Annotated[
            Literal["true", "false"],
            Field(description="false: a proof run, external authentication is switched off again at the end"),
        ] = "false",
    ) -> str:
        """Move Catalyst Center administrator logins onto Active Directory through ISE: an AD group and
        user, ISE's NAD for Catalyst Center, an authorization profile returning cisco-av-pair
        Role=<role>, a policy set for Catalyst Center's RADIUS logins, then external authentication on,
        a local and an AD test login, the ISE auth record, and an undo list. Every write is
        preview-first; uses the ise and Windows_Server (win_) servers; dangerous tier."""
        texts = (catc_ip, ad_group, ad_user, role)
        if any(not ch.isprintable() or ch in '"`' for t in texts for ch in t):
            raise ValueError("Arguments must be printable text without quotes or backticks.")
        try:
            ip = str(ipaddress.ip_address(catc_ip.strip()))
        except ValueError as exc:
            raise ValueError(f"catc_ip must be an IP address: {exc}") from exc
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", role.strip()):
            raise ValueError(f"role must be a Catalyst Center role name, not {role!r}.")
        group, user, role = ad_group.strip(), ad_user.strip() or "(ask the user)", role.strip()
        slug = role.lower().removesuffix("-role")
        profile = f"mcp-catc-{slug}"
        pset = "mcp-catc-admin-login"
        mirror = (
            f"""5. Break-glass mirror (mirror_local_accounts=true). Catalyst Center 3.2.2 asks ISE first
   (tested): once external authentication is on, a local account only logs in if ISE accepts it with a
   role. List the local accounts with {tool_ref("catc_api_call")} GET /dna/system/api/v1/user
   (authSource=internal): their usernames and roleList. Ask the user which are in use (their own
   admin and this server's account at least). The reply must name a BUILT-IN role (SUPER-ADMIN-ROLE,
   NETWORK-ADMIN-ROLE, OBSERVER-ROLE): 3.2.2 refuses a custom role with "Invalid user profile", so map
   an account with a custom role to the nearest built-in one and tell the user what it gains or
   loses (or leave it out: it then can't log in while external authentication is on). For each
   built-in role among them create, preview-first:
   an ISE identity group mcp-catc-mirror-<role> ({tool_ref("ise_create_group")}), an authorization
   profile mcp-catc-mirror-<role> ({tool_ref("ise_create_authz_profile")} with
   av_pairs=["Cisco:cisco-av-pair=Role=<role>"]), and per account an ISE internal user with the SAME
   name and password in that group ({tool_ref("ise_create_internal_user")}; the user types each
   password: never ask for it in chat if they can enter it themselves). The rules come in step 6.
   These users hold copies of local passwords: the undo deletes them."""
            if mirror_local_accounts == "true"
            else "5. Break-glass mirror: skipped (mirror_local_accounts=false). Say clearly that a local "
            "account may stop working while ISE answers, and get the user's explicit go before step 7."
        )
        mirror_rules = (
            """   For each mirror group: rule mcp-catc-mirror-<role> with condition
   "IdentityGroup:Name equals User Identity Groups:mcp-catc-mirror-<role>" -> profile
   mcp-catc-mirror-<role>, ranked above the AD rule (create the AD rule first, then the mirror rules)."""
            if mirror_local_accounts == "true"
            else ""
        )
        end = (
            f"""11. Switch off (keep_enabled=false): {tool_ref("catc_set_external_authentication")}
    enable=false (preview, approval), then {tool_ref("catc_test_login")} with the local admin once more.
    Then the undo, each preview-first, in this order: the mirror internal users (they hold copies of
    local passwords) and groups, policy set {pset} ({tool_ref("ise_delete_object")}), profile
    {profile} and the mirror profiles, the NAD if step 3 created it ({tool_ref("ise_delete_nad")}),
    and the AD user/group if step 2 created them for this proof (ask first)."""
            if keep_enabled == "false"
            else """11. Leave it on (keep_enabled=true). Recommend keeping the mirror users only as long as
    the user wants a break-glass path, and write the undo list down."""
        )
        return f"""Move Catalyst Center admin logins onto AD through ISE: members of AD group "{group}" get
{role}; prove it with AD user {user}. Catalyst Center sends RADIUS (PAP) from {ip}. Every write is
preview-first: show the preview, wait for the user's approval, then repeat the call with the confirm
token. Stop and report on any failure. Run in a quiet window: ask the user to confirm nobody else is
using Catalyst Center while external authentication is on.

1. Preconditions: {tool_ref("catc_get_policy_servers")}: an ISE entry must be COMPLETE with
   next_action "none"; if not, stop and name its next_action (the integration must be fixed first).
   {tool_ref("catc_get_external_authentication")}: note whether it is already on, the AAA attribute
   (default Cisco-AVPair) and that the ISE node is among its servers; if no server is listed, stop.
   Check that {role} is among its roles.
2. Active Directory: {tool_ref("win_list_ad_groups")} for "{group}"; create it with
   {tool_ref("win_create_ad_group")} if missing. {tool_ref("win_get_ad_user")} for {user}; create
   it with {tool_ref("win_create_ad_user")} if missing (the user sets the password) and add it with
   {tool_ref("win_add_group_member")}. On ISE: {tool_ref("ise_get_ad_join_point")} (joined, its
   name and domain), {tool_ref("ise_list_ad_groups")}; if "{group}" isn't selectable yet, add it with
   {tool_ref("ise_add_ad_groups")}. {tool_ref("ise_test_ad_user")} for {user} must list the group.
3. ISE NAD for Catalyst Center: {tool_ref("ise_get_nad")} "{ip}". If none, preview
   {tool_ref("ise_create_nad")} name "catalyst-center", ips ["{ip}"], with the RADIUS shared secret
   of Catalyst Center's ISE entry (the user enters it: Catalyst Center never returns it). If one
   exists, check it has a RADIUS secret and keep it.
4. Authorization profile: {tool_ref("ise_create_authz_profile")} name "{profile}", access accept,
   av_pairs=["Cisco:cisco-av-pair=Role={role}"] (the attribute must match step 1's AAA attribute).
{mirror}
6. Policy: create policy set "{pset}" with {tool_ref("ise_create_policy_set")}, condition
   "Network Access:Device IP Address equals {ip}" (the packet's source: the NAS-IP-Address Catalyst
   Center sends is not its own address, tested on 3.2.2), rank 0, allowed protocols that permit
   PAP (Default Network Access). Authentication: an identity source sequence mcp_catc_admins with stores
   {"Internal Users, then the AD join point" if mirror_local_accounts == "true" else "the AD join point"}
   ({tool_ref("ise_set_identity_sequence")}), used by an authentication rule in the set
   ({tool_ref("ise_create_authn_rule")}, condition "Network Access:Device IP Address equals {ip}").
   Authorization ({tool_ref("ise_create_authz_rule")}; insert each rule at rank 0, the last one created
   ends up first: ISE refuses a rank that doesn't exist yet): rule mcp-catc-ad with condition
   "<join point>:ExternalGroups equals <domain>/<path>/{group}" (the exact value from step 2) ->
   {profile}.
{mirror_rules}
   The set's Default rule stays DenyAccess. Review the set with {tool_ref("ise_get_policy_set")}.
7. Before enabling: {tool_ref("catc_test_login")} with the user's local admin (proves the password
   now; this server keeps its own session for about an hour, which is the undo path). Then
   {tool_ref("catc_set_external_authentication")} enable=true: show the preview with its lockout
   warning and apply only after approval.
8. Right after enabling: {tool_ref("catc_test_login")} with the local admin again. If it fails, at
   once {tool_ref("catc_set_external_authentication")} enable=false (preview, approval) and stop.
9. The AD login: {tool_ref("catc_test_login")} with {user}: it must pass with roles [{role}]
   (authSource external). Catalyst Center's logins are bare RADIUS Access-Requests (no accounting,
   no MAC), so ISE's session lists ({tool_ref("ise_get_auth_list")}) stay empty: read the hit
   counters instead with {tool_ref("ise_get_policy_set")} "{pset}": the set, the authentication rule
   and mcp-catc-ad must have counted the login; a hit on the set's Default rule means a group or
   condition didn't match (check {tool_ref("ise_test_ad_user")}). A local account that now logs in
   with authSource external went through its mirror rule.
10. Summary: what was created where (AD, ISE NAD, profile(s), sequence, policy set, mirror users),
    the login results with the roles granted, the fallback finding from step 9, and the undo list.
{end}"""

    @reg.prompt(title="Troubleshoot a client", uses=["catc", "ise"], tier=Tier.READ)
    def catc_client_troubleshoot(
        client: Annotated[
            str, Field(description="The client: MAC (best), IPv4 address or the username it logged in with")
        ],
        destination_ip: Annotated[
            str, Field(description="Optional: an IP the client can't reach, for a path trace")
        ] = "",
        expected_vlan: Annotated[
            str, Field(description="Optional: the VLAN the client should be in (number)")
        ] = "",
        hours: Annotated[str, Field(description="Look-back window in hours")] = "24",
    ) -> str:
        """Troubleshoot one wired or wireless client across Catalyst Center, its switch or WLC, and ISE:
        client 360 and its issues, the port or SSID, live CLI, path trace, ISE authentication history
        and failure reason, Catalyst Center's AAA health for the switch, then a diagnosis (auth
        failure, ISE unreachable or wrong shared secret, wrong VLAN, port or DHCP problem) and a fix
        that is only previewed. Read tier: nothing changes unless the user approves a previewed fix
        with another server's write tools."""
        texts = (client, destination_ip, expected_vlan, hours)
        if any(not ch.isprintable() or ch in '"`' for t in texts for ch in t):
            raise ValueError("Arguments must be printable text without quotes or backticks.")
        who = client.strip()
        if not who:
            raise ValueError("Give the client's MAC, IP or username.")
        try:
            window = float(hours)
        except ValueError as exc:
            raise ValueError(f"hours must be a number, not {hours!r}.") from exc
        if not 0 < window <= 168:
            raise ValueError("hours must be between 0 and 168.")
        dest = destination_ip.strip()
        if dest:
            try:
                dest = str(ipaddress.ip_address(dest))
            except ValueError as exc:
                raise ValueError(f"destination_ip must be an IP address: {exc}") from exc
        vlan = expected_vlan.strip()
        if vlan and not (vlan.isdigit() and 1 <= int(vlan) <= 4094):
            raise ValueError(f"expected_vlan must be a VLAN number, not {vlan!r}.")
        try:
            mac = norm_mac(who)
            find = f'MAC {mac}: {tool_ref("catc_client_360")} with mac "{mac}".'
        except InvalidRequest:  # not a MAC: an IP or a username
            mac = ""
            try:
                ip = str(ipaddress.ip_address(who))
                find = (
                    f'IP {ip}: {tool_ref("catc_find_host")} with ip "{ip}" (hours {window:g}) gives the '
                    f"MAC, switch and port (add search_devices with the site's access switches when "
                    f"Assurance has no record); then {tool_ref('catc_client_360')} with the MAC."
                )
            except ValueError:
                find = (
                    f'username "{who}": {tool_ref("catc_find_host")} with user "{who}" (hours {window:g}) '
                    "gives the MAC, switch, port, VLAN and site of each host that logged in with it; more "
                    f"than one: ask which. Then {tool_ref('catc_client_360')} with its MAC. If none "
                    f'matches, {tool_ref("ise_find_session")} with username "{who}" gives the MAC.'
                )
        mac_ref = f'"{mac}"' if mac else "the client's MAC (step 1)"
        path = (
            f"""4. Path: {tool_ref("catc_path_trace")} from the client's IP to {dest} (wait for the
   result); note where it stops or which ACL/interface drops it."""
            if dest
            else "4. Path: skipped (no destination_ip). If the user names something the client can't reach, "
            f"run {tool_ref('catc_path_trace')} from the client's IP to it."
        )
        vlan_check = (
            f"the access VLAN (or the VLAN ISE assigned) must be {vlan}"
            if vlan
            else "compare the access VLAN with the VLAN ISE's authorization profile assigns (step 5) and "
            "with the other clients on that switch (catc_list_clients by device)"
        )
        return f"""Troubleshoot client {who} (window {window:g} h). Read only: no tool here changes anything,
and any fix at the end is shown as a preview and applied only if the user approves it. If the ise tools are
missing, skip steps 5 and say ISE could not be checked.

1. Find it. {find} Note IP, user, host type, health, connection status, the switch and port (or WLC, AP,
   SSID), VLAN, site, onboarding and DHCP root causes, and last seen. A client Catalyst Center doesn't
   know at all: check the MAC with {tool_ref("ise_get_auth_history")} (it may never get past
   authentication, so Assurance never saw it).
2. Issues: {tool_ref("catc_list_issues")} for the client's switch/WLC and site in the window, and
   {tool_ref("catc_get_issue")} for the relevant ones (suggested commands, root cause). Issues stay active
   for hours after they clear: compare last_seen with now.
3. The device, live: {tool_ref("catc_run_show_commands")} on the switch with
   "show access-session mac <MAC> details" (status, method, policy, dACL, SGT, VLAN),
   "show interfaces <port> status", "show running-config interface <port>",
   "show device-tracking database mac <MAC>" and "show aaa servers | include RADIUS|State|Authen"
   (RADIUS UP? timeouts?); for a wireless client the WLC's "show wireless client mac-address <MAC> detail".
   VLAN: {vlan_check}.
{path}
5. ISE: {tool_ref("ise_get_auth_history")} for {mac_ref} (every attempt: pass/fail, rule, profile, SGT,
   NAD) and on a failure {tool_ref("ise_why_auth_failed")} (decoded reason, steps, fix);
   {tool_ref("ise_endpoint_360")} for its profile and group. No ISE record at all while the switch sends
   RADIUS (step 3) points at the shared secret or the NAD: {tool_ref("ise_get_nad")} with the switch's IP
   (exists, secret set). A wrong shared secret is silent in ISE, and a MAB lookup can still pass with it
   while 802.1X fails, so compare the methods. No ISE record does not prove the request never reached
   ISE: an EAP session the client abandons mid-way (it doesn't trust ISE's EAP certificate, or its
   supplicant is misconfigured) leaves no record either; the switch then shows the session
   Unauthorized with the method still Running and its RADIUS request counter rising without timeouts.
6. AAA health from Catalyst Center: {tool_ref("catc_network_services_health")} with service "aaa", the
   switch as device and hours {window:g}: quote its verdict line (success %, latency, EAP vs MAB failures
   on that switch). It lags the logins by minutes; an empty result right after a failure is not a pass.
7. Diagnosis: one of these, with the evidence for it:
   - authentication failure (ISE has the attempt and a reason: certificate, unknown endpoint, wrong group);
   - ISE not reached or wrong shared secret (no ISE record, RADIUS timeouts or dead on the switch, AAA
     health failures);
   - wrong VLAN or authorization (authenticated, but the VLAN/dACL/SGT differs from what is expected);
   - client side (the supplicant stops mid-EAP: the session is Unauthorized and still Running, no ISE
     record, Catalyst Center shows low health and often a DHCP root cause): fix the supplicant or trust
     ISE's EAP certificate on the client, nothing on the network;
   - port or link (down, err-disabled, no MAC learned) or DHCP (authenticated, no IP; DHCP root cause);
   - path (step 4 stops), or the client looks healthy (say so: nothing to fix on the network).
8. Fix, previewed only: name the change and show its preview without confirming it, e.g. register an unknown
   MAB endpoint ({tool_ref("ise_set_endpoint")}), re-trust the client's CA
   ({tool_ref("ise_list_certificates")} kind trusted), correct the access VLAN with a template
   ({tool_ref("catc_create_template")} then {tool_ref("catc_preview_template")}), or re-authenticate after an
   ISE change ({tool_ref("ise_coa_reauth")}). Apply only if the user approves, then repeat steps 3 and 5 to
   prove it.
9. Summary: the client, the diagnosis in one line, the evidence (one line per step), and the fix (proposed,
   or applied and verified)."""
