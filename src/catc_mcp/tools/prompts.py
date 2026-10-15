"""Workflow prompts owned by this server (core `@reg.prompt`, BUILDING-A-SERVER §5a)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import Field
from stutters_mcp_core import Tier, ToolRegistrar, tool_ref

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
   TRUSTED and the integration COMPLETE. If none, it has to be added with
   {tool_ref("catc_add_ise_server")} (ISE PAN IP/FQDN, a super-admin login, a RADIUS shared secret;
   suggest the user enters the secrets themselves rather than pasting them into the chat); when it
   stops at WAITING_USER_INPUT show the certificate fingerprints and, after the user confirms them,
   {tool_ref("catc_accept_ise_certificate")}. ISE needs ERS and the pxGrid persona. Both tools are
   dangerous tier: if they are missing here, stop and say ISE must be integrated first.
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
4. Provision: {tool_ref("catc_provision_devices")} with devices ["{switch_ip}"] and site
   "{site_path}". This pushes the AAA/RADIUS config pointing at ISE and creates the switch as a
   NAD in ISE. (Dangerous tier; if it isn't available, stop and say so.)
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
