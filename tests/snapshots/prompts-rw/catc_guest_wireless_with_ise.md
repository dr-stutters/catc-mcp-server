# catc_guest_wireless_with_ise

title: Guest wireless with ISE central web auth
arguments: {"guest_type": "Daily (default)", "keep": "false", "policy_set": "", "portal": "Sponsored Guest Portal (default)", "redirect_acl": "ACL_WEBAUTH_REDIRECT", "site": "Global/mcp-test-lab/mcp-test-bldg/Floor 1", "sponsor_group": "mcp-guest-sponsors", "ssid": "mcp-guest", "wlc": "mcp-catc-wlc"}

Guest Wi-Fi with ISE central web auth (CWA), the validated campus design: the ISE half (guest
type, sponsor group, portal, a CWA redirect authorization profile and the MAB redirect / Guest Flow
permit rules) joined to the Catalyst Center half (a Guest web-auth SSID with ISE as the auth server,
MAC filtering, AAA override and the redirect ACL, a wireless profile at the AP location, WLC
provisioning), then the WLC's intended-vs-deployed diff, a 9800 CLI check, ISE's policy explain
and an undo list. Every write is preview-first; uses the ise server; dangerous tier (provisioning).

## user

Build guest Wi-Fi with ISE central web auth (CWA): SSID "mcp-guest" at Global/mcp-test-lab/mcp-test-bldg/Floor 1 on WLC
mcp-catc-wlc; the redirect sends unknown guests to ISE portal "Sponsored Guest Portal (default)" through redirect ACL ACL_WEBAUTH_REDIRECT;
sponsors create "Daily (default)" accounts. Every write is preview-first: show the preview, wait for the user's
approval, then repeat the call with the confirm token. Stop and report on any failure. The flow (Cisco ISE
guest access prescriptive deployment guide, CWA with Catalyst 9800): the guest associates to an open SSID,
the WLC sends MAB to ISE, ISE answers with a redirect URL and ACL, the guest logs in on the portal, ISE
sends a CoA and the second MAB matches Guest Flow and is permitted.

1. Preconditions. Catalyst Center: `catc_get_policy_servers`: an ISE entry COMPLETE with
   next_action "none" (note its PSN address: the ACL in step 6 needs it).
   `catc_get_site_settings` for "Global/mcp-test-lab/mcp-test-bldg/Floor 1": client AAA (wireless) must point at that ISE; if
   not, stop and name the fix (`catc_update_site_aaa_settings`).
   `catc_get_wireless_controller` "mcp-catc-wlc": a Catalyst 9800 that Catalyst Center provisions
   site-based (per-device configuration off; with it on, use `catc_set_wlan_security`
   instead and stop here); note its building and managed AP locations.
   ISE: `ise_status` (ERS up); `ise_get_nad` for the WLC's management IP (a NAD
   with a RADIUS secret, usually created by Catalyst Center's provisioning; without it stop). Then
   `ise_policy_explain` with nad="mcp-catc-wlc" and flow="wireless-mab": the set it selects is
   where the guest rules go, and its authentication rule for MAB must have if_user_not_found CONTINUE
   (read it with `ise_get_policy_set`): otherwise ISE rejects the unknown guest MAC before
   any redirect.
2. ISE guest objects. `ise_list_guest_types`: "Daily (default)" exists (else ask: create it with
   `ise_set_guest_type` or pick another). `ise_list_sponsor_groups`: sponsor group "mcp-guest-sponsors" must list "Daily (default)"
   among its guest types: if it doesn't (or doesn't exist), preview `ise_set_sponsor_group`
   name "mcp-guest-sponsors" adding guest_types ["Daily (default)"] and keep its member groups.
   `ise_list_guest_portals`: "Sponsored Guest Portal (default)" exists and is a sponsored-guest or
   self-registration portal; note which guest types it allows.
3. CWA authorization profile: `ise_create_authz_profile` name "mcp-guest-cwa", access
   ACCESS_ACCEPT, redirect {type: CentralizedWebAuth, acl: ACL_WEBAUTH_REDIRECT, portal: Sponsored Guest Portal (default)}. The preview
   names the portal as ISE spells it and warns that the ACL must exist on the WLC (step 6).
4. Authorization rules in the policy set step 1 found (`ise_create_authz_rule`; insert each at rank 0, so the
   last one created ends up first):
   a. "mcp-guest-redirect": conditions ["Wireless_MAB", "Radius:Called-Station-ID endsWith :mcp-guest"],
      profiles ["mcp-guest-cwa"].
   b. "mcp-guest-permit": conditions ["Guest_Flow", "Radius:Called-Station-ID endsWith :mcp-guest"],
      profiles ["PermitAccess"] (a guest VLAN or dACL profile instead, if the user has one). Created
      second, it sits above the redirect rule: after the portal login the CoA'd session matches Guest
      Flow first.
   Read the set back with `ise_get_policy_set`.
5. The SSID: `catc_create_ssid` ssid="mcp-guest", security="OPEN", guest=true,
   l3_auth="web_auth", auth_server="auth_ise", mac_filtering=true, aaa_override=true,
   pre_auth_acl="ACL_WEBAUTH_REDIRECT" (site Global, so the wireless profile can carry it). The preview must show
   l3AuthType web_auth, authServer auth_ise, isMacFilteringEnabled, aaaOverride and aclName ACL_WEBAUTH_REDIRECT, and no
   warning about MAC filtering or AAA override. Then `catc_create_wireless_profile` name
   "mcp-guest-wireless", ssids ["mcp-guest"]; `catc_assign_profile_to_sites` "mcp-guest-wireless" to ["Global/mcp-test-lab/mcp-test-bldg/Floor 1"];
   if the WLC is not at a building yet, `catc_assign_devices_to_site` (the WLC to the
   building above Global/mcp-test-lab/mcp-test-bldg/Floor 1).
6. The redirect ACL. `catc_run_show_commands` on mcp-catc-wlc: "show ip access-lists ACL_WEBAUTH_REDIRECT".
   Catalyst Center sends only the ACL name. If the ACL is missing, offer it as a Day-N template on the
   WLC (`catc_create_template` -> `catc_commit_template` ->
   `catc_deploy_template`) with the guide's entries (deny = no redirect): deny udp any any eq
   domain, deny udp any eq domain any, deny udp any any eq bootps, deny ip any host <PSN>, deny ip host
   <PSN> any, permit tcp any any eq www, permit tcp any any eq 443 (the ISE portal on port 8443 stays
   reachable because traffic to the PSN is never redirected).
7. Provision: `catc_provision_wireless_controller` device "mcp-catc-wlc" with its managed AP
   locations (step 1's list plus Global/mcp-test-lab/mcp-test-bldg/Floor 1 if missing). Show the preview (it pushes the WLAN, policy profile
   and tags of every profile at those locations) and wait for approval.
8. Read back: `catc_get_wireless_controller` "mcp-catc-wlc": provisioning succeeded and "mcp-guest"
   is among its SSIDs, admin up and managed. `catc_get_wlc_config` wlc="mcp-catc-wlc" diff=true:
   a WLC with per-device configuration models shows the wlan_profiles record "mcp-guest_profile" and its policy
   profile in sync; a site-based WLC has no such models (the tool says so), and then step 9's CLI is
   the proof.
9. 9800 CLI (`catc_run_show_commands` on mcp-catc-wlc): "show wlan name mcp-guest_profile" (Security: MAC
   Filtering on with the ISE authorization list, no 802.1X, no web auth on the WLAN itself); "show
   wireless profile policy detailed mcp-guest_profile" (AAA Override and NAC (RADIUS NAC) enabled, the accounting
   list); "show running-config | section dynamic-author" (ISE as a CoA client: without it the portal
   login never re-authorizes the guest).
10. ISE side proof: `ise_policy_explain` nad="mcp-catc-wlc", flow="wireless-mab", attributes
    {"Radius:Called-Station-ID": "aa-bb-cc-dd-ee-ff:mcp-guest"}: it must hit mcp-guest-redirect with
    profile mcp-guest-cwa; adding "Network Access:UseCase": "Guest Flow" must hit mcp-guest-permit. No AP in a
    lab means no real guest: say so instead of claiming an end-to-end login. Summary: what was created
    where (ISE profile and rules, sponsor change, SSID, wireless profile and site, ACL, provisioning),
    the CLI findings and the undo list.
11. Undo (keep=false), each preview-first and applied only on approval, in this order:
    `catc_unassign_profile_from_sites` "mcp-guest-wireless" from ["Global/mcp-test-lab/mcp-test-bldg/Floor 1"], then
    `catc_provision_wireless_controller` again with the same managed AP locations (the WLAN and
    its policy profile leave the WLC), `catc_delete_wireless_profile` "mcp-guest-wireless",
    `catc_delete_ssid` "mcp-guest", the ACL template if step 6 deployed one (a negation template:
    'no ip access-list extended ACL_WEBAUTH_REDIRECT'), then on ISE `ise_delete_policy_rule` for
    mcp-guest-permit and mcp-guest-redirect, `ise_delete_object` kind authz_profile
    "mcp-guest-cwa", and the sponsor group change from step 2 if it made one (put the guest types back). Re-read
    with `catc_get_wireless_controller` and `ise_get_policy_set`: nothing named
    mcp-guest is left.
