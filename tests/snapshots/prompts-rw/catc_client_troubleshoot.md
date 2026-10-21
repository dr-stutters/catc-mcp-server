# catc_client_troubleshoot

title: Troubleshoot a client
arguments: {"client": "52:54:00:62:c6:b2", "destination_ip": "198.18.133.1", "expected_vlan": "10", "hours": "4"}

Troubleshoot one wired or wireless client across Catalyst Center, its switch or WLC, and ISE:
client 360 and its issues, the port or SSID, live CLI, path trace, ISE authentication history
and failure reason, Catalyst Center's AAA health for the switch, then a diagnosis (auth
failure, ISE unreachable or wrong shared secret, wrong VLAN, port or DHCP problem) and a fix
that is only previewed. Read tier: nothing changes unless the user approves a previewed fix
with another server's write tools.

## user

Troubleshoot client 52:54:00:62:c6:b2 (window 4 h). Read only: no tool here changes anything,
and any fix at the end is shown as a preview and applied only if the user approves it. If the ise tools are
missing, skip steps 5 and say ISE could not be checked.

1. Find it. MAC 52:54:00:62:c6:b2: `catc_client_360` with mac "52:54:00:62:c6:b2". Note IP, user, host type, health, connection status, the switch and port (or WLC, AP,
   SSID), VLAN, site, onboarding and DHCP root causes, and last seen. A client Catalyst Center doesn't
   know at all: check the MAC with `ise_get_auth_history` (it may never get past
   authentication, so Assurance never saw it).
2. Issues: `catc_list_issues` for the client's switch/WLC and site in the window, and
   `catc_get_issue` for the relevant ones (suggested commands, root cause). Issues stay active
   for hours after they clear: compare last_seen with now.
3. The device, live: `catc_run_show_commands` on the switch with
   "show access-session mac <MAC> details" (status, method, policy, dACL, SGT, VLAN),
   "show interfaces <port> status", "show running-config interface <port>",
   "show device-tracking database mac <MAC>" and "show aaa servers | include RADIUS|State|Authen"
   (RADIUS UP? timeouts?); for a wireless client the WLC's "show wireless client mac-address <MAC> detail".
   VLAN: the access VLAN (or the VLAN ISE assigned) must be 10.
4. Path: `catc_path_trace` from the client's IP to 198.18.133.1 (wait for the
   result); note where it stops or which ACL/interface drops it.
5. ISE: `ise_get_auth_history` for "52:54:00:62:c6:b2" (every attempt: pass/fail, rule, profile, SGT,
   NAD) and on a failure `ise_why_auth_failed` (decoded reason, steps, fix);
   `ise_endpoint_360` for its profile and group. No ISE record at all while the switch sends
   RADIUS (step 3) points at the shared secret or the NAD: `ise_get_nad` with the switch's IP
   (exists, secret set). A wrong shared secret is silent in ISE, and a MAB lookup can still pass with it
   while 802.1X fails, so compare the methods. No ISE record does not prove the request never reached
   ISE: an EAP session the client abandons mid-way (it doesn't trust ISE's EAP certificate, or its
   supplicant is misconfigured) leaves no record either; the switch then shows the session
   Unauthorized with the method still Running and its RADIUS request counter rising without timeouts.
6. AAA health from Catalyst Center: `catc_network_services_health` with service "aaa", the
   switch as device and hours 4: quote its verdict line (success %, latency, EAP vs MAB failures
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
   MAB endpoint (`ise_set_endpoint`), re-trust the client's CA
   (`ise_list_certificates` kind trusted), correct the access VLAN with a template
   (`catc_create_template` then `catc_preview_template`), or re-authenticate after an
   ISE change (`ise_coa_reauth`). Apply only if the user approves, then repeat steps 3 and 5 to
   prove it.
9. Summary: the client, the diagnosis in one line, the evidence (one line per step), and the fix (proposed,
   or applied and verified).
