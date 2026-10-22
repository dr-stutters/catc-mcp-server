# catc_group_policy_rollout

title: Roll out and prove a group-based policy
arguments: {"client_ips": "10.10.40.100, 10.10.40.101", "destination_group": "Production_Servers", "edge": "mcp-catc-fab-edge1", "policy": "deny", "source_group": "Contractors"}

Change one cell of ISE's TrustSec matrix and prove a Catalyst Center-managed edge enforces it:
the groups, the current cell in ISE and on the edge, the change (previewed, applied only on the
user's approval), the push, the edge's downloaded cell, the clients' SGTs, a test flow and the
counters. ISE stays the policy owner; Catalyst Center verifies. It never starts Catalyst Center's
group-based policy migration.

## user

Roll out "Deny IP" from Contractors to Production_Servers and prove mcp-catc-fab-edge1 enforces it. ISE owns the policy;
Catalyst Center only verifies. Every write below is a preview first: show it and apply it only when the user
approves it. Never start Catalyst Center's group-based policy migration (Policy > Group-Based Access Control):
it hands ISE's matrix to Catalyst Center and makes ISE's TrustSec objects read-only, which is the user's
decision alone. If the ise tools are missing, stop after step 2 and say the change has to be made in ISE.

1. Groups: `ise_list_sgts`: Contractors and Production_Servers exist (name and tag)? If one is missing, preview
   `ise_set_sgt` for it (in a lab, prefix new names with mcp-). `ise_list_sgacls`:
   "Deny IP" exists (Deny IP and Permit IP are built in).
2. Before: `ise_get_egress_matrix` with source Contractors and destination Production_Servers (ISE's cell, or the
   default), then `catc_get_group_policy_enforcement` with device mcp-catc-fab-edge1, source Contractors,
   destination Production_Servers, ips ["10.10.40.100", "10.10.40.101"]: the edge's environment data (COMPLETE? the ISE server listed?), whether
   'cts role-based enforcement' is configured, the cell it has now, and the clients' SGTs. Environment data
   not COMPLETE or no enforcement: fix that first (the switch is not a TrustSec device of ISE yet, or
   Catalyst Center has not provisioned it into the fabric), no matrix change will show. On a fabric edge the
   usual cause is RADIUS: `catc_run_show_commands` "show aaa servers" shows the ISE server DEAD
   when ISE has no route back to the edge's Loopback0 (the RLOC, which fabric provisioning makes the RADIUS
   source and the NAD's address). After that route is fixed the switch keeps the server DEAD until its
   automate-tester probe gets an answer (minutes); the environment data downloads after that.
3. Change: preview `ise_set_egress_policy` with source Contractors, destination Production_Servers, sgacls
   ["Deny IP"]; show the preview and apply it only on approval. Then preview
   `ise_push_trustsec_matrix` (sends a CoA so devices fetch the change now instead of at the
   next refresh) and apply it on approval.
4. Clients: each client's session must carry its group. `ise_find_session` with each client's IP
   or MAC shows the SGT ISE assigned. A client without the right SGT: the authorization rule it hits needs
   that security group in its result (preview `ise_update_policy_rule`), then re-authenticate it
   (preview `ise_coa_reauth`).
5. Edge after: `catc_get_group_policy_enforcement` again (same arguments). The pair's policy must
   be "Deny IP" with source_of_policy "cell downloaded from ISE", and each client IP bound to its SGT. An
   SD-Access edge keeps the clients' bindings in their VN's VRF ("show cts role-based sgt-map vrf <VN> all";
   the global table only has the switch's own addresses): the tool reads the VRFs too (the first 4; pass
   vrfs ["<VN>"] on a switch with more) and each binding shows its vrf. Not there yet: the push may still be
   running; wait a minute and read again (at most three times), then compare the edge's group name table
   with ISE's.
6. Test flow from 10.10.40.100 to 10.10.40.101: run it from the client (ping or a TCP connect; on a CML lab, the cml server's command
   tool runs it on the client node), then read the counters with
   `catc_get_group_policy_enforcement`: the pair's denied (deny) or permitted (permit) counters
   must have moved. Simulated switches (cat9000v): an SGACL with 'log' can crash the dataplane, and routed
   traffic out of the uplink is not counted; prove it between two clients on the same edge and subnet.
7. Summary: the cell before and after in ISE and on the edge, the clients' SGTs, the flow result with the
   counters, and the undo (preview only, not applied): `ise_set_egress_policy` back to the step 2
   cell, then `ise_push_trustsec_matrix`.
