# catc_admin_access_via_ise

title: Catalyst Center admin login through ISE
arguments: {"ad_group": "mcp-catc-admins", "ad_user": "mcp-catc-observer1", "catc_ip": "198.18.128.11", "keep_enabled": "false", "mirror_local_accounts": "true", "role": "OBSERVER-ROLE"}

Move Catalyst Center administrator logins onto Active Directory through ISE: an AD group and
user, ISE's NAD for Catalyst Center, an authorization profile returning cisco-av-pair
Role=<role>, a policy set for Catalyst Center's RADIUS logins, then external authentication on,
a local and an AD test login, the ISE auth record, and an undo list. Every write is
preview-first; uses the ise and Windows_Server (win_) servers; dangerous tier.

## user

Move Catalyst Center admin logins onto AD through ISE: members of AD group "mcp-catc-admins" get
OBSERVER-ROLE; prove it with AD user mcp-catc-observer1. Catalyst Center sends RADIUS (PAP) from 198.18.128.11. Every write is
preview-first: show the preview, wait for the user's approval, then repeat the call with the confirm
token. Stop and report on any failure. Run in a quiet window: ask the user to confirm nobody else is
using Catalyst Center while external authentication is on.

1. Preconditions: `catc_get_policy_servers`: an ISE entry must be COMPLETE with
   next_action "none"; if not, stop and name its next_action (the integration must be fixed first).
   `catc_get_external_authentication`: note whether it is already on, the AAA attribute
   (default Cisco-AVPair) and that the ISE node is among its servers; if no server is listed, stop.
   Check that OBSERVER-ROLE is among its roles.
2. Active Directory: `win_list_ad_groups` for "mcp-catc-admins"; create it with
   `win_create_ad_group` if missing. `win_get_ad_user` for mcp-catc-observer1; create
   it with `win_create_ad_user` if missing (the user sets the password) and add it with
   `win_add_group_member`. On ISE: `ise_get_ad_join_point` (joined, its
   name and domain), `ise_list_ad_groups`; if "mcp-catc-admins" isn't selectable yet, add it with
   `ise_add_ad_groups`. `ise_test_ad_user` for mcp-catc-observer1 must list the group.
3. ISE NAD for Catalyst Center: `ise_get_nad` "198.18.128.11". If none, preview
   `ise_create_nad` name "catalyst-center", ips ["198.18.128.11"], with the RADIUS shared secret
   of Catalyst Center's ISE entry (the user enters it: Catalyst Center never returns it). If one
   exists, check it has a RADIUS secret and keep it.
4. Authorization profile: `ise_create_authz_profile` name "mcp-catc-observer", access accept,
   av_pairs=["Cisco:cisco-av-pair=Role=OBSERVER-ROLE"] (the attribute must match step 1's AAA attribute).
5. Break-glass mirror (mirror_local_accounts=true). Catalyst Center 3.2.2 asks ISE first
   (tested): once external authentication is on, a local account only logs in if ISE accepts it with a
   role. List the local accounts with `catc_api_call` GET /dna/system/api/v1/user
   (authSource=internal): their usernames and roleList. Ask the user which are in use (their own
   admin and this server's account at least). The reply must name a BUILT-IN role (SUPER-ADMIN-ROLE,
   NETWORK-ADMIN-ROLE, OBSERVER-ROLE): 3.2.2 refuses a custom role with "Invalid user profile", so map
   an account with a custom role to the nearest built-in one and tell the user what it gains or
   loses (or leave it out: it then can't log in while external authentication is on). For each
   built-in role among them create, preview-first:
   an ISE identity group mcp-catc-mirror-<role> (`ise_create_group`), an authorization
   profile mcp-catc-mirror-<role> (`ise_create_authz_profile` with
   av_pairs=["Cisco:cisco-av-pair=Role=<role>"]), and per account an ISE internal user with the SAME
   name and password in that group (`ise_create_internal_user`; the user types each
   password: never ask for it in chat if they can enter it themselves). The rules come in step 6.
   These users hold copies of local passwords: the undo deletes them.
6. Policy: create policy set "mcp-catc-admin-login" with `ise_create_policy_set`, condition
   "Network Access:Device IP Address equals 198.18.128.11" (the packet's source: the NAS-IP-Address Catalyst
   Center sends is not its own address, tested on 3.2.2), rank 0, allowed protocols that permit
   PAP (Default Network Access). Authentication: an identity source sequence mcp_catc_admins with stores
   Internal Users, then the AD join point
   (`ise_set_identity_sequence`), used by an authentication rule in the set
   (`ise_create_authn_rule`, condition "Network Access:Device IP Address equals 198.18.128.11").
   Authorization (`ise_create_authz_rule`; insert each rule at rank 0, the last one created
   ends up first: ISE refuses a rank that doesn't exist yet): rule mcp-catc-ad with condition
   "<join point>:ExternalGroups equals <domain>/<path>/mcp-catc-admins" (the exact value from step 2) ->
   mcp-catc-observer.
   For each mirror group: rule mcp-catc-mirror-<role> with condition
   "IdentityGroup:Name equals User Identity Groups:mcp-catc-mirror-<role>" -> profile
   mcp-catc-mirror-<role>, ranked above the AD rule (create the AD rule first, then the mirror rules).
   The set's Default rule stays DenyAccess. Review the set with `ise_get_policy_set`.
7. Before enabling: `catc_test_login` with the user's local admin (proves the password
   now; this server keeps its own session for about an hour, which is the undo path). Then
   `catc_set_external_authentication` enable=true: show the preview with its lockout
   warning and apply only after approval.
8. Right after enabling: `catc_test_login` with the local admin again. If it fails, at
   once `catc_set_external_authentication` enable=false (preview, approval) and stop.
9. The AD login: `catc_test_login` with mcp-catc-observer1: it must pass with roles [OBSERVER-ROLE]
   (authSource external). Catalyst Center's logins are bare RADIUS Access-Requests (no accounting,
   no MAC), so ISE's session lists (`ise_get_auth_list`) stay empty: read the hit
   counters instead with `ise_get_policy_set` "mcp-catc-admin-login": the set, the authentication rule
   and mcp-catc-ad must have counted the login; a hit on the set's Default rule means a group or
   condition didn't match (check `ise_test_ad_user`). A local account that now logs in
   with authSource external went through its mirror rule.
10. Summary: what was created where (AD, ISE NAD, profile(s), sequence, policy set, mirror users),
    the login results with the roles granted, the fallback finding from step 9, and the undo list.
11. Switch off (keep_enabled=false): `catc_set_external_authentication`
    enable=false (preview, approval), then `catc_test_login` with the local admin once more.
    Then the undo, each preview-first, in this order: the mirror internal users (they hold copies of
    local passwords) and groups, policy set mcp-catc-admin-login (`ise_delete_object`), profile
    mcp-catc-observer and the mirror profiles, the NAD if step 3 created it (`ise_delete_nad`),
    and the AD user/group if step 2 created them for this proof (ask first).
