# suite_change_check

title: Change check across products (pre/post)
arguments: {"before": "", "change": "shut an access port on mcp-sw1", "expected": "mcp-banner", "phase": "pre", "servers": "catc,ise", "site": "Global/mcp-test-lab/mcp-test-bldg"}

Did anything else break? Snapshot every connected product before a change (phase=pre), then compare
after it (phase=post): SD-WAN overlay, ISE authentication, Catalyst Center health and the firewalls, one
report of what changed by severity, expected effects apart, and configuration objects that changed
outside the change (snapshot config sections). Skips the products whose server is not connected and says
so. Read-only: the snapshots are kept in the conversation, never on a server.

## user

This suite workflow uses these servers: ise (Cisco ISE), catc (Catalyst Center), catsdwan (Catalyst SD-WAN Manager), fmc (Secure Firewall Management Center).
Skipped legs (server not connected); say so in the first lines of your answer:
- catsdwan leg skipped: server not connected; not checked: the SD-WAN overlay (BFD sessions, OMP peers, app-route SLA, control connections, alarms).
- fmc leg skipped: server not connected; not checked: the firewalls (deployment state, HA, interface and VPN status).

Change check, phase pre: baseline snapshots before the change (shut an access port on mcp-sw1).

1. Call `ise_snapshot` with site="Global/mcp-test-lab/mcp-test-bldg". Keep the blob it returns exactly as returned: it is the ise 'before' for the post phase.
2. Call `catc_snapshot` with site="Global/mcp-test-lab/mcp-test-bldg". Keep the blob it returns exactly as returned: it is the catc 'before' for the post phase.
3. Summarise the baseline in two or three lines per product, listing anything already unhealthy (the change did not cause it). Do not paste the blobs into the summary.
4. Tell the user to make the change, then run suite_change_check with phase=post in this conversation (or pass the blobs as `before` in a new one).
