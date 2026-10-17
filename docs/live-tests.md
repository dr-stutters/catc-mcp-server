# Live tests

`tests/live` runs the server's tools against a real Catalyst Center:

```bash
uv run pytest tests/live -m live
```

Every live test creates its own `mcp-test-*` objects and removes them again. Nothing here is tied to one lab:
the Catalyst Center comes from the normal `CATC_*` settings, and the lab devices, sites, ISE, WLC, fabric and
PnP inputs come from the `CATC_LIVE_*` variables below. Set them in the environment or in `.env`
(`.env.example` lists them commented out). A test whose variables are unset **skips** and names the missing
variable. With no `.env` at all, the whole live suite skips.

## Catalyst Center and accounts

| Variable | Used by | Meaning |
|---|---|---|
| `CATC_URL`, `CATC_USERNAME`, `CATC_PASSWORD` (or `CATC_TOKEN`) | every live test | The Catalyst Center under test. Tests skip when unset or unreachable. Writes need an account with the `mcp-catc-dangerous` role or SUPER-ADMIN. |
| `CATC_RO_USERNAME`, `CATC_RO_PASSWORD` | `test_least_privilege.py` | An account with the `mcp-catc-ro` role ([least-privilege.md](least-privilege.md)) |
| `CATC_RW_USERNAME`, `CATC_RW_PASSWORD` | `test_least_privilege.py` | An account with the `mcp-catc-rw` role |

## Lab inputs (`CATC_LIVE_*`)

| Variable | Example | Used by | Meaning |
|---|---|---|---|
| `CATC_LIVE_ROUTER1` | `192.0.2.11` | phase2, activity, change window, compliance policy, compliance depth, safety, least privilege | Management IP of a managed, Reachable IOS-XE router |
| `CATC_LIVE_ROUTER2` | `192.0.2.12` | the same | A second router, an OSPF neighbour of router 1 over its `GigabitEthernet2`. The activity test shuts that link and brings it up again. The safety test deletes this router from the inventory and onboards it again. |
| `CATC_LIVE_PATH_TRACE` | `10.255.255.1,10.255.255.2` | phase2 | Optional. `source,dest` for the path trace. Default: router 1 to router 2. |
| `CATC_LIVE_BUILDING` | `Global/Lab/Building1` | least privilege, compliance policy, compliance depth, safety, onboard, AAA, wireless | A building where both routers are assigned and provisioned. Its parent area gets the test compliance policy, and the AAA test creates the building `mcp-test-nac` next to it. |
| `CATC_LIVE_FLOOR` | `Global/Lab/Building1/Floor1` | least privilege, PnP, wireless | A floor in that building |
| `CATC_LIVE_CLIENT_MAC` | `00:00:5e:00:53:01` | least privilege | Optional. A client MAC that Catalyst Center knows, for `catc_get_client` / `catc_client_360`. Without it, those two are skipped. |
| `CATC_LIVE_ONBOARD_SWITCH` | `192.0.2.20` | onboard, AAA | Management IP of a switch **not** in the inventory yet. It must be reachable over SSH/SNMP with the `mcp-test-cli` / `mcp-test-snmp-ro` credentials. The tests discover it, provision it and delete it again. |
| `CATC_LIVE_ISE_IP` | `192.0.2.30` | AAA | ISE PAN with ERS and the pxGrid persona on |
| `CATC_LIVE_ISE_FQDN` | `ise.example.com` | AAA | Its FQDN, as in its certificate |
| `CATC_LIVE_ISE_USERNAME`, `CATC_LIVE_ISE_PASSWORD` | | AAA | ISE admin credentials (integration and ERS NAD lookups) |
| `CATC_LIVE_RADIUS_SECRET` | | AAA | RADIUS shared secret for the integration and site AAA |
| `CATC_LIVE_ISE_CYCLE` | `1` | AAA | Optional. `1` removes an existing ISE integration and rebuilds it through the tools. Otherwise an existing integration is reused. |
| `CATC_LIVE_WLC` | `192.0.2.40` | wireless | Management IP of a Catalyst 9800 WLC (a 9800-CL is enough) that is already discovered |
| `CATC_LIVE_FABRIC_BUILDING` | `Global/Lab/Fabric1` | SD-Access | A building that is not a fabric site yet, with both fabric switches provisioned there |
| `CATC_LIVE_FABRIC_BORDER` | `192.0.2.51` | SD-Access | Switch for the border + control plane roles |
| `CATC_LIVE_FABRIC_EDGE` | `192.0.2.52` | SD-Access | Switch for the edge role |
| `CATC_LIVE_FABRIC_POOL` | `fabric-clients` | SD-Access | An IP pool reserved at the fabric building (anycast gateway) |
| `CATC_LIVE_FABRIC_PORT` | `GigabitEthernet1/0/3` | SD-Access | Optional. The edge port that gets a fabric port assignment (default shown). |
| `CATC_LIVE_PNP_SERIAL` | `9ABCDEF0123` or `auto` | PnP, RMA | Serial of an **Unclaimed** device in Plug and Play. `auto` takes the first Unclaimed C8000V. |
| `CATC_LIVE_DEVICE_USERNAME`, `CATC_LIVE_DEVICE_PASSWORD` | | PnP | CLI credentials that the day-0 template gives the claimed device |
| `CATC_LIVE_SNMP_RO`, `CATC_LIVE_SNMP_RW` | | PnP | SNMP communities for the day-0 template |
| `CATC_LIVE_RMA` | `1` | RMA | `1` runs the RMA test: it marks a device faulty and replaces it with the PnP device |
| `CATC_LIVE_RMA_DEVICE` | `192.0.2.12` | RMA | Optional. The faulty device; it must be Unreachable (powered off). Default: `CATC_LIVE_ROUTER2`. |

## Objects the device tests expect

The router, onboarding and least-privilege tests also use a few objects that must already exist with these
names. Create them once with the server's own tools:

| Object | Tool |
|---|---|
| Global CLI credential `mcp-test-cli` and SNMPv2 communities `mcp-test-snmp-ro` / `mcp-test-snmp-rw` (description = name) that reach your devices | `catc_create_global_credential` |
| Template project `mcp-test-dayn` with committed templates `mcp-test-loopback` (Routers: `interface Loopback{{ loop_id }}` / `description {{ desc }}` / `ip address {{ ip }} 255.255.255.255`) and `mcp-test-cdp` (Routers) | `catc_create_template_project`, `catc_create_template`, `catc_commit_template` |
| Switching profile `mcp-test-sw-profile` | `catc_create_switching_profile` |
| Discovery `mcp-test-disc-routers` that found the two routers | `catc_create_discovery` |

The suite's own lab seeds all of this with a script kept in the private lab repo (stutters-mcp-lab).

## Notes

- The SD-Access test skips when Catalyst Center refuses fabric sites because the SD-Access application isn't
  running (NCSP11008). `catc_status` shows it in `catc.sda`: the optional `sda` and `aca` packages must be
  DEPLOYED, not SKIPPED (System > Software Management).
- SWIM distribute/activate are covered by mocked unit tests only.
- [pnp.md](pnp.md) covers what PnP needs on CML (DHCP option 43, the day-0 workaround).
