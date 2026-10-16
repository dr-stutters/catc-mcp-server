# PnP and RMA in the lab: what works and what bites

Tools: `catc_list_pnp_devices`, `catc_claim_pnp_device`, `catc_reset_pnp_device`, `catc_delete_pnp_device`,
`catc_list_device_replacements`, `catc_mark_device_for_replacement`, `catc_replace_device`. Tested on Catalyst
Center 3.2.2-75131 with CML lab `mcp-catc-pnp` (`tests/live/test_live_pnp.py`).

## The lab

| Node | What | Address |
|---|---|---|
| `dhcp` (Alpine) | busybox `udhcpd`, one lease for pnp1's MAC, option 43 → Catalyst Center | 192.0.2.2 (static) |
| `pnp1` (cat8000v, empty day-0) | the device that onboards through PnP | DHCP 192.0.2.100 |
| `mgmt-sw`, `ext` | unmanaged switch, bridge to the management network (192.0.2.0/24 here) | |

The DHCP server is runtime state: the config file survives a lab stop/start on the node's disk, but `udhcpd` isn't
started at boot, and a rebuilt lab has neither. Configure it from the node's console (CML: `cml_configure_node`
with `mode="exec"`): write `/etc/udhcpd.conf` and start `udhcpd`:

```text
start 192.0.2.100
end 192.0.2.100
max_leases 1
interface eth0
static_lease <pnp1 MAC> 192.0.2.100
opt subnet 255.255.255.0
opt router <gateway>
opt 43 <option 43, hex-encoded: see below>
```

```bash
sudo udhcpd /etc/udhcpd.conf && pgrep -l udhcpd
```

The suite's own lab rebuild generates this step with a script kept in the private lab repo (stutters-mcp-lab).

### DHCP option 43

`5A1D;B2;K4;I192.0.2.10;J80` (Catalyst Center at 192.0.2.10): `5A` PnP, `1D` version, `B2` IPv4, `K4` HTTP transport, `I` server (the Catalyst
Center IP), `J` port. busybox udhcpd wants the string hex-encoded: `opt 43 354131443b...`
(`"5A1D;B2;K4;I<ip>;J80".encode().hex()` in Python). Only pnp1's MAC (pinned in the lab export) gets a lease
(`start` = `end`, `static_lease`), so the other lab devices on the bridge are never offered PnP.

## Findings

- **CML's day-0 CD suppresses autoinstall on cat8000v.** Even with an empty day-0 config the router logs
  `autoinstall ... Reason:12` and never asks DHCP for option 43, and the BOOTP lease it does get carries no usable
  mask. Workaround on the console (what the live test expects to be in place):
  ```text
  pnp profile pnp-zero-touch
   transport http ipv4 192.0.2.10 port 80
  interface GigabitEthernet1
   ip address dhcp
  ```
  The device then shows as **Unclaimed** in `catc_list_pnp_devices` within a minute or two.
- **A wiped pnp1 left at the setup dialog** ("Enter enable secret:") registers by itself, but the claim hangs at
  Planned/Connecting with `NCOB02066` (certificate/TLS). Answer the dialog (no), apply the profile above, then claim.
- **`hostname` is a blacklisted template command** (NCTP10081): give the hostname as the claim's `hostname`
  parameter, not in the day-0 template.
- Claimed with an *Onboarding Configuration* day-0 template (template variables as claim params) the device goes
  Provisioned → Managed at the claim site. Deleting the claimed device (`catc_delete_device`) also removes its PnP
  entry.
- The PnP list's `state` filter is the onboarding state (`Unclaimed`, `Planned`, `Onboarding`, `Provisioned`,
  `Error`).

## RMA depends on SWIM

`catc_mark_device_for_replacement` is refused with **NCRM11042** ("device image is not in the SWIM repository"):
Catalyst Center needs the faulty device's running image in the image repository to install it on the
replacement. Without a SWIM-importable `.bin` (roadmap D12: CML images boot `packages.conf`, nothing on
cisco.com may be downloaded overnight) the RMA tools are mock-tested only; their previews state the blocker.
After importing the image: mark r2 faulty → boot a blank cat8000v with r2's PID through PnP → `catc_replace_device`
→ check that the archived running config arrived (`CATC_LIVE_RMA=1 uv run pytest tests/live/test_live_pnp.py`).
