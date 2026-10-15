"""Print the cml_configure_node arguments that (re)create the PnP DHCP server of CML lab mcp-catc-pnp (D11/D23).

    uv run python scripts/pnp_dhcp.py [--catc 198.18.128.11]     # JSON for cml_configure_node
    # lab rebuild (rebuild-lab.sh, CatC extras):
    mc_soft cml cml_configure_node "$(uv run -q python scripts/pnp_dhcp.py)" --yes

The Alpine node `dhcp` (198.18.128.171, static) runs busybox udhcpd with exactly one lease, 198.18.128.172 for
pnp1's MAC 52:54:00:cd:30:df (pinned in the lab export), and DHCP option 43 pointing PnP at Catalyst Center:
'5A1D;B2;K4;I<catc ip>;J80' (5A = PnP, 1D = version, B2 = IPv4, K4 = HTTP, I = server, J = port). The config
lives on the node's disk but udhcpd isn't started at boot, and a rebuilt lab has neither: hence this step.
docs/pnp.md explains the PnP findings.
"""

from __future__ import annotations

import argparse
import json

PNP1_MAC = "52:54:00:cd:30:df"
LEASE_IP = "198.18.128.172"


def option43(catc_ip: str, port: int = 80) -> str:
    """Option 43 as busybox udhcpd wants it: the ASCII string, hex-encoded."""
    return f"5A1D;B2;K4;I{catc_ip};J{port}".encode().hex()


def conf(catc_ip: str) -> list[str]:
    return [
        f"start {LEASE_IP}",
        f"end {LEASE_IP}",
        "max_leases 1",
        "interface eth0",
        "lease_file /tmp/udhcpd.leases",
        f"static_lease {PNP1_MAC} {LEASE_IP}",
        "opt subnet 255.255.192.0",
        "opt router 198.18.128.1",
        "opt dns 198.18.133.1",
        "opt domain mcp.lab",
        "opt lease 3600",
        f"opt 43 {option43(catc_ip)}",
    ]


def lines(catc_ip: str) -> list[str]:
    body = "\\n".join(conf(catc_ip))
    return [
        f"printf '{body}\\n' | sudo tee /etc/udhcpd.conf >/dev/null",
        "sudo pkill udhcpc; sudo pkill udhcpd; sudo touch /tmp/udhcpd.leases",
        "sudo udhcpd /etc/udhcpd.conf && pgrep -l udhcpd",
    ]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--catc", default="198.18.128.11", help="Catalyst Center IP for option 43")
    a = ap.parse_args()
    print(json.dumps({"lab": "mcp-catc-pnp", "node": "dhcp", "mode": "exec", "lines": lines(a.catc)}))


if __name__ == "__main__":
    main()
