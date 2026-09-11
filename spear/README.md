# Spear — internal network assessment

Spear is DREAD's internal (LAN-side) product. It brings together capabilities
that usually mean juggling several separate tools:

| Capability | Comparable tool | Spear command |
|---|---|---|
| Host discovery + service enumeration | nmap host/port sweep | `spear scan <cidr>` |
| Name-resolution poisoning exposure | the *defensive inverse* of Responder | `spear poison-watch` |
| LAN interaction mapping + hardening | flow analysis | `spear monitor --from-file <flows.json>` |

> Use only on networks you own or are explicitly authorized to assess. `spear scan`
> targets private ranges by default and refuses public ranges unless `--allow-public`
> is given.

## Commands

```bash
# Discover live hosts and their services on a subnet (private ranges by default)
python spear/spear.py scan 192.168.1.0/24
python spear/spear.py scan 10.0.0.1-10.0.0.50 --json

# Passively watch for name-resolution poisoning exposure (LLMNR / NBT-NS).
# Never answers a query and never captures credentials — it reports which hosts
# are making poisonable lookups so you can disable LLMNR/NBT-NS. Needs privileges
# to bind UDP/137.
sudo python spear/spear.py poison-watch --duration 120

# Map observed LAN interactions and flag hardening issues (cleartext protocols,
# external egress). Feed it a JSON list of {src_ip, dst_ip, dst_port, protocol}.
python spear/spear.py monitor --from-file flows.json
```

Also available through the unified CLI: `python dread.py spear <command>`.

## Design

Network I/O (host liveness, TCP banners, packet capture) is injected into the
analysis classes, so the logic is unit-tested without touching the network and the
transport can be swapped (raw sockets, an external scanner, a live capture). The
poisoning monitor and LAN monitor are strictly **passive and defensive**: they
observe and report, they never poison, answer, or attack.

Findings are shaped like the rest of DREAD (severity, title, description,
remediation, affected hosts) so they can flow into Reports and DreadAI alongside
Probe and Scope results.
