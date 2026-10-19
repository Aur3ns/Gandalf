# Gandalf — Linux IPv4 firewall lab

Gandalf is a small **Python IPv4 packet-filtering experiment** using Linux Netfilter Queue (NFQUEUE). It can block selected source IPs/networks and destination TCP/UDP ports, rate-limit incoming ICMP echo requests, optionally flag passive ARP address-mapping changes, and log network-interface counters. It is intended for **controlled Linux lab environments**, not as a drop-in production firewall.

> **Safety:** Gandalf does **not** change iptables, nftables, or operating-system firewall rules automatically. Only run `--live` in a disposable VM or on a console-accessible machine, never as an untested change over SSH. The default sample `firewallrules.json` contains *real deny rules* (including TCP/UDP ports 80 and 81 and `172.0.0.0/8`); tailor them to your lab before routing traffic into NFQUEUE.

## What changed in the revival

The original project was created in 2023 but had an invalid hard-coded Fernet key, a half-implemented TCP administration service, a nonexistent `firewall.py` entry point in the README, fragile ARP-check logic and a string-valued boolean in its JSON config. These have been replaced with a focused IPv4 filtering engine with a pure-Python test layer.

- **Readable, validated JSON policy:** source IPv4 addresses, IPv4 CIDR networks (not string prefixes), TCP/UDP destination ports, ICMP echo-rate limit and an optional fragment restriction.
- **Deterministic unit tests and an offline simulation mode** work without `sudo`, iptables, Scapy or NetfilterQueue.
- **Opt-in live filtering** binds to a named Linux NFQUEUE (`--live --queue-num 1`). The queue's kernel rule is *always* managed separately by the operator.
- **Optional passive ARP monitoring** with Scapy (`--arp-interface`); a changed IP-to-MAC mapping is a **lead for investigation**, not conclusive spoofing detection.
- **Optional network statistics** via psutil (`--monitor-stats`) and rotating log files via `--log-file`.
- **No remote admin listener or hard-coded password.** Both were unrelated to the packet-filtering verdicts, and the old listener referred to missing functions.

## Supported scope and limitations

| Property | Behavior |
|---|---|
| OS | Linux only for live mode (with libnetfilter_queue / kernel NFQUEUE). Offline checks work wherever Python runs. |
| Protocol | **IPv4 only**. Does not inspect or secure IPv6. A normal `iptables` IPv4 rule does not apply to IPv6 traffic. |
| Hooks | Whatever IPv4 packets the operator selects in iptables. The examples use **INPUT** only. FORWARD and OUTPUT traffic are not included unless routed separately. |
| TCP/UDP | Destination port filter only. No TCP connection tracking, application parsing or deep packet inspection. |
| Fragmentation | `BlockIPv4Fragments: true` drops all fragmented IPv4 packets that reach the queue, limiting port-filter bypasses but potentially disrupting legitimate traffic. Set `false` only after understanding that later fragments cannot be checked for TCP/UDP ports. |
| ICMP | Sliding-window rate limiting of **echo requests** (`type=8, code=0`) by source IPv4 address. It is not a comprehensive DoS defense or a distributed flood detector. |
| ARP | Passive watcher on a local interface. ARP is not IPv4 data inside NFQUEUE; this mode reports suspicious mapping changes only, including legitimate changes. |
| Performance | Python/userspace packet processing, not suitable for high-throughput production appliances without dedicated testing. |

## Quick start: offline validation (recommended first)

Python **3.10+** is sufficient for policy checks, simulations, and tests. No third-party dependencies or root privileges are needed for these commands.

```bash
git clone https://github.com/Aur3ns/Gandalf.git
cd Gandalf
python3 gandalf.py --check-config
python3 -m unittest discover -s tests -v
```

To try the filter against a JSONL example with no live traffic:

```bash
cat > /tmp/gandalf-packets.jsonl <<'JSONL'
{"src":"192.168.43.181","dst":"192.168.43.1","protocol":"tcp","dport":443}
{"src":"10.0.0.5","dst":"192.168.43.1","protocol":"udp","dport":80}
{"src":"10.0.0.5","dst":"192.168.43.1","protocol":"tcp","dport":443}
JSONL
python3 gandalf.py --simulate /tmp/gandalf-packets.jsonl
```

Expected verdicts: `DROP` (source address), `DROP` (destination port), `ACCEPT` (no deny match).

## Configure the rules

Edit `firewallrules.json`:

```json
{
  "ListOfBannedIpAddr": ["192.168.43.181", "192.168.43.182"],
  "ListOfBannedPorts": [80, 81],
  "ListOfBannedPrefixes": ["172.0.0.0/8"],
  "TimeThreshold": 10,
  "PacketThreshold": 100,
  "BlockPingAttacks": true,
  "BlockIPv4Fragments": true
}
```

`ListOfBannedPrefixes` accepts **CIDR notation**: for example, `192.168.2.0/24`, not string fragments like `"172."`. `BlockPingAttacks` and `BlockIPv4Fragments` must be JSON booleans (`true`/`false`), **not** strings like `"True"`. Invalid or missing configuration causes Gandalf to **exit without binding a queue**.

The included rules are carried over from the project's original intended blocks. They are **examples, not safe defaults for every network**. Remove the sample restrictions before using the tool in another environment. Each ICMP echo is allowed until the source sends `PacketThreshold` echoes within `TimeThreshold` seconds; further echoes in that window are dropped.

## Live filtering on Debian / Ubuntu (disposable VM only)

### 1. Install prerequisites

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev libnetfilter-queue-dev iptables python3-venv
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` includes optional Scapy and psutil helpers as well as the NetfilterQueue binding. **Only NetfilterQueue is required** for basic live filtering.

### 2. Prepare a safe rollback path

Keep access to the machine's VM console. Check your existing firewall with `sudo iptables -S INPUT` and ensure queue 1 is not in use. Replace `eth0` below with your *actual* test interface (find it with `ip -brief link`). Don't run an untested firewall change over SSH.

In terminal A, **start the listener first**:

```bash
sudo .venv/bin/python gandalf.py --live --queue-num 1
```

In terminal B, install an explicit IPv4 INPUT hook, restricted to the chosen interface:

```bash
sudo iptables -I INPUT 1 -i eth0 -j NFQUEUE --queue-num 1 --queue-bypass
```

`--queue-bypass` means packets pass through this rule when no userspace listener is bound. **This is a fail-open recovery feature, not guaranteed protection if Gandalf stops.** While Gandalf is listening, dropped packets remain dropped.

To remove **exactly that hook**, from terminal B:

```bash
sudo iptables -D INPUT -i eth0 -j NFQUEUE --queue-num 1 --queue-bypass
```

Then stop Gandalf with Ctrl+C in terminal A. The program unbinds its NFQUEUE handler on exit. **Gandalf will not remove your iptables rule for you.** If you accidentally create multiple identical rules, list them with `sudo iptables -S INPUT` and remove each copy explicitly.

> **Warning:** iptables configuration and the NFQUEUE hook may conflict with existing ufw/firewalld/nftables rules, Docker networking or other filtering services. Use a disposable VM and document your original state before inserting a hook.

### Optional telemetry

Use a named interface for passive ARP monitoring, stats, and a rotating log:

```bash
sudo .venv/bin/python gandalf.py --live --queue-num 1 \
  --arp-interface eth0 --monitor-stats --log-file /var/log/gandalf.log
```

ARP changes can be legitimate; investigate logs rather than automatically blocking based on them. The program doesn't install system services or persist firewall rules across reboot.

## Troubleshooting

- **`ModuleNotFoundError: netfilterqueue`:** activate the correct Python virtual environment and install `libnetfilter-queue-dev` plus `NetfilterQueue` into it.
- **Permission error / NFQUEUE bind failure:** live mode needs root and an unused queue number.
- **No packets in logs:** Gandalf logs *denied* packet decisions, not every accepted packet. Verify the `iptables` rule actually covers your test interface and protocol.
- **Connectivity unexpectedly interrupted:** remove the exact NFQUEUE hook via the command above and inspect your ruleset. Your port/IP rules or `BlockIPv4Fragments` may be responsible.
- **IPv6 still works:** that's expected; the example uses IPv4 `iptables` only.
- **False ARP alert:** address reassignment, VM migration or DHCP changes can also change IP-to-MAC mappings.

## Docker: safe offline policy check

The old `DockerFile` was not a standard Docker build entry point and didn't reliably build the native NetfilterQueue extension. A replacement `Dockerfile` intentionally runs **only offline validation** without privileges or the host network:

```bash
docker build -t gandalf-lab .
docker run --rm gandalf-lab
```

This image does **not** intercept host traffic and is not a containerized firewall. Use the Linux VM procedure above for actual NFQUEUE experiments.

## Testing and security model

GitHub Actions compiles Python, validates the sample policy, and runs offline unit tests on Python 3.10, 3.12 and 3.13. These tests cover malformed packets, CIDR and destination-port rules, fragmentation, ICMP rate limits and JSON validation. **They do not demonstrate production-ready kernel integration**, real packet performance, IPv6 coverage or reliable attack detection.

The example lab hook uses NFQUEUE `--queue-bypass` for easier recovery at the cost of failing open when the listener is absent. Traffic outside the selected hook is not inspected. Do not confuse Gandalf with a host-wide, stateful firewall; layer it behind maintained kernel rules if ever experimenting beyond a VM.

## References

- [NetfilterQueue — Python binding](https://github.com/oremanj/python-netfilterqueue)
- [Linux iptables NFQUEUE and queue-bypass documentation](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)

## License

MIT. See [LICENSE](LICENSE).