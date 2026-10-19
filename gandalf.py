#!/usr/bin/env python3
"""Gandalf: auditable IPv4/NFQUEUE firewall for a controlled Linux lab.

The policy engine and parsers deliberately have no third-party dependencies.
Network hooks are available only with an explicit --live flag.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any

LOG = logging.getLogger("gandalf")
CONFIG_KEYS = frozenset({
    "ListOfBannedIpAddr", "ListOfBannedPorts", "ListOfBannedPrefixes",
    "TimeThreshold", "PacketThreshold", "BlockPingAttacks", "BlockIPv4Fragments",
})


class PolicyError(ValueError):
    """Configuration or packet validation failed."""


def positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0 < value <= 86400):
        raise PolicyError(f"{name} must be a positive number no greater than 86400")
    return float(value)


@dataclass(frozen=True)
class Rules:
    blocked_ips: frozenset[ipaddress.IPv4Address]
    blocked_networks: tuple[ipaddress.IPv4Network, ...]
    blocked_ports: frozenset[int]
    window_seconds: float
    ping_threshold: int
    block_ping: bool
    block_fragments: bool

    @classmethod
    def from_dict(cls, data: Any) -> "Rules":
        if not isinstance(data, dict):
            raise PolicyError("the rules file must contain a JSON object")
        unknown = data.keys() - CONFIG_KEYS
        if unknown:
            raise PolicyError(f"unknown rule keys: {', '.join(sorted(unknown))}")
        def array(key: str) -> list[Any]:
            value = data.get(key, [])
            if not isinstance(value, list):
                raise PolicyError(f"{key} must be an array")
            return value

        try:
            ips = frozenset(ipaddress.IPv4Address(s) for s in array("ListOfBannedIpAddr"))
            networks = tuple(ipaddress.IPv4Network(s, strict=False) for s in array("ListOfBannedPrefixes"))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError, TypeError) as exc:
            raise PolicyError(f"invalid IPv4 address or CIDR network: {exc}") from exc
        ports = set()
        for port in array("ListOfBannedPorts"):
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise PolicyError(f"invalid TCP/UDP destination port: {port!r}")
            ports.add(port)
        for key in ("BlockPingAttacks", "BlockIPv4Fragments"):
            if key in data and type(data[key]) is not bool:
                raise PolicyError(f"{key} must be JSON true or false, not a string")
        count = data.get("PacketThreshold", 100)
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 100000:
            raise PolicyError("PacketThreshold must be an integer between 1 and 100000")
        return cls(ips, networks, frozenset(ports),
                   positive_number(data.get("TimeThreshold", 10), "TimeThreshold"),
                   count, data.get("BlockPingAttacks", True), data.get("BlockIPv4Fragments", True))

    @classmethod
    def from_file(cls, path: Path) -> "Rules":
        try:
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"cannot read rules from {path}: {exc}") from exc


@dataclass(frozen=True)
class Packet:
    src: ipaddress.IPv4Address
    dst: ipaddress.IPv4Address
    protocol: int
    dport: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    fragmented: bool = False
    offset: int = 0


def parse_ipv4(payload: bytes) -> Packet:
    """Decode just enough IPv4 for filtering; invalid packets raise PolicyError.

    Not a full TCP/IP validator. NFQUEUE is attached to IPv4 only.
    """
    if len(payload) < 20 or payload[0] >> 4 != 4:
        raise PolicyError("not a complete IPv4 header")
    header_size = (payload[0] & 15) * 4
    total_length = int.from_bytes(payload[2:4], "big")
    if header_size < 20 or len(payload) < header_size or total_length < header_size or len(payload) < total_length:
        raise PolicyError("invalid IPv4 header length or truncated packet")
    flags_offset = int.from_bytes(payload[6:8], "big")
    offset = flags_offset & 0x1FFF
    fragmented = bool(offset or flags_offset & 0x2000)
    proto = payload[9]
    src = ipaddress.IPv4Address(payload[12:16])
    dst = ipaddress.IPv4Address(payload[16:20])
    data = payload[header_size:total_length]
    dport = None
    icmp_type = icmp_code = None
    if offset == 0:
        if proto in (6, 17):
            # Parse the destination port only after a complete minimum transport header.
            minimum_header = 20 if proto == 6 else 8
            if len(data) < minimum_header:
                raise PolicyError("truncated TCP/UDP header")
            dport = int.from_bytes(data[2:4], "big")
        if proto == 1:
            if len(data) < 8:
                raise PolicyError("truncated ICMP header")
            icmp_type, icmp_code = data[:2]
    return Packet(src, dst, proto, dport, icmp_type, icmp_code, fragmented, offset)


class Firewall:
    def __init__(self, rules: Rules):
        self.rules = rules
        self._ping_history: dict[ipaddress.IPv4Address, deque[float]] = {}

    def evaluate(self, packet: Packet, now: float | None = None) -> tuple[bool, str]:
        """Return (allowed, explanation); history is local to one callback thread."""
        if packet.src in self.rules.blocked_ips:
            return False, "blocked source IPv4 address"
        if any(packet.src in net for net in self.rules.blocked_networks):
            return False, "blocked source IPv4 network"
        if packet.fragmented and self.rules.block_fragments:
            return False, "IPv4 fragments blocked to prevent filtering bypass"
        if packet.dport in self.rules.blocked_ports and packet.protocol in (6, 17):
            return False, "blocked destination TCP/UDP port"
        if self.rules.block_ping and packet.protocol == 1 and packet.icmp_type == 8 and packet.icmp_code == 0:
            stamp = time.monotonic() if now is None else now
            history = self._ping_history.setdefault(packet.src, deque())
            while history and stamp - history[0] >= self.rules.window_seconds:
                history.popleft()
            if len(history) >= self.rules.ping_threshold:
                return False, "ICMP echo-rate limit exceeded"
            history.append(stamp)
            # Periodically reclaim stale source histories to bound long-lived growth.
            if len(self._ping_history) > 4096:
                self._ping_history = {
                    src: stamps for src, stamps in self._ping_history.items()
                    if stamps and stamp - stamps[-1] < self.rules.window_seconds
                }
                # Malicious clients with >4096 *active* sources cannot consume unlimited entries.
                if len(self._ping_history) > 4096:
                    oldest = min(self._ping_history, key=lambda src: self._ping_history[src][-1])
                    del self._ping_history[oldest]
        return True, "no matching deny rule"


def monitor_arp(interface: str) -> None:
    """Passive ARP inconsistency observer, not a proof of spoofing."""
    try:
        from scapy.all import ARP, sniff
    except ImportError:
        LOG.error("ARP monitoring requested; install scapy")
        return
    observed: dict[str, str] = {}
    def visit(frame: Any) -> None:
        if not frame.haslayer(ARP) or frame[ARP].op != 2:
            return
        ip, mac = str(frame[ARP].psrc), str(frame[ARP].hwsrc).lower()
        old = observed.get(ip)
        if old and old != mac:
            LOG.warning("ARP address mapping changed for %s: %s -> %s; investigate", ip, old, mac)
        observed[ip] = mac
        if len(observed) > 4096:
            observed.pop(next(iter(observed)))
    try:
        sniff(iface=interface, filter="arp", store=False, prn=visit)
    except Exception as exc:
        LOG.error("ARP monitor stopped: %s", exc)


def monitor_statistics() -> None:
    try:
        import psutil
    except ImportError:
        LOG.error("Statistics requested; install psutil")
        return
    while True:
        for name, stat in psutil.net_io_counters(pernic=True).items():
            LOG.info("Interface %s: sent=%s received=%s", name, stat.bytes_sent, stat.bytes_recv)
        time.sleep(30)


def run_live(firewall: Firewall, queue_number: int, arp_interface: str | None, stats: bool) -> None:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PolicyError("--live requires root on Linux; test in a disposable VM")
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError as exc:
        raise PolicyError("--live requires NetfilterQueue and libnetfilter_queue") from exc
    if arp_interface:
        threading.Thread(target=monitor_arp, args=(arp_interface,), daemon=True).start()
    if stats:
        threading.Thread(target=monitor_statistics, daemon=True).start()

    def callback(nfpkt: Any) -> None:
        try:
            packet = parse_ipv4(nfpkt.get_payload())
            allowed, reason = firewall.evaluate(packet)
            if not allowed:
                LOG.info("DROP src=%s dst=%s proto=%d reason=%s", packet.src, packet.dst, packet.protocol, reason)
        except Exception as exc:
            # Never leave a queued packet without a verdict, even on unexpected errors.
            LOG.exception("DROP packet rejected by engine: %s", exc)
            allowed = False
        if allowed:
            nfpkt.accept()
        else:
            nfpkt.drop()

    queue = NetfilterQueue()
    queue.bind(queue_number, callback)
    LOG.info("Listening on NFQUEUE %d; no iptables rules are created automatically", queue_number)
    try:
        queue.run()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        queue.unbind()


def simulate(firewall: Firewall, path: Path) -> int:
    """Process JSONL packet metadata from disk; never connect to the network."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PolicyError(f"cannot open simulation file: {exc}") from exc
    count = 0
    for line_no, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("record must be a JSON object")
            proto = obj["protocol"]
            if proto not in ("tcp", "udp", "icmp", "other"):
                raise ValueError("protocol must be tcp, udp, icmp or other")
            code = {"tcp": 6, "udp": 17, "icmp": 1, "other": 255}[proto]
            packet = Packet(
                ipaddress.IPv4Address(obj["src"]),
                ipaddress.IPv4Address(obj.get("dst", "127.0.0.1")),
                code,
                obj.get("dport"),
                8 if obj.get("icmp_echo", False) else None,
                0 if obj.get("icmp_echo", False) else None,
                bool(obj.get("fragmented", False)),
            )
            allowed, reason = firewall.evaluate(packet)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicyError(f"simulation line {line_no}: {exc}") from exc
        print(json.dumps({"line": line_no, "verdict": "ACCEPT" if allowed else "DROP", "reason": reason}))
        count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gandalf: IPv4 policy engine and opt-in Linux NFQUEUE firewall")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("firewallrules.json"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-config", action="store_true", help="validate rule syntax and exit")
    mode.add_argument("--simulate", type=Path, metavar="PACKETS.JSONL", help="simulate packet decisions offline")
    mode.add_argument("--live", action="store_true", help="run real NFQUEUE firewall (Linux root)")
    parser.add_argument("--queue-num", type=int, default=1)
    parser.add_argument("--arp-interface", metavar="IFACE", help="optional passive ARP inconsistency observer")
    parser.add_argument("--monitor-stats", action="store_true", help="optional per-interface statistics")
    parser.add_argument("--log-file", type=Path, help="optional rotating log file")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.log_file:
        fh = RotatingFileHandler(args.log_file, maxBytes=1048576, backupCount=3)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        LOG.addHandler(fh)
    try:
        if not 0 <= args.queue_num <= 65535:
            raise PolicyError("queue number must be between 0 and 65535")
        if (args.arp_interface or args.monitor_stats) and not args.live:
            raise PolicyError("ARP and interface monitoring require --live")
        rules = Rules.from_file(args.config)
        if args.check_config:
            print(f"OK: rules valid ({args.config})")
        elif args.simulate:
            print(f"Processed {simulate(Firewall(rules), args.simulate)} simulated packets")
        else:
            run_live(Firewall(rules), args.queue_num, args.arp_interface, args.monitor_stats)
        return 0
    except PolicyError as exc:
        LOG.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())