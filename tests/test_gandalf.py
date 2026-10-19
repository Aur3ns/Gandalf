"""Offline tests; no root privileges, sockets, NFQUEUE or firewall changes."""
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gandalf
from gandalf import Firewall, Packet, PolicyError, Rules, parse_ipv4, simulate, main


def packet_bytes(src='10.0.0.1', dst='10.0.0.2', proto=6, dport=443, fragmented=False, offset=0,
                 icmp_type=8, icmp_code=0, ihl=5):
    if proto in (6, 17):
        payload = struct.pack('!HH', 45555, dport) + (b'\x00' * 16)
    elif proto == 1:
        payload = bytes([icmp_type, icmp_code]) + b'\x00' * 6
    else:
        payload = b'\x00' * 8
    flags = (0x2000 if fragmented else 0) | offset
    header = struct.pack('!BBHHHBBH4s4s',
                         (4 << 4) | ihl, 0, 20 + len(payload), 1234, flags, 64,
                         proto, 0, ipaddress.IPv4Address(src).packed,
                         ipaddress.IPv4Address(dst).packed)
    return header + payload


class ConfigTests(unittest.TestCase):
    def test_repo_sample_valid(self):
        rules = Rules.from_file(Path(__file__).resolve().parents[1] / 'firewallrules.json')
        self.assertTrue(rules.block_fragments)
        self.assertEqual(rules.ping_threshold, 100)

    def test_defaults_and_valid_network(self):
        rules = Rules.from_dict({'ListOfBannedPrefixes': ['172.0.0.0/8']})
        self.assertEqual(str(rules.blocked_networks[0]), '172.0.0.0/8')
        self.assertTrue(rules.block_ping)

    def test_reject_string_boolean(self):
        with self.assertRaisesRegex(PolicyError, 'JSON true or false'):
            Rules.from_dict({'BlockPingAttacks': 'True'})

    def test_reject_bad_port(self):
        for port in [-1, 0, 65536, True, '443']:
            with self.subTest(port=port), self.assertRaises(PolicyError):
                Rules.from_dict({'ListOfBannedPorts': [port]})

    def test_reject_ambiguous_text_prefix(self):
        with self.assertRaises(PolicyError):
            Rules.from_dict({'ListOfBannedPrefixes': ['172.']})

    def test_reject_bad_ip(self):
        with self.assertRaises(PolicyError):
            Rules.from_dict({'ListOfBannedIpAddr': ['999.5.5.5']})

    def test_reject_unknown_key(self):
        with self.assertRaisesRegex(PolicyError, 'unknown rule keys'):
            Rules.from_dict({'BlockPongAttacks': True})

    def test_bad_json_and_missing_policy_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'missing.json'
            with self.assertRaises(PolicyError):
                Rules.from_file(path)
            path.write_text('{oops')
            with self.assertRaises(PolicyError):
                Rules.from_file(path)


class ParseTests(unittest.TestCase):
    def test_tcp_ipv4(self):
        p = parse_ipv4(packet_bytes(dport=22))
        self.assertEqual((str(p.src), str(p.dst), p.dport), ('10.0.0.1', '10.0.0.2', 22))
        self.assertFalse(p.fragmented)

    def test_udp_ipv4(self):
        p = parse_ipv4(packet_bytes(proto=17, dport=80))
        self.assertEqual((p.protocol, p.dport), (17, 80))

    def test_echo_request_type(self):
        p = parse_ipv4(packet_bytes(proto=1))
        self.assertEqual((p.icmp_type, p.icmp_code), (8, 0))

    def test_invalid_packet_rejected(self):
        samples = [b'', b'\x40' * 8, b'\x60' + b'\x00' * 24,
                   packet_bytes()[:16], packet_bytes(ihl=4)]
        for sample in samples:
            with self.subTest(sample=sample[:8]), self.assertRaises(PolicyError):
                parse_ipv4(sample)

    def test_short_tcp_udp_icmp_headers_are_rejected(self):
        for protocol, length in ((6, 19), (17, 7), (1, 7)):
            with self.subTest(protocol=protocol):
                raw = bytearray(packet_bytes(proto=protocol))
                raw = raw[:20 + length]
                raw[2:4] = struct.pack("!H", len(raw))
                with self.assertRaises(PolicyError):
                    parse_ipv4(bytes(raw))

    def test_fragment(self):
        p = parse_ipv4(packet_bytes(fragmented=True))
        self.assertTrue(p.fragmented)
        p2 = parse_ipv4(packet_bytes(offset=1))
        self.assertTrue(p2.fragmented)
        self.assertIsNone(p2.dport)

    def test_truncated_transport(self):
        p = bytearray(packet_bytes())
        p[2:4] = struct.pack('!H', 23)
        with self.assertRaises(PolicyError):
            parse_ipv4(bytes(p[:23]))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.rules = Rules.from_dict({
            'ListOfBannedIpAddr': ['10.0.0.2'],
            'ListOfBannedPorts': [80],
            'ListOfBannedPrefixes': ['172.16.0.0/12'],
            'BlockPingAttacks': True,
            'PacketThreshold': 2,
            'TimeThreshold': 10,
            'BlockIPv4Fragments': True,
        })
        self.fw = Firewall(self.rules)

    def evaluate(self, src='10.0.0.1', proto=6, port=443, **extra):
        packet = Packet(ipaddress.IPv4Address(src), ipaddress.IPv4Address('10.0.0.99'), proto,
                        port, extra.get('icmp_type'), extra.get('icmp_code'),
                        extra.get('fragmented', False))
        return self.fw.evaluate(packet, now=extra.get('now', 100))

    def test_source_ip_block(self):
        self.assertFalse(self.evaluate(src='10.0.0.2')[0])

    def test_cidr_block_is_not_string_prefix(self):
        self.assertFalse(self.evaluate(src='172.16.8.1')[0])
        self.assertTrue(self.evaluate(src='172.32.8.1')[0])

    def test_tcp_and_udp_port_block(self):
        self.assertFalse(self.evaluate(port=80, proto=6)[0])
        self.assertFalse(self.evaluate(port=80, proto=17)[0])
        self.assertTrue(self.evaluate(port=443, proto=6)[0])

    def test_fragments_blocked(self):
        self.assertFalse(self.evaluate(port=None, fragmented=True)[0])

    def test_icmp_rate_limit_sliding_window(self):
        kw = dict(proto=1, port=None, icmp_type=8, icmp_code=0)
        self.assertTrue(self.evaluate(now=100, **kw)[0])
        self.assertTrue(self.evaluate(now=101, **kw)[0])
        self.assertFalse(self.evaluate(now=102, **kw)[0])
        self.assertTrue(self.evaluate(now=110, **kw)[0])

    def test_other_icmp_messages_not_limited(self):
        for _ in range(10):
            self.assertTrue(self.evaluate(proto=1, port=None, icmp_type=0, icmp_code=0)[0])

    def test_queue_callback_accepts_and_drops_without_real_root_or_network(self):
        fake_queue = mock.MagicMock()
        packets = []
        def fake_run():
            callback = fake_queue.bind.call_args.args[1]
            for raw in [packet_bytes(src='10.0.0.2'), packet_bytes(src='10.0.0.1')]:
                p = mock.MagicMock()
                p.get_payload.return_value = raw
                callback(p)
                packets.append(p)
            broken = mock.MagicMock()
            broken.get_payload.return_value = b'bad'
            callback(broken)
            packets.append(broken)
        fake_queue.run.side_effect = fake_run
        with mock.patch.object(gandalf.os, 'geteuid', return_value=0), \
             mock.patch.dict(sys.modules, {'netfilterqueue': mock.Mock(NetfilterQueue=lambda: fake_queue)}):
            gandalf.run_live(self.fw, 1, None, False)
        packets[0].drop.assert_called_once()
        packets[1].accept.assert_called_once()
        packets[2].drop.assert_called_once()
        fake_queue.unbind.assert_called_once()

    def test_simulation_outputs_correct_verdicts(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / 'samples.jsonl'
            f.write_text('\n'.join([json.dumps({'src': '10.0.0.2', 'protocol': 'tcp', 'dport': 443}),
                                      json.dumps({'src': '10.0.0.1', 'protocol': 'udp', 'dport': 53})]))
            self.assertEqual(simulate(self.fw, f), 2)

    def test_cli_check_config(self):
        self.assertEqual(main(['--check-config']), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)