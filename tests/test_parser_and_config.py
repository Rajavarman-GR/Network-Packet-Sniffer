import os
import tempfile
import unittest

import scapy.all as scapy

from core.filter_engine import build_bpf_filter
from core.packet_manager import PacketManager
from core.parser import get_packet_metadata
from utils.config import default_config, load_config, save_config


class ParserAndConfigTests(unittest.TestCase):
    def test_ipv6_metadata_is_detected(self):
        packet = scapy.Ether() / scapy.IPv6(src="2001::1", dst="2001::2") / scapy.ICMPv6EchoRequest()

        metadata = get_packet_metadata(packet)

        self.assertEqual(metadata["protocol"], "ICMPv6")
        self.assertEqual(metadata["src"], "2001::1")
        self.assertEqual(metadata["dst"], "2001::2")

    def test_config_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            config = default_config()
            config["max_packets"] = 1234

            save_config(config_path, config)
            loaded = load_config(config_path)

            self.assertEqual(loaded["max_packets"], 1234)

    def test_parser_protocols_and_packet_timestamp(self):
        timestamp = 1700000000
        packets = [
            (scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.TCP(sport=1234, dport=80), "TCP"),
            (scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.UDP(sport=1234, dport=53) / scapy.DNS(), "DNS"),
            (scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.ICMP(), "ICMP"),
            (scapy.ARP(psrc="192.0.2.1", pdst="192.0.2.2"), "ARP"),
        ]

        for packet, protocol in packets:
            packet.time = timestamp
            metadata = get_packet_metadata(packet, "%Y")
            self.assertEqual(metadata["protocol"], protocol)
            self.assertEqual(metadata["timestamp"], "2023")

        reply = scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / scapy.ICMPv6EchoReply()
        self.assertEqual(get_packet_metadata(reply)["protocol"], "ICMPv6")

    def test_packet_manager_ids_survive_eviction(self):
        manager = PacketManager(max_packets=2)
        first, _ = manager.add("first", {"protocol": "TCP"})
        second, _ = manager.add("second", {"protocol": "UDP"})
        third, evicted = manager.add("third", {"protocol": "ARP"})

        self.assertEqual(first["id"], 1)
        self.assertEqual(second["id"], 2)
        self.assertEqual(third["id"], 3)
        self.assertEqual(evicted["id"], first["id"])
        self.assertIsNone(manager.get(first["id"]))
        self.assertEqual(manager.get(second["id"])["packet"], "second")

    def test_filter_engine_supports_dns_and_rejects_invalid_values(self):
        self.assertEqual(build_bpf_filter("DNS"), "(udp port 53 or tcp port 53)")
        self.assertEqual(
            build_bpf_filter("TCP", src_ip="192.0.2.1", dst_ip="192.0.2.2", ports=443),
            "tcp and host 192.0.2.1 and host 192.0.2.2 and port 443",
        )
        self.assertEqual(build_bpf_filter("TCP", src_ip="bad input", ports="80 or tcp"), "tcp")

    def test_invalid_config_uses_safe_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write("not json")
            loaded = load_config(config_path)
            self.assertEqual(loaded, default_config())


if __name__ == "__main__":
    unittest.main()
