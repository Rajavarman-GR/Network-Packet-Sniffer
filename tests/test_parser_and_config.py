import os
import tempfile
import unittest

import scapy.all as scapy

from ai.detector import ThreatDetector
from ai.feature_extractor import FEATURE_NAMES, extract_features
from ai.flow_tracker import FlowTracker
from ai.model_loader import ModelLoader
from core.filter_engine import build_bpf_filter
from core.packet_manager import PacketManager
from core.parser import get_packet_metadata, get_payload_preview, matches_display_filter, packet_search_text
from utils.config import default_config, load_config, save_config


class ParserAndConfigTests(unittest.TestCase):
    def test_feature_schema_and_flow_context_are_deterministic(self):
        packet = scapy.IP(src="192.0.2.1", dst="192.0.2.2", ttl=42) / scapy.TCP(sport=1234, dport=443, flags="S")
        metadata = get_packet_metadata(packet)
        tracker = FlowTracker(max_flows=2, expiration_seconds=10)
        context = tracker.observe(packet, metadata, timestamp=1000)
        features = extract_features(packet, metadata, context)

        self.assertEqual(len(features), len(FEATURE_NAMES))
        self.assertEqual(features[0], len(packet))
        self.assertEqual(features[FEATURE_NAMES.index("ip_ttl_or_hop_limit")], 42.0)
        self.assertEqual(context["source_packet_count"], 1)
        self.assertEqual(features[FEATURE_NAMES.index("protocol_tcp")], 1.0)
        self.assertEqual(features[FEATURE_NAMES.index("protocol_icmpv6")], 0.0)

    def test_flow_tracker_expires_old_context(self):
        tracker = FlowTracker(max_flows=1, expiration_seconds=2, window_seconds=2)
        packet = scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.UDP(sport=1, dport=2)
        metadata = get_packet_metadata(packet)
        tracker.observe(packet, metadata, timestamp=100)
        refreshed = tracker.observe(packet, metadata, timestamp=103)
        self.assertEqual(len(tracker.flows), 1)
        self.assertEqual(refreshed["source_packet_count"], 1)

    def test_missing_model_is_unavailable(self):
        loader = ModelLoader("missing.joblib", "missing.json")
        detector = ThreatDetector(loader)
        result = detector.predict([0.0] * len(FEATURE_NAMES))
        self.assertFalse(detector.is_available())
        self.assertEqual(result["label"], "UNAVAILABLE")

    def test_incompatible_model_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "model.joblib")
            metadata_path = os.path.join(temp_dir, "metadata.json")
            save_config(model_path, {})
            with open(metadata_path, "w", encoding="utf-8") as handle:
                handle.write("{\"feature_schema_version\": \"wrong\", \"features\": []}")
            loader = ModelLoader(model_path, metadata_path)
            self.assertFalse(loader.available)

    def test_detector_structured_results_with_test_loader(self):
        class FakeLoader:
            available = True
            model_name = "test-model"
            model_version = "test-1"

            def __init__(self, label):
                self.label = label

            def predict(self, features):
                return self.label

            def confidence(self, features):
                return 0.9

        features = [0.0] * len(FEATURE_NAMES)
        benign = ThreatDetector(FakeLoader("BENIGN")).predict(features)
        suspicious = ThreatDetector(FakeLoader("SUSPICIOUS")).predict(features)
        self.assertEqual(benign["label"], "BENIGN")
        self.assertEqual(benign["risk_score"], 2)
        self.assertEqual(suspicious["label"], "SUSPICIOUS")
        self.assertEqual(suspicious["risk_score"], 72)
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

    def test_display_filter_and_search_fields(self):
        packet = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.TCP(sport=443, dport=50000)
        metadata = get_packet_metadata(packet)
        search_text = packet_search_text(packet, metadata)

        self.assertIn("02:00:00:00:00:01", search_text)
        self.assertTrue(matches_display_filter(packet, metadata, "TCP", "192.0.2.1"))
        self.assertFalse(matches_display_filter(packet, metadata, "UDP"))

    def test_payload_preview_handles_text_binary_and_truncation(self):
        text_preview = get_payload_preview(scapy.Raw(load=b"GET / HTTP/1.1\r\n"))
        self.assertTrue(text_preview["printable"])
        self.assertIn("GET / HTTP/1.1", text_preview["text"])

        binary_preview = get_payload_preview(scapy.Raw(load=bytes(range(256))))
        self.assertFalse(binary_preview["printable"])
        self.assertTrue(binary_preview["hex"])

        truncated = get_payload_preview(scapy.Raw(load=b"a" * 5000), max_bytes=4096)
        self.assertTrue(truncated["truncated"])
        self.assertEqual(len(truncated["text"]), 4096)


if __name__ == "__main__":
    unittest.main()
