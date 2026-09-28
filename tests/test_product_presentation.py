import unittest

from core.explanations import PROTOCOL_EXPLANATIONS, build_beginner_summary, explain_protocol
from gui.presentation import EMPTY_STATES, dashboard_model, decoder_view_model, investigation_groups, operation_label
from utils.config import normalize_config
from utils.theme import SIZES, get_tokens


class ExplanationTests(unittest.TestCase):
    def test_supported_protocol_registry_includes_requested_protocols(self):
        expected = {"Ethernet", "ARP", "IPv4", "IPv6", "TCP", "UDP", "DNS", "HTTP", "TLS", "FTP", "ICMP", "ICMPv6", "Raw"}
        self.assertTrue(expected.issubset(PROTOCOL_EXPLANATIONS))

    def test_alias_and_current_packet_facts(self):
        explanation = explain_protocol("TCP", {"sport": 52134, "dport": 443})
        self.assertEqual("Reliable transport", explanation["title"])
        self.assertIn("52134 → 443", explanation["indication"])
        self.assertNotIn("threat", explanation["description"].lower())

    def test_unknown_protocol_is_safe(self):
        self.assertIn("No beginner explanation", explain_protocol("NewThing")["description"])

    def test_missing_and_malformed_results(self):
        summary = build_beginner_summary({"layers": None, "application": None})
        self.assertEqual([], summary["protocol_stack"])
        self.assertIn("No protocol layers", summary["what_happened"])
        self.assertEqual([], build_beginner_summary(None)["protocol_stack"])

    def test_beginner_summary_preserves_stack_and_security_uncertainty(self):
        summary = build_beginner_summary({"layers": [{"name": "Ether"}, {"name": "IP"}, {"name": "TCP"}],
                                          "application": {"protocol": "TLS", "content_type": "ApplicationData"},
                                          "security_findings": ["Possible pattern"]})
        self.assertEqual(["Ethernet", "IPv4", "TCP", "TLS"], summary["protocol_stack"])
        self.assertIn("encrypted", summary["what_happened"])
        self.assertEqual(["Possible pattern"], summary["findings"])


class ThemeTokenTests(unittest.TestCase):
    def test_dark_light_semantic_tokens_and_fallback(self):
        dark, light = get_tokens("dark"), get_tokens("light")
        for key in ("background", "surface", "elevated", "border", "text", "muted", "accent", "success", "warning", "danger", "info"):
            self.assertIn(key, dark)
            self.assertIn(key, light)
        self.assertEqual(dark, get_tokens("unexpected"))
        self.assertGreater(SIZES["control_height"], 0)
        for theme in (dark, light):
            self.assertIn("navigation", theme)
            self.assertIn("selection", theme)
            self.assertIn("disabled", theme)

    def test_existing_theme_setting_remains_compatible(self):
        self.assertEqual("light", normalize_config({"theme": "light"})["theme"])
        self.assertEqual("dark", normalize_config({"theme": "old-theme"})["theme"])


class WorkspacePresentationTests(unittest.TestCase):
    def test_decoder_modes_keep_progressive_disclosure(self):
        decoded = {"layers": [{"name": "TCP", "fields": [("dport", "443")]}],
                   "application": {"protocol": "TLS"}, "payload": {"present": True, "length": 3, "ascii": "abc", "hex": "61 62 63", "truncated": False},
                   "security_findings": ["Heuristic evidence"]}
        beginner = decoder_view_model(decoded, "Beginner")
        analyst = decoder_view_model(decoded, "Analyst")
        technical = decoder_view_model(decoded, "Technical / Raw")
        self.assertIn("summary", beginner)
        self.assertEqual("TLS", analyst["application"]["protocol"])
        self.assertEqual("Decoder heuristic", analyst["finding_source"])
        self.assertEqual("61 62 63", analyst["payload"]["hex"])
        self.assertEqual("dport", technical["layers"][0]["fields"][0][0])

    def test_dashboard_marks_unavailable_analysis_instead_of_inventing_zero(self):
        model = dashboard_model({"packets": 4, "suspicious_ai": 1})
        self.assertEqual(4, model["packets"])
        self.assertIsNone(model["active_flows"])
        self.assertIsNone(model["security_findings"])

    def test_dashboard_counts_retained_investigation(self):
        model = dashboard_model({}, {"flows": [1, 2], "findings": [{"source_type": "decoder_heuristic"}],
                                    "total_bytes": 30, "packet_count": 2})
        self.assertEqual((2, 30, 1), (model["active_flows"], model["bytes"], model["security_findings"]))

    def test_investigation_evidence_is_grouped_with_packet_navigation_ids(self):
        data = {"analyses": [{"packet_id": 7, "metadata": {"timestamp": "12:00:00", "src": "a", "dst": "b"}}],
                "dns": [{"packet_id": 7, "kind": "query", "queried_domain": "example.test", "record_type": "A"}],
                "http": [], "tls": [], "findings": [{"packet_id": 7, "source_type": "ai", "details": {"label": "SUSPICIOUS"}},
                                                          {"packet_id": 7, "source_type": "decoder_heuristic", "details": {"message": "credential pattern"}}],
                "timeline": [{"packet_id": 7, "event_type": "dns_query", "description": "DNS query", "timestamp": 1.0}]}
        groups = investigation_groups(data)
        self.assertEqual(7, groups["DNS"][0][6])
        self.assertEqual("a", groups["AI Findings"][0][3])
        self.assertEqual("AI classification", groups["AI Findings"][0][1])
        self.assertEqual("Heuristic indicator", groups["Security Findings"][0][1])
        self.assertEqual(1, len(groups["Timeline"]))

    def test_empty_state_and_operation_labels_are_actionable(self):
        self.assertIn("PCAP", EMPTY_STATES["packets"][1])
        self.assertEqual("Loading PCAP — 128 packets processed", operation_label("loading", "128 packets processed"))
        self.assertEqual("Error", operation_label("error"))


if __name__ == "__main__":
    unittest.main()
