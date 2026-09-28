import unittest

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from core.analysis import analyze_packet
from core.investigation import InvestigationEngine


class UnifiedAnalysisTests(unittest.TestCase):
    def test_packet_analysis_keeps_decoder_observations_separate_from_ai(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=1234, dport=21) / Raw(load=b"PASS secret\r\n")
        packet.time = 10.0
        ai = {"available": True, "label": "SUSPICIOUS", "confidence": 0.8,
              "risk_score": 64, "model_version": "fake-1"}
        result = analyze_packet(packet, packet_id=91, ai_result=ai)
        self.assertEqual(91, result["packet_id"])
        self.assertEqual("FTP", result["decoder"]["application_protocol"])
        self.assertEqual("SUSPICIOUS", result["ai"]["label"])
        self.assertTrue(result["decoder"]["findings"])
        self.assertTrue(result["decoder"]["payload"]["present"])

    def test_empty_non_application_ai_unavailable_and_malformed(self):
        self.assertEqual([], InvestigationEngine().analyze([])["analyses"])
        no_raw = analyze_packet(IP(src="192.0.2.1", dst="192.0.2.2") / TCP())
        self.assertFalse(no_raw["decoder"]["payload"]["present"])
        self.assertFalse(no_raw["ai"]["available"])
        malformed = analyze_packet(object(), packet_id=5)
        self.assertEqual("malformed", malformed["status"])
        result = InvestigationEngine().analyze([{"id": 5, "packet": object()}])
        self.assertEqual(1, result["packet_count"])
        self.assertEqual(0, result["total_bytes"])


class InvestigationEngineTests(unittest.TestCase):
    def test_bidirectional_conversation_and_evidence_references(self):
        request = Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(sport=53000, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="example.test", qtype="A"))
        response = Ether() / IP(src="192.0.2.53", dst="192.0.2.1") / UDP(sport=53, dport=53000) / DNS(
            qr=1, qd=DNSQR(qname="example.test", qtype="A"))
        request.time, response.time = 20, 22
        result = InvestigationEngine().analyze([
            {"id": 7, "packet": request, "src": "192.0.2.1", "dst": "192.0.2.53", "sport": 53000,
             "dport": 53, "protocol": "DNS", "length": len(request), "ai_result": None},
            {"id": 8, "packet": response, "src": "192.0.2.53", "dst": "192.0.2.1", "sport": 53,
             "dport": 53000, "protocol": "DNS", "length": len(response), "ai_result": None},
        ])
        self.assertEqual(1, len(result["flows"]))
        flow = result["flows"][0]
        self.assertEqual("bidirectional_conversation", flow["semantic"])
        self.assertEqual([7, 8], flow["packet_ids"])
        self.assertEqual(2, flow["packet_count"])
        self.assertEqual(2.0, flow["duration"])
        self.assertEqual("example.test", result["dns"][0]["queried_domain"])
        self.assertEqual(7, result["dns"][0]["packet_id"])
        dns_events = [event for event in result["timeline"] if event["event_type"].startswith("dns_")]
        self.assertEqual(["dns_query", "dns_response"], [event["event_type"] for event in dns_events])
        self.assertEqual(sorted(event["timestamp"] for event in result["timeline"]),
                         [event["timestamp"] for event in result["timeline"]])
        talker = next(item for item in result["top_talkers"] if item["source"] == "192.0.2.1")
        self.assertEqual(1, talker["packet_count"])
        self.assertEqual(len(request), talker["byte_count"])

    def test_security_finding_keeps_source_type_and_packet_id(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=21) / Raw(load=b"PASS secret\r\n")
        result = InvestigationEngine().analyze([{"id": 44, "packet": packet, "src": "192.0.2.1",
            "dst": "192.0.2.2", "sport": 30000, "dport": 21, "protocol": "TCP", "length": len(packet)}])
        finding = next(item for item in result["findings"] if item["source_type"] == "decoder_heuristic")
        self.assertEqual(44, finding["packet_id"])
        self.assertIn("FTP", finding["details"]["message"])


if __name__ == "__main__":
    unittest.main()
