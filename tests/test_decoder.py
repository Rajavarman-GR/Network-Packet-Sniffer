import unittest

import scapy.all as scapy

from core.decoder import (
    DECODER_REGISTRY,
    analyze_payload_findings,
    analyze_payload_security,
    create_default_registry,
    decode_application_layer,
    decode_layers,
    decode_packet,
    inspect_payload,
)
from core.decoders import DecoderRegistry, ProtocolDecoder


def _packet(payload=b"", layer=None):
    layer = layer or scapy.TCP(dport=80)
    packet = scapy.Ether() / scapy.IP() / layer
    return packet / scapy.Raw(load=payload) if payload else packet


def _client_hello(hostname="example.com"):
    hostname = hostname.encode("ascii")
    name = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    names = len(name).to_bytes(2, "big") + name
    extension = b"\x00\x00" + len(names).to_bytes(2, "big") + names
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x00\x2f"
            + b"\x01\x00" + len(extension).to_bytes(2, "big") + extension)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


class _CustomDecoder(ProtocolDecoder):
    name = "custom"
    priority = 10

    def applies(self, packet, payload):
        return payload.startswith(b"CUSTOM")

    def decode(self, packet, payload):
        return {"protocol": "CUSTOM", "data": payload[6:].decode("ascii")}


class DecoderRegistryTests(unittest.TestCase):
    def test_default_registry_has_protocol_plugins(self):
        self.assertEqual({"dns", "tls", "http", "ftp", "icmp"},
                         {item.name.casefold() for item in DECODER_REGISTRY.decoders()})

    def test_registration_lookup_and_case_insensitive_name(self):
        registry = DecoderRegistry()
        decoder = _CustomDecoder()
        self.assertIs(registry.register(decoder), decoder)
        self.assertIs(registry.get("CUSTOM"), decoder)
        self.assertEqual((decoder,), registry.decoders())

    def test_duplicate_registration_rejected_or_explicitly_replaced(self):
        registry = DecoderRegistry()
        first = _CustomDecoder()
        second = _CustomDecoder()
        registry.register(first)
        with self.assertRaisesRegex(ValueError, "already registered"):
            registry.register(second)
        registry.register(second, replace=True)
        self.assertIs(registry.get("custom"), second)

    def test_registration_requires_contract(self):
        with self.assertRaises(TypeError):
            DecoderRegistry().register(type("Bad", (), {"name": "bad"})())
        with self.assertRaises(ValueError):
            DecoderRegistry().register(type("Nameless", (), {"name": " "})())

    def test_detection_fallback_and_public_api(self):
        registry = DecoderRegistry()
        registry.register(_CustomDecoder())
        packet = _packet(b"CUSTOMhello")
        decoder = registry.detect(packet, b"CUSTOMhello")
        self.assertEqual("custom", decoder.name)
        self.assertIsNone(registry.detect(packet, b"unknown"))
        result = decode_packet(packet)
        self.assertTrue({"layers", "application", "security_findings"}.issubset(result))

    def test_matching_continues_after_malformed_plugin_detection(self):
        class Broken(_CustomDecoder):
            name = "broken"
            priority = 20

            def applies(self, packet, payload):
                raise ValueError("bad input")

        registry = DecoderRegistry()
        registry.register(Broken())
        good = _CustomDecoder()
        registry.register(good)
        self.assertIs(registry.detect(None, b"CUSTOMok"), good)


class GenericLayerTests(unittest.TestCase):
    def test_ethernet_ipv4_tcp_and_options_are_walked(self):
        packet = scapy.Ether() / scapy.IP(src="10.0.0.5", ttl=64) / scapy.TCP(options=[("MSS", 1460)]) / scapy.Raw(load=b"x")
        layers = decode_layers(packet)
        self.assertEqual(["Ether", "IP", "TCP", "Raw"], [layer["name"] for layer in layers])
        fields = dict(next(layer for layer in layers if layer["name"] == "IP")["fields"])
        self.assertEqual("10.0.0.5", fields["src"])
        tcp = dict(layers[2]["fields"])
        self.assertIn("MSS", tcp["options"])

    def test_ipv6_extension_header_is_walked(self):
        packet = scapy.IPv6() / scapy.IPv6ExtHdrHopByHop() / scapy.UDP()
        names = [layer["name"] for layer in decode_layers(packet)]
        self.assertIn("IPv6", names)
        self.assertIn("IPv6ExtHdrHopByHop", names)
        self.assertIn("UDP", names)

    def test_arp_and_dns_fields_are_rendered_by_scapy(self):
        arp = scapy.Ether() / scapy.ARP(op=1, psrc="192.168.1.5", pdst="192.168.1.1")
        fields = dict(next(layer for layer in decode_layers(arp) if layer["name"] == "ARP")["fields"])
        self.assertIn("who-has", fields["op"])
        dns = _packet(layer=scapy.UDP() / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com")))
        self.assertIn("DNS", [layer["name"] for layer in decode_layers(dns)])

    def test_raw_field_is_bounded_and_contains_total(self):
        packet = _packet(b"A" * 10000)
        raw = dict(next(layer for layer in decode_layers(packet) if layer["name"] == "Raw")["fields"])
        self.assertLess(len(raw["load"]), 230)
        self.assertIn("bytes total", raw["load"])

    def test_none_and_unexpected_values_are_safe(self):
        self.assertEqual([], decode_layers(None))
        self.assertIsNone(decode_application_layer(None))
        result = decode_packet(None)
        self.assertEqual([], result["layers"])
        self.assertIsNone(result["application"])
        self.assertEqual([], result["security_findings"])


class HTTPDecoderTests(unittest.TestCase):
    def test_get_request_exposes_method_path_host_and_headers(self):
        result = decode_application_layer(_packet(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\n"))
        self.assertEqual("HTTP", result["protocol"])
        self.assertEqual("GET", result["method"])
        self.assertEqual("/index.html", result["path"])
        self.assertEqual("example.com", result["host"])
        self.assertEqual("text/plain", result["content_type"])

    def test_post_request_has_content_length_and_body_preview(self):
        result = decode_application_layer(_packet(b"POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"))
        self.assertEqual("POST", result["method"])
        self.assertEqual("5", result["content_length"])
        self.assertEqual("hello", result["body_preview"])

    def test_response_status_and_body_truncation(self):
        result = decode_application_layer(_packet(b"HTTP/1.1 200 OK\r\nContent-Length: 300\r\n\r\n" + b"x" * 300))
        self.assertEqual("response", result["kind"])
        self.assertEqual(200, result["status_code"])
        self.assertEqual(256, len(result["body_preview"]))
        self.assertTrue(result["body_truncated"])

    def test_malformed_or_binary_http_like_data_is_rejected_safely(self):
        self.assertIsNone(decode_application_layer(_packet(b"GET not-an-http-line\r\n\xff\x00")))
        binary = decode_application_layer(_packet(b"HTTP/1.1 200 OK\r\n\r\n\x00\xff\x01"))
        self.assertEqual("", binary["body_preview"])
        self.assertTrue(binary["body_preview_hex"])

    def test_incomplete_headers_are_reported(self):
        result = decode_application_layer(_packet(b"GET / HTTP/1.1\r\nHost: example.org"))
        self.assertEqual("example.org", result["host"])
        self.assertFalse(result["headers_complete"])

    def test_content_length_reports_an_incomplete_body(self):
        result = decode_application_layer(_packet(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhi"))
        self.assertTrue(result["body_incomplete"])
        self.assertTrue(result["body_truncated"])


class TLSDecoderTests(unittest.TestCase):
    def test_client_hello_and_sni(self):
        result = decode_application_layer(_packet(_client_hello(), scapy.TCP(dport=443)))
        self.assertEqual("TLS", result["protocol"])
        self.assertEqual("Handshake", result["content_type"])
        self.assertEqual("ClientHello", result["handshake_type"])
        self.assertEqual("example.com", result["server_name"])

    def test_truncated_client_hello_is_identified_without_crashing(self):
        payload = _client_hello()[:-8]
        result = decode_application_layer(_packet(payload, scapy.TCP(dport=443)))
        self.assertEqual("ClientHello", result["handshake_type"])
        self.assertTrue(result["record_truncated"])

    def test_tls_application_data_is_recognized_as_encrypted_record(self):
        result = decode_application_layer(_packet(b"\x17\x03\x03\x00\x03abc", scapy.TCP(dport=443)))
        self.assertEqual("ApplicationData", result["content_type"])
        self.assertNotIn("server_name", result)

    def test_invalid_tls_like_and_incomplete_headers_are_rejected(self):
        self.assertIsNone(decode_application_layer(_packet(b"\x16\x02\x03\x00\x01x")))
        self.assertIsNone(decode_application_layer(_packet(b"\x16\x03")))


class DNSDecoderTests(unittest.TestCase):
    def test_dns_query_exposes_question_type_and_transaction_id(self):
        packet = scapy.Ether() / scapy.IP() / scapy.UDP() / scapy.DNS(id=123, rd=1, qd=scapy.DNSQR(qname="example.com", qtype="A"))
        result = decode_application_layer(packet)
        self.assertEqual("DNS", result["protocol"])
        self.assertEqual("query", result["kind"])
        self.assertEqual(123, result["transaction_id"])
        self.assertEqual("example.com", result["queried_domain"])
        self.assertEqual("A", result["record_type"])

    def test_dns_response_answer_and_nxdomain(self):
        answer_packet = scapy.Ether() / scapy.IP() / scapy.UDP() / scapy.DNS(
            id=7, qr=1, qd=scapy.DNSQR(qname="example.com"),
            an=scapy.DNSRR(rrname="example.com", type="A", ttl=60, rdata="192.0.2.1"),
        )
        answer = decode_application_layer(answer_packet)
        self.assertEqual("response", answer["kind"])
        self.assertEqual("192.0.2.1", answer["answers"][0]["data"])
        nx_packet = scapy.Ether() / scapy.IP() / scapy.UDP() / scapy.DNS(qr=1, rcode=3, qd=scapy.DNSQR(qname="missing.example"))
        self.assertTrue(decode_application_layer(nx_packet)["nxdomain"])

    def test_malformed_dns_layer_is_safe(self):
        packet = scapy.Ether() / scapy.IP() / scapy.UDP() / scapy.DNS(qdcount=1, qd=None)
        result = decode_application_layer(packet)
        self.assertEqual("DNS", result["protocol"])
        self.assertEqual([], result["questions"])


class FTPDecoderTests(unittest.TestCase):
    def test_user_and_pass_commands_are_decoded_and_flagged(self):
        for payload, command in ((b"USER analyst\r\n", "USER"), (b"PASS secret\r\n", "PASS")):
            result = decode_application_layer(_packet(payload, scapy.TCP(dport=21)))
            self.assertEqual(command, result["command"])
            self.assertTrue(any("FTP" in item for item in analyze_payload_security(_packet(payload))))
        self.assertIn("Cleartext FTP USER command detected.", analyze_payload_security(_packet(b"USER analyst\r\n")))
        self.assertIn("Cleartext FTP PASS (password) command detected.", analyze_payload_security(_packet(b"PASS secret\r\n")))

    def test_other_command_and_numeric_response(self):
        command = decode_application_layer(_packet(b"RETR report.txt\r\n"))
        response = decode_application_layer(_packet(b"230 User logged in\r\n"))
        self.assertEqual("RETR", command["command"])
        self.assertEqual(230, response["code"])
        self.assertEqual("response", response["kind"])


class ICMPDecoderTests(unittest.TestCase):
    def test_echo_request_and_reply_fields(self):
        request = decode_application_layer(scapy.IP() / scapy.ICMP(type=8, id=12, seq=4))
        reply = decode_application_layer(scapy.IP() / scapy.ICMP(type=0, id=12, seq=4))
        self.assertEqual("Echo Request", request["type_name"])
        self.assertEqual(12, request["identifier"])
        self.assertEqual(4, reply["sequence"])

    def test_icmpv6_echo_where_supported(self):
        packet = scapy.IPv6() / scapy.ICMPv6EchoRequest(id=9, seq=2)
        result = decode_application_layer(packet)
        self.assertEqual("ICMPv6", result["protocol"])
        self.assertEqual("Echo Request", result["type_name"])
        self.assertEqual(9, result["identifier"])

    def test_icmpv6_error_message_type_and_code(self):
        packet = scapy.IPv6() / scapy.ICMPv6DestUnreach(code=4)
        result = decode_application_layer(packet)
        self.assertEqual("ICMPv6", result["protocol"])
        self.assertEqual("Destination Unreachable", result["type_name"])
        self.assertEqual(4, result["code"])


class PayloadAndSecurityTests(unittest.TestCase):
    def test_payload_ascii_hex_length_and_truncation_are_bounded(self):
        packet = _packet(b"hello\x00world")
        view = inspect_payload(packet, max_bytes=5)
        self.assertEqual(11, view["length"])
        self.assertEqual("hello", view["ascii"])
        self.assertEqual("68 65 6c 6c 6f", view["hex"])
        self.assertTrue(view["truncated"])

    def test_missing_raw_payload_has_empty_preview(self):
        view = inspect_payload(scapy.IP() / scapy.TCP())
        self.assertFalse(view["present"])
        self.assertEqual("", view["hex"])

    def test_basic_auth_is_structured_and_legacy_message_is_preserved(self):
        packet = _packet(b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n")
        self.assertTrue(any("user:password" in message for message in analyze_payload_security(packet)))
        finding = next(item for item in analyze_payload_findings(packet) if item["category"] == "cleartext_credentials")
        self.assertTrue(finding["heuristic"])
        self.assertEqual("HTTP Authorization header", finding["source"])

    def test_file_signatures_pem_base64_and_password_indicators(self):
        cases = (
            (b"\x89PNG\r\n\x1a\ncontent", "PNG"),
            (b"\xff\xd8\xffjpeg", "JPEG"),
            (b"%PDF-1.7\n", "PDF"),
            (b"PK\x03\x04archive", "ZIP"),
            (b"\x7fELFbinary", "ELF"),
            (b"-----BEGIN PRIVATE KEY-----", "PEM"),
            (b"password=hidden", "password"),
            (b"A" * 48, "base64"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertTrue(any(expected.lower() in finding.lower() for finding in analyze_payload_security(_packet(payload))))

    def test_benign_payload_has_no_inappropriate_findings(self):
        self.assertEqual([], analyze_payload_security(_packet(b"hello, ordinary packet")))

    def test_bundle_keeps_legacy_keys_and_adds_structured_results(self):
        result = decode_packet(_packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        self.assertTrue({"layers", "application", "security_findings"}.issubset(result))
        self.assertIn("payload", result)
        self.assertIn("findings", result)
        self.assertEqual("HTTP", result["application"]["protocol"])


if __name__ == "__main__":
    unittest.main()
