import unittest

import scapy.all as scapy

from core.decoder import (
    analyze_payload_security,
    decode_application_layer,
    decode_layers,
    decode_packet,
)


def _build_client_hello_with_sni(hostname):
    """Hand-build a minimal TLS record + Handshake + ClientHello with a
    server_name (SNI) extension, byte-for-byte per RFC 8446 / RFC 6066,
    so decode_application_layer can be exercised without a live capture
    or the optional scapy-tls addon."""

    hostname_bytes = hostname.encode("ascii")
    name_entry = bytes([0]) + len(hostname_bytes).to_bytes(2, "big") + hostname_bytes
    server_name_list = len(name_entry).to_bytes(2, "big") + name_entry
    sni_extension = (0).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list

    client_version = bytes([3, 3])
    random_bytes = bytes(32)
    session_id = b""
    cipher_suites = bytes([0x00, 0x2F])
    compression_methods = bytes([0x00])

    body = (
        client_version
        + random_bytes
        + bytes([len(session_id)]) + session_id
        + len(cipher_suites).to_bytes(2, "big") + cipher_suites
        + bytes([len(compression_methods)]) + compression_methods
        + len(sni_extension).to_bytes(2, "big") + sni_extension
    )

    handshake = bytes([1]) + len(body).to_bytes(3, "big") + body
    return bytes([22, 3, 3]) + len(handshake).to_bytes(2, "big") + handshake


class DecodeLayersTests(unittest.TestCase):
    def test_generic_layer_walk_covers_ether_ip_tcp(self):
        packet = scapy.Ether() / scapy.IP(src="10.0.0.5", ttl=64) / scapy.TCP(dport=443)
        layers = decode_layers(packet)
        names = [layer["name"] for layer in layers]
        self.assertEqual(names, ["Ether", "IP", "TCP"])
        ip_fields = dict(next(l for l in layers if l["name"] == "IP")["fields"])
        self.assertEqual(ip_fields["src"], "10.0.0.5")
        self.assertEqual(ip_fields["ttl"], "64")

    def test_arp_operation_is_human_readable(self):
        packet = scapy.Ether() / scapy.ARP(op=1, psrc="192.168.1.5", pdst="192.168.1.1")
        arp_fields = dict(next(l for l in decode_layers(packet) if l["name"] == "ARP")["fields"])
        self.assertIn("who-has", arp_fields["op"])

    def test_long_field_values_are_truncated(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP() / scapy.Raw(load=b"A" * 1000)
        raw_fields = dict(next(l for l in decode_layers(packet) if l["name"] == "Raw")["fields"])
        self.assertLess(len(raw_fields["load"]), 1000)
        self.assertIn("chars total", raw_fields["load"])


class DecodeApplicationLayerTests(unittest.TestCase):
    def test_http_request_is_parsed(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(dport=80) / scapy.Raw(load=payload)
        result = decode_application_layer(packet)
        self.assertEqual(result["protocol"], "HTTP")
        self.assertEqual(result["kind"], "request")
        self.assertEqual(result["headers"]["Host"], "example.com")

    def test_http_response_body_preview(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(sport=80) / scapy.Raw(load=payload)
        result = decode_application_layer(packet)
        self.assertEqual(result["kind"], "response")
        self.assertEqual(result["body_preview"], "hello")

    def test_tls_client_hello_sni_is_extracted(self):
        payload = _build_client_hello_with_sni("example.com")
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(dport=443) / scapy.Raw(load=payload)
        result = decode_application_layer(packet)
        self.assertEqual(result["protocol"], "TLS")
        self.assertEqual(result["content_type"], "Handshake")
        self.assertEqual(result["handshake_type"], "ClientHello")
        self.assertEqual(result["server_name"], "example.com")

    def test_arbitrary_binary_payload_does_not_false_positive(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(dport=12345) / scapy.Raw(load=bytes(range(256)))
        self.assertIsNone(decode_application_layer(packet))

    def test_no_raw_layer_returns_none(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP()
        self.assertIsNone(decode_application_layer(packet))


class AnalyzePayloadSecurityTests(unittest.TestCase):
    def test_http_basic_auth_is_decoded(self):
        payload = (
            b"GET /secret HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n"
        )
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(dport=80) / scapy.Raw(load=payload)
        findings = analyze_payload_security(packet)
        self.assertTrue(any("user:password" in f for f in findings))

    def test_ftp_user_command_is_flagged(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(dport=21) / scapy.Raw(load=b"USER admin\r\n")
        findings = analyze_payload_security(packet)
        self.assertTrue(any("USER" in f for f in findings))

    def test_embedded_png_signature_is_flagged(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP() / scapy.Raw(load=b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
        findings = analyze_payload_security(packet)
        self.assertTrue(any("PNG" in f for f in findings))

    def test_no_payload_returns_no_findings(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP()
        self.assertEqual(analyze_payload_security(packet), [])


class DecodePacketTests(unittest.TestCase):
    def test_bundles_all_three_analyses(self):
        packet = scapy.Ether() / scapy.IP() / scapy.TCP(dport=80) / scapy.Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        bundle = decode_packet(packet)
        self.assertEqual(set(bundle.keys()), {"layers", "application", "security_findings"})
        self.assertTrue(len(bundle["layers"]) >= 3)
        self.assertEqual(bundle["application"]["protocol"], "HTTP")


if __name__ == "__main__":
    unittest.main()
