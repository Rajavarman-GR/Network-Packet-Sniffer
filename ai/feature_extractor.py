"""Deterministic runtime feature schema shared by training and inference."""

import scapy.all as scapy

FEATURE_SCHEMA_VERSION = "1.0"
FEATURE_NAMES = (
    "packet_length",
    "protocol_tcp",
    "protocol_udp",
    "protocol_dns",
    "protocol_arp",
    "protocol_icmp",
    "protocol_icmpv6",
    "protocol_other",
    "source_port",
    "destination_port",
    "tcp_flags",
    "payload_length",
    "ip_ttl_or_hop_limit",
    "source_packet_count",
    "destination_packet_count",
    "source_byte_count",
    "destination_byte_count",
    "packet_rate",
    "byte_rate",
    "unique_destination_count",
    "unique_destination_port_count",
    "connection_frequency",
    "dns_activity",
)


def extract_features(packet, metadata, context):
    """Return one feature vector in the stable FEATURE_NAMES order."""
    protocol = metadata.get("protocol", "OTHER")
    protocol_values = {
        "protocol_tcp": float(protocol == "TCP"),
        "protocol_udp": float(protocol == "UDP"),
        "protocol_dns": float(protocol == "DNS"),
        "protocol_arp": float(protocol == "ARP"),
        "protocol_icmp": float(protocol == "ICMP"),
        "protocol_icmpv6": float(protocol == "ICMPv6"),
        "protocol_other": float(protocol not in {"TCP", "UDP", "DNS", "ARP", "ICMP", "ICMPv6"}),
    }
    payload_length = len(bytes(packet[scapy.Raw].load)) if packet.haslayer(scapy.Raw) else 0
    tcp_flags = int(packet[scapy.TCP].flags) if packet.haslayer(scapy.TCP) else 0
    ttl = 0
    if packet.haslayer(scapy.IP):
        ttl = int(packet[scapy.IP].ttl or 0)
    elif packet.haslayer(scapy.IPv6):
        ttl = int(packet[scapy.IPv6].hlim or 0)

    values = {
        "packet_length": len(packet),
        **protocol_values,
        "source_port": int(metadata.get("sport") or 0),
        "destination_port": int(metadata.get("dport") or 0),
        "tcp_flags": tcp_flags,
        "payload_length": payload_length,
        "ip_ttl_or_hop_limit": ttl,
        "source_packet_count": context.get("source_packet_count", 0),
        "destination_packet_count": context.get("destination_packet_count", 0),
        "source_byte_count": context.get("source_byte_count", 0),
        "destination_byte_count": context.get("destination_byte_count", 0),
        "packet_rate": context.get("packet_rate", 0.0),
        "byte_rate": context.get("byte_rate", 0.0),
        "unique_destination_count": context.get("unique_destination_count", 0),
        "unique_destination_port_count": context.get("unique_destination_port_count", 0),
        "connection_frequency": context.get("connection_frequency", 0.0),
        "dns_activity": 1.0 if protocol == "DNS" else 0.0,
    }
    return [float(values[name]) for name in FEATURE_NAMES]
