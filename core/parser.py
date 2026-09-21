import time

import scapy.all as scapy


def packet_summary(packet):
    return packet.summary()


def packet_length(packet):
    return len(packet)


def has_tcp(packet):
    return packet.haslayer(scapy.TCP)


def has_udp(packet):
    return packet.haslayer(scapy.UDP)


def has_icmp(packet):
    return packet.haslayer(scapy.ICMP) or _has_icmpv6_echo(packet)


def _has_icmpv6_echo(packet):
    return (
        packet.haslayer(scapy.ICMPv6EchoRequest)
        or packet.haslayer(scapy.ICMPv6EchoReply)
    )


def get_packet_metadata(packet, timestamp_format="%H:%M:%S"):
    try:
        timestamp = time.strftime(timestamp_format, time.localtime(float(packet.time)))
    except (AttributeError, TypeError, ValueError):
        timestamp = time.strftime(timestamp_format)

    metadata = {
        "timestamp": timestamp,
        "src": "",
        "dst": "",
        "src_mac": "",
        "dst_mac": "",
        "protocol": "OTHER",
        "sport": "",
        "dport": "",
        "length": len(packet),
    }

    if packet.haslayer(scapy.Ether):
        metadata["src"] = packet[scapy.Ether].src
        metadata["dst"] = packet[scapy.Ether].dst
        metadata["src_mac"] = packet[scapy.Ether].src
        metadata["dst_mac"] = packet[scapy.Ether].dst

    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        metadata["src"] = ip_layer.src
        metadata["dst"] = ip_layer.dst
    elif packet.haslayer(scapy.IPv6):
        ipv6_layer = packet[scapy.IPv6]
        metadata["src"] = ipv6_layer.src
        metadata["dst"] = ipv6_layer.dst
    elif packet.haslayer(scapy.ARP):
        arp_layer = packet[scapy.ARP]
        metadata["src"] = arp_layer.psrc or ""
        metadata["dst"] = arp_layer.pdst or ""
        metadata["protocol"] = "ARP"
        return metadata

    if packet.haslayer(scapy.DNS):
        metadata["protocol"] = "DNS"
        if packet.haslayer(scapy.TCP):
            metadata["sport"] = packet[scapy.TCP].sport
            metadata["dport"] = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            metadata["sport"] = packet[scapy.UDP].sport
            metadata["dport"] = packet[scapy.UDP].dport
    elif packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        metadata["protocol"] = "TCP"
        metadata["sport"] = tcp_layer.sport
        metadata["dport"] = tcp_layer.dport
    elif packet.haslayer(scapy.UDP):
        udp_layer = packet[scapy.UDP]
        metadata["protocol"] = "UDP"
        metadata["sport"] = udp_layer.sport
        metadata["dport"] = udp_layer.dport
    elif packet.haslayer(scapy.ICMP):
        metadata["protocol"] = "ICMP"
    elif _has_icmpv6_echo(packet):
        metadata["protocol"] = "ICMPv6"

    return metadata


def packet_search_text(packet, metadata):
    """Return searchable packet fields without changing retained packet state."""
    fields = [
        metadata.get("timestamp", ""),
        metadata.get("src", ""),
        metadata.get("dst", ""),
        metadata.get("src_mac", ""),
        metadata.get("dst_mac", ""),
        metadata.get("protocol", ""),
        metadata.get("sport", ""),
        metadata.get("dport", ""),
    ]
    return " ".join(str(value) for value in fields if value).lower()


def matches_display_filter(packet, metadata, protocol="ALL", keyword=""):
    known_protocols = {"TCP", "UDP", "DNS", "ARP", "ICMP", "ICMPv6"}
    row_protocol = metadata.get("protocol", "")
    if protocol == "Other" and row_protocol in known_protocols:
        return False
    if protocol not in {"ALL", "Other"} and row_protocol != protocol:
        return False
    return not keyword.strip() or keyword.strip().lower() in packet_search_text(packet, metadata)


def get_payload_preview(packet, max_bytes=4096):
    """Return bounded text and hex previews for a packet's Raw payload."""
    if not packet.haslayer(scapy.Raw):
        return {"present": False, "text": "", "hex": "", "truncated": False, "printable": False}

    payload = bytes(packet[scapy.Raw].load)
    preview = payload[:max_bytes]
    printable_bytes = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in preview)
    printable = bool(preview) and printable_bytes / len(preview) >= 0.85
    return {
        "present": True,
        "text": preview.decode("utf-8", errors="replace") if printable else "",
        "hex": preview.hex(" "),
        "truncated": len(payload) > max_bytes,
        "printable": printable,
    }