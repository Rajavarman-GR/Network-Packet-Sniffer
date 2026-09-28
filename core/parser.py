import time
import math
import struct

import scapy.all as scapy


def packet_summary(packet):
    return packet.summary()


def packet_length(packet):
    try:
        value = getattr(packet, "wirelen", None)
        if value is not None and int(value) >= 0:
            return int(value)
    except (AttributeError, TypeError, ValueError, OverflowError):
        pass
    try:
        original = getattr(packet, "original", None)
        if isinstance(original, (bytes, bytearray, memoryview)):
            return len(original)
    except (AttributeError, TypeError, ValueError):
        pass
    try:
        return len(packet)
    except (AttributeError, TypeError, ValueError, OverflowError, struct.error):
        return 0


def _has_layer(packet, layer):
    try:
        return bool(packet is not None and packet.haslayer(layer))
    except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
        return False


def has_tcp(packet):
    return _has_layer(packet, scapy.TCP)


def has_udp(packet):
    return _has_layer(packet, scapy.UDP)


def has_icmp(packet):
    return _has_layer(packet, scapy.ICMP) or _has_icmpv6_echo(packet)


def _has_icmpv6_echo(packet):
    return (
        _has_layer(packet, scapy.ICMPv6EchoRequest)
        or _has_layer(packet, scapy.ICMPv6EchoReply)
    )


def get_packet_metadata(packet, timestamp_format="%H:%M:%S"):
    try:
        packet_time = float(packet.time)
        if not math.isfinite(packet_time):
            raise ValueError("non-finite packet timestamp")
        timestamp = time.strftime(timestamp_format, time.localtime(packet_time))
    except (AttributeError, TypeError, ValueError, OverflowError, OSError):
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
        "length": packet_length(packet),
    }

    if _has_layer(packet, scapy.Ether):
        try:
            metadata["src"] = packet[scapy.Ether].src or ""
            metadata["dst"] = packet[scapy.Ether].dst or ""
            metadata["src_mac"] = metadata["src"]
            metadata["dst_mac"] = metadata["dst"]
        except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
            pass

    if _has_layer(packet, scapy.IP):
        try:
            ip_layer = packet[scapy.IP]
            metadata["src"] = ip_layer.src or ""
            metadata["dst"] = ip_layer.dst or ""
        except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
            pass
    elif _has_layer(packet, scapy.IPv6):
        try:
            ipv6_layer = packet[scapy.IPv6]
            metadata["src"] = ipv6_layer.src or ""
            metadata["dst"] = ipv6_layer.dst or ""
        except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
            pass
    elif _has_layer(packet, scapy.ARP):
        try:
            arp_layer = packet[scapy.ARP]
            metadata["src"] = arp_layer.psrc or ""
            metadata["dst"] = arp_layer.pdst or ""
            metadata["protocol"] = "ARP"
        except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
            pass
        if metadata["protocol"] == "ARP":
            return metadata

    if _has_layer(packet, scapy.DNS):
        metadata["protocol"] = "DNS"
        _read_ports(packet, metadata)
    elif _has_layer(packet, scapy.TCP):
        metadata["protocol"] = "TCP"
        _read_ports(packet, metadata, scapy.TCP)
    elif _has_layer(packet, scapy.UDP):
        metadata["protocol"] = "UDP"
        _read_ports(packet, metadata, scapy.UDP)
    elif _has_layer(packet, scapy.ICMP):
        metadata["protocol"] = "ICMP"
    elif _has_icmpv6_echo(packet):
        metadata["protocol"] = "ICMPv6"

    return metadata


def _read_ports(packet, metadata, transport=None):
    for layer in ((transport,) if transport is not None else (scapy.TCP, scapy.UDP)):
        if not _has_layer(packet, layer):
            continue
        try:
            metadata["sport"] = packet[layer].sport
            metadata["dport"] = packet[layer].dport
        except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
            pass
        return


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
    try:
        limit = max(0, int(max_bytes))
    except (TypeError, ValueError, OverflowError):
        limit = 4096
    if not _has_layer(packet, scapy.Raw):
        return {"present": False, "text": "", "hex": "", "truncated": False, "printable": False}

    try:
        payload = packet[scapy.Raw].load or b""
        length = len(payload)
        preview = bytes(payload[:limit])
    except (AttributeError, TypeError, ValueError, IndexError, OverflowError, struct.error):
        return {"present": False, "text": "", "hex": "", "truncated": False, "printable": False}
    printable_bytes = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in preview)
    printable = bool(preview) and printable_bytes / len(preview) >= 0.85
    return {
        "present": True,
        "text": preview.decode("utf-8", errors="replace") if printable else "",
        "hex": preview.hex(" "),
        "truncated": length > limit,
        "printable": printable,
    }
