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
        "protocol": "OTHER",
        "sport": "",
        "dport": "",
        "length": len(packet),
    }

    if packet.haslayer(scapy.Ether):
        metadata["src"] = packet[scapy.Ether].src
        metadata["dst"] = packet[scapy.Ether].dst

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