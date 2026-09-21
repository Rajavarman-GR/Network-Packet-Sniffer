import ipaddress


def build_bpf_filter(protocol, src_ip=None, dst_ip=None, ports=None):
    if not protocol or protocol == "ALL":
        return ""

    protocol_map = {
        "TCP": "tcp",
        "UDP": "udp",
        "ICMP": "icmp",
        "ARP": "arp",
        "DNS": "(udp port 53 or tcp port 53)",
        "ICMPv6": "icmp6",
    }

    expression = protocol_map.get(protocol)
    if expression is None:
        return ""

    parts = [expression]
    if _valid_ip(src_ip):
        parts.append(f"host {src_ip}")
    if _valid_ip(dst_ip):
        parts.append(f"host {dst_ip}")
    if _valid_port(ports):
        parts.append(f"port {ports}")

    return " and ".join(parts)


def _valid_ip(value):
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    return True


def _valid_port(value):
    try:
        return 1 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False
