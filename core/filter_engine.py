def build_bpf_filter(protocol, src_ip=None, dst_ip=None, ports=None):
    if not protocol or protocol == "ALL":
        return ""

    protocol_map = {
        "TCP": "tcp",
        "UDP": "udp",
        "ICMP": "icmp",
        "ARP": "arp",
        "DNS": "udp port 53",
        "ICMPv6": "icmp6",
    }

    expression = protocol_map.get(protocol)
    if expression is None:
        return ""

    parts = [expression]
    if src_ip:
        parts.append(f"host {src_ip}")
    if dst_ip:
        parts.append(f"host {dst_ip}")
    if ports:
        parts.append(f"port {ports}")

    return " and ".join(parts)
