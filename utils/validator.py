import ipaddress

from core.interfaces import get_network_interfaces


def validate_interface(interface):
    return bool(interface) and interface in get_network_interfaces()


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False


def validate_protocol(protocol):
    return protocol in {"ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "ICMPv6"}


def validate_export_filename(filename):
    return bool(filename and str(filename).strip())