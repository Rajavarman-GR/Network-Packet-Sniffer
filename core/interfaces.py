import psutil
import scapy.all as scapy


def get_network_interfaces():
    try:
        return list(psutil.net_if_addrs().keys())
    except (OSError, psutil.Error):
        return []


def resolve_scapy_interface(interface_name):
    """Map a readable psutil name to Scapy's capture interface identifier."""
    if not interface_name:
        return interface_name

    if interface_name in scapy.conf.ifaces:
        return interface_name

    for interface in scapy.conf.ifaces.values():
        names = {
            getattr(interface, "name", ""),
            getattr(interface, "description", ""),
            getattr(interface, "network_name", ""),
        }
        if interface_name in names:
            return interface.name
    return interface_name