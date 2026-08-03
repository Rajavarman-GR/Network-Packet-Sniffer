import psutil


def get_network_interfaces():

    interfaces = psutil.net_if_addrs()

    return list(interfaces.keys())