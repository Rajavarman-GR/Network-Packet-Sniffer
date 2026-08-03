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

    return packet.haslayer(scapy.ICMP)