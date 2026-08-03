import scapy.all as scapy


class PacketSniffer:

    def __init__(self):

        self.sniffer = None

        self.running = False

    ##################################################

    def start(self, interface, callback):

        if self.running:
            return

        self.sniffer = scapy.AsyncSniffer(
            iface=interface,
            prn=callback,
            store=False
        )

        self.sniffer.start()

        self.running = True

    ##################################################

    def stop(self):

        if self.sniffer and self.running:

            self.sniffer.stop()

            self.running = False