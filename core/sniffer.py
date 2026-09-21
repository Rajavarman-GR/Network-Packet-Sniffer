import scapy.all as scapy


class PacketSniffer:

    def __init__(self):
        self.sniffer = None
        self.running = False
        self.filter_expression = None

    def start(self, interface, callback, filter_expression=None):
        if self.running:
            return

        self.filter_expression = filter_expression or ""
        self.sniffer = scapy.AsyncSniffer(
            iface=interface,
            prn=callback,
            store=False,
            filter=self.filter_expression
        )

        self.sniffer.start()
        self.running = True

    def stop(self):
        """Stop packet capture safely."""
        if not self.running:
            return

        try:
            if self.sniffer is not None:
                self.sniffer.stop()
        except Exception as exc:
            print(f"[Sniffer] Stop Error: {exc}")
        finally:
            self.sniffer = None
            self.running = False
            self.filter_expression = None