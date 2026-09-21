import scapy.all as scapy

from utils.logger import log_error


class PacketSniffer:

    def __init__(self):
        self.sniffer = None
        self.running = False
        self.filter_expression = None

    def start(self, interface, callback, filter_expression=None):
        if self.running:
            return False

        self.filter_expression = filter_expression or ""
        self.sniffer = scapy.AsyncSniffer(
            iface=interface,
            prn=callback,
            store=False,
            filter=self.filter_expression
        )

        try:
            self.sniffer.start()
        except Exception:
            self.sniffer = None
            self.filter_expression = None
            raise
        self.running = True
        return True

    def stop(self):
        """Stop packet capture safely."""
        if not self.running:
            return

        try:
            if self.sniffer is not None and getattr(self.sniffer, "running", True):
                self.sniffer.stop()
        except Exception as exc:
            log_error(f"Capture stop error: {exc}")
        finally:
            self.sniffer = None
            self.running = False
            self.filter_expression = None