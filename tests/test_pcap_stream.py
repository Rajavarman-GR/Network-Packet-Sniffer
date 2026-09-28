import os
import threading
import tempfile
import unittest

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap
from scapy.utils import PcapWriter

from core.pcap import iter_pcap_batches


class PcapStreamingTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)

    def path(self, name="sample.pcap"):
        return os.path.join(self.temporary_directory.name, name)

    def test_empty_capture(self):
        path = self.path("empty.pcap")
        writer = PcapWriter(path, linktype=1, sync=True)
        writer.close()
        self.assertEqual([], list(iter_pcap_batches(path, batch_size=4)))

    def test_single_and_mixed_protocol_capture(self):
        packets = [
            Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=10, dport=80),
            Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(sport=11, dport=53) / DNS(qd=DNSQR(qname="example.test")),
            Ether() / ARP(psrc="192.0.2.3", pdst="192.0.2.4"),
        ]
        path = self.path()
        wrpcap(path, packets)
        batches = list(iter_pcap_batches(path, batch_size=2))
        self.assertEqual([2, 1], [len(batch) for batch in batches])
        self.assertTrue(batches[1][0].haslayer(ARP))
        self.assertTrue(batches[0][1].haslayer(DNS))

    def test_large_capture_is_yielded_in_bounded_batches_and_can_cancel(self):
        path = self.path("large.pcap")
        wrpcap(path, [Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1000 + i, dport=53) for i in range(301)])
        batches = list(iter_pcap_batches(path, batch_size=32))
        self.assertEqual(301, sum(map(len, batches)))
        self.assertLessEqual(max(map(len, batches)), 32)
        cancelled = threading.Event()
        cancelled.set()
        self.assertEqual([], list(iter_pcap_batches(path, batch_size=32, cancel_event=cancelled)))

    def test_invalid_capture_reports_reader_error(self):
        path = self.path("invalid.pcap")
        with open(path, "wb") as handle:
            handle.write(b"not a pcap")
        with self.assertRaises(Exception):
            list(iter_pcap_batches(path))


if __name__ == "__main__":
    unittest.main()
