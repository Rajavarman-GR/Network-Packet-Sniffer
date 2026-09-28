"""Streaming PCAP iteration with bounded packet batches."""

import scapy.all as scapy


def iter_pcap_batches(path, batch_size=128, cancel_event=None):
    """Yield bounded batches while closing the reader on success or failure."""
    batch_size = max(1, int(batch_size))
    batch = []
    # Own the underlying file descriptor outside Scapy's constructor too.
    # PcapReader validates the magic header while constructing itself, before
    # its context manager can be entered; this outer context closes malformed
    # files reliably on Windows when that validation raises.
    with open(str(path), "rb") as source:
        with scapy.PcapReader(source) as capture:
            for packet in capture:
                if cancel_event is not None and cancel_event.is_set():
                    break
                batch.append(packet)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
    if batch:
        yield batch
