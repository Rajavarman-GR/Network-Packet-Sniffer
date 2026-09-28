"""Streaming PCAP iteration with bounded packet batches."""

import scapy.all as scapy


def iter_pcap_batches(path, batch_size=128, cancel_event=None):
    """Yield bounded batches while closing the reader on success or failure."""
    batch_size = max(1, int(batch_size))
    batch = []
    with scapy.PcapReader(str(path)) as capture:
        for packet in capture:
            if cancel_event is not None and cancel_event.is_set():
                break
            batch.append(packet)
            if len(batch) >= batch_size:
                yield batch
                batch = []
    if batch:
        yield batch
