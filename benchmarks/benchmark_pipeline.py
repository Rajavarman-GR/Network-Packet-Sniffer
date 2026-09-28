"""Benchmark parser, decoder, analysis, flow, PCAP, and retention paths.

Run with ``python -m benchmarks.benchmark_pipeline``. Packet construction and
PCAP writing are setup work and are excluded from the reported stage timings.
"""

import argparse
import json
import platform
import time
import tracemalloc
import uuid
from pathlib import Path

import scapy.config

# Benchmarks use only synthetic offline packets; avoid Npcap interface discovery.
scapy.config._set_conf_sockets = lambda: None
import scapy
import scapy.all as scapy_all
scapy_all.conf.ifaces.reload = lambda: None

from ai.flow_tracker import FlowTracker
from core.analysis import analyze_packet
from core.decoder import decode_packet
from core.investigation import InvestigationEngine
from core.packet_manager import PacketManager
from core.parser import get_packet_metadata
from core.pcap import iter_pcap_batches


def build_packets(count):
    packets = []
    for index in range(count):
        source = "192.0.2.{}".format((index % 250) + 1)
        destination = "198.51.100.{}".format(((index // 250) % 250) + 1)
        packet = scapy_all.IP(src=source, dst=destination) / scapy_all.UDP(
            sport=(10000 + index % 50000), dport=53
        ) / scapy_all.Raw(load=b"benchmark-payload")
        packet.time = 1700000000 + index / 1000.0
        packets.append(packet)
    return packets


def _measure(name, packet_count, callback):
    started = time.perf_counter()
    callback()
    elapsed = time.perf_counter() - started
    return {
        "stage": name,
        "input_packets": packet_count,
        "elapsed_seconds": round(elapsed, 6),
        "packets_per_second": round(packet_count / elapsed, 2) if elapsed else None,
    }


def _run_each(items, callback):
    for item in items:
        callback(item)


def benchmark_scale(count, pcap_batch_size=128, retention_limit=10000):
    packets = build_packets(count)
    records = []
    measurements = []

    measurements.append(_measure("parser_metadata", count, lambda: records.extend(
        {"packet": packet, "id": index + 1,
         **get_packet_metadata(packet, "%H:%M:%S")}
        for index, packet in enumerate(packets)
    )))
    measurements.append(_measure("decoder", count, lambda: _run_each(packets, decode_packet)))
    unavailable = {"available": False, "label": "UNAVAILABLE", "confidence": None,
                   "risk_score": None, "model_version": None}
    measurements.append(_measure("unified_analysis_with_parser_metadata", count,
        lambda: _run_each(records, lambda record: analyze_packet(
            record["packet"], record["id"], record, unavailable))))

    tracker = FlowTracker(max_flows=10000, max_endpoints=10000)
    measurements.append(_measure("runtime_flow_tracker", count, lambda: _run_each(records, lambda record:
        tracker.observe(record["packet"], record, record["packet"].time))))
    investigation_count = min(count, retention_limit)
    engine = InvestigationEngine(max_records=retention_limit)
    investigation_results = [None]
    measurements.append(_measure("investigation_engine", investigation_count, lambda:
        investigation_results.__setitem__(0, engine.analyze(records))))

    pcap_path = Path.cwd() / ".benchmark-{}-{}.pcap".format(uuid.uuid4().hex, count)
    try:
        with pcap_path.open("xb"):
            pass
        scapy_all.wrpcap(str(pcap_path), packets)
        packets_read = [0]

        def read_pcap():
            for batch in iter_pcap_batches(pcap_path, pcap_batch_size):
                packets_read[0] += len(batch)

        measurement = _measure("pcap_stream_batches", count, read_pcap)
        measurement["batch_size"] = pcap_batch_size
        measurement["packets_read"] = packets_read[0]
        measurements.append(measurement)
    finally:
        pcap_path.unlink(missing_ok=True)

    tracemalloc.start()
    manager = PacketManager(max_packets=retention_limit)
    def retain_packets():
        for index, packet in enumerate(packets):
            metadata = {key: value for key, value in records[index].items()
                        if key not in {"id", "packet"}}
            manager.add(packet, metadata)

    retention_measurement = _measure("packet_retention", count, retain_packets)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    retention_measurement.update({"retained_records": len(manager),
                                  "retention_limit": retention_limit,
                                  "python_allocation_peak_bytes": peak,
                                  "packet_objects_preallocated": True})
    measurements.append(retention_measurement)

    return {
        "packet_count": count,
        "measurements": measurements,
        "investigation_retained_packets": (investigation_results[0] or {}).get("packet_count"),
        "investigation_conversations": len((investigation_results[0] or {}).get("flows", [])),
        "flow_tracker_flows": len(tracker.flows),
        "flow_tracker_endpoints": len(tracker.endpoints),
    }


def build_argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scales", nargs="+", type=int, default=[1000, 10000, 50000])
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--retention-limit", type=int, default=10000)
    return parser


def main(argv=None):
    args = build_argument_parser().parse_args(argv)
    if any(count < 1 for count in args.scales) or args.batch_size < 1 or args.retention_limit < 1:
        raise SystemExit("scales, batch size, and retention limit must be positive")
    results = [benchmark_scale(count, args.batch_size, args.retention_limit) for count in args.scales]
    print(json.dumps({"python": platform.python_version(), "platform": platform.platform(),
                      "scapy": scapy.__version__, "results": results}, indent=2))


if __name__ == "__main__":
    main()
