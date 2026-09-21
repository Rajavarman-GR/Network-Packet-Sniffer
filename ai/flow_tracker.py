"""Bounded, worker-thread traffic context for runtime feature extraction."""

from collections import defaultdict, deque
import time


class FlowTracker:
    def __init__(self, max_flows=10000, expiration_seconds=300, window_seconds=60, max_unique_values=1000):
        self.max_flows = max(1, int(max_flows))
        self.expiration_seconds = max(1, float(expiration_seconds))
        self.window_seconds = max(1, float(window_seconds))
        self.max_unique_values = max(1, int(max_unique_values))
        self.flows = {}
        self.endpoints = {}
        self._sequence = 0

    def observe(self, packet, metadata, timestamp=None):
        now = float(timestamp if timestamp is not None else time.time())
        self._expire(now)
        source = metadata.get("src", "")
        destination = metadata.get("dst", "")
        sport = int(metadata.get("sport") or 0)
        dport = int(metadata.get("dport") or 0)
        protocol = metadata.get("protocol", "OTHER")
        flow_key = (source, destination, sport, dport, protocol)
        length = len(packet)
        flow = self.flows.get(flow_key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                oldest_key = min(self.flows, key=lambda key: self.flows[key]["last_seen"])
                del self.flows[oldest_key]
            flow = {"first_seen": now, "last_seen": now, "packets": 0, "bytes": 0}
            self.flows[flow_key] = flow
        flow["last_seen"] = now
        flow["packets"] += 1
        flow["bytes"] += length
        self._sequence += 1

        source_stats = self._endpoint(source, now)
        destination_stats = self._endpoint(destination, now)
        source_stats["packet_times"].append(now)
        source_stats["bytes"] += length
        if len(source_stats["destinations"]) < self.max_unique_values:
            source_stats["destinations"].add(destination)
        if len(source_stats["destination_ports"]) < self.max_unique_values:
            source_stats["destination_ports"].add(dport)
        destination_stats["packet_times"].append(now)
        destination_stats["bytes"] += length

        elapsed = max(now - source_stats["packet_times"][0], 1.0)
        return {
            "source_packet_count": len(source_stats["packet_times"]),
            "destination_packet_count": len(destination_stats["packet_times"]),
            "source_byte_count": source_stats["bytes"],
            "destination_byte_count": destination_stats["bytes"],
            "packet_rate": len(source_stats["packet_times"]) / elapsed,
            "byte_rate": source_stats["bytes"] / elapsed,
            "unique_destination_count": len(source_stats["destinations"]),
            "unique_destination_port_count": len(source_stats["destination_ports"]),
            "connection_frequency": flow["packets"] / max(now - flow["first_seen"], 1.0),
        }

    def _endpoint(self, address, now):
        if address not in self.endpoints:
            self.endpoints[address] = {
                "last_seen": now,
                "bytes": 0,
                "packet_times": deque(),
                "destinations": set(),
                "destination_ports": set(),
            }
        endpoint = self.endpoints[address]
        endpoint["last_seen"] = now
        return endpoint

    def _expire(self, now):
        cutoff = now - self.window_seconds
        for endpoint in list(self.endpoints):
            stats = self.endpoints[endpoint]
            while stats["packet_times"] and stats["packet_times"][0] < cutoff:
                stats["packet_times"].popleft()
            if now - stats["last_seen"] > self.expiration_seconds:
                del self.endpoints[endpoint]
        for flow_key, flow in list(self.flows.items()):
            if now - flow["last_seen"] > self.expiration_seconds:
                del self.flows[flow_key]

    def clear(self):
        self.flows.clear()
        self.endpoints.clear()
        self._sequence = 0
