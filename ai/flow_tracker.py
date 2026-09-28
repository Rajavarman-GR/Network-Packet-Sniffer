"""Bounded, worker-thread traffic context for runtime feature extraction."""

from collections import OrderedDict, deque
import math
import struct
import time

MAX_PACKET_TIMESTAMPS_PER_ENDPOINT = 6000


class FlowTracker:
    """Track bounded directed flows and endpoint context for runtime features.

    Expiration is swept periodically, and each endpoint keeps at most 6,000
    recent packet timestamps so burst traffic cannot grow the history forever.
    """

    def __init__(self, max_flows=10000, expiration_seconds=300, window_seconds=60,
                 max_unique_values=1000, max_endpoints=None, expiration_sweep_seconds=1.0):
        self.max_flows = max(1, int(max_flows))
        self.max_endpoints = max(1, int(max_endpoints or self.max_flows))
        self.expiration_seconds = max(1, float(expiration_seconds))
        self.window_seconds = max(1, float(window_seconds))
        self.max_unique_values = max(1, int(max_unique_values))
        self.expiration_sweep_seconds = max(0.1, float(expiration_sweep_seconds))
        self.flows = OrderedDict()
        self.endpoints = OrderedDict()
        self._last_expiration_sweep = None

    def observe(self, packet, metadata, timestamp=None):
        try:
            now = float(timestamp if timestamp is not None else time.time())
        except (TypeError, ValueError, OverflowError):
            now = time.time()
        if not math.isfinite(now):
            now = time.time()
        self._expire(now)
        source = metadata.get("src", "")
        destination = metadata.get("dst", "")
        sport = _int_or_zero(metadata.get("sport"))
        dport = _int_or_zero(metadata.get("dport"))
        protocol = metadata.get("protocol", "OTHER")
        flow_key = (source, destination, sport, dport, protocol)
        try:
            length = max(0, int(metadata.get("length") or len(packet)))
        except (AttributeError, TypeError, ValueError, OverflowError, struct.error):
            length = 0
        flow = self.flows.get(flow_key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self.flows.popitem(last=False)
            flow = {"first_seen": now, "last_seen": now, "packets": 0, "bytes": 0}
            self.flows[flow_key] = flow
        else:
            self.flows.move_to_end(flow_key)
        flow["last_seen"] = now
        flow["packets"] += 1
        flow["bytes"] += length
        source_stats = self._endpoint(source, now)
        destination_stats = self._endpoint(destination, now)
        self._prune_endpoint(source_stats, now - self.window_seconds)
        if destination_stats is not source_stats:
            self._prune_endpoint(destination_stats, now - self.window_seconds)
        source_stats["packet_times"].append(now)
        source_stats["bytes"] += length
        if len(source_stats["destinations"]) < self.max_unique_values:
            source_stats["destinations"].add(destination)
        if len(source_stats["destination_ports"]) < self.max_unique_values:
            source_stats["destination_ports"].add(dport)
        if destination_stats is not source_stats:
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
            if len(self.endpoints) >= self.max_endpoints:
                self.endpoints.popitem(last=False)
            self.endpoints[address] = {
                "last_seen": now,
                "bytes": 0,
                "packet_times": deque(maxlen=MAX_PACKET_TIMESTAMPS_PER_ENDPOINT),
                "destinations": set(),
                "destination_ports": set(),
            }
        endpoint = self.endpoints[address]
        endpoint["last_seen"] = now
        self.endpoints.move_to_end(address)
        return endpoint

    @staticmethod
    def _prune_endpoint(stats, cutoff):
        while stats["packet_times"] and stats["packet_times"][0] < cutoff:
            stats["packet_times"].popleft()

    def _expire(self, now):
        if (self._last_expiration_sweep is not None
                and now >= self._last_expiration_sweep
                and now - self._last_expiration_sweep < self.expiration_sweep_seconds):
            return
        for endpoint, stats in list(self.endpoints.items()):
            if now - stats["last_seen"] > self.expiration_seconds:
                del self.endpoints[endpoint]
        for flow_key, flow in list(self.flows.items()):
            if now - flow["last_seen"] > self.expiration_seconds:
                del self.flows[flow_key]
        self._last_expiration_sweep = now

    def clear(self):
        self.flows.clear()
        self.endpoints.clear()
        self._last_expiration_sweep = None


def _int_or_zero(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
