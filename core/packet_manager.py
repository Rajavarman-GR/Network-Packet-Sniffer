from collections import deque

from utils.config import MAX_RETAINED_PACKETS


class PacketManager:
	"""Keep a bounded collection of packets with stable identifiers."""

	def __init__(self, max_packets=10000):
		self.max_packets = min(MAX_RETAINED_PACKETS, max(1, int(max_packets)))
		self._packets = deque()
		self._by_id = {}
		self._next_id = 1

	def add(self, packet, metadata):
		record = {"id": self._next_id, "packet": packet, **metadata}
		self._next_id += 1
		evicted = self._packets.popleft() if len(self._packets) >= self.max_packets else None
		if evicted is not None:
			self._by_id.pop(evicted["id"], None)
		self._packets.append(record)
		self._by_id[record["id"]] = record
		return record, evicted

	def get(self, packet_id):
		try:
			packet_id = int(packet_id)
		except (TypeError, ValueError):
			return None
		return self._by_id.get(packet_id)

	def update(self, packet_id, values):
		record = self.get(packet_id)
		if record is None:
			return None
		record.update(values)
		return record

	def records(self):
		return list(self._packets)

	def clear(self):
		self._packets.clear()
		self._by_id.clear()

	def set_max_packets(self, max_packets):
		self.max_packets = min(MAX_RETAINED_PACKETS, max(1, int(max_packets)))
		while len(self._packets) > self.max_packets:
			evicted = self._packets.popleft()
			self._by_id.pop(evicted["id"], None)

	def __len__(self):
		return len(self._packets)
