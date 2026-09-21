from collections import deque


class PacketManager:
	"""Keep a bounded collection of packets with stable identifiers."""

	def __init__(self, max_packets=10000):
		self.max_packets = max(1, int(max_packets))
		self._packets = deque()
		self._next_id = 1

	def add(self, packet, metadata):
		record = {"id": self._next_id, "packet": packet, **metadata}
		self._next_id += 1
		evicted = self._packets.popleft() if len(self._packets) >= self.max_packets else None
		self._packets.append(record)
		return record, evicted

	def get(self, packet_id):
		try:
			packet_id = int(packet_id)
		except (TypeError, ValueError):
			return None
		return next((record for record in self._packets if record["id"] == packet_id), None)

	def records(self):
		return list(self._packets)

	def clear(self):
		self._packets.clear()

	def set_max_packets(self, max_packets):
		self.max_packets = max(1, int(max_packets))
		while len(self._packets) > self.max_packets:
			self._packets.popleft()

	def __len__(self):
		return len(self._packets)
