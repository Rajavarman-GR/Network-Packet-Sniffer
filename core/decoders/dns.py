"""Structured DNS query and answer summaries from Scapy's DNS layers."""

from .base import ProtocolDecoder

try:
    import scapy.all as scapy
except ImportError:  # pragma: no cover - Scapy is a project dependency
    scapy = None

_RECORD_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def _name(value):
    if isinstance(value, bytes):
        return value.rstrip(b"\0").decode("ascii", "replace").rstrip(".")
    return str(value or "").rstrip(".")


def _section_items(section, count, limit=64):
    """Handle Scapy's packet chains and list-like DNS sections safely."""
    if section is None:
        return []
    is_collection = isinstance(section, (list, tuple)) or (
        not hasattr(section, "fields_desc") and hasattr(section, "__iter__")
    )
    if count is None:
        try:
            count = len(section) if is_collection else 1
        except TypeError:
            count = 1
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = 1 if not is_collection else 0
    if count <= 0:
        return []
    if is_collection:
        try:
            return list(section)[:min(count, limit)]
        except TypeError:
            return []
    items = []
    current = section
    while current is not None and len(items) < min(count, limit):
        items.append(current)
        nxt = getattr(current, "payload", None)
        if nxt is current or nxt is None or nxt.__class__.__name__ == "NoPayload":
            break
        current = nxt
    return items


class DNSDecoder(ProtocolDecoder):
    name = "DNS"
    priority = 100

    def applies(self, packet, payload):
        return bool(scapy and hasattr(packet, "haslayer") and packet.haslayer(scapy.DNS))

    def decode(self, packet, payload):
        dns = packet.getlayer(scapy.DNS)
        is_response = bool(getattr(dns, "qr", 0))
        result = {
            "protocol": "DNS",
            "kind": "response" if is_response else "query",
            "transaction_id": getattr(dns, "id", None),
            "flags": {
                "qr": int(getattr(dns, "qr", 0) or 0), "opcode": int(getattr(dns, "opcode", 0) or 0),
                "aa": bool(getattr(dns, "aa", 0)), "tc": bool(getattr(dns, "tc", 0)),
                "rd": bool(getattr(dns, "rd", 0)), "ra": bool(getattr(dns, "ra", 0)),
                "rcode": int(getattr(dns, "rcode", 0) or 0),
            },
            "questions": [], "answers": [],
        }
        for question in _section_items(getattr(dns, "qd", None), getattr(dns, "qdcount", None)):
            qtype = int(getattr(question, "qtype", 0) or 0)
            item = {"name": _name(getattr(question, "qname", "")), "type": _RECORD_TYPES.get(qtype, "TYPE{}".format(qtype)), "type_code": qtype}
            result["questions"].append(item)
        for answer in _section_items(getattr(dns, "an", None), getattr(dns, "ancount", None)):
            rtype = int(getattr(answer, "type", 0) or 0)
            result["answers"].append({
                "name": _name(getattr(answer, "rrname", "")),
                "type": _RECORD_TYPES.get(rtype, "TYPE{}".format(rtype)),
                "type_code": rtype, "ttl": getattr(answer, "ttl", None),
                "data": str(getattr(answer, "rdata", ""))[:512],
            })
        if result["questions"]:
            result["queried_domain"] = result["questions"][0]["name"]
            result["record_type"] = result["questions"][0]["type"]
        result["nxdomain"] = is_response and result["flags"]["rcode"] == 3
        return result
