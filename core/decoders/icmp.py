"""ICMP and ICMPv6 type/code and echo metadata."""

from .base import ProtocolDecoder

try:
    import scapy.all as scapy
except ImportError:  # pragma: no cover - Scapy is a project dependency
    scapy = None

_ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect", 8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem"}
_ICMPV6_TYPES = {128: "Echo Request", 129: "Echo Reply", 1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded", 4: "Parameter Problem", 133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement"}


def _icmpv6_layer_types(packet):
    try:
        layers = packet.layers()
    except (AttributeError, TypeError):
        return ()
    return tuple(
        layer_type for layer_type in layers
        if layer_type.__name__.startswith("ICMPv6")
        and {field.name for field in getattr(layer_type, "fields_desc", ())}.issuperset({"type", "code"})
    )


class ICMPDecoder(ProtocolDecoder):
    name = "ICMP"
    priority = 60

    def applies(self, packet, payload):
        return bool(scapy and hasattr(packet, "haslayer") and (
            packet.haslayer(scapy.ICMP) or _icmpv6_layer_types(packet)
        ))

    def decode(self, packet, payload):
        if packet.haslayer(scapy.ICMP):
            layer = packet.getlayer(scapy.ICMP)
            message_type = int(layer.type)
            result = {"protocol": "ICMP", "type": message_type, "type_name": _ICMP_TYPES.get(message_type, "Unknown"), "code": int(layer.code)}
            if message_type in {0, 8}:
                result.update({"identifier": int(layer.id), "sequence": int(layer.seq)})
            return result
        for layer_type in _icmpv6_layer_types(packet):
            if packet.haslayer(layer_type):
                layer = packet.getlayer(layer_type)
                message_type = int(getattr(layer, "type", getattr(layer, "typecode", 0)))
                result = {"protocol": "ICMPv6", "type": message_type, "type_name": _ICMPV6_TYPES.get(message_type, layer_type.__name__), "code": int(getattr(layer, "code", 0))}
                if message_type in {128, 129} and hasattr(layer, "id") and hasattr(layer, "seq"):
                    result.update({"identifier": int(layer.id), "sequence": int(layer.seq)})
                return result
        return {"protocol": "ICMPv6"}
