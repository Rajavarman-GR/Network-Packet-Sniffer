"""Defensive packet-level TLS record and ClientHello inspection."""

from .base import ProtocolDecoder

_CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
_HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange"}


def _extract_sni(handshake_body):
    """Parse a bounded ClientHello body and return a hostname when present."""
    data = handshake_body
    pos = 0
    if len(data) < 34:
        return None
    pos += 2 + 32
    session_len = data[pos]
    pos += 1
    if pos + session_len + 2 > len(data):
        return None
    pos += session_len
    cipher_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    if pos + cipher_len + 1 > len(data):
        return None
    pos += cipher_len
    compression_len = data[pos]
    pos += 1
    if pos + compression_len > len(data):
        return None
    pos += compression_len
    if pos == len(data):
        return None
    if pos + 2 > len(data):
        return None
    extensions_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    end = min(len(data), pos + extensions_len)
    while pos + 4 <= end:
        ext_type = int.from_bytes(data[pos:pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        body_start = pos + 4
        body_end = body_start + ext_len
        if body_end > end:
            return None
        if ext_type == 0 and ext_len >= 5:
            names_len = int.from_bytes(data[body_start:body_start + 2], "big")
            name_pos = body_start + 2
            names_end = min(body_end, name_pos + names_len)
            while name_pos + 3 <= names_end:
                name_type = data[name_pos]
                name_len = int.from_bytes(data[name_pos + 1:name_pos + 3], "big")
                name_pos += 3
                if name_pos + name_len > names_end:
                    return None
                if name_type == 0:
                    return data[name_pos:name_pos + name_len].decode("ascii", "replace")
                name_pos += name_len
        pos = body_end
    return None


def _parse_tls(payload):
    if len(payload) < 5 or payload[0] not in _CONTENT_TYPES or payload[1] != 3:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    version_minor = payload[2]
    result = {
        "protocol": "TLS",
        "content_type": _CONTENT_TYPES[payload[0]],
        "record_version": "{}.{}".format(payload[1], version_minor),
        "version": "SSL 3.0" if version_minor == 0 else "TLS 1.{}".format(max(0, version_minor - 1)),
        "record_length": record_length,
        "record_truncated": len(payload) - 5 < record_length,
    }
    if payload[0] != 22:
        return result
    if len(payload) < 6:
        result["handshake_truncated"] = True
        return result
    handshake_type = payload[5]
    result["handshake_type"] = _HANDSHAKE_TYPES.get(handshake_type, "unknown ({})".format(handshake_type))
    if handshake_type != 1:
        return result
    result["client_hello"] = True
    if len(payload) < 9:
        result["handshake_truncated"] = True
        return result
    handshake_length = int.from_bytes(payload[6:9], "big")
    result["handshake_length"] = handshake_length
    if len(payload) - 9 < handshake_length:
        result["handshake_truncated"] = True
        return result
    sni = _extract_sni(payload[9:9 + handshake_length])
    if sni:
        result["server_name"] = sni
    return result


class TLSDecoder(ProtocolDecoder):
    name = "TLS"
    priority = 90

    def applies(self, packet, payload):
        return _parse_tls(payload) is not None

    def decode(self, packet, payload):
        return _parse_tls(payload)
