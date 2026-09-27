"""Deep packet decode / decipher support.

This module is intentionally separate from core/parser.py: parser.py
produces the small, fixed metadata dict used for the packet table and
AI features. decoder.py produces a much richer, human-readable
breakdown of a single packet on demand (when the user asks to
"decode"/"analyze" a packet), including:

  * a generic, complete field-by-field dissection of every layer scapy
    recognizes (Ethernet, ARP, IPv4/IPv6, TCP options, DNS records, ...)
  * best-effort application-layer decoding for protocols scapy does not
    reassemble on a single async-sniffed packet (plaintext HTTP, and a
    manual TLS record / ClientHello SNI parse)
  * lightweight payload security heuristics (cleartext credentials,
    embedded file signatures, base64-looking blobs)

Nothing here mutates the packet or touches Tkinter - it is pure data
in, structured data out, so it is unit-testable without a display.
"""

import base64
import re

import scapy.all as scapy


# ---------------------------------------------------------------------
# 1. Generic per-layer field dissection
# ---------------------------------------------------------------------

def decode_layers(packet, max_field_chars=200):
    """Walk every layer of the packet and return, for each one, its
    class name and every declared field rendered the same way scapy's
    own .show() would render it (via each field's i2repr), so this
    covers ARP, DNS answers, TCP options, IPv6 extension headers, etc.
    without hand-listing every protocol scapy supports."""

    layers = []
    current = packet

    while current is not None and not isinstance(current, scapy.NoPayload):

        fields = []

        for field in current.fields_desc:

            try:
                value = current.getfieldval(field.name)
                display = field.i2repr(current, value)
            except Exception:
                display = repr(getattr(current, field.name, None))

            display = str(display)

            if len(display) > max_field_chars:
                display = display[:max_field_chars] + f"... [{len(display)} chars total]"

            fields.append((field.name, display))

        layers.append({
            "name": current.__class__.__name__,
            "fields": fields,
        })

        current = current.payload

    return layers


# ---------------------------------------------------------------------
# 2. Application-layer best-effort decoding
# ---------------------------------------------------------------------

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _decode_http(payload):

    if not (payload.startswith(_HTTP_METHODS) or payload.startswith(b"HTTP/")):
        return None

    head, _, body = payload.partition(b"\r\n\r\n")

    lines = head.decode("iso-8859-1", errors="replace").split("\r\n")

    if not lines or not lines[0]:
        return None

    start_line = lines[0]

    headers = {}

    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()

    return {
        "kind": "response" if start_line.startswith("HTTP/") else "request",
        "start_line": start_line,
        "headers": headers,
        "body_preview": body[:256].decode("iso-8859-1", errors="replace"),
        "body_truncated": len(body) > 256,
    }


# TLS ContentType values (RFC 8446 section 5.1)
_TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
}

_TLS_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    14: "ServerHelloDone",
    16: "ClientKeyExchange",
}


def _decode_tls(payload):
    """Parse just enough of a TLS record header (and, for a
    ClientHello, its SNI extension) to be useful - this is a manual,
    read-only byte walk, not a scapy TLS layer, so it works without
    the optional scapy-tls addon and without full session reassembly."""

    if len(payload) < 5:
        return None

    content_type = payload[0]

    if content_type not in _TLS_CONTENT_TYPES:
        return None

    version = (payload[1], payload[2])

    if version[0] != 3:
        return None

    record = {
        "content_type": _TLS_CONTENT_TYPES[content_type],
        "version": f"TLS 1.{version[1] - 1}" if version[1] >= 1 else "SSL 3.0",
    }

    if content_type != 22 or len(payload) < 6:
        return record

    handshake_type = payload[5]
    record["handshake_type"] = _TLS_HANDSHAKE_TYPES.get(handshake_type, f"unknown ({handshake_type})")

    if handshake_type == 1:
        sni = _extract_sni(payload)
        if sni:
            record["server_name"] = sni

    return record


def _extract_sni(payload):
    """Walk a ClientHello's fixed fields then its extensions looking
    for extension type 0 (server_name) / name type 0 (host_name)."""

    try:
        pos = 9  # record header(5) + handshake header(4)
        pos += 2  # client_version
        pos += 32  # random
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len
        compression_len = payload[pos]
        pos += 1 + compression_len

        if pos + 2 > len(payload):
            return None

        extensions_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = pos + extensions_len

        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            ext_body_start = pos + 4

            if ext_type == 0:  # server_name
                sni_list_len = int.from_bytes(payload[ext_body_start:ext_body_start + 2], "big")
                sni_pos = ext_body_start + 2
                sni_end = sni_pos + sni_list_len
                while sni_pos + 3 <= sni_end:
                    name_type = payload[sni_pos]
                    name_len = int.from_bytes(payload[sni_pos + 1:sni_pos + 3], "big")
                    name_start = sni_pos + 3
                    if name_type == 0:
                        return payload[name_start:name_start + name_len].decode("ascii", errors="replace")
                    sni_pos = name_start + name_len

            pos = ext_body_start + ext_len

    except (IndexError, UnicodeError):
        return None

    return None


def decode_application_layer(packet):
    """Best-effort decode of the raw payload as HTTP or TLS. Returns
    None when neither pattern matches (e.g. an unrecognized or
    encrypted-looking binary payload)."""

    if not packet.haslayer(scapy.Raw):
        return None

    payload = bytes(packet[scapy.Raw].load)

    http = _decode_http(payload)
    if http is not None:
        return {"protocol": "HTTP", **http}

    tls = _decode_tls(payload)
    if tls is not None:
        return {"protocol": "TLS", **tls}

    return None


# ---------------------------------------------------------------------
# 3. Payload security heuristics
# ---------------------------------------------------------------------

_FILE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP/Office archive"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"-----BEGIN", "PEM key/certificate block"),
)

_BASE64_RUN = re.compile(rb"(?:[A-Za-z0-9+/]{40,}={0,2})")


def analyze_payload_security(packet):
    """Return a list of short, human-readable findings about a
    packet's raw payload. This is heuristic pattern-matching, not a
    classifier - it exists to flag things worth a closer look, not to
    make a verdict."""

    findings = []

    if not packet.haslayer(scapy.Raw):
        return findings

    payload = bytes(packet[scapy.Raw].load)

    for signature, description in _FILE_SIGNATURES:
        if payload.startswith(signature):
            findings.append(f"Embedded file signature detected: {description}")
            break

    lowered = payload.lower()

    if b"authorization: basic " in lowered:
        try:
            start = lowered.index(b"authorization: basic ") + len(b"authorization: basic ")
            token = payload[start:start + 200].split(b"\r\n")[0].split(b" ")[0]
            decoded = base64.b64decode(token + b"=" * (-len(token) % 4)).decode("utf-8", errors="replace")
            findings.append(f"Cleartext HTTP Basic credentials: {decoded}")
        except Exception:
            findings.append("Cleartext HTTP Basic Authorization header detected (could not decode).")

    if payload.startswith(b"USER ") or b"\r\nUSER " in payload:
        findings.append("Cleartext FTP USER command detected.")

    if payload.startswith(b"PASS ") or b"\r\nPASS " in payload:
        findings.append("Cleartext FTP PASS (password) command detected.")

    if b"password" in lowered and b"http" not in lowered[:4]:
        findings.append("Payload contains the literal word 'password' in cleartext.")

    match = _BASE64_RUN.search(payload)
    if match:
        findings.append(f"Possible base64-encoded data ({len(match.group())} chars).")

    return findings


def decode_packet(packet):
    """Convenience entry point bundling all three analyses for a
    single packet - this is what the GUI's Decode dialog calls."""

    return {
        "layers": decode_layers(packet),
        "application": decode_application_layer(packet),
        "security_findings": analyze_payload_security(packet),
    }
