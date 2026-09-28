"""Public facade for passive, packet-level deep decoding.

The parser remains responsible for lightweight table/AI metadata. This module
provides an independent plugin registry and stable functions used by the GUI.
It never mutates packets, performs network I/O, or depends on Tkinter/AI code.
"""

import base64
import re

import scapy.all as scapy

from core.decoders import (
    DecoderRegistry, DNSDecoder, FTPDecoder, HTTPDecoder, ICMPDecoder, TLSDecoder,
    make_finding,
)

MAX_FIELD_CHARS = 200
MAX_PAYLOAD_PREVIEW_BYTES = 256
MAX_SECURITY_SCAN_BYTES = 65536
_FILE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"), (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP/Office archive"), (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"), (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"), (b"-----BEGIN", "PEM key/certificate block"),
)
_BASE64_RUN = re.compile(rb"(?:[A-Za-z0-9+/]{40,}={0,2})")


def create_default_registry():
    registry = DecoderRegistry()
    for decoder in (DNSDecoder(), TLSDecoder(), HTTPDecoder(), FTPDecoder(), ICMPDecoder()):
        registry.register(decoder)
    return registry


DECODER_REGISTRY = create_default_registry()


def _raw_payload(packet):
    if packet is None or not callable(getattr(packet, "haslayer", None)):
        return b""
    try:
        raw = packet.getlayer(scapy.Raw)
        return bytes(raw.load) if raw is not None else b""
    except (AttributeError, TypeError, ValueError):
        return b""


def _render_field(layer, field, max_field_chars):
    try:
        value = layer.getfieldval(field.name)
        if isinstance(value, (bytes, bytearray, memoryview)) and len(value) > max_field_chars:
            sample = bytes(value[:max(0, max_field_chars // 2)])
            display = repr(sample) + "... [{} bytes total]".format(len(value))
        elif isinstance(value, (list, tuple)) and len(value) > 64:
            display = repr(value[:64]) + "... [{} items total]".format(len(value))
        elif value is None:
            # Some Scapy fields (notably SourceMACField) resolve defaults
            # through the local routing table inside i2repr. Missing packet
            # values must stay passive and must not trigger host lookups.
            display = "None"
        else:
            display = field.i2repr(layer, value)
    except (AttributeError, TypeError, ValueError, IndexError, OverflowError):
        try:
            display = repr(getattr(layer, field.name, None))
        except Exception:
            display = "<unavailable>"
    display = str(display)
    if len(display) > max_field_chars:
        display = display[:max_field_chars] + "... [{} chars total]".format(len(display))
    return display


def decode_layers(packet, max_field_chars=MAX_FIELD_CHARS):
    """Dynamically render Scapy's declared fields across the layer chain."""
    layers = []
    current = packet
    seen = set()
    try:
        limit = max(1, int(max_field_chars))
    except (TypeError, ValueError):
        limit = MAX_FIELD_CHARS
    while current is not None and not isinstance(current, scapy.NoPayload):
        if id(current) in seen:
            break
        seen.add(id(current))
        fields = []
        for field in getattr(current, "fields_desc", ()):
            fields.append((field.name, _render_field(current, field, limit)))
        layers.append({"name": current.__class__.__name__, "fields": fields})
        current = getattr(current, "payload", None)
    return layers


def decode_application_layer(packet):
    """Decode the highest-priority matching protocol plugin, if any."""
    payload = _raw_payload(packet)
    decoder = DECODER_REGISTRY.detect(packet, payload) if packet is not None else None
    if decoder is None:
        return None
    try:
        return decoder.decode(packet, payload)
    except (AttributeError, TypeError, ValueError, IndexError, OverflowError):
        return None


def inspect_payload(packet, max_bytes=MAX_PAYLOAD_PREVIEW_BYTES):
    """Return bounded payload size, hex, ASCII and truncation metadata."""
    payload = _raw_payload(packet)
    try:
        limit = max(0, int(max_bytes))
    except (TypeError, ValueError):
        limit = MAX_PAYLOAD_PREVIEW_BYTES
    preview = payload[:limit]
    return {
        "present": bool(payload),
        "length": len(payload),
        "hex": preview.hex(" "),
        "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in preview),
        "truncated": len(payload) > limit,
    }


def analyze_payload_findings(packet):
    """Return structured heuristic findings; these are not verdicts."""
    if packet is None or not _raw_payload(packet):
        return []
    payload = _raw_payload(packet)
    scanned = payload[:MAX_SECURITY_SCAN_BYTES]
    findings = []
    for signature, description in _FILE_SIGNATURES:
        if scanned.startswith(signature):
            findings.append(make_finding("embedded_file", "Embedded file signature detected: {}".format(description), signature.hex(" "), "payload signature"))
            break

    lowered = scanned.lower()
    if b"authorization: basic " in lowered:
        start = lowered.index(b"authorization: basic ") + len(b"authorization: basic ")
        token = scanned[start:start + 200].split(b"\r\n", 1)[0].split(None, 1)[0]
        try:
            credentials = base64.b64decode(token + b"=" * (-len(token) % 4), validate=True).decode("utf-8", "replace")
            message = "Cleartext HTTP Basic credentials: {}".format(credentials)
        except (ValueError, base64.binascii.Error):
            message = "Cleartext HTTP Basic Authorization header detected (could not decode)."
        findings.append(make_finding("cleartext_credentials", message, token.decode("ascii", "replace"), "HTTP Authorization header"))

    for command in (b"USER", b"PASS"):
        match = re.search(rb"(?im)(?:^|\r\n)" + command + rb"[ \t]+([^\r\n]*)", scanned)
        if match:
            message = (
                "Cleartext FTP USER command detected." if command == b"USER"
                else "Cleartext FTP PASS (password) command detected."
            )
            findings.append(make_finding(
                "cleartext_credentials", message,
                match.group(1).decode("iso-8859-1", "replace"), "FTP {} command".format(command.decode()),
            ))

    if b"password" in lowered and b"http" not in lowered[:4]:
        findings.append(make_finding("cleartext_secret", "Payload contains the literal word 'password' in cleartext.", "password", "payload text"))
    match = _BASE64_RUN.search(scanned)
    if match:
        findings.append(make_finding("encoded_data", "Possible base64-encoded data ({} chars).".format(len(match.group())), match.group()[:80].decode("ascii", "replace"), "payload pattern"))
    for decoder in DECODER_REGISTRY.matching(packet, payload):
        try:
            findings.extend(decoder.findings(packet, payload))
        except (AttributeError, TypeError, ValueError, IndexError, OverflowError):
            continue
    unique = []
    messages = set()
    for finding in findings:
        if finding["message"] not in messages:
            messages.add(finding["message"])
            unique.append(finding)
    return unique


def analyze_payload_security(packet):
    """Compatibility API: return legacy human-readable finding strings."""
    return [finding["message"] for finding in analyze_payload_findings(packet)]


def decode_packet(packet):
    """Return the compatible decode bundle plus structured forensic data."""
    application = decode_application_layer(packet)
    findings = analyze_payload_findings(packet)
    return {
        "layers": decode_layers(packet),
        "application": application,
        "security_findings": [finding["message"] for finding in findings],
        "findings": findings,
        "payload": inspect_payload(packet),
    }
