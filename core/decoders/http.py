"""Bounded, packet-level HTTP request and response inspection."""

import re

from .base import ProtocolDecoder, make_finding

_REQUEST_LINE = re.compile(rb"^([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([^\r\n ]+) HTTP/(\d+\.\d+)$")
_RESPONSE_LINE = re.compile(rb"^HTTP/(\d+\.\d+) ([0-9]{3})(?: ([^\r\n]*))?$")
_HEADER_LIMIT = 16384
_BODY_PREVIEW_LIMIT = 256


def _parse_http(payload):
    if not payload:
        return None
    separator = payload.find(b"\r\n\r\n")
    if separator < 0:
        header_bytes = payload[:_HEADER_LIMIT]
        body = b""
        complete_headers = False
    else:
        header_bytes = payload[:min(separator, _HEADER_LIMIT)]
        body = payload[separator + 4:]
        complete_headers = separator <= _HEADER_LIMIT
    lines = header_bytes.split(b"\r\n")
    if not lines:
        return None
    first = lines[0]
    request = _REQUEST_LINE.fullmatch(first)
    response = _RESPONSE_LINE.fullmatch(first)
    if request:
        method, uri, version = (part.decode("ascii", "replace") for part in request.groups())
        result = {
            "kind": "request", "method": method, "uri": uri,
            "path": uri, "version": version,
        }
    elif response:
        version, status, reason = response.groups()
        version = version.decode("ascii")
        reason = (reason or b"").decode("iso-8859-1", "replace")
        result = {
            "kind": "response", "version": version, "status_code": int(status),
            "reason": reason, "status_line": first.decode("iso-8859-1", "replace"),
        }
    else:
        return None

    headers = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        key, value = line.split(b":", 1)
        if not key or any(byte <= 32 or byte >= 127 for byte in key):
            continue
        headers[key.decode("ascii")] = value.strip().decode("iso-8859-1", "replace")

    content_type = next((value for key, value in headers.items() if key.casefold() == "content-type"), None)
    content_length = next((value for key, value in headers.items() if key.casefold() == "content-length"), None)
    try:
        declared_body_length = int(content_length) if content_length is not None else None
        if declared_body_length is not None and declared_body_length < 0:
            declared_body_length = None
    except ValueError:
        declared_body_length = None
    body_preview_bytes = body[:_BODY_PREVIEW_LIMIT]
    body_is_binary = bool(body_preview_bytes) and sum(
        byte in (9, 10, 13) or 32 <= byte < 127 for byte in body_preview_bytes
    ) / len(body_preview_bytes) < 0.85
    result.update({
        "protocol": "HTTP",
        "start_line": first.decode("iso-8859-1", "replace"),
        "headers": headers,
        "host": next((value for key, value in headers.items() if key.casefold() == "host"), None),
        "content_type": content_type,
        "content_length": content_length,
        "body_preview": "" if body_is_binary else body_preview_bytes.decode("utf-8", "replace"),
        "body_preview_hex": body_preview_bytes.hex(" ") if body_is_binary else "",
        "body_truncated": len(body) > _BODY_PREVIEW_LIMIT or (
            declared_body_length is not None and len(body) < declared_body_length
        ),
        "body_incomplete": declared_body_length is not None and len(body) < declared_body_length,
        "headers_complete": complete_headers,
    })
    return result


class HTTPDecoder(ProtocolDecoder):
    name = "HTTP"
    priority = 80

    def applies(self, packet, payload):
        return _parse_http(payload) is not None

    def decode(self, packet, payload):
        return _parse_http(payload)

    def findings(self, packet, payload):
        match = re.search(rb"(?im)^Authorization\s*:\s*Basic\s+([^\s\r\n]+)", payload[:65536])
        if not match:
            return []
        import base64
        token = match.group(1)
        try:
            credentials = base64.b64decode(token, validate=True).decode("utf-8", "replace")
            message = "Cleartext HTTP Basic credentials: {}".format(credentials)
        except (ValueError, base64.binascii.Error):
            message = "Cleartext HTTP Basic Authorization header detected (could not decode)."
        return [make_finding("cleartext_credentials", message, token.decode("ascii", "replace"), "HTTP Authorization header")]
