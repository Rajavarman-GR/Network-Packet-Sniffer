"""Beginner-facing descriptions for structured Decoder results.

This module formats Decoder facts for presentation and has no GUI dependency.
It deliberately avoids turning protocol presence into a security verdict.
"""

PROTOCOL_EXPLANATIONS = {
    "Ethernet": ("Link-layer framing", "Ethernet carries frames between devices on a local network."),
    "ARP": ("Local address lookup", "ARP maps an IPv4 address to a link-layer address on a local network."),
    "IPv4": ("Internet Protocol v4", "IPv4 carries packets between network addresses."),
    "IP": ("Internet Protocol v4", "IPv4 carries packets between network addresses."),
    "IPv6": ("Internet Protocol v6", "IPv6 carries packets between network addresses."),
    "TCP": ("Reliable transport", "TCP tracks a connection and provides ordered, reliable delivery."),
    "UDP": ("Datagram transport", "UDP sends datagrams without establishing a transport connection."),
    "DNS": ("Domain Name System", "DNS asks for or returns information associated with a domain name."),
    "HTTP": ("Web application protocol", "HTTP carries web requests and responses, often in readable form when unencrypted."),
    "TLS": ("Transport Layer Security", "TLS protects application traffic; application data is encrypted."),
    "FTP": ("File Transfer Protocol", "FTP carries file-transfer commands and responses; classic FTP is commonly unencrypted."),
    "ICMP": ("Internet control messaging", "ICMP carries network status and diagnostic messages."),
    "ICMPv6": ("IPv6 control messaging", "ICMPv6 carries IPv6 status, diagnostic, and neighbor messages."),
    "Raw": ("Undissected payload", "Raw contains bytes that Scapy has not dissected into another layer."),
}

_ALIASES = {"Ether": "Ethernet", "IP": "IPv4"}


def explain_protocol(protocol, fields=None, application=None):
    """Return a conservative explanation record, tolerating incomplete input."""
    name = str(protocol or "Unknown")
    canonical = _ALIASES.get(name, name)
    title, description = PROTOCOL_EXPLANATIONS.get(
        canonical, ("Unrecognized protocol", "No beginner explanation is registered for this layer."))
    fields = fields if isinstance(fields, dict) else {}
    facts = []
    if canonical in {"IPv4", "IPv6"}:
        src, dst = fields.get("src"), fields.get("dst")
        if src or dst:
            facts.append("Addresses: {} → {}".format(src or "unknown", dst or "unknown"))
    elif canonical in {"TCP", "UDP"}:
        sport, dport = fields.get("sport"), fields.get("dport")
        if sport is not None or dport is not None:
            facts.append("Ports: {} → {}".format(sport if sport is not None else "?", dport if dport is not None else "?"))
    if application and isinstance(application, dict) and application.get("protocol") == canonical:
        facts.append("Decoded application protocol: {}".format(canonical))
    return {"protocol": canonical, "title": title, "description": description,
            "indication": "; ".join(facts) or "This layer is present in the decoded packet.",
            "important_fields": tuple(fields),
            "why_care": "Protocol and field context can help explain how this packet fits into the conversation."}


def build_beginner_summary(decoded):
    """Build concise summary text from a decoder result, including malformed results."""
    if not isinstance(decoded, dict):
        return {"protocol_stack": [], "what_happened": "Decoder result is unavailable.", "why_it_matters": "No packet facts are available to interpret.", "inspect_next": "Review the packet bytes or decode it again."}
    layers = decoded.get("layers") if isinstance(decoded.get("layers"), list) else []
    names = [str(item.get("name", "Unknown")) for item in layers if isinstance(item, dict)]
    app = decoded.get("application") if isinstance(decoded.get("application"), dict) else None
    stack = [_ALIASES.get(name, name) for name in names]
    if app and app.get("protocol") and app["protocol"] not in stack:
        stack.append(str(app["protocol"]))
    protocol = str(app.get("protocol")) if app else (stack[-1] if stack else "Unknown")
    what = "{} packet decoded across {} layer{}.".format(protocol, len(names), "" if len(names) == 1 else "s") if names else "No protocol layers were available in the decoder result."
    if app and app.get("protocol") == "DNS":
        what = "DNS {} packet{} decoded.".format(app.get("kind", "message"), "" if app.get("kind") == "query" else "")
        if app.get("queried_domain"):
            what += " It asks about {}.".format(app["queried_domain"])
    elif app and app.get("protocol") == "HTTP":
        what = "HTTP {} to {} decoded.".format(app.get("method", "message"), app.get("host") or "an unspecified host")
    elif app and app.get("protocol") == "TLS":
        what = "TLS {} record decoded; application data, if present, remains encrypted.".format(app.get("content_type", ""))
    findings = decoded.get("security_findings") if isinstance(decoded.get("security_findings"), list) else []
    return {"protocol_stack": stack, "what_happened": what,
            "why_it_matters": "Protocol context helps identify the role of this traffic. Presence alone does not establish malicious activity.",
            "inspect_next": "Review decoded application details, then the technical fields and bounded payload preview." if app else "Review the protocol fields and bounded payload preview.",
            "findings": findings}
