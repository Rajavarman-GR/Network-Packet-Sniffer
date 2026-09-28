"""Pure presentation models shared by the Tk workspaces and unit tests."""

from datetime import datetime

from core.explanations import build_beginner_summary


EMPTY_STATES = {
    "overview": ("Overview is waiting for traffic.", "Start a capture or open a PCAP to see retained traffic summaries."),
    "packets": ("No packets captured yet.", "Start a live capture or open a PCAP file to begin analysis."),
    "flows": ("No conversations available.", "Capture traffic and analyze retained packets to build conversations."),
    "investigation": ("No evidence to display.", "Analyze retained packets or load a PCAP to build investigation evidence."),
    "findings": ("No findings currently available.", "AI and heuristic findings appear when evidence matches their separate rules."),
    "dns": ("No DNS activity in this investigation.", "DNS evidence is shown when a supported DNS packet is present."),
    "http": ("No HTTP activity in this investigation.", "HTTP evidence is shown when a supported HTTP packet is present."),
    "tls": ("No TLS activity in this investigation.", "TLS evidence is shown when a supported TLS record is present."),
    "timeline": ("No timeline events are available.", "Events are added when packets and protocol evidence are analyzed."),
}


def investigation_groups(data):
    """Return grouped evidence rows while preserving packet IDs and source type."""
    keys = ("DNS", "HTTP", "TLS", "AI Findings", "Security Findings", "Timeline")
    groups = {key: [] for key in keys}
    if not isinstance(data, dict):
        return groups
    analyses = {str(item.get("packet_id")): item for item in data.get("analyses", ()) if isinstance(item, dict)}
    timeline_by_id = {}
    for event in data.get("timeline", ()):
        if isinstance(event, dict):
            timeline_by_id.setdefault(str(event.get("packet_id")), event)

    def row(item, label, desc=None):
        packet_id = item.get("packet_id")
        analysis = analyses.get(str(packet_id), {})
        meta = analysis.get("metadata", {})
        event = timeline_by_id.get(str(packet_id), {})
        timestamp = meta.get("timestamp")
        if not timestamp and event.get("timestamp") is not None:
            try:
                timestamp = datetime.fromtimestamp(float(event["timestamp"])).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError, OSError, OverflowError):
                timestamp = event.get("timestamp")
        return (str(timestamp or "—"), label,
                str(desc or ""), str(meta.get("src") or "—"), str(meta.get("dst") or "—"),
                "#{}".format(packet_id) if packet_id is not None else "—", packet_id)

    for protocol in ("DNS", "HTTP", "TLS"):
        for item in data.get(protocol.casefold(), ()):
            if not isinstance(item, dict):
                continue
            if protocol == "DNS":
                label = "DNS {}".format(item.get("kind", "activity"))
                desc = "{} ({})".format(item.get("queried_domain") or "name unavailable", item.get("record_type") or "type unavailable")
            elif protocol == "HTTP":
                label = "HTTP {}".format(item.get("kind", "activity"))
                desc = "{} {}{}".format(item.get("method") or "message", item.get("host") or "", item.get("path") or "")
            else:
                label = "TLS {}".format(item.get("handshake_type") or "record")
                desc = "Server name: {}".format(item.get("server_name") or "not present in this packet")
            groups[protocol].append(row(item, label, desc))
    for item in data.get("findings", ()):
        if not isinstance(item, dict):
            continue
        ai = item.get("source_type") == "ai"
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        label = "AI classification" if ai else "Heuristic indicator"
        desc = details.get("label") if ai else details.get("message")
        groups["AI Findings" if ai else "Security Findings"].append(row(item, label, desc or item.get("kind", "Finding")))
    for event in data.get("timeline", ()):
        if isinstance(event, dict):
            item = {"packet_id": event.get("packet_id")}
            groups["Timeline"].append(row(item, str(event.get("event_type", "Event")).replace("_", " ").title(), event.get("description")))
    for group in keys:
        groups[group].sort(key=lambda evidence: evidence[0])
    return groups


def dashboard_model(counts, investigation=None):
    """Build trustworthy overview figures; unavailable inputs stay unavailable."""
    counts = counts if isinstance(counts, dict) else {}
    investigation = investigation if isinstance(investigation, dict) else None
    return {
        "packets": counts.get("packets", 0),
        "packets_per_second": counts.get("packets_per_second"),
        "active_flows": len(investigation.get("flows", ())) if investigation is not None else None,
        "bytes": investigation.get("total_bytes") if investigation is not None else None,
        "suspicious_ai": counts.get("suspicious_ai", 0),
        "high_risk_ai": counts.get("high_risk_ai", 0),
        "security_findings": sum(item.get("source_type") != "ai" for item in investigation.get("findings", ()) if isinstance(item, dict)) if investigation is not None else None,
        "retained_packets": investigation.get("packet_count") if investigation is not None else None,
    }


def decoder_view_model(decoded, mode):
    """Expose only the structured sections appropriate to a decoder mode."""
    decoded = decoded if isinstance(decoded, dict) else {}
    application = decoded.get("application") if isinstance(decoded.get("application"), dict) else None
    payload = decoded.get("payload") if isinstance(decoded.get("payload"), dict) else {"present": False, "length": 0, "ascii": "", "hex": "", "truncated": False}
    findings = decoded.get("security_findings") if isinstance(decoded.get("security_findings"), list) else []
    if mode == "Analyst":
        return {"mode": mode, "application": application, "findings": findings, "payload": payload,
                "finding_source": "Decoder heuristic"}
    if mode == "Technical / Raw":
        layers = decoded.get("layers") if isinstance(decoded.get("layers"), list) else []
        return {"mode": mode, "layers": layers, "payload": payload}
    return {"mode": "Beginner", "summary": build_beginner_summary(decoded)}


def operation_label(state, detail=None):
    """Stable user-facing labels for capture and background activity states."""
    labels = {"idle": "Idle", "capturing": "Capturing", "loading": "Loading PCAP",
              "analyzing": "Analyzing retained packets", "completed": "Completed", "error": "Error"}
    label = labels.get(state, "Idle")
    return "{} — {}".format(label, detail) if detail else label
