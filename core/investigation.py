"""Deterministic flow and protocol evidence summaries over packet records."""

from collections import defaultdict, deque
from datetime import datetime, timezone
import math

from core.analysis import analyze_packet


def _time_value(packet, metadata):
    value = getattr(packet, "time", None)
    try:
        result = float(value)
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        text = metadata.get("timestamp")
        try:
            return datetime.strptime(text, "%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        except (TypeError, ValueError):
            return 0.0


def _packet_length(packet, metadata):
    try:
        return max(0, int(metadata.get("length") or len(packet)))
    except (AttributeError, TypeError, ValueError, OverflowError):
        return 0


class InvestigationEngine:
    """Build conversations, top talkers, protocol evidence, and a timeline."""

    def __init__(self, max_records=10000):
        self.max_records = max(1, int(max_records))

    def analyze(self, records, cancel_event=None):
        records = deque(records or (), maxlen=self.max_records)
        flows, talkers = {}, defaultdict(lambda: {"packet_count": 0, "byte_count": 0})
        dns, http, tls, findings, timeline, analyses = [], [], [], [], [], []
        for index, record in enumerate(records):
            if cancel_event is not None and cancel_event.is_set():
                break
            packet = record.get("packet")
            packet_id = record.get("id", index + 1)
            metadata = dict(record)
            ai_result = record.get("ai_result")
            analysis = analyze_packet(packet, packet_id, metadata, ai_result)
            analyses.append(analysis)
            src, dst = str(metadata.get("src") or ""), str(metadata.get("dst") or "")
            sport, dport = str(metadata.get("sport") or ""), str(metadata.get("dport") or "")
            protocol = str(metadata.get("protocol") or "OTHER")
            length = _packet_length(packet, metadata)
            ts = _time_value(packet, metadata)
            if src:
                talkers[src]["packet_count"] += 1
                talkers[src]["byte_count"] += length
            # Canonical endpoint order groups both packet directions. The record retains
            # an explicit conversation semantic; it is not a directional flow.
            left, right = (src, str(sport)), (dst, str(dport))
            endpoints = tuple(sorted((left, right)))
            key = (protocol, endpoints)
            flow = flows.setdefault(key, {
                "semantic": "bidirectional_conversation", "source": endpoints[0][0],
                "destination": endpoints[1][0], "source_port": endpoints[0][1],
                "destination_port": endpoints[1][1], "protocol": protocol,
                "packet_count": 0, "total_bytes": 0, "first_timestamp": ts,
                "last_timestamp": ts, "packet_ids": [],
            })
            flow["packet_count"] += 1
            flow["total_bytes"] += length
            flow["first_timestamp"] = min(flow["first_timestamp"], ts)
            flow["last_timestamp"] = max(flow["last_timestamp"], ts)
            flow["packet_ids"].append(packet_id)
            app = analysis["decoder"]["application"] or {}
            timeline.append(_event(ts, "packet", packet_id,
                "{} {} → {}".format(protocol, src or "?", dst or "?"),
                {"source": src, "destination": dst, "length": length}))
            if app.get("protocol") == "DNS":
                questions, answers = app.get("questions", []), app.get("answers", [])
                dns.append({"source": src, "destination": dst,
                    "queried_domain": (questions[0].get("name") if questions else None),
                    "record_type": (questions[0].get("type") if questions else None),
                    "kind": app.get("kind"), "response": answers, "packet_id": packet_id})
                timeline.append(_event(ts, "dns_" + str(app.get("kind", "message")), packet_id,
                    "DNS {}".format(app.get("kind", "message")), {"domain": questions[0].get("name") if questions else None}))
            elif app.get("protocol") == "HTTP":
                item = {"source": src, "destination": dst, "method": app.get("method"),
                    "host": app.get("host"), "path": app.get("path"), "kind": app.get("kind"), "packet_id": packet_id}
                http.append(item)
                timeline.append(_event(ts, "http_" + str(app.get("kind", "message")), packet_id,
                    "HTTP {} {}".format(app.get("kind", "message"), app.get("method") or app.get("path") or ""), item))
            elif app.get("protocol") == "TLS":
                item = {"source": src, "destination": dst, "server_name": app.get("server_name"),
                    "handshake_type": app.get("handshake_type"), "packet_id": packet_id}
                tls.append(item)
                timeline.append(_event(ts, "tls_handshake", packet_id,
                    "TLS {}".format(app.get("handshake_type", "record")), item))
            ai = analysis["ai"]
            if ai.get("available") and ai.get("label") in {"SUSPICIOUS", "HIGH RISK"}:
                finding = {"source_type": "ai", "kind": ai.get("label"), "packet_id": packet_id, "details": ai}
                findings.append(finding)
                timeline.append(_event(ts, "ai_finding", packet_id, "AI {} finding".format(ai["label"]), finding))
            for observation in analysis["decoder"]["findings"]:
                finding = {"source_type": "decoder_heuristic", "kind": observation.get("category"),
                    "packet_id": packet_id, "details": observation}
                findings.append(finding)
                timeline.append(_event(ts, "security_finding", packet_id, observation.get("message", "Security observation"), finding))
        for flow in flows.values():
            flow["duration"] = max(0.0, flow["last_timestamp"] - flow["first_timestamp"])
        timeline.sort(key=lambda event: (event["timestamp"], _packet_id_order(event["packet_id"]), event["event_type"], event["description"]))
        return {"analyses": analyses, "flows": sorted(flows.values(), key=lambda f: (f["protocol"], f["source"], f["destination"], f["source_port"], f["destination_port"])),
            "top_talkers": [{"source": host, **values} for host, values in sorted(talkers.items(), key=lambda x: (-x[1]["byte_count"], x[0]))],
            "dns": dns, "http": http, "tls": tls, "findings": findings, "timeline": timeline,
            "packet_count": len(records), "total_bytes": sum(_packet_length(r.get("packet"), r) for r in records)}


def _event(timestamp, event_type, packet_id, description, context):
    return {"timestamp": timestamp, "event_type": event_type, "packet_id": packet_id,
        "description": description, "context": context}


def _packet_id_order(packet_id):
    try:
        return (0, int(packet_id))
    except (TypeError, ValueError, OverflowError):
        return (1, str(packet_id))
