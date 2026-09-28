"""Unified, packet-level view over parser, decoder, and runtime AI results."""

from core.decoder import decode_packet
from core.parser import get_packet_metadata


def analyze_packet(packet, packet_id=None, metadata=None, ai_result=None):
    """Build a stable analysis record without changing any subsystem semantics."""
    malformed = packet is None or not callable(getattr(packet, "haslayer", None))
    if metadata is None:
        try:
            metadata = get_packet_metadata(packet) if not malformed else {}
        except Exception:
            metadata = {}
            malformed = True
    metadata = dict(metadata or {})
    try:
        decoded = decode_packet(packet) if not malformed else None
    except Exception:
        decoded = None
        malformed = True
    application = (decoded or {}).get("application")
    payload = (decoded or {}).get("payload", {"present": False, "length": 0})
    findings = list((decoded or {}).get("findings", ()))
    return {
        "packet_id": packet_id,
        "timestamp": getattr(packet, "time", None) if not malformed else None,
        "metadata": metadata,
        "decoder": {
            "matched": application is not None,
            "application_protocol": application.get("protocol") if application else None,
            "application": application,
            "layers": (decoded or {}).get("layers", []),
            "payload": payload,
            "findings": findings,
            "status": "malformed" if malformed else ("matched" if application else "no_match"),
        },
        "ai": dict(ai_result) if ai_result is not None else {
            "available": False, "label": "UNAVAILABLE", "confidence": None,
            "risk_score": None, "model_version": None,
        },
        "status": "malformed" if malformed else "complete",
    }
