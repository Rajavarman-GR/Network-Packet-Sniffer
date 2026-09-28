"""Small contract shared by packet-level protocol decoders."""


class ProtocolDecoder:
    """Protocol decoder contract: name, applicability, decode and findings."""

    name = "unknown"
    priority = 0

    def applies(self, packet, payload):
        raise NotImplementedError

    def decode(self, packet, payload):
        raise NotImplementedError

    def findings(self, packet, payload):
        return []


def make_finding(category, message, evidence="", source="payload"):
    """Build a uniform heuristic finding without implying a verdict."""
    return {
        "category": category,
        "message": message,
        "evidence": evidence,
        "source": source,
        "heuristic": True,
    }
