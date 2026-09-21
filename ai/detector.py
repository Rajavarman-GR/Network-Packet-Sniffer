from ai.model_loader import ModelLoader


class ThreatDetector:
    def __init__(self, loader=None):
        self.loader = loader or ModelLoader()

    def is_available(self):
        return self.loader.available

    @property
    def status(self):
        if not self.is_available():
            return "unavailable"
        return f"{self.loader.model_name} {self.loader.model_version}".strip()

    def predict(self, features):
        if not self.is_available():
            return self._unavailable()
        try:
            raw_label = str(self.loader.predict(features)).upper()
            confidence = self.loader.confidence(features)
            label = self._normalize_label(raw_label)
            return {
                "available": True,
                "label": label,
                "confidence": confidence,
                "risk_score": self._risk_score(label, confidence),
                "model_version": self.loader.model_version,
            }
        except Exception:
            return self._unavailable()

    @staticmethod
    def _unavailable():
        return {
            "available": False,
            "label": "UNAVAILABLE",
            "confidence": None,
            "risk_score": None,
            "model_version": None,
        }

    @staticmethod
    def _normalize_label(label):
        if label in {"1", "TRUE", "THREAT", "SUSPICIOUS", "MALICIOUS"}:
            return "SUSPICIOUS"
        if label in {"2", "HIGH", "HIGH_RISK", "HIGH RISK"}:
            return "HIGH RISK"
        if label in {"0", "FALSE", "BENIGN", "NORMAL"}:
            return "BENIGN"
        return label

    @staticmethod
    def _risk_score(label, confidence):
        if confidence is None:
            return None
        if label == "HIGH RISK":
            return round(confidence * 100)
        if label == "SUSPICIOUS":
            return round(confidence * 80)
        return round((1.0 - confidence) * 20)