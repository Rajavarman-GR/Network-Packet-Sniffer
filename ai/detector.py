import os

import joblib

import numpy as np


class ThreatDetector:

    """AI-based threat detection for network packets."""

    def __init__(self):
        model_path = os.path.join(os.path.dirname(__file__), "threat_model.pkl")
        self.model = None

        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
        except Exception as exc:
            print(f"[ThreatDetector] Failed to load model: {exc}")

    def detect(self, packet):
        """Detect if a packet represents a potential threat.

        Args:
            packet: Scapy packet object

        Returns:
            bool: True if threat detected, False otherwise
        """
        if self.model is None:
            return False

        try:
            features = np.array([
                [
                    len(packet),
                    packet.time % 1
                ]
            ])
            prediction = self.model.predict(features)
            return prediction[0] == 1
        except Exception as exc:
            print(f"[ThreatDetector] Detection error: {exc}")
            return False

    def is_available(self):
        """Check if the threat detection model is loaded."""
        return self.model is not None