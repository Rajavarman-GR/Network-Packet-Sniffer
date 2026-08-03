import joblib

import numpy as np


class ThreatDetector:

    def __init__(self):

        try:

            self.model = joblib.load("ai/threat_model.pkl")

        except Exception:

            self.model = None

    def detect(self, packet):

        if self.model is None:

            return False

        features = np.array([

            [

                len(packet),

                packet.time % 1

            ]

        ])

        prediction = self.model.predict(features)

        return prediction[0] == 1