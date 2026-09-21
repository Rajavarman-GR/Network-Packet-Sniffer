"""Trusted local model loading and compatibility validation."""

import json
from pathlib import Path

import joblib

from ai.feature_extractor import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from utils.logger import log_error


class ModelLoader:
    def __init__(self, model_path=None, metadata_path=None):
        base = Path(__file__).parent / "model"
        self.model_path = Path(model_path) if model_path else base / "threat_model.joblib"
        self.metadata_path = Path(metadata_path) if metadata_path else base / "metadata.json"
        self.model = None
        self.metadata = {}
        self.error = None
        self._load()

    def _load(self):
        if not self.model_path.is_file() or not self.metadata_path.is_file():
            self.error = "No trusted local model and metadata found"
            return
        try:
            with self.metadata_path.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            if metadata.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
                raise ValueError("feature schema version mismatch")
            if tuple(metadata.get("features", ())) != FEATURE_NAMES:
                raise ValueError("feature names do not match runtime schema")
            model = joblib.load(self.model_path)
            if not callable(getattr(model, "predict", None)):
                raise ValueError("model has no predict method")
            expected_count = getattr(model, "n_features_in_", len(FEATURE_NAMES))
            if int(expected_count) != len(FEATURE_NAMES):
                raise ValueError("model feature count does not match runtime schema")
            self.model = model
            self.metadata = metadata
        except Exception as exc:
            self.error = str(exc)
            log_error(f"Threat model unavailable: {exc}")

    @property
    def available(self):
        return self.model is not None

    @property
    def model_name(self):
        return self.metadata.get("model_name", "")

    @property
    def model_version(self):
        return self.metadata.get("model_version", "")

    def predict(self, features):
        if not self.available:
            raise RuntimeError(self.error or "model unavailable")
        return self.model.predict([features])[0]

    def confidence(self, features):
        if not self.available:
            return None
        if callable(getattr(self.model, "predict_proba", None)):
            probabilities = self.model.predict_proba([features])[0]
            return float(max(probabilities))
        return None
