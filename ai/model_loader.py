"""Trusted local model loading and compatibility validation."""

import json
import numbers
import os
from pathlib import Path

import joblib

from ai.feature_extractor import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from utils.logger import log_error

MAX_METADATA_BYTES = 256 * 1024


class ModelLoader:
    def __init__(self, model_path=None, metadata_path=None):
        base = Path(__file__).parent / "model"
        self.model_path = Path(model_path).expanduser() if model_path else base / "threat_model.joblib"
        self.metadata_path = Path(metadata_path).expanduser() if metadata_path else base / "metadata.json"
        self.model = None
        self.metadata = {}
        self.error = None
        self._load()

    def _load(self):
        if _is_network_path(self.model_path) or _is_network_path(self.metadata_path):
            self.error = "Runtime model and metadata must be trusted local files"
            log_error("Threat model unavailable: UNC paths are not accepted on Windows")
            return
        if not self.model_path.is_file() or not self.metadata_path.is_file():
            self.error = "No trusted local model and metadata found"
            return
        try:
            with self.metadata_path.open("rb") as handle:
                raw_metadata = handle.read(MAX_METADATA_BYTES + 1)
            if len(raw_metadata) > MAX_METADATA_BYTES:
                raise ValueError("model metadata exceeds the 256 KiB size limit")
            metadata = json.loads(raw_metadata.decode("utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("model metadata must be a JSON object")
            if metadata.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
                raise ValueError("feature schema version mismatch")
            if tuple(metadata.get("features", ())) != FEATURE_NAMES:
                raise ValueError("feature names do not match runtime schema")
            for key in ("model_name", "model_version"):
                if not isinstance(metadata.get(key), str) or not metadata[key].strip():
                    raise ValueError("model metadata is missing a valid {}".format(key))
            declared_classes = metadata.get("classes")
            if (not isinstance(declared_classes, list) or not declared_classes
                    or any(not isinstance(value, str) or not value for value in declared_classes)
                    or len(declared_classes) != len(set(declared_classes))):
                raise ValueError("model metadata has invalid classes")
            model = joblib.load(self.model_path)
            if not callable(getattr(model, "predict", None)):
                raise ValueError("model has no predict method")
            expected_count = getattr(model, "n_features_in_", None)
            if not isinstance(expected_count, numbers.Integral) or isinstance(expected_count, bool):
                raise ValueError("model is missing a valid n_features_in_ feature count")
            if int(expected_count) != len(FEATURE_NAMES):
                raise ValueError("model feature count does not match runtime schema")
            model_classes = getattr(model, "classes_", None)
            if model_classes is None or [str(value) for value in model_classes] != declared_classes:
                raise ValueError("model classes do not match runtime metadata")
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


def _is_network_path(path):
    """Reject UNC/network paths before touching serialized model artifacts."""
    if os.name != "nt":
        return False
    value = str(path).replace("/", "\\")
    return value.startswith("\\\\")
