"""Dataset adapter for the runtime 23-feature flow schema.

This module validates a local CSV against the exact contract that runtime feature
extraction expects:

    23 feature columns + label

The adapter intentionally rejects malformed input rather than silently guessing
feature mappings. If a public dataset does not map to the same semantics, the
adapter raises a clear error instead of inventing a runtime feature name.
"""

from __future__ import annotations

import csv
import math
from pathlib import Path

from ai.feature_extractor import FEATURE_NAMES

REQUIRED_COLUMNS = list(FEATURE_NAMES) + ["label"]


def normalize_label(value):
    """Return a normalized label from common binary traffic-label encodings."""
    if value is None:
        raise ValueError("Label is missing.")

    text = str(value).strip()
    if not text:
        raise ValueError("Label is empty.")

    lowered = text.lower()
    if lowered in {"0", "0.0", "benign", "normal", "safe", "false", "non-malicious"}:
        return "BENIGN"
    if lowered in {"1", "1.0", "suspicious", "malicious", "threat", "attack", "true", "anomaly"}:
        return "SUSPICIOUS"
    if lowered in {"high_risk", "high-risk", "high risk"}:
        return "SUSPICIOUS"
    raise ValueError(f"Unsupported label value: {value!r}. Expected BENIGN or SUSPICIOUS.")


def _validate_feature_name(name):
    if name not in FEATURE_NAMES:
        raise ValueError(f"Unexpected feature column: {name!r}. Only runtime schema columns are accepted.")


def _parse_numeric(value, feature_name, row_number):
    if value is None or str(value).strip() == "":
        raise ValueError(f"Missing value for feature {feature_name!r} on row {row_number}.")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric value for feature {feature_name!r} on row {row_number}: {value!r}") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"invalid numeric value for feature {feature_name!r} on row {row_number}: {value!r}")
    return numeric


def load_training_dataset(path):
    """Load a CSV dataset and validate it against the runtime feature contract.

    Returns a list of dictionaries ordered exactly as FEATURE_NAMES + ["label"].
    This is intentionally strict: if a public dataset uses different columns or a
    semantically different feature name, the adapter rejects it instead of silently
    inventing a mapping.
    """
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    with dataset_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("Dataset is missing a header row.")

        normalized_fieldnames = [str(name).strip() for name in reader.fieldnames]
        if len(normalized_fieldnames) != len(set(normalized_fieldnames)):
            raise ValueError("Dataset contains duplicate column names.")

        missing_features = [name for name in FEATURE_NAMES if name not in normalized_fieldnames]
        if missing_features:
            raise ValueError(f"Dataset is missing feature columns: {missing_features}")
        if "label" not in normalized_fieldnames:
            raise ValueError("Dataset is missing required label column.")

        for field_name in normalized_fieldnames:
            if field_name == "label":
                continue
            _validate_feature_name(field_name)

        rows = []
        for row_number, row in enumerate(reader, start=2):
            if row is None:
                continue
            normalized_row = {}
            for feature_name in FEATURE_NAMES:
                raw_value = row.get(feature_name)
                normalized_row[feature_name] = _parse_numeric(raw_value, feature_name, row_number)
            label_raw = row.get("label")
            normalized_row["label"] = normalize_label(label_raw)
            rows.append(normalized_row)

    if not rows:
        raise ValueError("Dataset is empty or contains no valid rows.")
    return rows


def get_feature_matrix(rows):
    """Return the X/Y arrays used by the training pipeline."""
    features = [[float(row[name]) for name in FEATURE_NAMES] for row in rows]
    labels = [row["label"] for row in rows]
    return features, labels
