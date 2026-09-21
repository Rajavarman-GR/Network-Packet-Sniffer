"""Train a local threat model from a documented feature CSV.

Usage:
    python training/train.py dataset.csv

The CSV must contain every column in ai.feature_extractor.FEATURE_NAMES and a
`label` column. Labels should be 0/1 or benign/suspicious. No data is downloaded.
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ai.feature_extractor import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


MODEL_DIR = ROOT / "ai" / "model"


def load_dataset(path):
    with Path(path).open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = set(FEATURE_NAMES) | {"label"}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"Dataset is missing columns: {sorted(missing)}")
    features = [[float(row[name]) for name in FEATURE_NAMES] for row in rows]
    labels = [row["label"] for row in rows]
    return features, labels


def train(dataset_path, output_dir=MODEL_DIR):
    features, labels = load_dataset(dataset_path)
    pipeline = Pipeline([
        ("scale", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")),
    ])
    pipeline.fit(features, labels)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, output_dir / "threat_model.joblib")
    metadata = {
        "model_name": "network-packet-random-forest",
        "model_version": "1.0",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "features": list(FEATURE_NAMES),
        "classes": [str(value) for value in pipeline.classes_],
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return pipeline


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python training/train.py dataset.csv")
    train(sys.argv[1])
