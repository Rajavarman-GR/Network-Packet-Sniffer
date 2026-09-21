"""Evaluate a trained local model using the same feature CSV schema."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
from sklearn.metrics import classification_report

from training.train import load_dataset, MODEL_DIR


def evaluate(dataset_path, model_dir=MODEL_DIR):
    features, labels = load_dataset(dataset_path)
    model = joblib.load(Path(model_dir) / "threat_model.joblib")
    predictions = model.predict(features)
    report = classification_report(labels, predictions, zero_division=0)
    print(report)
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python training/evaluate.py dataset.csv")
    evaluate(sys.argv[1])
