"""Train a local threat model from a runtime feature CSV.

Usage::

    python training/train.py dataset.csv [--output-dir PATH] [--force]

The default destination contains the runtime model files. Existing artifacts
are never replaced unless --force is given explicitly.
"""

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ai.feature_extractor import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


MODEL_DIR = ROOT / "ai" / "model"
RESEARCH_MODEL_DIR = MODEL_DIR / "unsw_flow"


def load_dataset(path):
    with Path(path).expanduser().open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = set(FEATURE_NAMES) | {"label"}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"Dataset is missing columns: {sorted(missing)}")
    features = [[float(row[name]) for name in FEATURE_NAMES] for row in rows]
    labels = [row["label"] for row in rows]
    return features, labels


def _is_within(path, parent):
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_output_paths(output_dir):
    output_dir = Path(output_dir).expanduser().resolve()
    research_dir = RESEARCH_MODEL_DIR.resolve()
    if _is_within(output_dir, research_dir):
        raise ValueError(
            "Runtime training output cannot be placed in the UNSW research artifact directory."
        )
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError("Model output path must be a directory: {}".format(output_dir))
    return output_dir, output_dir / "threat_model.joblib", output_dir / "metadata.json"


def _ensure_output_available(model_path, metadata_path, force):
    existing = [path for path in (model_path, metadata_path) if path.exists() or path.is_symlink()]
    invalid = [path for path in existing if not path.is_file() and not path.is_symlink()]
    if invalid:
        raise IsADirectoryError("Model output target is not a file: {}".format(invalid[0]))
    if existing and not force:
        raise FileExistsError(
            "Runtime model artifacts already exist; choose another --output-dir or pass --force explicitly."
        )


def _stage_and_save(pipeline, metadata, output_dir, model_path, metadata_path, force):
    output_dir.mkdir(parents=True, exist_ok=True)
    _ensure_output_available(model_path, metadata_path, force)
    with tempfile.TemporaryDirectory(prefix=".runtime-training-", dir=str(output_dir)) as staging_dir:
        staged_model = Path(staging_dir) / "threat_model.joblib"
        staged_metadata = Path(staging_dir) / "metadata.json"
        joblib.dump(pipeline, staged_model)
        staged_metadata.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

        if force:
            _replace_pair(staged_model, staged_metadata, model_path, metadata_path)
        else:
            _install_new_pair(staged_model, staged_metadata, model_path, metadata_path)


def _install_new_pair(staged_model, staged_metadata, model_path, metadata_path):
    created = []
    try:
        with staged_model.open("rb") as source, model_path.open("xb") as destination:
            created.append(model_path)
            shutil.copyfileobj(source, destination)
        with staged_metadata.open("rb") as source, metadata_path.open("xb") as destination:
            created.append(metadata_path)
            shutil.copyfileobj(source, destination)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def _replace_pair(staged_model, staged_metadata, model_path, metadata_path):
    backups = {}
    installed = []
    token = uuid.uuid4().hex
    targets = ((model_path, staged_model), (metadata_path, staged_metadata))
    try:
        for destination, _ in targets:
            if destination.exists() or destination.is_symlink():
                backup = destination.with_name(".{}.{}.backup".format(destination.name, token))
                os.replace(destination, backup)
                backups[destination] = backup
        for destination, staged in targets:
            os.replace(staged, destination)
            installed.append(destination)
    except Exception:
        for destination in installed:
            destination.unlink(missing_ok=True)
        for destination, backup in backups.items():
            if backup.exists() or backup.is_symlink():
                os.replace(backup, destination)
        raise
    else:
        for backup in backups.values():
            backup.unlink(missing_ok=True)


def train(dataset_path, output_dir=MODEL_DIR, force=False):
    output_dir, model_path, metadata_path = _resolve_output_paths(output_dir)
    _ensure_output_available(model_path, metadata_path, force)
    features, labels = load_dataset(dataset_path)
    pipeline = Pipeline([
        ("scale", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")),
    ])
    pipeline.fit(features, labels)
    metadata = {
        "model_name": "network-packet-random-forest",
        "model_version": "1.0",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "features": list(FEATURE_NAMES),
        "classes": [str(value) for value in pipeline.classes_],
    }
    _stage_and_save(pipeline, metadata, output_dir, model_path, metadata_path, force)
    return pipeline


def build_argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output-dir", type=Path, default=MODEL_DIR,
                        help="Output directory (defaults to the runtime model directory).")
    parser.add_argument("--force", action="store_true",
                        help="Explicitly replace existing runtime artifacts in the output directory.")
    return parser


def main(argv=None):
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        train(args.dataset, args.output_dir, force=args.force)
    except (OSError, ValueError, csv.Error) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
