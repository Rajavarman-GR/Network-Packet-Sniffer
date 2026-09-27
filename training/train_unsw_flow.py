"""Train a dedicated UNSW-NB15 flow model, separate from packet inference."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import uuid

import joblib
import numpy as np
import sklearn

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.prepare_unsw import validate_unsw_dataset
from training.unsw_model_pipeline import (
    build_attack_category_pipeline,
    build_binary_pipeline,
    build_unsw_model_metadata,
)
from training.unsw_flow_schema import TARGET_ATTACK_CATEGORY, TARGET_LABEL

MODEL_ROOT = ROOT / "ai" / "model"
FLOW_MODEL_ROOT = MODEL_ROOT / "unsw_flow"
PACKET_MODEL_PATH = MODEL_ROOT / "threat_model.joblib"
PIPELINE_FILENAME = "unsw_flow_pipeline.joblib"
METADATA_FILENAME = "metadata.json"
DEFAULT_DATASET_ROOT = Path(r"D:\Datasets\UNSW-NB15")


def build_argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=(TARGET_LABEL, TARGET_ATTACK_CATEGORY),
        required=True,
        help="Choose the binary label or attack-category target.",
    )
    dataset_root = Path(os.environ.get("UNSW_NB15_DIR", str(DEFAULT_DATASET_ROOT)))
    parser.add_argument(
        "--train",
        type=Path,
        default=dataset_root / "UNSW_NB15_training-set.csv",
        help="Training CSV; defaults to the local UNSW-NB15 training split.",
    )
    parser.add_argument(
        "--test",
        type=Path,
        default=dataset_root / "UNSW_NB15_testing-set.csv",
        help="Testing CSV; defaults to the local UNSW-NB15 testing split.",
    )
    parser.add_argument(
        "--output",
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=FLOW_MODEL_ROOT,
        help="UNSW flow artifact root; target-specific subdirectory is created inside it.",
    )
    parser.add_argument("--random-seed", type=int, default=42)
    return parser


def resolve_output_directory(output_root, target):
    """Resolve a target-specific directory and reject packet-model locations."""
    if target not in {TARGET_LABEL, TARGET_ATTACK_CATEGORY}:
        raise ValueError("Unsupported UNSW target: {!r}.".format(target))

    output_root = Path(output_root).expanduser().resolve()
    if output_root.exists() and not output_root.is_dir():
        raise ValueError("UNSW output root must be a directory: {}".format(output_root))

    target_directory_name = "binary" if target == TARGET_LABEL else "attack_category"
    target_directory = (output_root / target_directory_name).resolve()
    model_root = MODEL_ROOT.resolve()
    flow_root = FLOW_MODEL_ROOT.resolve()
    packet_model = PACKET_MODEL_PATH.resolve()

    if _paths_overlap(target_directory, packet_model):
        raise ValueError("UNSW output path overlaps the packet detector model path.")
    if _is_within(target_directory, model_root) and not _is_within(target_directory, flow_root):
        raise ValueError(
            "Output under ai/model must use the dedicated ai/model/unsw_flow directory."
        )
    return target_directory


def train_unsw_flow(train_path, test_path, target, output_dir=FLOW_MODEL_ROOT, random_seed=42):
    """Validate, fit on the official training split, and write separate artifacts."""
    if target not in {TARGET_LABEL, TARGET_ATTACK_CATEGORY}:
        raise ValueError("Unsupported UNSW target: {!r}.".format(target))
    prepared = validate_unsw_dataset(train_path, test_path, target=target)
    target_directory = resolve_output_directory(output_dir, target)
    artifact_path = target_directory / PIPELINE_FILENAME
    metadata_path = target_directory / METADATA_FILENAME
    _ensure_output_available(target_directory, artifact_path, metadata_path)
    target_directory.mkdir(parents=True, exist_ok=True)

    train_features, train_targets, train_counts = _collect_split(
        prepared.iter_train(), prepared.train_rows, prepared.predictor_columns, target
    )
    test_counts = _count_targets(prepared.iter_test())
    metadata = build_unsw_model_metadata(target)
    class_names = metadata["expected_class_names"]
    missing_training_classes = [
        class_name for class_name in class_names if train_counts.get(class_name, 0) == 0
    ]
    if missing_training_classes:
        raise ValueError(
            "Training split is missing expected target classes: {}.".format(
                missing_training_classes
            )
        )

    pipeline = (
        build_binary_pipeline()
        if target == TARGET_LABEL
        else build_attack_category_pipeline()
    )
    pipeline.set_params(classifier__random_state=random_seed)
    pipeline.fit(train_features, train_targets)

    train_path = Path(train_path)
    test_path = Path(test_path)
    metadata.update({
        "class_names": class_names,
        "class_counts": {
            "train": _ordered_counts(class_names, train_counts),
            "test": _ordered_counts(class_names, test_counts),
        },
        "train_row_count": prepared.train_rows,
        "test_row_count": prepared.test_rows,
        "random_seed": random_seed,
        "classifier_parameters": {
            **metadata["classifier_parameters"],
            "random_state": random_seed,
        },
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "source_files": {
            "train": {"filename": train_path.name, "sha256": _sha256_file(train_path)},
            "test": {"filename": test_path.name, "sha256": _sha256_file(test_path)},
        },
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })
    _save_artifacts(pipeline, metadata, target_directory, artifact_path, metadata_path)
    return {
        "artifact_path": artifact_path,
        "metadata_path": metadata_path,
        "metadata": metadata,
    }


def _collect_split(rows, expected_count, predictor_columns, target):
    features = np.empty((expected_count, len(predictor_columns)), dtype=object)
    targets = np.empty(
        expected_count,
        dtype=np.int64 if target == TARGET_LABEL else object,
    )
    target_counts = Counter()
    count = 0
    for count, (predictor_row, target_value) in enumerate(rows, start=1):
        if count > expected_count:
            raise ValueError("Validated split changed while it was being read.")
        features[count - 1] = [predictor_row[name] for name in predictor_columns]
        targets[count - 1] = target_value
        target_counts[target_value] += 1
    if count != expected_count:
        raise ValueError("Validated split row count changed while it was being read.")
    return features, targets, target_counts


def _count_targets(rows):
    counts = Counter()
    for _, target_value in rows:
        counts[target_value] += 1
    return counts


def _ordered_counts(class_names, counts):
    return {str(name): int(counts.get(name, 0)) for name in class_names}


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_output_available(target_directory, artifact_path, metadata_path):
    if _paths_overlap(target_directory.resolve(), PACKET_MODEL_PATH.resolve()):
        raise ValueError("UNSW output path overlaps the packet detector model path.")
    if artifact_path.exists() or metadata_path.exists():
        raise FileExistsError(
            "UNSW artifacts already exist in {}; choose another output root.".format(
                target_directory
            )
        )


def _save_artifacts(pipeline, metadata, target_directory, artifact_path, metadata_path):
    token = uuid.uuid4().hex
    temporary_artifact = target_directory / (".{}.{}.tmp".format(PIPELINE_FILENAME, token))
    temporary_metadata = target_directory / (".{}.{}.tmp".format(METADATA_FILENAME, token))
    try:
        joblib.dump(pipeline, temporary_artifact)
        with temporary_metadata.open("x", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
            handle.write("\n")
        os.replace(temporary_artifact, artifact_path)
        try:
            os.replace(temporary_metadata, metadata_path)
        except Exception:
            artifact_path.unlink(missing_ok=True)
            raise
    finally:
        temporary_artifact.unlink(missing_ok=True)
        temporary_metadata.unlink(missing_ok=True)


def _is_within(path, parent):
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _paths_overlap(first, second):
    return first == second or _is_within(first, second) or _is_within(second, first)


def main(argv=None):
    args = build_argument_parser().parse_args(argv)
    result = train_unsw_flow(
        args.train,
        args.test,
        args.target,
        output_dir=args.output_dir,
        random_seed=args.random_seed,
    )
    print("Pipeline artifact: {}".format(result["artifact_path"]))
    print("Metadata: {}".format(result["metadata_path"]))


if __name__ == "__main__":
    main()