"""Evaluate a saved UNSW-NB15 flow pipeline on its held-out test split."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_curve,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.prepare_unsw import validate_unsw_dataset
from training.train_unsw_flow import (
    DEFAULT_DATASET_ROOT,
    FLOW_MODEL_ROOT,
    METADATA_FILENAME,
    PACKET_MODEL_PATH,
    PIPELINE_FILENAME,
    _is_within,
    _paths_overlap,
    _sha256_file,
)
from training.unsw_model_pipeline import (
    build_unsw_model_metadata,
)
from training.unsw_flow_schema import TARGET_ATTACK_CATEGORY, TARGET_LABEL
from training.research import feature_importance, experiment_metadata, summarize_dataset
from training.research import render_report


def build_argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True, help="UNSW flow pipeline artifact.")
    parser.add_argument("--metadata", type=Path, help="Metadata JSON; defaults beside the artifact.")
    dataset_root = Path(os.environ.get("UNSW_NB15_DIR") or DEFAULT_DATASET_ROOT).expanduser()
    parser.add_argument(
        "--train",
        type=Path,
        default=dataset_root / "UNSW_NB15_training-set.csv",
    )
    parser.add_argument(
        "--test",
        type=Path,
        default=dataset_root / "UNSW_NB15_testing-set.csv",
    )
    parser.add_argument("--format", choices=("json", "text"), default="json", help="Report output format.")
    return parser


def evaluate_unsw_flow(artifact_path, train_path, test_path, metadata_path=None):
    """Evaluate an existing flow pipeline; never fit or refit it."""
    artifact_path = _validate_artifact_path(artifact_path)
    metadata_path = Path(metadata_path) if metadata_path else artifact_path.parent / METADATA_FILENAME
    metadata = _load_metadata(metadata_path)
    target = metadata["target"]

    prepared = validate_unsw_dataset(train_path, test_path, target=target)
    _validate_source_files(metadata, train_path, test_path)
    if prepared.train_rows != metadata["train_row_count"]:
        raise ValueError("Training split row count does not match artifact metadata.")
    if prepared.test_rows != metadata["test_row_count"]:
        raise ValueError("Testing split row count does not match artifact metadata.")

    pipeline = joblib.load(artifact_path)
    if not isinstance(pipeline, Pipeline):
        raise ValueError("UNSW flow artifact is not a scikit-learn Pipeline.")
    if getattr(pipeline, "target_column", None) != target:
        raise ValueError("Pipeline target does not match its metadata.")
    if not callable(getattr(pipeline, "predict", None)):
        raise ValueError("UNSW flow pipeline has no predict method.")

    test_features, test_targets, test_counts = _collect_test_split(
        prepared.iter_test(), prepared.test_rows, prepared.predictor_columns, target
    )
    if _ordered_counts(metadata["class_names"], test_counts) != metadata["class_counts"]["test"]:
        raise ValueError("Testing target counts do not match artifact metadata.")

    predictions = np.asarray(pipeline.predict(test_features))
    if len(predictions) != len(test_targets):
        raise ValueError("Pipeline returned a different number of predictions than test rows.")

    report = _build_report(
        pipeline,
        test_features,
        target,
        test_targets,
        predictions,
        metadata["class_names"],
    )
    report["evaluation_context"] = "independent_test_set"
    report["experiment"] = experiment_metadata(
        "UNSW-NB15", metadata["source_files"]["test"]["sha256"], target,
        metadata.get("model_version"),
        type(pipeline.named_steps["classifier"]).__name__,
        metadata["classifier_parameters"], metadata["random_seed"],
        "independent_test_set",
    )
    report["feature_importance"] = feature_importance(pipeline)
    report["dataset_summary"] = summarize_dataset(test_path, test_counts,
        source_sha256=metadata["source_files"]["test"]["sha256"])
    return report


def _validate_artifact_path(artifact_path):
    artifact_path = Path(artifact_path).expanduser().resolve()
    model_root = PACKET_MODEL_PATH.parent.resolve()
    flow_root = FLOW_MODEL_ROOT.resolve()
    packet_model = PACKET_MODEL_PATH.resolve()
    if artifact_path.name != PIPELINE_FILENAME:
        raise ValueError("Expected a dedicated {!r} flow artifact.".format(PIPELINE_FILENAME))
    if _paths_overlap(artifact_path, packet_model):
        raise ValueError("Packet detector model artifacts cannot be evaluated as UNSW flows.")
    if _is_within(artifact_path, model_root) and not _is_within(artifact_path, flow_root):
        raise ValueError("UNSW artifacts under ai/model must be inside ai/model/unsw_flow.")
    if not artifact_path.is_file():
        raise FileNotFoundError("UNSW pipeline artifact not found: {}".format(artifact_path))
    return artifact_path


def _load_metadata(metadata_path):
    metadata_path = Path(metadata_path)
    if not metadata_path.is_file():
        raise FileNotFoundError("UNSW metadata file not found: {}".format(metadata_path))
    try:
        with metadata_path.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Could not read UNSW metadata: {}".format(exc)) from exc
    _validate_metadata(metadata)
    return metadata


def _validate_metadata(metadata):
    if not isinstance(metadata, dict):
        raise ValueError("UNSW metadata must be a JSON object.")
    target = metadata.get("target")
    if target not in {TARGET_LABEL, TARGET_ATTACK_CATEGORY}:
        raise ValueError("UNSW metadata has an unsupported target.")
    expected = build_unsw_model_metadata(target)
    for key in (
        "model_family",
        "schema_version",
        "target",
        "predictor_columns",
        "numeric_predictor_columns",
        "categorical_predictor_columns",
        "excluded_columns",
    ):
        if metadata.get(key) != expected[key]:
            raise ValueError("UNSW metadata field {!r} does not match the flow schema.".format(key))

    class_names = expected["expected_class_names"]
    if metadata.get("class_names") != class_names:
        raise ValueError("UNSW metadata class names do not match the selected target.")
    if metadata.get("expected_class_names") != class_names:
        raise ValueError("UNSW metadata expected classes do not match the selected target.")
    if not isinstance(metadata.get("random_seed"), int):
        raise ValueError("UNSW metadata is missing an integer random seed.")
    expected_classifier = {
        **expected["classifier_parameters"],
        "random_state": metadata["random_seed"],
    }
    if metadata.get("classifier_parameters") != expected_classifier:
        raise ValueError("UNSW metadata classifier parameters do not match the supported design.")
    for key in ("train_row_count", "test_row_count"):
        if not isinstance(metadata.get(key), int) or metadata[key] <= 0:
            raise ValueError("UNSW metadata has an invalid {!r}.".format(key))

    counts = metadata.get("class_counts")
    if not isinstance(counts, dict) or set(counts) != {"train", "test"}:
        raise ValueError("UNSW metadata class counts must contain train and test splits.")
    for split_counts in counts.values():
        if not isinstance(split_counts, dict) or set(split_counts) != {str(name) for name in class_names}:
            raise ValueError("UNSW metadata class-count classes do not match the target.")
        if any(not isinstance(value, int) or value < 0 for value in split_counts.values()):
            raise ValueError("UNSW metadata contains invalid class counts.")
    for split_name, row_count_key in (("train", "train_row_count"), ("test", "test_row_count")):
        if sum(counts[split_name].values()) != metadata[row_count_key]:
            raise ValueError("UNSW metadata class counts do not sum to the split row count.")
    if any(value == 0 for value in counts["train"].values()):
        raise ValueError("UNSW metadata training split is missing an expected class.")

    source_files = metadata.get("source_files")
    if not isinstance(source_files, dict) or set(source_files) != {"train", "test"}:
        raise ValueError("UNSW metadata must include train and test source-file records.")
    for source in source_files.values():
        if not isinstance(source, dict):
            raise ValueError("UNSW source-file metadata must be an object.")
        filename = source.get("filename")
        digest = source.get("sha256")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ValueError("UNSW source metadata must contain a filename, not a local path.")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.lower())
        ):
            raise ValueError("UNSW source metadata has an invalid SHA-256 digest.")


def _validate_source_files(metadata, train_path, test_path):
    for split, path in (("train", train_path), ("test", test_path)):
        path = Path(path)
        source = metadata["source_files"][split]
        if source["filename"] != path.name:
            raise ValueError("{} CSV filename does not match artifact metadata.".format(split.title()))
        if source["sha256"] != _sha256_file(path):
            raise ValueError("{} CSV SHA-256 does not match artifact metadata.".format(split.title()))


def _collect_test_split(rows, expected_count, predictor_columns, target):
    features = np.empty((expected_count, len(predictor_columns)), dtype=object)
    targets = np.empty(
        expected_count,
        dtype=np.int64 if target == TARGET_LABEL else object,
    )
    counts = Counter()
    count = 0
    for count, (predictor_row, target_value) in enumerate(rows, start=1):
        if count > expected_count:
            raise ValueError("Testing split changed while it was being read.")
        features[count - 1] = [predictor_row[name] for name in predictor_columns]
        targets[count - 1] = target_value
        counts[target_value] += 1
    if count != expected_count:
        raise ValueError("Testing split row count changed while it was being read.")
    return features, targets, counts


def _ordered_counts(class_names, counts):
    return {str(name): int(counts.get(name, 0)) for name in class_names}


def _build_report(pipeline, features, target, truth, predictions, class_names):
    class_support = _ordered_counts(class_names, Counter(truth.tolist()))
    report = {
        "target": target,
        "sample_count": int(len(truth)),
        "class_names": list(class_names),
        "accuracy": float(accuracy_score(truth, predictions)),
        "class_support": class_support,
        "confusion_matrix": confusion_matrix(truth, predictions, labels=class_names).tolist(),
    }

    if target == TARGET_LABEL:
        precision, recall, f1, _ = precision_recall_fscore_support(
            truth,
            predictions,
            labels=[1],
            average="binary",
            pos_label=1,
            zero_division=0,
        )
        report.update({
            "positive_class": 1,
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "support": int(class_support["1"]),
            "per_class": {
                str(name): {
                    "precision": float(item[0]), "recall": float(item[1]),
                    "f1": float(item[2]), "support": int(item[3]),
                }
                for name, item in zip(class_names, zip(*precision_recall_fscore_support(
                    truth, predictions, labels=class_names, average=None, zero_division=0
                )))
            },
            "macro_average": _average_metrics(truth, predictions, class_names, "macro"),
            "weighted_average": _average_metrics(truth, predictions, class_names, "weighted"),
        })
    else:
        precision, recall, f1, support = precision_recall_fscore_support(
            truth,
            predictions,
            labels=class_names,
            average=None,
            zero_division=0,
        )
        per_class = {}
        for index, class_name in enumerate(class_names):
            per_class[str(class_name)] = {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
        report["per_class"] = per_class
        report["macro_average"] = _average_metrics(
            truth, predictions, class_names, "macro"
        )
        report["weighted_average"] = _average_metrics(
            truth, predictions, class_names, "weighted"
        )

    roc_auc = _maybe_roc_auc(pipeline, features, truth, target, class_names)
    if roc_auc is not None:
        report["roc_auc"] = roc_auc
    curve_data = _roc_curve_data(pipeline, features, truth, target, class_names)
    if curve_data is not None:
        report["roc_curve"] = curve_data
    return report


def _average_metrics(truth, predictions, class_names, average):
    precision, recall, f1, _ = precision_recall_fscore_support(
        truth,
        predictions,
        labels=class_names,
        average=average,
        zero_division=0,
    )
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }


def _maybe_roc_auc(pipeline, features, truth, target, class_names):
    if len(set(truth.tolist())) < len(class_names):
        return None
    try:
        model_classes = list(pipeline.classes_)
    except AttributeError:
        return None

    predict_proba = getattr(pipeline, "predict_proba", None)
    if callable(predict_proba):
        scores = np.asarray(predict_proba(features))
        if target == TARGET_LABEL:
            try:
                positive_index = model_classes.index(1)
            except ValueError:
                return None
            if scores.ndim != 2 or scores.shape[1] != len(model_classes):
                return None
            return float(roc_auc_score(truth, scores[:, positive_index]))
        if scores.ndim != 2 or scores.shape[1] != len(model_classes):
            return None
        try:
            ordered_scores = scores[:, [model_classes.index(name) for name in class_names]]
            return float(roc_auc_score(
                truth,
                ordered_scores,
                labels=class_names,
                multi_class="ovr",
                average="macro",
            ))
        except (ValueError, IndexError):
            return None

    if target == TARGET_LABEL:
        decision_function = getattr(pipeline, "decision_function", None)
        if callable(decision_function) and len(model_classes) == 2:
            scores = np.asarray(decision_function(features))
            if scores.ndim == 1:
                if model_classes[1] != 1:
                    scores = -scores
                return float(roc_auc_score(truth, scores))
        return None
    return None


def _roc_curve_data(pipeline, features, truth, target, class_names):
    if len(set(truth.tolist())) < len(class_names):
        return None
    predict_proba = getattr(pipeline, "predict_proba", None)
    if not callable(predict_proba):
        return None
    try:
        model_classes = list(pipeline.classes_)
        scores = np.asarray(predict_proba(features))
    except (AttributeError, ValueError, TypeError):
        return None
    if scores.ndim != 2 or scores.shape[1] != len(model_classes):
        return None
    if target == TARGET_LABEL:
        try:
            column = model_classes.index(1)
        except ValueError:
            return None
        fpr, tpr, thresholds = roc_curve(truth, scores[:, column], pos_label=1)
        return {"average": "binary", "positive_class": 1,
                "false_positive_rate": fpr.tolist(), "true_positive_rate": tpr.tolist(),
                "thresholds": thresholds.tolist()}
    curves = {}
    for name in class_names:
        try:
            column = model_classes.index(name)
        except ValueError:
            return None
        binary_truth = np.asarray([1 if value == name else 0 for value in truth])
        if len(set(binary_truth.tolist())) < 2:
            return None
        fpr, tpr, thresholds = roc_curve(binary_truth, scores[:, column], pos_label=1)
        curves[str(name)] = {"false_positive_rate": fpr.tolist(),
            "true_positive_rate": tpr.tolist(), "thresholds": thresholds.tolist()}
    return {"average": "one_vs_rest", "per_class": curves}


def main(argv=None):
    args = build_argument_parser().parse_args(argv)
    report = evaluate_unsw_flow(
        args.artifact,
        args.train,
        args.test,
        metadata_path=args.metadata,
    )
    print(render_report(report) if args.format == "text" else json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
