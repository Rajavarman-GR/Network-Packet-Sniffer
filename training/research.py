"""Reusable, presentation-neutral helpers for UNSW flow research reports."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
from pathlib import Path

from training.unsw_flow_schema import (
    CATEGORICAL_PREDICTOR_COLUMNS, NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS, UNSW_FLOW_SCHEMA_VERSION,
)


def summarize_dataset(path, target_values, dataset_id="UNSW-NB15", source_sha256=None):
    """Summarize validated targets and the repository's fixed predictor schema."""
    path = Path(path)
    counts = Counter({str(key): int(value) for key, value in target_values.items()}) if hasattr(target_values, "items") else Counter(str(value) for value in target_values)
    return {
        "dataset_id": str(dataset_id), "source_file": path.name,
        "source_sha256": source_sha256 or sha256_file(path), "row_count": sum(counts.values()),
        "class_distribution": dict(sorted(counts.items())),
        "predictor_count": len(PREDICTOR_COLUMNS),
        "numeric_feature_count": len(NUMERIC_PREDICTOR_COLUMNS),
        "categorical_feature_count": len(CATEGORICAL_PREDICTOR_COLUMNS),
        "schema_version": UNSW_FLOW_SCHEMA_VERSION,
    }


def sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_importance(pipeline):
    """Report estimator importance with raw and transformed names clearly labeled."""
    classifier = pipeline.named_steps.get("classifier")
    values = getattr(classifier, "feature_importances_", None)
    if values is None:
        return {"available": False, "reason": "classifier_has_no_feature_importances", "features": []}
    preprocessor = pipeline.named_steps.get("preprocessor")
    try:
        transformed = list(preprocessor.get_feature_names_out())
    except (AttributeError, ValueError, TypeError):
        transformed = []
    result = []
    for index, importance in enumerate(values):
        result.append({
            "transformed_feature": transformed[index] if index < len(transformed) else "transformed_{}".format(index),
            "importance": float(importance),
            "raw_dataset_feature": _raw_feature_name(transformed[index]) if index < len(transformed) else None,
        })
    return {"available": True, "features": sorted(result, key=lambda item: (-item["importance"], item["transformed_feature"]))}


def _raw_feature_name(transformed_name):
    name = transformed_name.split("__", 1)[-1]
    for column in sorted(PREDICTOR_COLUMNS, key=len, reverse=True):
        if name == column or name.startswith(column + "_"):
            return column
    return None


def experiment_metadata(dataset_id, source_hash, target, model_version, classifier,
                        hyperparameters, random_seed, evaluation_context):
    return {
        "dataset_id": dataset_id, "source_sha256": source_hash, "target": target,
        "schema_version": UNSW_FLOW_SCHEMA_VERSION, "model_version": model_version,
        "classifier": classifier, "hyperparameters": dict(hyperparameters),
        "random_seed": random_seed, "evaluation_context": evaluation_context,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def visualization_data(report):
    """Return JSON-ready chart data; unsupported metrics remain explicitly absent."""
    return {
        "confusion_matrix": report.get("confusion_matrix"),
        "class_names": report.get("class_names"),
        "roc_curve": report.get("roc_curve"),
        "precision_recall": report.get("per_class"),
        "feature_importance": report.get("feature_importance"),
    }


def render_report(report):
    """Compact human-readable representation of a machine-readable evaluation."""
    lines = ["Evaluation: {}".format(report.get("evaluation_context", "unspecified")),
             "Target: {}".format(report.get("target", "unknown")),
             "Samples: {}".format(report.get("sample_count", 0))]
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        if report.get(key) is not None:
            lines.append("{}: {:.4f}".format(key.replace("_", " ").title(), report[key]))
    lines.append("Confusion matrix: {}".format(report.get("confusion_matrix", [])))
    if report.get("per_class"):
        lines.append("Per-class metrics:")
        for name, metrics in report["per_class"].items():
            lines.append("  {}: precision={:.4f}, recall={:.4f}, F1={:.4f}, support={}".format(
                name, metrics["precision"], metrics["recall"], metrics["f1"], metrics["support"]))
    for key in ("macro_average", "weighted_average"):
        if report.get(key):
            metrics = report[key]
            lines.append("{}: precision={:.4f}, recall={:.4f}, F1={:.4f}".format(
                key.replace("_", " ").title(), metrics["precision"], metrics["recall"], metrics["f1"]))
    return "\n".join(lines)
