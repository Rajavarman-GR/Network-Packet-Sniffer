"""Run internal validation and feature-sensitivity audits on UNSW training data only."""

import argparse
import csv
import gc
import json
import math
from pathlib import Path
import sys
import time

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.unsw_flow_schema import (
    ALLOWED_COLUMNS,
    CATEGORICAL_PREDICTOR_COLUMNS,
    EXPECTED_ATTACK_CATEGORIES,
    EXPECTED_LABEL_VALUES,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    REQUIRED_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_LABEL,
)

RANDOM_SEED = 42
VALIDATION_FRACTION = 0.2
BATCH_CLASSIFIER_PARAMETERS = {
    "n_estimators": 400,
    "class_weight": "balanced",
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}
PROTECTED_TEST_FILENAME = "unsw_nb15_testing-set.csv"
SEQUENCE_NUMBER_FEATURES = ("stcpb", "dtcpb")


def build_argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--training-data",
        type=Path,
        required=True,
        help="Explicit path to an UNSW-NB15 training CSV; no test-file default is used.",
    )
    parser.add_argument("--validation-fraction", type=float, default=VALIDATION_FRACTION)
    parser.add_argument("--random-state", type=int, default=RANDOM_SEED)
    return parser


def load_training_data(training_data_path):
    """Validate and load one explicit UNSW training CSV; never opens a test file."""
    if training_data_path is None:
        raise ValueError("An explicit training-data path is required.")
    path = Path(training_data_path).expanduser()
    if path.name.casefold() == PROTECTED_TEST_FILENAME:
        raise ValueError("The official UNSW testing CSV cannot be used for this audit.")
    if not path.is_file():
        raise FileNotFoundError("UNSW training CSV not found: {}".format(path))

    header = _read_and_validate_header(path)
    row_count = 0
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row_number, row in enumerate(reader, start=2):
            _validate_row(path, row_number, row, header)
            row_count += 1
    if row_count == 0:
        raise ValueError("UNSW training CSV is empty.")

    features = np.empty((row_count, len(PREDICTOR_COLUMNS)), dtype=object)
    labels = np.empty(row_count, dtype=np.int8)
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            if index >= row_count:
                raise ValueError("Training CSV changed while the audit was loading it.")
            features[index] = [
                float(row[name]) if name in NUMERIC_PREDICTOR_COLUMNS else row[name]
                for name in PREDICTOR_COLUMNS
            ]
            labels[index] = int(row[TARGET_LABEL])
    if index + 1 != row_count:
        raise ValueError("Training CSV row count changed while the audit was loading it.")
    return features, labels


def create_internal_split(labels, validation_fraction=VALIDATION_FRACTION, random_state=RANDOM_SEED):
    """Return stratified indices for diagnostics within the supplied training CSV."""
    if not 0.0 < validation_fraction < 1.0:
        raise ValueError("validation_fraction must be strictly between 0 and 1.")
    indices = np.arange(len(labels))
    return train_test_split(
        indices,
        test_size=validation_fraction,
        random_state=random_state,
        stratify=labels,
    )


def build_feature_variants():
    """Return the four controlled feature sets in canonical schema order."""
    no_sequence_numbers = set(SEQUENCE_NUMBER_FEATURES)
    all_connection_counts = {name for name in PREDICTOR_COLUMNS if name.startswith("ct_")}
    definitions = (
        ("A_all_42", set()),
        ("B_without_stcpb_dtcpb", no_sequence_numbers),
        ("C_without_ct_features", all_connection_counts),
        ("D_without_stcpb_dtcpb_and_ct", no_sequence_numbers | all_connection_counts),
    )
    return {
        name: tuple(column for column in PREDICTOR_COLUMNS if column not in excluded)
        for name, excluded in definitions
    }


def build_variant_pipeline(selected_columns):
    """Build an unfitted audit pipeline for exactly the selected UNSW features."""
    selected_columns = tuple(selected_columns)
    if not selected_columns:
        raise ValueError("At least one UNSW predictor must be selected.")
    if len(selected_columns) != len(set(selected_columns)):
        raise ValueError("Selected UNSW predictors contain duplicates.")
    unexpected = sorted(set(selected_columns) - set(PREDICTOR_COLUMNS))
    if unexpected:
        raise ValueError("Unexpected or excluded UNSW predictors: {}.".format(unexpected))

    numeric_indices = tuple(
        index for index, name in enumerate(selected_columns)
        if name in NUMERIC_PREDICTOR_COLUMNS
    )
    categorical_indices = tuple(
        index for index, name in enumerate(selected_columns)
        if name in CATEGORICAL_PREDICTOR_COLUMNS
    )
    if not numeric_indices or not categorical_indices:
        raise ValueError("Each audit variant must include numeric and categorical predictors.")

    preprocessor = ColumnTransformer(
        transformers=(
            ("numeric", StandardScaler(), numeric_indices),
            ("categorical", OneHotEncoder(handle_unknown="ignore"), categorical_indices),
        ),
        remainder="drop",
    )
    return Pipeline(
        steps=(
            ("preprocessor", preprocessor),
            ("classifier", RandomForestClassifier(**BATCH_CLASSIFIER_PARAMETERS)),
        )
    )


def audit_training_data(
    training_data_path,
    validation_fraction=VALIDATION_FRACTION,
    random_state=RANDOM_SEED,
):
    """Train four in-memory variants on one internal split from a training CSV.

    This function accepts only one explicit input file and writes no artifacts.
    """
    features, labels = load_training_data(training_data_path)
    train_indices, validation_indices = create_internal_split(
        labels,
        validation_fraction=validation_fraction,
        random_state=random_state,
    )
    variants = build_feature_variants()
    variant_results = []

    for variant_name, selected_columns in variants.items():
        selected_indices = [PREDICTOR_COLUMNS.index(name) for name in selected_columns]
        variant_features = features[:, selected_indices]
        internal_train = variant_features[train_indices]
        internal_validation = variant_features[validation_indices]
        internal_train_labels = labels[train_indices]
        internal_validation_labels = labels[validation_indices]

        pipeline = build_variant_pipeline(selected_columns)
        start_time = time.perf_counter()
        pipeline.fit(internal_train, internal_train_labels)
        training_seconds = time.perf_counter() - start_time

        predictions = pipeline.predict(internal_validation)
        precision, recall, f1, _ = precision_recall_fscore_support(
            internal_validation_labels,
            predictions,
            labels=[1],
            average="binary",
            pos_label=1,
            zero_division=0,
        )
        preprocessor = pipeline.named_steps["preprocessor"]
        classifier = pipeline.named_steps["classifier"]
        importance_by_feature = _aggregate_importance(
            preprocessor,
            classifier.feature_importances_,
            selected_columns,
        )
        top_features = sorted(
            importance_by_feature.items(),
            key=lambda item: (-item[1], item[0]),
        )[:15]
        sensitive_features = (
            "stcpb",
            "dtcpb",
            "ct_state_ttl",
            "ct_srv_dst",
            "ct_dst_src_ltm",
        )

        variant_results.append({
            "name": variant_name,
            "predictor_columns": list(selected_columns),
            "original_predictor_count": len(selected_columns),
            "transformed_feature_count": len(preprocessor.get_feature_names_out()),
            "internal_validation": {
                "accuracy": float(accuracy_score(internal_validation_labels, predictions)),
                "precision_positive_1": float(precision),
                "recall_positive_1": float(recall),
                "f1_positive_1": float(f1),
                "support_positive_1": int(np.count_nonzero(internal_validation_labels == 1)),
                "confusion_matrix_actual_0_1_predicted_0_1": confusion_matrix(
                    internal_validation_labels, predictions, labels=[0, 1]
                ).tolist(),
            },
            "training_seconds": training_seconds,
            "top_15_original_features": [
                {"feature": name, "importance": value} for name, value in top_features
            ],
            "sensitivity_features": {
                name: importance_by_feature.get(name)
                for name in sensitive_features
            },
            "all_original_feature_importances": importance_by_feature,
        })

        del pipeline, variant_features, internal_train, internal_validation, predictions
        del preprocessor, classifier, importance_by_feature, top_features
        del internal_train_labels, internal_validation_labels
        gc.collect()

    result = {
        "study": "INTERNAL VALIDATION AND FEATURE-SENSITIVITY ONLY",
        "source_filename": Path(training_data_path).name,
        "target": TARGET_LABEL,
        "official_test_data_used": False,
        "official_training_rows": int(len(labels)),
        "internal_split": {
            "method": "stratified train_test_split on the supplied training CSV only",
            "training_fraction": 1.0 - validation_fraction,
            "validation_fraction": validation_fraction,
            "random_state": random_state,
            "internal_training_rows": int(len(train_indices)),
            "internal_validation_rows": int(len(validation_indices)),
        },
        "classifier_parameters": dict(BATCH_CLASSIFIER_PARAMETERS),
        "variants": variant_results,
    }
    del features, labels
    gc.collect()
    return result


def _read_and_validate_header(path):
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames
    if not header:
        raise ValueError("{} is missing a CSV header row.".format(path))
    if any(name is None or name == "" for name in header):
        raise ValueError("{} contains an empty column name.".format(path))
    if len(header) != len(set(header)):
        raise ValueError("{} contains duplicate column names.".format(path))
    columns = set(header)
    missing = sorted(set(REQUIRED_COLUMNS) - columns)
    unexpected = sorted(columns - ALLOWED_COLUMNS)
    if missing:
        raise ValueError("{} is missing required training columns: {}.".format(path, missing))
    if unexpected:
        raise ValueError("{} contains unexpected columns: {}.".format(path, unexpected))
    return tuple(header)


def _validate_row(path, row_number, row, header):
    if None in row or any(row.get(name) is None for name in header):
        raise ValueError("{} has a malformed row {}.".format(path, row_number))
    if not row["id"].strip():
        raise ValueError("{} has an empty id on row {}.".format(path, row_number))
    if row[TARGET_LABEL] not in EXPECTED_LABEL_VALUES:
        raise ValueError("{} has invalid label on row {}.".format(path, row_number))

    for name in NUMERIC_PREDICTOR_COLUMNS:
        try:
            value = float(row[name])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "{} has invalid numeric value for {!r} on row {}.".format(path, name, row_number)
            ) from exc
        if not math.isfinite(value):
            raise ValueError(
                "{} has non-finite numeric value for {!r} on row {}.".format(
                    path, name, row_number
                )
            )
    for name in CATEGORICAL_PREDICTOR_COLUMNS:
        if not row[name].strip():
            raise ValueError(
                "{} has an empty categorical value for {!r} on row {}.".format(
                    path, name, row_number
                )
            )
    if TARGET_ATTACK_CATEGORY in row and row[TARGET_ATTACK_CATEGORY] not in EXPECTED_ATTACK_CATEGORIES:
        raise ValueError("{} has invalid attack_cat on row {}.".format(path, row_number))


def _aggregate_importance(preprocessor, feature_importances, selected_columns):
    numeric_slice = preprocessor.output_indices_["numeric"]
    categorical_slice = preprocessor.output_indices_["categorical"]
    numeric_columns = [name for name in selected_columns if name in NUMERIC_PREDICTOR_COLUMNS]
    categorical_columns = [name for name in selected_columns if name in CATEGORICAL_PREDICTOR_COLUMNS]
    aggregated = {
        name: float(feature_importances[numeric_slice.start + index])
        for index, name in enumerate(numeric_columns)
    }

    encoder = preprocessor.named_transformers_["categorical"]
    offset = categorical_slice.start
    for name, categories in zip(categorical_columns, encoder.categories_):
        stop = offset + len(categories)
        aggregated[name] = float(np.sum(feature_importances[offset:stop]))
        offset = stop
    if offset != categorical_slice.stop:
        raise RuntimeError("Fitted one-hot features do not align with categorical schema.")
    return aggregated


def main(argv=None):
    args = build_argument_parser().parse_args(argv)
    result = audit_training_data(
        args.training_data,
        validation_fraction=args.validation_fraction,
        random_state=args.random_state,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()