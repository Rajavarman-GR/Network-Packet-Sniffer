"""Validate and stream UNSW-NB15 flow data without training a model."""

import csv
from dataclasses import dataclass
import math
from pathlib import Path
from typing import Tuple

from training.unsw_flow_schema import (
    ALLOWED_COLUMNS,
    CATEGORICAL_PREDICTOR_COLUMNS,
    EXPECTED_ATTACK_CATEGORIES,
    EXPECTED_LABEL_VALUES,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    REQUIRED_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_COLUMNS,
    TARGET_LABEL,
    UNSW_FLOW_SCHEMA_VERSION,
)

@dataclass(frozen=True)
class PreparedUNSWFlowData:
    """Validated source files and a streaming, target-separated row interface."""

    train_path: Path
    test_path: Path
    target_column: str
    predictor_columns: Tuple[str, ...]
    train_rows: int
    test_rows: int
    schema_version: str = UNSW_FLOW_SCHEMA_VERSION

    def iter_train(self):
        return _iter_rows(self.train_path, self.predictor_columns, self.target_column)

    def iter_test(self):
        return _iter_rows(self.test_path, self.predictor_columns, self.target_column)


def validate_unsw_dataset(train_path, test_path, target=TARGET_LABEL):
    """Validate both official splits and return their prepared-data descriptor.

    The returned object streams ``(predictors, target_value)`` pairs. Predictor
    dictionaries never contain ``id`` or either target column.
    """
    train_path = Path(train_path)
    test_path = Path(test_path)
    if target not in TARGET_COLUMNS:
        raise ValueError(
            "Unsupported target {!r}. Expected {!r} or {!r}.".format(
                target, TARGET_LABEL, TARGET_ATTACK_CATEGORY
            )
        )

    train_header = _read_header(train_path)
    test_header = _read_header(test_path)
    _validate_header(train_path, train_header, target)
    _validate_header(test_path, test_header, target)

    if set(train_header) != set(test_header):
        missing_from_test = sorted(set(train_header) - set(test_header))
        missing_from_train = sorted(set(test_header) - set(train_header))
        raise ValueError(
            "Train/test column mismatch: missing from test={}, missing from train={}.".format(
                missing_from_test, missing_from_train
            )
        )

    if target not in train_header or target not in test_header:
        raise ValueError("Target column {!r} must exist in both splits.".format(target))

    train_count = _validate_rows(train_path, train_header, target)
    test_count = _validate_rows(test_path, test_header, target)
    if train_count == 0 or test_count == 0:
        raise ValueError("Train and test splits must both contain at least one data row.")

    predictor_columns = tuple(PREDICTOR_COLUMNS)
    if set(predictor_columns) & set(TARGET_COLUMNS + ("id",)):
        raise ValueError("UNSW predictor schema contains an excluded target or id column.")

    return PreparedUNSWFlowData(
        train_path=train_path,
        test_path=test_path,
        target_column=target,
        predictor_columns=predictor_columns,
        train_rows=train_count,
        test_rows=test_count,
    )


def load_unsw_flow_data(train_path, test_path, target=TARGET_LABEL):
    """Validate files and return a path-backed object that streams split rows."""
    return validate_unsw_dataset(train_path, test_path, target=target)


def _read_header(path):
    if not path.is_file():
        raise FileNotFoundError("UNSW CSV file not found: {}".format(path))
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("{} is missing a CSV header row.".format(path))
        header = reader.fieldnames
    if any(name is None or name == "" for name in header):
        raise ValueError("{} contains an empty column name.".format(path))
    if len(header) != len(set(header)):
        raise ValueError("{} contains duplicate column names.".format(path))
    return header


def _validate_header(path, header, target):
    columns = set(header)
    missing = sorted(set(REQUIRED_COLUMNS) - columns)
    unexpected = sorted(columns - ALLOWED_COLUMNS)
    if missing:
        raise ValueError("{} is missing required columns: {}.".format(path, missing))
    if unexpected:
        raise ValueError("{} contains unexpected columns: {}.".format(path, unexpected))
    if target not in columns:
        raise ValueError("{} is missing requested target column {!r}.".format(path, target))


def _validate_rows(path, header, target):
    row_count = 0
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row_number, row in enumerate(reader, start=2):
            if None in row or any(row.get(name) is None for name in header):
                raise ValueError("{} has a malformed row {}.".format(path, row_number))
            _validate_row(path, row_number, row, target)
            row_count += 1
    return row_count


def _validate_row(path, row_number, row, target):
    if not row["id"].strip():
        raise ValueError("{} has an empty id on row {}.".format(path, row_number))

    label = row[TARGET_LABEL]
    if label not in EXPECTED_LABEL_VALUES:
        raise ValueError(
            "{} has invalid label {!r} on row {}; expected 0 or 1.".format(
                path, label, row_number
            )
        )

    for column in NUMERIC_PREDICTOR_COLUMNS:
        value = row[column]
        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "{} has invalid numeric value for {!r} on row {}: {!r}.".format(
                    path, column, row_number, value
                )
            ) from exc
        if not math.isfinite(numeric_value):
            raise ValueError(
                "{} has non-finite numeric value for {!r} on row {}: {!r}.".format(
                    path, column, row_number, value
                )
            )

    for column in CATEGORICAL_PREDICTOR_COLUMNS:
        if not row[column].strip():
            raise ValueError(
                "{} has an empty categorical value for {!r} on row {}.".format(
                    path, column, row_number
                )
            )

    if TARGET_ATTACK_CATEGORY in row:
        category = row[TARGET_ATTACK_CATEGORY]
        if category not in EXPECTED_ATTACK_CATEGORIES:
            raise ValueError(
                "{} has invalid attack_cat {!r} on row {}; expected one of {}.".format(
                    path, category, row_number, sorted(EXPECTED_ATTACK_CATEGORIES)
                )
            )
    elif target == TARGET_ATTACK_CATEGORY:
        raise ValueError("{} is missing requested target column 'attack_cat'.".format(path))


def _iter_rows(path, predictor_columns, target):
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("{} is missing a CSV header row.".format(path))
        for row_number, row in enumerate(reader, start=2):
            if None in row or any(row.get(name) is None for name in reader.fieldnames):
                raise ValueError("{} has a malformed row {}.".format(path, row_number))
            _validate_row(path, row_number, row, target)
            features = {
                name: float(row[name]) if name in NUMERIC_PREDICTOR_COLUMNS else row[name]
                for name in predictor_columns
            }
            target_value = int(row[target]) if target == TARGET_LABEL else row[target]
            yield features, target_value