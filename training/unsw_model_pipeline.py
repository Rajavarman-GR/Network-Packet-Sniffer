"""Build unfitted sklearn pipelines for the separate UNSW flow schema."""

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from training.unsw_flow_schema import (
    CATEGORICAL_PREDICTOR_COLUMNS,
    EXPECTED_ATTACK_CATEGORIES,
    EXPECTED_LABEL_VALUES,
    EXCLUDED_PREDICTOR_COLUMNS,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_COLUMNS,
    TARGET_LABEL,
    UNSW_FLOW_SCHEMA_VERSION,
)

MODEL_FAMILY = "unsw_flow"
RANDOM_SEED = 42
CLASSIFIER_PARAMETERS = {
    "n_estimators": 400,
    "class_weight": "balanced",
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}

NUMERIC_COLUMN_INDICES = tuple(range(len(NUMERIC_PREDICTOR_COLUMNS)))
CATEGORICAL_COLUMN_INDICES = tuple(
    range(len(NUMERIC_PREDICTOR_COLUMNS), len(PREDICTOR_COLUMNS))
)


class UNSWFeatureSchemaGuard(BaseEstimator, TransformerMixin):
    """Reject predictor inputs outside the validated UNSW schema."""

    def fit(self, X, y=None):
        self._validate(X)
        return self

    def transform(self, X):
        columns = getattr(X, "columns", None)
        if columns is not None:
            self._validate_column_names(columns)
            return X.loc[:, list(PREDICTOR_COLUMNS)]

        values = np.asarray(X, dtype=object)
        if values.ndim != 2 or values.shape[1] != len(PREDICTOR_COLUMNS):
            raise ValueError(
                "UNSW inputs must contain exactly {} predictors in PREDICTOR_COLUMNS order.".format(
                    len(PREDICTOR_COLUMNS)
                )
            )
        return values

    def _validate(self, X):
        columns = getattr(X, "columns", None)
        if columns is not None:
            self._validate_column_names(columns)
            return
        self.transform(X)

    @staticmethod
    def _validate_column_names(columns):
        names = list(columns)
        if len(names) != len(set(names)):
            raise ValueError("UNSW input contains duplicate predictor columns.")
        expected = set(PREDICTOR_COLUMNS)
        actual = set(names)
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        if missing or unexpected:
            raise ValueError(
                "UNSW input columns do not match the predictor schema: missing={}, unexpected={}.".format(
                    missing, unexpected
                )
            )


def build_binary_pipeline():
    """Return an unfitted pipeline targeting the binary ``label`` column."""
    return _build_pipeline(TARGET_LABEL)


def build_attack_category_pipeline():
    """Return an unfitted pipeline targeting the ``attack_cat`` column."""
    return _build_pipeline(TARGET_ATTACK_CATEGORY)


def build_unsw_model_metadata(target):
    """Build metadata for a UNSW pipeline without writing it to disk."""
    if target not in TARGET_COLUMNS:
        raise ValueError(
            "Unsupported target {!r}. Expected {!r} or {!r}.".format(
                target, TARGET_LABEL, TARGET_ATTACK_CATEGORY
            )
        )

    expected_classes = (
        [int(value) for value in sorted(EXPECTED_LABEL_VALUES)]
        if target == TARGET_LABEL
        else sorted(EXPECTED_ATTACK_CATEGORIES)
    )
    return {
        "model_family": MODEL_FAMILY,
        "schema_version": UNSW_FLOW_SCHEMA_VERSION,
        "target": target,
        "predictor_columns": list(PREDICTOR_COLUMNS),
        "numeric_predictor_columns": list(NUMERIC_PREDICTOR_COLUMNS),
        "categorical_predictor_columns": list(CATEGORICAL_PREDICTOR_COLUMNS),
        "excluded_columns": list(EXCLUDED_PREDICTOR_COLUMNS),
        "classifier_parameters": dict(CLASSIFIER_PARAMETERS),
        "random_seed": RANDOM_SEED,
        "expected_class_names": expected_classes,
    }


def _build_pipeline(target):
    if target not in TARGET_COLUMNS:
        raise ValueError("Unsupported UNSW target: {!r}.".format(target))
    if set(PREDICTOR_COLUMNS) & set(EXCLUDED_PREDICTOR_COLUMNS):
        raise ValueError("UNSW predictor schema contains an excluded column.")
    if len(PREDICTOR_COLUMNS) != 42 or len(NUMERIC_PREDICTOR_COLUMNS) != 39:
        raise ValueError("UNSW predictor schema does not match the validated 42-column contract.")
    if CATEGORICAL_PREDICTOR_COLUMNS != ("proto", "service", "state"):
        raise ValueError("UNSW categorical predictor schema is not the validated contract.")

    preprocessor = ColumnTransformer(
        transformers=(
            ("numeric", StandardScaler(), NUMERIC_COLUMN_INDICES),
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                CATEGORICAL_COLUMN_INDICES,
            ),
        ),
        remainder="drop",
    )
    classifier = RandomForestClassifier(**CLASSIFIER_PARAMETERS)
    pipeline = Pipeline(
        steps=(
            ("schema_guard", UNSWFeatureSchemaGuard()),
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        )
    )
    pipeline.target_column = target
    return pipeline