import unittest

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from ai.feature_extractor import FEATURE_NAMES
from training.unsw_model_pipeline import (
    CATEGORICAL_COLUMN_INDICES,
    CLASSIFIER_PARAMETERS,
    MODEL_FAMILY,
    NUMERIC_COLUMN_INDICES,
    UNSWFeatureSchemaGuard,
    build_attack_category_pipeline,
    build_binary_pipeline,
    build_unsw_model_metadata,
)
from training.unsw_flow_schema import (
    CATEGORICAL_PREDICTOR_COLUMNS,
    EXPECTED_ATTACK_CATEGORIES,
    EXCLUDED_PREDICTOR_COLUMNS,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_LABEL,
    UNSW_FLOW_SCHEMA_VERSION,
)


class UNSWModelPipelineTests(unittest.TestCase):
    def test_binary_builder_returns_unfitted_pipeline(self):
        pipeline = build_binary_pipeline()

        self.assertIsInstance(pipeline, Pipeline)
        self.assertEqual(pipeline.target_column, TARGET_LABEL)
        self.assertFalse(hasattr(pipeline, "n_features_in_"))

    def test_attack_category_builder_returns_unfitted_pipeline(self):
        pipeline = build_attack_category_pipeline()

        self.assertIsInstance(pipeline, Pipeline)
        self.assertEqual(pipeline.target_column, TARGET_ATTACK_CATEGORY)
        self.assertFalse(hasattr(pipeline, "n_features_in_"))

    def test_numeric_transformer_selects_exact_numeric_predictors(self):
        pipeline = build_binary_pipeline()
        preprocessor = pipeline.named_steps["preprocessor"]
        selected_indices = preprocessor.transformers[0][2]

        self.assertIsInstance(preprocessor, ColumnTransformer)
        self.assertIsInstance(preprocessor.transformers[0][1], StandardScaler)
        self.assertEqual(selected_indices, NUMERIC_COLUMN_INDICES)
        self.assertEqual(
            tuple(PREDICTOR_COLUMNS[index] for index in selected_indices),
            NUMERIC_PREDICTOR_COLUMNS,
        )

    def test_categorical_transformer_selects_exact_categorical_predictors(self):
        pipeline = build_binary_pipeline()
        preprocessor = pipeline.named_steps["preprocessor"]
        selected_indices = preprocessor.transformers[1][2]

        self.assertIsInstance(preprocessor.transformers[1][1], OneHotEncoder)
        self.assertEqual(selected_indices, CATEGORICAL_COLUMN_INDICES)
        self.assertEqual(
            tuple(PREDICTOR_COLUMNS[index] for index in selected_indices),
            ("proto", "service", "state"),
        )
        self.assertEqual(CATEGORICAL_PREDICTOR_COLUMNS, ("proto", "service", "state"))

    def test_id_and_targets_are_not_in_predictor_schema(self):
        self.assertEqual(len(PREDICTOR_COLUMNS), 42)
        self.assertFalse(set(PREDICTOR_COLUMNS) & set(EXCLUDED_PREDICTOR_COLUMNS))
        self.assertNotIn("id", PREDICTOR_COLUMNS)
        self.assertNotIn(TARGET_LABEL, PREDICTOR_COLUMNS)
        self.assertNotIn(TARGET_ATTACK_CATEGORY, PREDICTOR_COLUMNS)

    def test_named_schema_guard_rejects_excluded_columns(self):
        invalid_columns = list(PREDICTOR_COLUMNS) + ["id"]

        with self.assertRaisesRegex(ValueError, "unexpected=.*id"):
            UNSWFeatureSchemaGuard._validate_column_names(invalid_columns)

    def test_binary_pipeline_excludes_both_targets(self):
        pipeline = build_binary_pipeline()
        metadata = build_unsw_model_metadata(TARGET_LABEL)

        self.assertEqual(metadata["target"], TARGET_LABEL)
        self.assertNotIn(TARGET_LABEL, metadata["predictor_columns"])
        self.assertNotIn(TARGET_ATTACK_CATEGORY, metadata["predictor_columns"])
        self.assertEqual(
            tuple(PREDICTOR_COLUMNS[index] for index in pipeline.named_steps["preprocessor"].transformers[0][2]
                  + pipeline.named_steps["preprocessor"].transformers[1][2]),
            PREDICTOR_COLUMNS,
        )

    def test_attack_category_is_multiclass_target_and_label_is_excluded(self):
        metadata = build_unsw_model_metadata(TARGET_ATTACK_CATEGORY)
        pipeline = build_attack_category_pipeline()

        self.assertEqual(metadata["target"], TARGET_ATTACK_CATEGORY)
        self.assertNotIn(TARGET_LABEL, metadata["predictor_columns"])
        self.assertNotIn(TARGET_ATTACK_CATEGORY, metadata["predictor_columns"])
        self.assertIsInstance(pipeline.named_steps["classifier"], RandomForestClassifier)

    def test_predictor_order_is_deterministic(self):
        first = build_unsw_model_metadata(TARGET_LABEL)["predictor_columns"]
        second = build_unsw_model_metadata(TARGET_LABEL)["predictor_columns"]

        self.assertEqual(first, second)
        self.assertEqual(first, list(PREDICTOR_COLUMNS))

    def test_unknown_categories_are_ignored_deterministically(self):
        encoder = build_binary_pipeline().named_steps["preprocessor"].transformers[1][1]

        self.assertEqual(encoder.handle_unknown, "ignore")

    def test_classifier_parameters_match_design(self):
        classifier = build_binary_pipeline().named_steps["classifier"]
        multiclass_classifier = build_attack_category_pipeline().named_steps["classifier"]
        expected = {
            "n_estimators": 400,
            "class_weight": "balanced",
            "random_state": 42,
            "n_jobs": -1,
        }

        self.assertEqual(CLASSIFIER_PARAMETERS, expected)
        for candidate in (classifier, multiclass_classifier):
            self.assertEqual(candidate.get_params(), {
                **candidate.get_params(),
                **expected,
            })

    def test_metadata_has_flow_schema_family_and_version(self):
        metadata = build_unsw_model_metadata(TARGET_LABEL)

        self.assertEqual(metadata["model_family"], "unsw_flow")
        self.assertEqual(metadata["model_family"], MODEL_FAMILY)
        self.assertEqual(metadata["schema_version"], UNSW_FLOW_SCHEMA_VERSION)
        self.assertEqual(metadata["excluded_columns"], list(EXCLUDED_PREDICTOR_COLUMNS))
        self.assertEqual(metadata["classifier_parameters"], CLASSIFIER_PARAMETERS)
        self.assertEqual(metadata["random_seed"], 42)
        self.assertEqual(metadata["expected_class_names"], [0, 1])

    def test_metadata_reports_multiclass_expected_classes(self):
        metadata = build_unsw_model_metadata(TARGET_ATTACK_CATEGORY)

        self.assertEqual(metadata["expected_class_names"], sorted(EXPECTED_ATTACK_CATEGORIES))

    def test_metadata_does_not_reuse_packet_schema(self):
        metadata = build_unsw_model_metadata(TARGET_LABEL)

        self.assertEqual(metadata["schema_version"], UNSW_FLOW_SCHEMA_VERSION)
        self.assertEqual(metadata["model_family"], "unsw_flow")
        self.assertNotIn("feature_schema_version", metadata)
        self.assertFalse(set(metadata["predictor_columns"]) & set(FEATURE_NAMES))

    def test_schema_guard_rejects_wrong_array_width(self):
        guard = UNSWFeatureSchemaGuard()

        with self.assertRaisesRegex(ValueError, "exactly 42 predictors"):
            guard.transform(np.zeros((1, 43), dtype=object))


if __name__ == "__main__":
    unittest.main()