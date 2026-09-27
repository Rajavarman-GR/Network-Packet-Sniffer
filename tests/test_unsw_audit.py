import csv
import os
import tempfile
import unittest

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from training.audit_unsw_flow import (
    BATCH_CLASSIFIER_PARAMETERS,
    PROTECTED_TEST_FILENAME,
    build_argument_parser,
    build_feature_variants,
    build_variant_pipeline,
    create_internal_split,
    load_training_data,
)
from training.unsw_flow_schema import (
    CATEGORICAL_PREDICTOR_COLUMNS,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_LABEL,
)


class UNSWAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = self.temporary_directory.name
        self.rows = []
        for index in range(20):
            label = str(index % 2)
            self.rows.append({
                **{name: str(index + 0.25) for name in NUMERIC_PREDICTOR_COLUMNS},
                "proto": "tcp" if index % 2 else "udp",
                "service": "http" if index % 2 else "-",
                "state": "FIN" if index % 2 else "INT",
                "id": str(index + 1),
                TARGET_LABEL: label,
                TARGET_ATTACK_CATEGORY: "DoS" if label == "1" else "Normal",
            })

    def _write_csv(self, filename, rows=None):
        path = os.path.join(self.root, filename)
        rows = self.rows if rows is None else rows
        columns = ["id"] + list(PREDICTOR_COLUMNS) + [TARGET_LABEL, TARGET_ATTACK_CATEGORY]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_audit_cli_requires_explicit_training_file(self):
        with self.assertRaises(SystemExit):
            build_argument_parser().parse_args([])

    def test_official_test_filename_is_rejected(self):
        path = self._write_csv(PROTECTED_TEST_FILENAME)

        with self.assertRaisesRegex(ValueError, "testing CSV cannot be used"):
            load_training_data(path)

    def test_training_loader_returns_only_declared_predictors_and_label(self):
        path = self._write_csv("small-training.csv")

        features, labels = load_training_data(path)

        self.assertEqual(features.shape, (20, 42))
        self.assertEqual(labels.shape, (20,))
        self.assertEqual(set(labels.tolist()), {0, 1})

    def test_internal_split_is_stratified_reproducible_and_disjoint(self):
        labels = np.array([0] * 50 + [1] * 50)

        first_train, first_validation = create_internal_split(labels)
        second_train, second_validation = create_internal_split(labels)

        self.assertTrue(np.array_equal(first_train, second_train))
        self.assertTrue(np.array_equal(first_validation, second_validation))
        self.assertEqual(len(first_validation), 20)
        self.assertEqual(set(first_train) & set(first_validation), set())
        self.assertEqual(np.bincount(labels[first_validation]).tolist(), [10, 10])

    def test_variants_remove_only_requested_features(self):
        variants = build_feature_variants()
        sequence_numbers = {"stcpb", "dtcpb"}
        ct_features = {name for name in PREDICTOR_COLUMNS if name.startswith("ct_")}

        self.assertEqual(len(variants["A_all_42"]), 42)
        self.assertEqual(
            set(variants["B_without_stcpb_dtcpb"]),
            set(PREDICTOR_COLUMNS) - sequence_numbers,
        )
        self.assertEqual(
            set(variants["C_without_ct_features"]),
            set(PREDICTOR_COLUMNS) - ct_features,
        )
        self.assertEqual(
            set(variants["D_without_stcpb_dtcpb_and_ct"]),
            set(PREDICTOR_COLUMNS) - sequence_numbers - ct_features,
        )
        self.assertEqual(variants["A_all_42"], PREDICTOR_COLUMNS)

    def test_variant_pipeline_selects_exact_preprocessing_and_classifier(self):
        columns = build_feature_variants()["B_without_stcpb_dtcpb"]
        pipeline = build_variant_pipeline(columns)
        preprocessor = pipeline.named_steps["preprocessor"]
        numeric_indices = preprocessor.transformers[0][2]
        categorical_indices = preprocessor.transformers[1][2]

        self.assertIsInstance(preprocessor, ColumnTransformer)
        self.assertIsInstance(preprocessor.transformers[0][1], StandardScaler)
        self.assertIsInstance(preprocessor.transformers[1][1], OneHotEncoder)
        self.assertEqual(preprocessor.transformers[1][1].handle_unknown, "ignore")
        self.assertEqual(
            tuple(columns[index] for index in numeric_indices),
            tuple(name for name in NUMERIC_PREDICTOR_COLUMNS if name in columns),
        )
        self.assertEqual(
            tuple(columns[index] for index in categorical_indices),
            CATEGORICAL_PREDICTOR_COLUMNS,
        )
        self.assertIsInstance(pipeline.named_steps["classifier"], RandomForestClassifier)
        self.assertEqual(
            {key: pipeline.named_steps["classifier"].get_params()[key]
             for key in BATCH_CLASSIFIER_PARAMETERS},
            BATCH_CLASSIFIER_PARAMETERS,
        )
        self.assertFalse(hasattr(pipeline.named_steps["classifier"], "n_features_in_"))

    def test_pipeline_rejects_targets_and_id_as_features(self):
        for disallowed in ("id", TARGET_LABEL, TARGET_ATTACK_CATEGORY):
            with self.subTest(disallowed=disallowed):
                with self.assertRaisesRegex(ValueError, "Unexpected or excluded"):
                    build_variant_pipeline(("dur", "proto", disallowed))

    def test_variant_feature_types_remain_covered(self):
        for columns in build_feature_variants().values():
            self.assertTrue(any(name in NUMERIC_PREDICTOR_COLUMNS for name in columns))
            self.assertTrue(any(name in CATEGORICAL_PREDICTOR_COLUMNS for name in columns))


if __name__ == "__main__":
    unittest.main()