import csv
import os
import tempfile
import unittest

from training.prepare_unsw import load_unsw_flow_data, validate_unsw_dataset
from training.unsw_flow_schema import (
    CATEGORICAL_PREDICTOR_COLUMNS,
    EXPECTED_ATTACK_CATEGORIES,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_LABEL,
    UNSW_FLOW_SCHEMA_VERSION,
)


class UNSWFlowPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = self.temporary_directory.name
        self.base_row = {
            **{name: "1.5" for name in NUMERIC_PREDICTOR_COLUMNS},
            **{name: "value" for name in CATEGORICAL_PREDICTOR_COLUMNS},
            "id": "1",
            TARGET_LABEL: "0",
            TARGET_ATTACK_CATEGORY: "Normal",
        }

    def _write_csv(self, filename, rows, columns=None):
        path = os.path.join(self.root, filename)
        columns = columns or list(self.base_row)
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _valid_pair(self, train_rows=None, test_rows=None, columns=None):
        train_rows = train_rows or [dict(self.base_row)]
        test_rows = test_rows or [dict(self.base_row, id="2", **{TARGET_LABEL: "1", TARGET_ATTACK_CATEGORY: "DoS"})]
        train_path = self._write_csv("train.csv", train_rows, columns)
        test_path = self._write_csv("test.csv", test_rows, columns)
        return train_path, test_path

    def test_valid_train_test_schema_preserves_splits(self):
        train_rows = [dict(self.base_row), dict(self.base_row, id="3")]
        test_rows = [dict(self.base_row, id="4")]
        train_path, test_path = self._valid_pair(train_rows, test_rows)

        prepared = load_unsw_flow_data(train_path, test_path)

        self.assertEqual(prepared.train_rows, 2)
        self.assertEqual(prepared.test_rows, 1)
        self.assertEqual(len(list(prepared.iter_train())), 2)
        self.assertEqual(len(list(prepared.iter_test())), 1)

    def test_missing_required_column_is_rejected(self):
        columns = [name for name in self.base_row if name != "dur"]
        train_path, test_path = self._valid_pair(columns=columns)

        with self.assertRaisesRegex(ValueError, "missing required columns.*dur"):
            validate_unsw_dataset(train_path, test_path)

    def test_unexpected_column_is_rejected(self):
        row = dict(self.base_row, extra_feature="1")
        columns = list(row)
        train_path = self._write_csv("train.csv", [row], columns)
        test_path = self._write_csv("test.csv", [row], columns)

        with self.assertRaisesRegex(ValueError, "unexpected columns.*extra_feature"):
            validate_unsw_dataset(train_path, test_path)

    def test_train_test_schema_mismatch_is_rejected(self):
        train_path = self._write_csv("train.csv", [dict(self.base_row)])
        test_columns = [name for name in self.base_row if name != TARGET_ATTACK_CATEGORY]
        test_path = self._write_csv("test.csv", [dict(self.base_row)], test_columns)

        with self.assertRaisesRegex(ValueError, "Train/test column mismatch"):
            validate_unsw_dataset(train_path, test_path)

    def test_invalid_binary_label_is_rejected(self):
        row = dict(self.base_row, **{TARGET_LABEL: "2"})
        train_path, test_path = self._valid_pair([row])

        with self.assertRaisesRegex(ValueError, "invalid label"):
            validate_unsw_dataset(train_path, test_path)

    def test_missing_requested_target_is_rejected(self):
        columns = [name for name in self.base_row if name != TARGET_ATTACK_CATEGORY]
        train_path, test_path = self._valid_pair(columns=columns)

        with self.assertRaisesRegex(ValueError, "missing requested target column 'attack_cat'"):
            validate_unsw_dataset(train_path, test_path, target=TARGET_ATTACK_CATEGORY)

    def test_id_is_never_a_predictor(self):
        train_path, test_path = self._valid_pair()

        prepared = validate_unsw_dataset(train_path, test_path)
        features, _ = next(prepared.iter_train())

        self.assertNotIn("id", prepared.predictor_columns)
        self.assertNotIn("id", features)

    def test_label_is_separate_from_predictors(self):
        train_path, test_path = self._valid_pair()

        prepared = validate_unsw_dataset(train_path, test_path, target=TARGET_LABEL)
        features, target_value = next(prepared.iter_train())

        self.assertNotIn(TARGET_LABEL, prepared.predictor_columns)
        self.assertNotIn(TARGET_LABEL, features)
        self.assertEqual(target_value, 0)

    def test_attack_category_is_not_a_predictor_for_binary_target(self):
        train_path, test_path = self._valid_pair()

        prepared = validate_unsw_dataset(train_path, test_path, target=TARGET_LABEL)
        features, _ = next(prepared.iter_train())

        self.assertNotIn(TARGET_ATTACK_CATEGORY, prepared.predictor_columns)
        self.assertNotIn(TARGET_ATTACK_CATEGORY, features)

    def test_invalid_numeric_value_is_rejected(self):
        row = dict(self.base_row, dur="NaN")
        train_path, test_path = self._valid_pair([row])

        with self.assertRaisesRegex(ValueError, "non-finite numeric value.*dur"):
            validate_unsw_dataset(train_path, test_path)

    def test_invalid_numeric_text_is_rejected(self):
        row = dict(self.base_row, dur="not-a-number")
        train_path, test_path = self._valid_pair([row])

        with self.assertRaisesRegex(ValueError, "invalid numeric value.*dur"):
            validate_unsw_dataset(train_path, test_path)

    def test_empty_categorical_value_is_rejected(self):
        row = dict(self.base_row, proto=" ")
        train_path, test_path = self._valid_pair([row])

        with self.assertRaisesRegex(ValueError, "empty categorical value.*proto"):
            validate_unsw_dataset(train_path, test_path)

    def test_invalid_attack_category_is_rejected(self):
        row = dict(self.base_row, **{TARGET_ATTACK_CATEGORY: "unknown"})
        train_path, test_path = self._valid_pair([row])

        with self.assertRaisesRegex(ValueError, "invalid attack_cat"):
            validate_unsw_dataset(train_path, test_path)

    def test_attack_category_target_is_separate_from_predictors(self):
        row = dict(self.base_row, **{TARGET_ATTACK_CATEGORY: "DoS"})
        train_path, test_path = self._valid_pair([row])

        prepared = validate_unsw_dataset(train_path, test_path, target=TARGET_ATTACK_CATEGORY)
        features, target_value = next(prepared.iter_train())

        self.assertNotIn(TARGET_LABEL, features)
        self.assertNotIn(TARGET_ATTACK_CATEGORY, features)
        self.assertEqual(target_value, "DoS")

    def test_schema_version_and_predictor_contract_are_explicit(self):
        train_path, test_path = self._valid_pair()

        prepared = validate_unsw_dataset(train_path, test_path)

        self.assertEqual(UNSW_FLOW_SCHEMA_VERSION, "1.0")
        self.assertEqual(prepared.schema_version, UNSW_FLOW_SCHEMA_VERSION)
        self.assertEqual(set(prepared.predictor_columns), set(PREDICTOR_COLUMNS))
        self.assertEqual(len(NUMERIC_PREDICTOR_COLUMNS), 39)
        self.assertEqual(len(CATEGORICAL_PREDICTOR_COLUMNS), 3)
        self.assertEqual(len(EXPECTED_ATTACK_CATEGORIES), 10)


if __name__ == "__main__":
    unittest.main()