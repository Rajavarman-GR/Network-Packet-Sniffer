import csv
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from training.evaluate_unsw_flow import (
    _build_report,
    build_argument_parser as build_evaluation_parser,
    evaluate_unsw_flow,
)
from training.train_unsw_flow import (
    FLOW_MODEL_ROOT,
    METADATA_FILENAME,
    PACKET_MODEL_PATH,
    PIPELINE_FILENAME,
    build_argument_parser as build_training_parser,
    resolve_output_directory,
    train_unsw_flow,
)
from training.unsw_model_pipeline import (
    build_attack_category_pipeline,
    build_binary_pipeline,
    build_unsw_model_metadata,
)
from training.unsw_flow_schema import (
    EXPECTED_ATTACK_CATEGORIES,
    EXCLUDED_PREDICTOR_COLUMNS,
    NUMERIC_PREDICTOR_COLUMNS,
    PREDICTOR_COLUMNS,
    TARGET_ATTACK_CATEGORY,
    TARGET_LABEL,
)


class FakePipeline:
    def __init__(self, target):
        self.target_column = target
        self.params = {}
        self.features = None
        self.targets = None

    def set_params(self, **params):
        self.params.update(params)
        return self

    def fit(self, features, targets):
        self.features = features
        self.targets = targets
        return self


class UNSWTrainingTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.row = {
            **{name: "1.25" for name in NUMERIC_PREDICTOR_COLUMNS},
            "proto": "tcp",
            "service": "http",
            "state": "FIN",
            "id": "1",
            TARGET_LABEL: "0",
            TARGET_ATTACK_CATEGORY: "Normal",
        }

    def _write_csv(self, filename, rows):
        path = self.root / filename
        columns = ["id"] + list(PREDICTOR_COLUMNS) + [TARGET_LABEL, TARGET_ATTACK_CATEGORY]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _write_binary_pair(self):
        train_rows = [
            dict(self.row, id="train-1", **{TARGET_LABEL: "0", TARGET_ATTACK_CATEGORY: "Normal"}),
            dict(self.row, id="train-2", **{TARGET_LABEL: "1", TARGET_ATTACK_CATEGORY: "DoS"}),
        ]
        test_rows = [
            dict(self.row, id="test-1", **{TARGET_LABEL: "0", TARGET_ATTACK_CATEGORY: "Normal"}),
            dict(self.row, id="test-2", **{TARGET_LABEL: "1", TARGET_ATTACK_CATEGORY: "Exploits"}),
        ]
        return self._write_csv("train.csv", train_rows), self._write_csv("test.csv", test_rows)

    def test_training_cli_requires_a_supported_target(self):
        parser = build_training_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args([])
        with self.assertRaises(SystemExit):
            parser.parse_args(["--target", "unsupported"])

    def test_evaluation_cli_requires_a_specific_artifact(self):
        with self.assertRaises(SystemExit):
            build_evaluation_parser().parse_args([])

    def test_binary_builder_and_metadata_exclude_attack_category(self):
        pipeline = build_binary_pipeline()
        metadata = build_unsw_model_metadata(TARGET_LABEL)

        self.assertEqual(pipeline.target_column, TARGET_LABEL)
        self.assertNotIn(TARGET_ATTACK_CATEGORY, metadata["predictor_columns"])
        self.assertNotIn(TARGET_ATTACK_CATEGORY, PREDICTOR_COLUMNS)

    def test_multiclass_builder_and_metadata_exclude_label(self):
        pipeline = build_attack_category_pipeline()
        metadata = build_unsw_model_metadata(TARGET_ATTACK_CATEGORY)

        self.assertEqual(pipeline.target_column, TARGET_ATTACK_CATEGORY)
        self.assertNotIn(TARGET_LABEL, metadata["predictor_columns"])
        self.assertNotIn(TARGET_LABEL, PREDICTOR_COLUMNS)

    def test_id_and_targets_are_never_predictors(self):
        self.assertNotIn("id", PREDICTOR_COLUMNS)
        self.assertFalse(set(PREDICTOR_COLUMNS) & set(EXCLUDED_PREDICTOR_COLUMNS))

    def test_output_paths_are_target_specific_and_flow_only(self):
        output_root = self.root / "unsw_flow"

        binary = resolve_output_directory(output_root, TARGET_LABEL)
        multiclass = resolve_output_directory(output_root, TARGET_ATTACK_CATEGORY)

        self.assertEqual(binary, (output_root / "binary").resolve())
        self.assertEqual(multiclass, (output_root / "attack_category").resolve())
        self.assertNotEqual(binary, multiclass)

    def test_packet_model_and_ambiguous_model_root_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "overlaps the packet detector"):
            resolve_output_directory(PACKET_MODEL_PATH, TARGET_LABEL)
        with self.assertRaisesRegex(ValueError, "dedicated ai/model/unsw_flow"):
            resolve_output_directory(PACKET_MODEL_PATH.parent, TARGET_LABEL)

    def test_training_records_schema_predictors_hashes_and_split_counts(self):
        train_path, test_path = self._write_binary_pair()
        fake_pipeline = FakePipeline(TARGET_LABEL)
        output_root = self.root / "unsw_flow"

        with patch("training.train_unsw_flow.build_binary_pipeline", return_value=fake_pipeline), \
                patch("training.train_unsw_flow._save_artifacts") as save_artifacts:
            result = train_unsw_flow(
                train_path,
                test_path,
                TARGET_LABEL,
                output_dir=output_root,
                random_seed=42,
            )

        metadata = result["metadata"]
        self.assertEqual(fake_pipeline.features.shape, (2, 42))
        self.assertEqual(len(fake_pipeline.targets), 2)
        self.assertEqual(fake_pipeline.params["classifier__random_state"], 42)
        self.assertEqual(metadata["train_row_count"], 2)
        self.assertEqual(metadata["test_row_count"], 2)
        self.assertEqual(metadata["predictor_columns"], list(PREDICTOR_COLUMNS))
        self.assertEqual(metadata["schema_version"], "1.0")
        self.assertEqual(metadata["model_family"], "unsw_flow")
        self.assertEqual(metadata["source_files"]["train"]["filename"], train_path.name)
        self.assertEqual(metadata["source_files"]["test"]["filename"], test_path.name)
        self.assertEqual(metadata["class_counts"]["train"], {"0": 1, "1": 1})
        self.assertEqual(metadata["class_counts"]["test"], {"0": 1, "1": 1})
        self.assertNotIn(str(self.root), json.dumps(metadata))
        self.assertEqual(save_artifacts.call_args.args[0], fake_pipeline)

    def test_training_refuses_to_overwrite_existing_flow_artifacts(self):
        train_path, test_path = self._write_binary_pair()
        output_root = self.root / "unsw_flow"
        target_directory = output_root / "binary"
        target_directory.mkdir(parents=True)
        (target_directory / PIPELINE_FILENAME).touch()

        with self.assertRaises(FileExistsError):
            train_unsw_flow(train_path, test_path, TARGET_LABEL, output_dir=output_root)

    def test_evaluator_reports_metrics_without_refitting(self):
        train_path, test_path = self._write_binary_pair()
        artifact_directory = self.root / "unsw_flow" / "binary"
        artifact_directory.mkdir(parents=True)
        artifact_path = artifact_directory / PIPELINE_FILENAME
        artifact_path.write_bytes(b"mocked artifact")
        metadata_path = artifact_directory / METADATA_FILENAME
        metadata = build_unsw_model_metadata(TARGET_LABEL)
        metadata.update({
            "class_names": [0, 1],
            "train_row_count": 2,
            "test_row_count": 2,
            "random_seed": 42,
            "classifier_parameters": {
                "n_estimators": 400,
                "class_weight": "balanced",
                "random_state": 42,
                "n_jobs": -1,
            },
            "class_counts": {"train": {"0": 1, "1": 1}, "test": {"0": 1, "1": 1}},
            "source_files": {
                "train": {"filename": train_path.name, "sha256": _hash(train_path)},
                "test": {"filename": test_path.name, "sha256": _hash(test_path)},
            },
        })
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        pipeline = build_binary_pipeline()

        with patch("training.evaluate_unsw_flow.joblib.load", return_value=pipeline), \
                patch.object(pipeline, "predict", return_value=np.array([0, 1])) as predict, \
                patch.object(pipeline, "fit", side_effect=AssertionError("must not refit")) as fit:
            report = evaluate_unsw_flow(artifact_path, train_path, test_path)

        fit.assert_not_called()
        self.assertEqual(predict.call_args.args[0].shape, (2, 42))
        self.assertEqual(report["sample_count"], 2)
        self.assertIn("precision", report)
        self.assertIn("recall", report)
        self.assertIn("f1", report)
        self.assertIn("confusion_matrix", report)
        self.assertNotIn("roc_auc", report)

    def test_evaluator_reports_multiclass_per_class_and_averages(self):
        classes = sorted(EXPECTED_ATTACK_CATEGORIES)
        truth = np.array(["Normal", "DoS"], dtype=object)
        predictions = np.array(["Normal", "Normal"], dtype=object)

        report = _build_report(None, None, TARGET_ATTACK_CATEGORY, truth, predictions, classes)

        self.assertEqual(set(report["per_class"]), set(classes))
        self.assertIn("support", report["per_class"]["DoS"])
        self.assertIn("macro_average", report)
        self.assertIn("weighted_average", report)
        self.assertEqual(report["sample_count"], 2)


def _hash(path):
    import hashlib

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()