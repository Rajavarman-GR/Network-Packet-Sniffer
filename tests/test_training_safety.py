import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai.feature_extractor import FEATURE_NAMES
from training.train import (
    MODEL_DIR,
    RESEARCH_MODEL_DIR,
    _resolve_output_paths,
    build_argument_parser,
    train,
)


class RuntimeTrainingSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.dataset = self.root / "features.csv"
        self.dataset.write_text("placeholder", encoding="utf-8")
        self.output_dir = self.root / "runtime-model"

    @staticmethod
    def training_rows():
        features = [
            [float((row + 1) * ((column % 5) + 1)) for column in range(len(FEATURE_NAMES))]
            for row in range(4)
        ]
        return features, ["BENIGN", "SUSPICIOUS", "BENIGN", "SUSPICIOUS"]

    def test_cli_exposes_explicit_output_and_force_controls(self):
        args = build_argument_parser().parse_args([
            str(self.dataset), "--output-dir", str(self.output_dir), "--force",
        ])

        self.assertEqual(args.output_dir, self.output_dir)
        self.assertTrue(args.force)

    def test_existing_runtime_artifacts_are_refused_without_force(self):
        self.output_dir.mkdir()
        model_path = self.output_dir / "threat_model.joblib"
        metadata_path = self.output_dir / "metadata.json"
        model_path.write_bytes(b"existing-model")
        metadata_path.write_bytes(b"existing-metadata")

        with patch("training.train.load_dataset") as load_dataset:
            with self.assertRaisesRegex(FileExistsError, "--force"):
                train(self.dataset, self.output_dir)

        load_dataset.assert_not_called()
        self.assertEqual(model_path.read_bytes(), b"existing-model")
        self.assertEqual(metadata_path.read_bytes(), b"existing-metadata")

    def test_explicit_force_replaces_only_the_requested_runtime_pair(self):
        self.output_dir.mkdir()
        model_path = self.output_dir / "threat_model.joblib"
        metadata_path = self.output_dir / "metadata.json"
        model_path.write_bytes(b"old-model")
        metadata_path.write_text('{"old": true}', encoding="utf-8")
        with patch("training.train.load_dataset", return_value=self.training_rows()):
            fitted = train(self.dataset, self.output_dir, force=True)

        self.assertTrue(model_path.is_file())
        self.assertTrue(metadata_path.is_file())
        self.assertNotEqual(model_path.read_bytes(), b"old-model")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["features"], list(FEATURE_NAMES))
        self.assertEqual(metadata["classes"], [str(label) for label in fitted.classes_])
        self.assertFalse(any(self.output_dir.glob(".runtime-training-*")))

    def test_runtime_training_cannot_target_unsw_research_artifact_tree(self):
        with self.assertRaisesRegex(ValueError, "UNSW research artifact directory"):
            _resolve_output_paths(RESEARCH_MODEL_DIR / "binary")

        # The default runtime root remains valid and distinct from the UNSW tree.
        _, model_path, metadata_path = _resolve_output_paths(MODEL_DIR)
        self.assertEqual(model_path.name, "threat_model.joblib")
        self.assertEqual(metadata_path.name, "metadata.json")
        self.assertNotEqual(model_path.parent, RESEARCH_MODEL_DIR)


if __name__ == "__main__":
    unittest.main()
