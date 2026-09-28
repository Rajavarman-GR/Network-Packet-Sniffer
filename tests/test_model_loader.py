import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai.feature_extractor import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ai.model_loader import ModelLoader


class CompatibleModel:
    n_features_in_ = len(FEATURE_NAMES)
    classes_ = ("BENIGN", "SUSPICIOUS")

    @staticmethod
    def predict(values):
        return ["BENIGN"]


class ModelLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.model_path = self.root / "model.joblib"
        self.metadata_path = self.root / "metadata.json"
        self.model_path.write_bytes(b"trusted test fixture placeholder")

    @staticmethod
    def metadata(**updates):
        metadata = {
            "model_name": "test-model",
            "model_version": "1.0",
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "features": list(FEATURE_NAMES),
            "classes": ["BENIGN", "SUSPICIOUS"],
        }
        metadata.update(updates)
        return metadata

    def write_metadata(self, metadata):
        self.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    def load_with_model(self, model, metadata=None):
        self.write_metadata(metadata or self.metadata())
        with patch("ai.model_loader.joblib.load", return_value=model):
            return ModelLoader(self.model_path, self.metadata_path)

    def test_valid_model_requires_and_matches_full_runtime_contract(self):
        loader = self.load_with_model(CompatibleModel())

        self.assertTrue(loader.available)
        self.assertIsNone(loader.error)

    def test_missing_feature_count_is_unavailable_instead_of_assumed(self):
        model = type("NoFeatureCountModel", (), {
            "classes_": CompatibleModel.classes_,
            "predict": CompatibleModel.predict,
        })()
        loader = self.load_with_model(model)

        self.assertFalse(loader.available)
        self.assertIn("n_features_in_", loader.error)

    def test_incorrect_feature_count_is_rejected(self):
        model = type("WrongFeatureCountModel", (), {
            "n_features_in_": len(FEATURE_NAMES) - 1,
            "classes_": CompatibleModel.classes_,
            "predict": CompatibleModel.predict,
        })()
        loader = self.load_with_model(model)

        self.assertFalse(loader.available)
        self.assertIn("feature count", loader.error)

    def test_schema_features_and_model_version_are_required(self):
        for update, expected in (
            ({"feature_schema_version": "wrong"}, "schema version"),
            ({"features": list(reversed(FEATURE_NAMES))}, "feature names"),
            ({"model_version": ""}, "model_version"),
        ):
            with self.subTest(update=update):
                loader = self.load_with_model(CompatibleModel(), self.metadata(**update))
                self.assertFalse(loader.available)
                self.assertIn(expected, loader.error)

    def test_classes_must_match_model_and_metadata(self):
        wrong_metadata = self.metadata(classes=["BENIGN"])
        loader = self.load_with_model(CompatibleModel(), wrong_metadata)
        self.assertFalse(loader.available)
        self.assertIn("model classes", loader.error)

    def test_model_without_predict_is_rejected(self):
        model = type("NoPredictModel", (), {
            "n_features_in_": len(FEATURE_NAMES),
            "classes_": CompatibleModel.classes_,
        })()
        loader = self.load_with_model(model)
        self.assertFalse(loader.available)
        self.assertIn("predict method", loader.error)

    def test_oversized_metadata_is_rejected_before_deserialization(self):
        self.metadata_path.write_text(" " * (256 * 1024 + 1), encoding="utf-8")
        with patch("ai.model_loader.joblib.load") as load_model:
            loader = ModelLoader(self.model_path, self.metadata_path)

        self.assertFalse(loader.available)
        self.assertIn("size limit", loader.error)
        load_model.assert_not_called()

    def test_network_model_path_is_rejected_without_loading(self):
        with patch("ai.model_loader.joblib.load") as load_model:
            loader = ModelLoader(r"\\example.invalid\share\model.joblib", self.metadata_path)

        self.assertFalse(loader.available)
        self.assertIn("local files", loader.error)
        load_model.assert_not_called()


if __name__ == "__main__":
    unittest.main()
