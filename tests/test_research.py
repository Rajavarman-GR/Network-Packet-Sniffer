import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from training.research import (
    feature_importance, render_report, summarize_dataset, visualization_data,
)


class ResearchReportTests(unittest.TestCase):
    def test_dataset_summary_contains_schema_counts_hash_and_distribution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.csv"
            path.write_text("data", encoding="utf-8")
            summary = summarize_dataset(path, {0: 2, 1: 1})
        self.assertEqual(3, summary["row_count"])
        self.assertEqual({"0": 2, "1": 1}, summary["class_distribution"])
        self.assertEqual(42, summary["predictor_count"])
        self.assertEqual(39, summary["numeric_feature_count"])
        self.assertEqual(3, summary["categorical_feature_count"])
        self.assertEqual(64, len(summary["source_sha256"]))
        json.dumps(summary)

    def test_feature_importance_names_raw_and_transformed_columns(self):
        pipeline = SimpleNamespace(named_steps={
            "classifier": SimpleNamespace(feature_importances_=[0.75, 0.25]),
            "preprocessor": SimpleNamespace(get_feature_names_out=lambda: [
                "numeric__dur", "categorical__proto_tcp",
            ]),
        })
        result = feature_importance(pipeline)
        self.assertEqual("numeric__dur", result["features"][0]["transformed_feature"])
        self.assertEqual("dur", result["features"][0]["raw_dataset_feature"])
        self.assertEqual("proto", result["features"][1]["raw_dataset_feature"])

    def test_report_formats_keep_unavailable_chart_data_empty(self):
        report = {"target": "label", "sample_count": 2, "evaluation_context": "independent_test_set",
                  "accuracy": 1.0, "confusion_matrix": [[1, 0], [0, 1]], "class_names": [0, 1]}
        self.assertIn("Accuracy: 1.0000", render_report(report))
        self.assertIsNone(visualization_data(report)["roc_curve"])
        json.dumps(visualization_data(report))


if __name__ == "__main__":
    unittest.main()
