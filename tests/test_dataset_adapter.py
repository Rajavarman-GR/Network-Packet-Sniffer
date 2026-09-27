import csv
import os
import tempfile
import unittest

from ai.feature_extractor import FEATURE_NAMES
from training.dataset_adapter import load_training_dataset, normalize_label


class DatasetAdapterContractTests(unittest.TestCase):
    def _write_csv(self, rows, fieldnames):
        handle = tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", delete=False)
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.remove(handle.name))
        return handle.name

    def test_valid_schema_is_normalized_to_runtime_contract(self):
        rows = [
            {
                **{name: 1.0 for name in FEATURE_NAMES},
                "label": "BENIGN",
            },
            {
                **{name: 2.0 for name in FEATURE_NAMES},
                "label": "SUSPICIOUS",
            },
        ]
        path = self._write_csv(rows, list(FEATURE_NAMES) + ["label"])

        dataset = load_training_dataset(path)

        self.assertEqual(len(dataset), 2)
        self.assertEqual(list(dataset[0].keys()), list(FEATURE_NAMES) + ["label"])
        self.assertEqual(dataset[0]["label"], "BENIGN")
        self.assertEqual(dataset[1]["label"], "SUSPICIOUS")
        self.assertEqual(dataset[0]["packet_length"], 1.0)

    def test_missing_column_is_rejected(self):
        fieldnames = list(FEATURE_NAMES[:-1]) + ["label"]
        rows = [{"packet_length": 10.0, "label": "BENIGN"}]
        path = self._write_csv(rows, fieldnames)

        with self.assertRaisesRegex(ValueError, "missing feature"):
            load_training_dataset(path)

    def test_invalid_numeric_values_are_rejected(self):
        rows = [
            {
                **{name: 1.0 for name in FEATURE_NAMES},
                "label": "BENIGN",
            }
        ]
        rows[0]["packet_length"] = "NaN"
        path = self._write_csv(rows, list(FEATURE_NAMES) + ["label"])

        with self.assertRaisesRegex(ValueError, "invalid numeric"):
            load_training_dataset(path)

    def test_label_values_are_normalized(self):
        self.assertEqual(normalize_label("0"), "BENIGN")
        self.assertEqual(normalize_label("1"), "SUSPICIOUS")
        self.assertEqual(normalize_label("BENIGN"), "BENIGN")
        self.assertEqual(normalize_label("Suspicious"), "SUSPICIOUS")

    def test_feature_order_is_preserved(self):
        rows = [{**{name: 0.0 for name in FEATURE_NAMES}, "label": "BENIGN"}]
        path = self._write_csv(rows, list(FEATURE_NAMES) + ["label"])

        dataset = load_training_dataset(path)

        self.assertEqual(list(dataset[0].keys()), list(FEATURE_NAMES) + ["label"])

    def test_unsw_schema_is_rejected_without_unsafe_feature_mapping(self):
        unsw_columns = [
            "id", "dur", "proto", "service", "state", "spkts", "dpkts",
            "sbytes", "dbytes", "rate", "sttl", "dttl", "sload", "dload",
            "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin",
            "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
            "dmean", "trans_depth", "response_body_len", "ct_srv_src",
            "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
            "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
            "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports", "attack_cat", "label",
        ]
        path = self._write_csv([{column: "0" for column in unsw_columns}], unsw_columns)

        with self.assertRaisesRegex(ValueError, "missing feature"):
            load_training_dataset(path)


if __name__ == "__main__":
    unittest.main()
