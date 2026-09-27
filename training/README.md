# Offline Model Training

This directory contains the optional offline training pipeline. It is not imported by the desktop capture application.

## Dataset

Provide a local CSV with one row per packet or flow and these exact columns:

- Every name in `ai.feature_extractor.FEATURE_NAMES`
- `label`, typically `0`/`1` or `BENIGN`/`SUSPICIOUS`

The dataset is not downloaded, generated, or committed by this repository. Feature extraction for a production dataset must use the same parser and flow-context rules as runtime inference.

### Runtime contract and compatibility

The training contract is strict: `training/dataset_adapter.py` accepts only the runtime schema and rejects anything that does not match it exactly. This is intentional. A public dataset such as CIC-IDS, UNSW-NB15, or a packet flow export can be used only if its columns can be mapped to the runtime 23 features with equivalent semantics; it must not be renamed or reshaped to invent missing runtime features.

If a public dataset is not already in the same feature semantics, the adapter raises a clear error rather than guessing a mapping. This repository does not contain a real production dataset and therefore does not train a model from a fabricated or synthetic one.

## UNSW-NB15 Flow Preparation

`training/unsw_flow_schema.py` and `training/prepare_unsw.py` define a separate,
validation-only flow-level pipeline for the UNSW-NB15 train/test CSVs. This schema
is not compatible with the current packet-level 23-feature detector, and UNSW
flow features must not be mapped into or passed to that detector.

The preparation stage validates the CSVs and exposes the original train/test
splits through a streaming API. It does not train a model, fit an encoder or
scaler, or write derived datasets. The official train/test split is preserved.
`label` is the default binary classification target; `attack_cat` is an optional
alternative target. `id` is excluded from predictors. When `label` is the target,
`attack_cat` is also excluded from predictors; neither target is ever returned
as a predictor.

`training/unsw_model_pipeline.py` builds unfitted binary and attack-category
scikit-learn pipelines using this schema. Building a pipeline does not train it,
fit preprocessing, or create model artifacts. This remains separate from the
packet-level detector.

Example validation call:

```python
from training.prepare_unsw import load_unsw_flow_data

data = load_unsw_flow_data("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv")
for features, label in data.iter_train():
	...
```

## Train

```bash
python training/train.py path/to/dataset.csv
```

This writes `ai/model/threat_model.joblib` and `ai/model/metadata.json`. Treat both files as trusted local artifacts. Serialized joblib files can execute code while loading; do not use unreviewed files.

## Evaluate

```bash
python training/evaluate.py path/to/test.csv
```

The command prints a scikit-learn classification report. Do not claim model accuracy without recording the dataset, split, and evaluation output.
