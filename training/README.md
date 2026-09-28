# Offline Model Training

This directory contains the optional offline training pipeline. It is not imported by the desktop capture application.

## Dataset

Provide a local CSV with one row per packet or flow and these exact columns:

- Every name in `ai.feature_extractor.FEATURE_NAMES`
- `label`, typically `0`/`1` or `BENIGN`/`SUSPICIOUS`

The dataset is not downloaded, generated, or committed by this repository. Feature extraction for a production dataset must use the same parser and flow-context rules as runtime inference.

### Runtime contract and compatibility

`training/dataset_adapter.py` is a strict adapter that accepts only the runtime schema and rejects anything that does not match it exactly. The `training/train.py` script does **not** call this adapter: its CSV reader checks for required columns and casts features to floats, but performs less validation. Training with that script fits on all provided rows and does not create a train/test split. It refuses to replace existing model files unless `--force` is explicitly supplied, accepts `--output-dir`, and refuses output under `ai/model/unsw_flow`.

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

## UNSW-NB15 Training and Evaluation

`training/train_unsw_flow.py` trains the separate UNSW flow model; it does not
train the packet-level detector. Select one target per model: `label` for binary
classification or `attack_cat` for attack-category classification. The official
train/test split is preserved, and the pipeline fits scaling and categorical
encoding only on training predictors.

Training creates a single fitted pipeline artifact with preprocessing and
classifier together, plus a metadata JSON file. The default artifact directories
are `ai/model/unsw_flow/binary/` and
`ai/model/unsw_flow/attack_category/`. Existing artifacts are not overwritten.
These files are separate from `ai/model/threat_model.joblib` and are not consumed
by the live packet detector.

```bash
python training/train_unsw_flow.py --target label
python training/train_unsw_flow.py --target attack_cat
python training/evaluate_unsw_flow.py --artifact ai/model/unsw_flow/binary/unsw_flow_pipeline.joblib
```

The CLI accepts explicit `--train` and `--test` paths; `UNSW_NB15_DIR` can also
select the directory containing the standard split filenames. Evaluation
validates artifact metadata and source-file hashes, then reports metrics from
the held-out testing split without refitting preprocessing or the classifier.

### Recorded Binary Run

A real binary UNSW flow model was trained once with target `label`, 42 validated
UNSW flow predictors, and the official train/test split preserved. Preprocessing
was fitted on the training split only. The artifact is intentionally excluded
from normal Git because its size is approximately 468 MB; the training and
evaluation code remains versioned. The binary does not represent or measure the
packet-level live detector.

Reproduce the run from a clean checkout with the official CSV paths available:

```bash
python training/train_unsw_flow.py --target label --train path/to/UNSW_NB15_training-set.csv --test path/to/UNSW_NB15_testing-set.csv
python training/evaluate_unsw_flow.py --artifact ai/model/unsw_flow/binary/unsw_flow_pipeline.joblib --train path/to/UNSW_NB15_training-set.csv --test path/to/UNSW_NB15_testing-set.csv
```

Training refuses to overwrite existing artifacts. Evaluation uses the official
test split and does not refit. The following manifest identifies the recorded
local run; it is provenance, not a production-performance claim.

| Item | Recorded value |
|---|---|
| Model family / target | `unsw_flow` / `label` |
| Schema version | `1.0` |
| Artifact | `ai/model/unsw_flow/binary/unsw_flow_pipeline.joblib` |
| Artifact size | 468,491,866 bytes |
| Artifact SHA-256 | `45b0ffba67c16010023fb1124dbc5e230d1b2d62bef2f876a7300c099836ace1` |
| Train / test rows | 175,341 / 82,332 |
| Random seed | `42` |
| Classifier | Random forest, 400 trees, balanced class weights, `n_jobs=-1` |
| Train CSV SHA-256 | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| Test CSV SHA-256 | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |
| Python / scikit-learn | `3.14.4` / `1.9.1` |

Recorded held-out results for this dataset split:

| Metric | Value |
|---|---:|
| Precision (positive class `1`) | 0.850321042715983 |
| Recall (positive class `1`) | 0.9757345804288361 |
| F1 (positive class `1`) | 0.9087211093990755 |
| ROC-AUC | 0.9812888017175387 |
| Confusion matrix (actual rows `0, 1`; predicted columns `0, 1`) | `[[29214, 7786], [1100, 44232]]` |

These results describe only this held-out UNSW-NB15 split. They do not establish
production readiness, generalization to other traffic, or performance of the
live packet detector.

The manifest above records a previous local run. The generated binary, metadata
file, and source CSVs are not present in the current checkout, so this repository
state cannot independently verify or reproduce those metrics. They are not a
runtime AI result. When set, `UNSW_NB15_DIR` now supplies both default split paths;
explicit `--train` and `--test` arguments override their respective defaults.

## Train

```bash
python training/train.py path/to/dataset.csv
```

This writes `ai/model/threat_model.joblib` and `ai/model/metadata.json` only when neither already exists. To choose a different output directory use `--output-dir path/to/runtime-model`; to replace an existing pair deliberately, pass `--force`. The two destinations are staged before installation. Runtime outputs cannot be written inside `ai/model/unsw_flow/`. Treat both files as trusted local artifacts. Serialized joblib files can execute code while loading; do not use unreviewed files.

## Evaluate

```bash
python training/evaluate.py path/to/test.csv
```

The command prints a scikit-learn classification report. Do not claim model accuracy without recording the dataset, split, and evaluation output.
