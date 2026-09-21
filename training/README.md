# Offline Model Training

This directory contains the optional offline training pipeline. It is not imported by the desktop capture application.

## Dataset

Provide a local CSV with one row per packet or flow and these exact columns:

- Every name in `ai.feature_extractor.FEATURE_NAMES`
- `label`, typically `0`/`1` or `BENIGN`/`SUSPICIOUS`

The dataset is not downloaded, generated, or committed by this repository. Feature extraction for a production dataset must use the same parser and flow-context rules as runtime inference.

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
