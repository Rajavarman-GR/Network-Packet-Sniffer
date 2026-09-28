# Runtime AI and FlowTracker Audit

This describes the current source in `ai/` and its GUI worker integration. Runtime AI is an optional per-packet classifier with bounded context. It is not a confirmed-maliciousness verdict and is not the UNSW flow research model.

## Runtime data flow

```text
live callback or PCAP batch
  → GUI-thread parser + PacketManager record (stable packet ID)
  → AI input queue, maxsize 1,000 (only if ModelLoader is available)
  → AI worker
       ├─ FlowTracker.observe(packet, metadata, packet.time)
       ├─ extract_features(packet, metadata, context)
       └─ ThreatDetector.predict(23-value vector)
  → AI result queue, maxsize 1,000
  → Tk poll updates retained record and visible row by packet ID
```

The Scapy capture callback only attempts a nonblocking packet-queue put. The Tk thread drains at most 200 queued packets per scheduled callback, parses metadata, stores them, and puts them on the AI queue. The AI worker is a daemon thread started only when a compatible local model is available. The worker updates `FlowTracker`, creates features and predicts; it does not touch Tk widgets. Result polling runs on Tk and ignores results for records already evicted. A new capture clears the tracker through a reset marker sent through the AI queue.

Queue saturation is lossy by design: a full capture queue drops the packet; a full AI input queue skips that prediction; a full result queue drops the result. Those paths log warnings. AI overload therefore does not backpressure the capture callback. A queued record can remain `Pending` if its input was skipped. An evicted record will not receive a late result.

## Exact runtime feature schema

`ai.feature_extractor.FEATURE_NAMES` is the canonical ordered tuple, schema version `1.0`. `extract_features` creates a name-to-value dictionary and returns `[float(values[name]) for name in FEATURE_NAMES]`; ordering therefore comes from the tuple, not dictionary iteration. The vector is 23 numeric values.

| # | Feature | Source | Type | Meaning / runtime context | Missing-value behavior and bounds |
|---:|---|---|---|---|---|
| 1 | `packet_length` | Parser metadata (`length`), otherwise `len(packet)` | Packet | Captured wire length when available; parser otherwise checks Scapy original bytes and then serialized length. | Missing/falsey metadata falls back to `len`; parser may return 0 for malformed input. Not clamped by feature extractor. |
| 2 | `protocol_tcp` | `metadata.protocol` | Packet | 1 when parser classifies this packet as TCP; otherwise 0. | Always 0/1. Parser gives DNS precedence when a DNS layer is present. |
| 3 | `protocol_udp` | `metadata.protocol` | Packet | UDP indicator. | Always 0/1. |
| 4 | `protocol_dns` | `metadata.protocol` | Packet | DNS indicator. | Always 0/1; DNS can supersede TCP/UDP classification. |
| 5 | `protocol_arp` | `metadata.protocol` | Packet | ARP indicator. | Always 0/1. |
| 6 | `protocol_icmp` | `metadata.protocol` | Packet | ICMP indicator. | Always 0/1. |
| 7 | `protocol_icmpv6` | `metadata.protocol` | Packet | Parser-recognized ICMPv6 echo indicator. | Always 0/1; parser detection is narrower than the Decoder's ICMPv6 plugin. |
| 8 | `protocol_other` | `metadata.protocol` | Packet | 1 for any value outside TCP, UDP, DNS, ARP, ICMP, ICMPv6. | Always 0/1; absent protocol defaults to OTHER. |
| 9 | `source_port` | Parser metadata `sport` | Packet | Source transport port. | Empty/missing becomes 0; normally valid transport port range 0–65535. |
| 10 | `destination_port` | Parser metadata `dport` | Packet | Destination transport port. | Empty/missing becomes 0; normally valid transport port range 0–65535. |
| 11 | `tcp_flags` | Scapy TCP `flags` | Packet | Integer bit mask of TCP flags. | 0 when no TCP layer; bounded by the TCP flag field. |
| 12 | `payload_length` | Scapy `Raw.load` | Packet | Length of the complete Raw layer payload, not the bounded display preview. | 0 without Raw; no explicit feature-level cap. |
| 13 | `ip_ttl_or_hop_limit` | Scapy IPv4 TTL or IPv6 hop limit | Packet | Network-layer lifetime/hop field. | 0 if neither layer/value; protocol field is byte-sized. |
| 14 | `source_packet_count` | FlowTracker source endpoint timestamp deque | Context | Number of stored source endpoint timestamps after the 60-second prune and current packet insertion. | 0 if no context; at most 6,000 due to deque `maxlen`. |
| 15 | `destination_packet_count` | FlowTracker destination endpoint timestamp deque | Context | Number of stored destination endpoint timestamps after prune and current insertion. | 0 if no context; at most 6,000. For self-directed traffic the same endpoint is counted once. |
| 16 | `source_byte_count` | FlowTracker endpoint scalar | Context | Cumulative bytes observed for the source endpoint while its state remains. | 0 if absent; not window-pruned or numerically clamped. |
| 17 | `destination_byte_count` | FlowTracker endpoint scalar | Context | Cumulative bytes observed for the destination endpoint while its state remains. | 0 if absent; not window-pruned or numerically clamped. Self-directed traffic is counted once. |
| 18 | `packet_rate` | Source timestamps and current packet time | Context | Stored source packets divided by `max(now - oldest stored timestamp, 1.0)`. | 0 if absent; timestamp sample count capped at 6,000. Rate has a one-second denominator floor. |
| 19 | `byte_rate` | Source byte scalar and same elapsed interval | Context | Cumulative source bytes divided by the interval used for packet rate. | 0 if absent; not independently clamped; affected by history cap and endpoint retention. |
| 20 | `unique_destination_count` | FlowTracker source endpoint destination set | Context | Distinct destination address values seen by this source endpoint. | 0 if absent; set additions stop at 1,000; values are not aged out before endpoint expiry. |
| 21 | `unique_destination_port_count` | FlowTracker source endpoint destination-port set | Context | Distinct destination ports seen by the source endpoint. | 0 if absent; set additions stop at 1,000; values are not aged out before endpoint expiry. |
| 22 | `connection_frequency` | Current directed flow's packet counter and first-seen time | Context | Directed 5-tuple packet count divided by `max(now - first_seen, 1.0)`. It is a packet frequency proxy, not TCP connection establishment counting. | 0 if missing context; one-second denominator floor; flow counter has no numeric cap before expiration/eviction. |
| 23 | `dns_activity` | `metadata.protocol` | Packet | 1 when protocol is DNS, else 0. | Always 0/1; same parser DNS classification as feature 4. |

Feature extraction expects a Scapy-like packet and valid parser output. It does not have a general “unknown” feature value: metadata fields default to zero/OTHER, but an extraction exception is caught by the AI worker and that packet gets an unavailable result.

## FlowTracker state and semantics

The AI context is **directional**, distinct from the Investigation engine's bidirectional conversations. A key is `(source address, destination address, source port, destination port, protocol)`. Ports are coerced to integers with zero fallback. Reverse traffic has a different key. Each flow stores first/last timestamp, packet count, and bytes. `connection_frequency` is flow packet count over age, not a count of SYNs or new TCP sessions.

Each endpoint has `last_seen`, cumulative `bytes`, a deque of packet timestamps (`maxlen=6,000`), a set of observed destination addresses, and a set of destination ports. The source endpoint receives the packet timestamp, bytes, destination address and destination port. The destination endpoint receives timestamp and bytes. When source and destination are the same address, the endpoint is updated once, so self-directed traffic is not doubled. Timestamp deques are pruned against a default 60-second window before the current timestamp is appended; bytes and destination sets are not pruned on that window. The two set caps default to 1,000 and stop accepting new unique values once full.

Defaults cap directed flows and endpoints at 10,000 each. They use ordered dictionaries: observing a flow/endpoint moves it to the most-recent end, and reaching a cap discards the oldest entry. Expiration is swept at most once per second; flow and endpoint state expires when its last-seen age is greater than 300 seconds. Time is taken from `packet.time` when supplied, with current-time fallback for invalid/missing values. PCAP timestamps therefore drive the same state as live capture timestamps.

The 6,000 timestamp cap is independent of the 60-second age window. During a burst, old timestamps can be removed by deque capacity before they age out; packet-count/rate context then reflects only the timestamps still stored. This is a documented semantic limitation, not equivalent to an uncapped exact sliding window. The Tracker is in-memory and reset on **New Capture**.

## Model loading and prediction

`ModelLoader` expects `ai/model/threat_model.joblib` and adjacent `ai/model/metadata.json` unless test/custom paths are supplied. Current repository tree has neither artifact. Loader behavior:

1. If either file is missing, set an error and leave `available=False`.
2. Read JSON metadata; require `feature_schema_version == "1.0"` and exact ordered `features == FEATURE_NAMES`.
3. Require nonempty `model_name`, `model_version`, and unique string `classes` metadata.
4. Load the joblib object, then require callable `predict`, a present integral `n_features_in_` equal to 23, and exact agreement between estimator `classes_` and metadata classes.
5. Store the object and metadata only after all checks pass. Metadata files over 256 KiB and UNC paths on Windows are rejected. Any loading/validation exception is logged and leaves the model unavailable.

The loader does not compare a cryptographic model hash, inspect estimator class, or validate probability calibration. Metadata validation occurs before deserialization, but it does not make deserialization safe. `joblib.load` uses pickle-based serialization: load only model files from trusted local sources. UNC paths are rejected on Windows; local paths and mapped drives still require the operator to trust their contents.

For each available model prediction, `ThreatDetector` calls `predict([features])[0]`. It then calls `predict_proba([features])` when available and reports the largest class probability as `confidence`; otherwise confidence is `None`. Labels are uppercased and normalize `1/TRUE/THREAT/SUSPICIOUS/MALICIOUS` to `SUSPICIOUS`, `2/HIGH/HIGH_RISK/HIGH RISK` to `HIGH RISK`, and `0/FALSE/BENIGN/NORMAL` to `BENIGN`. Other outputs remain as their uppercased text.

The current `risk_score` formula is a display transformation, not an independently calibrated risk model: with confidence `c`, `HIGH RISK` gives `round(100*c)`, `SUSPICIOUS` gives `round(80*c)`, and other labels give `round(20*(1-c))`. If probabilities are unavailable, risk score is `None`. The implementation does not establish that confidence is a calibrated attack probability or that this score estimates real-world harm.

If the model is missing/incompatible, the GUI reports AI unavailable and stores `{available: false, label: UNAVAILABLE, confidence: null, risk_score: null, model_version: null}`. Prediction-time exceptions also become that record. The label is not a clean bill of health.

## Runtime classifier training utility

`training/train.py` can fit a `StandardScaler` plus 100-tree balanced `RandomForestClassifier` from a CSV whose columns match the runtime 23-feature names plus `label`. Its reader converts features to float but is less strict than `training/dataset_adapter.py`; it does not use that adapter, perform a train/test split, or record a dataset hash. It refuses to overwrite existing runtime output unless `--force` is explicit, and cannot write into `ai/model/unsw_flow`. `--output-dir` selects a separate destination. `training/evaluate.py` loads the model and prints a classification report on a supplied CSV; it does not independently validate metadata or protect against untrusted serialization. These scripts are prototype local utilities, not evidence of a supplied or production-trained runtime model.

## Semantics

- **AI classification ≠ confirmed maliciousness.** It is a label produced by the loaded classifier for one packet's features and bounded prior context.
- **Confidence ≠ guaranteed probability of attack.** It is the maximum value returned by the estimator's `predict_proba`, if available.
- **Risk score ≠ calibrated threat probability.** It is the label-specific arithmetic display formula above.
- AI output, Decoder heuristics, and protocol observations are distinct evidence categories. None alone proves malicious activity.

## Runtime AI vs UNSW research

| Aspect | Runtime AI | UNSW research pipeline |
|---|---|---|
| Input | One Scapy packet, parser metadata, directional in-memory FlowTracker context | One UNSW-NB15 flow row from local CSV |
| Schema | 23 packet/context floats, version 1.0 | 42 UNSW predictors: 39 numeric + 3 categorical, schema 1.0 |
| Purpose | Optional per-packet label in live/PCAP GUI | Offline research training, held-out evaluation, and training-data audit |
| Data source | Local CSV utility may train; no runtime model/data currently checked in | User-supplied UNSW official split CSVs; dataset not included |
| Model | Loaded from `ai/model/threat_model.joblib`; training utility uses scaler + 100-tree RF | Pipeline with schema guard, scaler, one-hot encoder, and 400-tree RF |
| Execution | AI worker during capture/PCAP processing | Separate command-line programs; not imported by live detector |
| Evaluation | No production metric claim is bundled with live detector | Independent test-split evaluator checks artifact/source metadata; separate audit uses internal split of explicit training CSV only |
| Interchangeable? | No | No |

The checked-in code and tests define these contracts. This workspace contains no runtime model. It does contain an ignored, untracked UNSW binary and metadata at `ai/model/unsw_flow/binary/`; the binary's SHA-256 matches the manifest in [training/README.md](../training/README.md). The official CSVs are absent, so the recorded UNSW evaluation cannot be re-run from this workspace. The UNSW artifact is not loaded by the runtime detector. Its joblib contents have not been deserialized during this audit.
