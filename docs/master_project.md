# Network Packet Sniffer — Master Project Audit

**Audit basis:** source tree at `1b6699b` (`main`), inspected locally on 2026-09-28. The Git working tree was clean at audit start. This is a code-grounded description; see individual technical documents for deeper details. Git tracks no model binary, dataset, packet capture, or saved investigation case. The local workspace contains an ignored, untracked UNSW binary and metadata; no runtime threat model or dataset CSV is present.

## Project in one page

| Item | Verified description |
|---|---|
| Name | Network Packet Sniffer |
| More precise description | A passive desktop packet capture, packet-level protocol Decoder, and bounded-retention investigation workbench. |
| Category / users | Python/Tkinter network traffic analysis tool for learners, educators, and defensive analysts inspecting authorized live traffic or PCAP files. |
| Main problem addressed | Make packet capture, protocol facts, optional per-packet model outputs, and packet-referenced summaries inspectable in one local desktop UI. |
| Main path | Scapy capture or PCAP → bounded GUI processing/PacketManager → parser and optional AI worker → on-demand Decoder and retained-window investigation → Tk workspaces. |
| AI status | Optional local runtime model for a 23-feature packet/context vector. No runtime model is present. AI output is not a confirmed threat verdict. |
| Research path | Separate UNSW-NB15 flow-level pipeline with 42 predictors; offline CLI only, not loaded by live packet capture. |
| Major boundaries | Packet-level decoding only; no TCP reassembly, session reconstruction, or TLS decryption. Investigation only covers retained records. |
| Execution / safety | Passive only: no scanning, packet injection, blocking, or threat-intelligence integration. PCAP/payload data may be sensitive. |

“Network Packet Sniffer” is still an accurate repository name. A descriptive subtitle such as **Passive Packet Analysis and Investigation Workbench** states its actual breadth more precisely without inventing a separate brand.

## Verified technology stack

### Runtime stack

| Technology | Repository evidence / role |
|---|---|
| Python | Application, workers, Decoder, training and tests; README supports Python 3.11+. CI specifies 3.11. |
| Scapy (`scapy`) | `AsyncSniffer`, packet/layer dissection, `PcapReader`, and PCAP export. |
| Tkinter / ttk | Python standard-library desktop GUI, notebooks, tables, dialogs, and event loop. Requires a Tk-enabled Python distribution. |
| `psutil` | Enumerates interface names via `net_if_addrs`; Scapy interface names are resolved in `core/interfaces.py`. |
| `unittest` | Standard-library test runner; tests use synthetic Scapy packets, files, and fixtures. |
| GitHub Actions | `.github/workflows/tests.yml`: Ubuntu, Python 3.11, requirements install, compileall, unittest discovery on push/PR. |

### Research/training stack

| Technology | Repository evidence / role |
|---|---|
| NumPy (`numpy`) | UNSW training/evaluation/audit arrays and pipeline processing. |
| scikit-learn (`scikit-learn`) | Runtime training utility plus UNSW preprocessing, classifiers, and metrics. Package availability alone does not mean a runtime model exists. |
| joblib | Serializes/loads local runtime and UNSW sklearn artifacts. Treat all joblib artifacts as trusted executable inputs. |
| pandas | Not declared or required. The UNSW readers use Python's `csv` module and convert rows into NumPy arrays for training/evaluation. |
| UNSW-NB15 files | User-supplied CSVs; official data is not downloaded. Training and evaluation preserve the official train/test split. |

The runtime detector also needs joblib and scikit-learn when loading/using a fitted sklearn model. NumPy and scikit-learn are declared in the same `requirements.txt` used by the runtime and research tools; dependencies are not divided into optional extras.

### Data, configuration, and operating system

| Concern | Verified implementation |
|---|---|
| PCAP | Scapy `PcapReader` streaming read in batches (128 default); Scapy `wrpcap` export. |
| Packet/model data | Scapy packet objects; feature dataset CSV; UNSW train/test CSV; JSON metadata and reports; joblib sklearn pipelines. |
| Configuration | `config.json` at repo root. `utils.config` normalizes theme, retention, interface/protocol, auto-scroll, timestamp format. Default 10,000 retained packets; max 20,000. |
| Logging | Python `logging` to `logs/sniffer.log`; `utils/logger.py` creates the log directory during import. |
| OS support | Python/Tkinter and Scapy-supported capture stack. Live capture may need Npcap on Windows, libpcap on Linux/macOS and OS privileges. Windows file cleanup is explicitly handled for malformed PCAP headers. |
| Network activity | Passive capture only. No outbound threat-intelligence or dataset download is performed by runtime. |

`requirements.txt` declares `scapy`, `psutil`, `numpy`, `joblib`, and `scikit-learn`. Tkinter, `unittest`, threading, queues, JSON, CSV, logging, and PCAP-independent GUI plumbing use Python standard-library modules. Runtime capture/GUI dependencies and offline ML dependencies overlap in one requirements file; the repository does not split them into extras.

## Architecture and packet flow

The high-level and internal diagrams, module boundaries, worker lifecycle, resource bounds, and six runtime flow diagrams are in [architecture.md](architecture.md). The key verified path is:

```text
Live: Scapy callback → packet queue (1,000) → Tk drain (≤200 per tick)
  → parser metadata → PacketManager → packet row + optional AI queue
  → AI worker (FlowTracker → 23 features → model) → result queue → Tk update

PCAP: I/O worker/PcapReader → ≤128 packet batch → eight-item I/O queue
  → Tk consumes batch → parser → PacketManager + optional AI queue
  → table refresh → automatic retained-window investigation

On demand: selected packet → Decoder facade/plugins → Decoder dialog
Investigation: retained record list → unified analysis → conversations/evidence/timeline
```

Not every packet synchronously passes through every component. Parser/retention run on Tk; AI inference, PCAP reading, export, and investigation use workers; Decoder opens on demand. `core.analysis.analyze_packet()` is called from `InvestigationEngine`, not as a required capture-time stage.

### Unified analysis boundary

```text
retained packet + optional AI result
  → parser metadata (if not already supplied)
  → Decoder bundle (fields/application/payload/heuristics)
  → separate AI result or explicit unavailable record
  → analysis record {metadata, decoder, ai, status}
```

Parser/Decoder exceptions are caught at this boundary and can produce `malformed` status. If no AI result is supplied, the analysis record contains `available: false`, `UNAVAILABLE`, and null confidence/risk/version. Decoder matching/no-match and AI state remain distinct. Unified analysis does not generate an AI prediction or combine the categories into a single threat verdict.

### GUI navigation

```text
Main window: menu + capture toolbar + status
  └── Overview | Packets | Flows | Investigation | Statistics
                       │         │           │
                       │         └─ double-click → packet ID → Packets selection
                       ├─ selected packet → Decoder dialog
                       │                      Beginner | Analyst | Technical / Raw
                       └─ File/toolbar → Open PCAP / Settings; Help → guide/About
```

The Flows table represents conversation data from the latest Investigation run; it is not a live view of AI FlowTracker's directed state. Packet navigation relies on PacketManager's stable IDs. If display filtering hides a retained packet, navigation clears the filter. Settings persist the current theme and capture/display preferences in root `config.json`.

## Runtime AI audit

The complete current 23-feature schema, source, type, meaning, bounds, FlowTracker expiration and self-directed traffic, model-loader checks, prediction/label/risk semantics, and limitations are documented in [ai_architecture.md](ai_architecture.md). Summary:

- AI input is queued only when a compatible local model loaded. FlowTracker state is updated inside the single AI worker before the packet feature vector is created.
- The key is directed `(src, dst, sport, dport, protocol)`. Endpoint histories have a 6,000 timestamp cap, context window default 60 seconds, and state expiration default 300 seconds (periodic sweep); there are 10,000 flow/endpoint bounds and 1,000 unique destination/port bounds.
- Feature order is explicitly built from `FEATURE_NAMES`, schema version `1.0`. Source/context values default to numeric values; extraction errors are converted to unavailable results.
- Metadata requires the exact schema version and ordered feature names before `joblib.load`; callable `predict` is required. Feature count is compared with 23 when the model exposes `n_features_in_`, but missing count metadata falls back to 23 and therefore passes. No artifact hash is checked.
- `predict_proba` maximum is called confidence when present. Risk score is a formula based on the normalized label and confidence. Neither is established as calibrated threat likelihood.
- If the model is absent/incompatible, records show unavailable; absent model files are the current checked-in state.

Serialized joblib models must be treated as trusted artifacts: metadata checks are not a security sandbox around deserialization.

## Runtime model vs UNSW research model

| Aspect | Runtime AI | UNSW research |
|---|---|---|
| Input | Packet plus runtime parser and FlowTracker state | One flow row from user-supplied UNSW CSV |
| Schema | 23 numeric features, runtime schema v1.0 | 42 predictors (39 numeric, `proto`/`service`/`state` categorical), UNSW schema v1.0 |
| Goal | Optional per-packet classification during live or PCAP GUI work | Offline binary or attack-category flow experiment |
| Training | `training/train.py`, 100-tree balanced RandomForest + scaler; no split/evaluation safeguards | `train_unsw_flow.py`, schema guard + StandardScaler + OneHotEncoder + 400-tree balanced RandomForest |
| Evaluation | Legacy helper reports classification report on supplied feature CSV | Evaluator checks metadata and input file hashes/counts, predicts official test split without fitting |
| Artifact | `ai/model/threat_model.joblib` + `metadata.json` | Dedicated `ai/model/unsw_flow/{binary,attack_category}/` pipeline + metadata |
| Checked-in artifact/data | No runtime artifact/data tracked or present | No UNSW artifact/data tracked in Git; ignored local binary + metadata are present, source CSVs absent |
| Interchangeability | No | No |

### UNSW pipeline and safeguards

`unsw_flow_schema.py` declares all 42 predictors and target/excluded columns. `prepare_unsw.py` validates exact allowed CSV headers, numeric finiteness, categorical non-emptiness, target values, and train/test schema agreement. It returns path-backed iterators and preserves the official split; targets and `id` are excluded from predictors. Preparation alone does not create derived data or fit anything.

`train_unsw_flow.py` revalidates, collects each split into in-memory NumPy object arrays, counts classes, fits `StandardScaler` to 39 numeric columns and `OneHotEncoder(handle_unknown="ignore")` to 3 categorical columns on training predictors only, then fits a 400-tree balanced RandomForest (seed 42 by default). It writes one pipeline and JSON metadata with schema, classes/counts, row counts, seed, classifier and Python/sklearn versions, training time, and train/test filenames plus SHA-256 hashes. Target-specific output directories refuse existing artifact/metadata and avoid overlap with the runtime model path. Writes use temporary names and replace operations.

`evaluate_unsw_flow.py` verifies metadata against the source schema, checks filenames and SHA-256 hashes, row counts and class counts, checks that the deserialized object is a sklearn `Pipeline` with the expected target and `predict`, then predicts the official test split without fitting/refitting. It produces accuracy, confusion matrix, precision/recall/F1, optional ROC-AUC/curve, dataset summary and feature importance. Deserialization still requires a trusted artifact. `audit_unsw_flow.py` accepts one explicit training CSV, refuses the canonical official test filename, creates a stratified 80/20 internal split (seed 42 default), and fits four feature variants for comparison. It does not load or use the official test split and writes no model artifacts.

The workspace includes the ignored, untracked binary `ai/model/unsw_flow/binary/unsw_flow_pipeline.joblib` (468,491,866 bytes) plus metadata. Its SHA-256 was independently read as `45b0ffba67c16010023fb1124dbc5e230d1b2d62bef2f876a7300c099836ace1`, matching the recorded manifest. Metadata says 175,341 training rows, 82,332 test rows, target `label`, seed 42, scikit-learn 1.9.1, Python 3.14.4 and training timestamp 2026-09-27. The CSVs are absent, so their hashes and historical held-out evaluation cannot be reverified or rerun. The joblib artifact was not deserialized in this audit. It is not a performance result for the runtime packet detector.

## Decoder and beginner explanations

See [decoder.md](decoder.md) for plugin-by-plugin detection, fields, limits, and heuristics. The registry contains DNS, TLS, HTTP, FTP, and ICMP/ICMPv6 plugins. Generic Scapy layer traversal supplements those plugins. The Decoder opens on Beginner mode; Analyst presents decoded application information; Technical / Raw shows Scapy layer fields and bounded payload. `core/explanations.py` converts structured decoded facts into cautious language, without doing parsing or threat inference.

Limitations: no TCP stream reassembly, session reconstruction, or TLS decryption; packet-spanning application headers are not assembled. Heuristic findings scan a limited byte range for small patterns and can have false positives/misses.

## Investigation and PCAP behavior

`InvestigationEngine` analyzes at most its configured `max_records` from the supplied record iterable (default 10,000). It calls unified analysis per record, groups bidirectional conversations by canonical protocol/address/port endpoints, tracks source talkers, appends DNS/HTTP/TLS plugin results, keeps AI findings separate from Decoder heuristics, and creates deterministic event ordering. It retains packet IDs for navigation but is not a persistent case database. The GUI shows six evidence tabs plus Flows and Statistics.

Protocol extraction is delegated to `core.decoder`; investigation does not have a second DNS/HTTP/TLS parser. It only has packet objects currently retained. If AI processing is still underway, an investigation may include unavailable AI for records that had no result when read (or may observe AI updates arriving during the worker because the record list is shallow). Re-running analysis refreshes the view.

`iter_pcap_batches()` wraps file and `PcapReader` lifetimes in contexts, yields 128 by default, checks cancellation after reading each packet and before appending it to the batch, and yields a final partial batch on successful/cancelled iteration. The GUI uses a bounded eight-result queue and timed producer backpressure. Captured count may exceed retained count. Export writes visible, filtered packet records through `wrpcap` on an I/O worker.

More behavior and presentation limits are in [investigation.md](investigation.md) and [user_guide.md](user_guide.md).

## Performance

`benchmarks/benchmark_pipeline.py` builds synthetic IPv4/UDP/DNS-shaped packets with a small Raw body. Setup packet construction and PCAP writing are excluded from each stage timer. It measures parser metadata, Decoder, unified analysis with explicit AI unavailable, runtime FlowTracker, bounded Investigation, streamed PCAP reads, and PacketManager retention. It measures Python allocation peak via `tracemalloc` around retention only; Scapy packets are prebuilt, so that is neither total process memory nor RSS. The CLI defaults to 1,000/10,000/50,000 packets, batch size 128, retention 10,000. These figures are diagnostic, not real capture performance or a before/after claim.

Recorded values and caveats are in [performance.md](performance.md). In particular, the 50,000-row Investigation measurement analyzes only the retained 10,000 rows. Timings vary by host and should not be compared to a different host/run without repeating the workload.

## Testing and CI

At this audit, the suite contains **134 tests** across 12 modules:

| Test module | Count | Primary coverage |
|---|---:|---|
| `test_dataset_adapter.py` | 6 | Exact runtime CSV schema, numeric features, labels, malformed datasets. |
| `test_decoder.py` | 35 | Decoder plugins, protocol fields, malformed/truncated packets, payload bounds and heuristic findings. |
| `test_investigation.py` | 4 | Conversation/evidence grouping, packet IDs, timeline, cancellation/retention. |
| `test_parser_and_config.py` | 19 | Metadata, filters, malformed values, FlowTracker bounds/expiry/self-traffic, model compatibility, config. |
| `test_pcap_stream.py` | 4 | Batches, cancellation, invalid capture and resource cleanup. |
| `test_product_presentation.py` | 12 | Explanations, display models, empty states, themes/config compatibility. |
| `test_research.py` | 3 | Dataset summaries, feature importance, report helpers. |
| `test_unsw_audit.py` | 8 | Training-only split/audit, variants and safeguards. |
| `test_unsw_flow_schema.py` | 15 | UNSW header/row/target validation and streaming contracts. |
| `test_unsw_model_pipeline.py` | 15 | Unfitted pipeline schema, encoders, metadata and artifact separation. |
| `test_unsw_training.py` | 11 | Training/evaluation metadata, hashes, non-refit behavior and output safeguards. |
| `test_worker_queue.py` | 2 | Backpressure and shutdown termination. |

The suite has parser and Decoder malformed/truncation tests, PCAP lifecycle tests, queue concurrency tests and extensive UNSW schema/model/evaluation tests. It does not constitute a live capture-driver test or an end-to-end interactive GUI launch test; GUI support is mostly through pure presentation/theme behavior. CI runs on Ubuntu/Python 3.11. Managed Windows hosts may need a writable Scapy cache/temp directory or offline Scapy test setup, without changing production code or weakening tests.

## Security-conscious design and remaining limitations

- Retention, queues, Tracker maps, timestamp history, Decoder preview, HTTP parsing and heuristic scan have explicit bounds.
- Malformed values are handled in parser/Decoder/analysis boundaries; malformed PCAP descriptor cleanup is explicit.
- Capture callback is nonblocking. Worker queues bound memory and use drops/backpressure according to stage.
- Shutdown signals workers and bounds joins, but cannot interrupt an OS read or model call already in progress.
- joblib model deserialization is unsafe for untrusted files. Runtime metadata checks do not prove artifact trust or model validity.
- No runtime model/data is bundled. Model output has no checked-in production evaluation or calibration evidence.
- AI/context queue overflow can skip work; bounded endpoint history affects rate/count semantics.
- GUI Treeviews are not virtualized; large input files are read incrementally but only a small retained window is kept and rendering work occurs on Tk.
- PCAP investigation cannot access evicted packets. Investigation output is transient, not saved as a case.
- Packet-level Decoder cannot reconstruct TCP streams or decrypt TLS; SNI is available only if visible in a ClientHello packet.
- Heuristics are a small pattern scanner, not a signature engine or malware verdict.
- Windows live startup/capture depends on Scapy/Npcap interface discovery, installation, and permissions; interactive startup was not part of automated tests.
- Current audit attempted `main.py` with workspace-local temp/cache, but no titled window or traceback appeared within about 10 seconds; it was stopped. The GUI getting through initialization into `create_body()` could not be verified in this environment.

No active scanning, packet injection, automated blocking, threat-intelligence feed, alert engine, IOC engine, persistent case store, or complete SOC workflow is present.

## Verified module reference

| Module | Responsibility | Main inputs → outputs | Main dependencies |
|---|---|---|---|
| `main.py` | Tk application entry point | starts root and `PacketSnifferApp` | Tkinter, `gui.main_window` |
| `core/sniffer.py` | Scapy live capture wrapper | interface/filter/callback → capture lifecycle | Scapy |
| `core/parser.py` | Lightweight parsing/filter/search/preview | packet → metadata/text/preview | Scapy, time/math |
| `core/filter_engine.py` | Build validated BPF expressions | protocol/IP/port → BPF string | `ipaddress` |
| `core/interfaces.py` | OS interface listing and Scapy mapping | interface names → capture ID | psutil, Scapy |
| `core/packet_manager.py` | Bounded FIFO and packet identity | packet + metadata → record/eviction | collections |
| `core/worker_queue.py` | Shutdown-aware bounded put | queue/item/event → success/failure | queue |
| `core/pcap.py` | Streaming PCAP iterator | path/cancel → packet batches | Scapy |
| `core/decoder.py`, `core/decoders/*` | Generic layer and protocol inspection | packet → layer/application/payload/findings | Scapy, stdlib parsing |
| `core/explanations.py` | Beginner-facing protocol explanations | structured Decoder facts → conservative summary | stdlib |
| `core/analysis.py` | Unified packet analysis record | packet/metadata/optional AI → separated result | parser, Decoder |
| `core/investigation.py` | Retained packet summaries | records/cancel → flows, talkers, evidence, timeline | analysis |
| `ai/flow_tracker.py` | Bounded directional context | packet/metadata/time → context metrics | collections, time |
| `ai/feature_extractor.py` | Runtime 23-vector | packet/metadata/context → ordered floats | Scapy |
| `ai/model_loader.py` | Runtime model/schema loader | joblib + JSON → validated optional estimator | joblib, JSON |
| `ai/detector.py` | Runtime prediction semantics | vector → AI result | model loader |
| `gui/main_window.py` | Active GUI, workflows and workers | user input/results → widgets and queues | Tk, core, AI |
| `gui/presentation.py` | Pure view-model helpers | analysis data → groups/labels/metrics | core explanations only |
| `gui/settings_dialog.py` | Settings UI and persistence | preferences → normalized config | Tk, config |
| `utils/config.py` | Config defaults/normalization/I/O | `config.json` → validated settings | JSON, time |
| `utils/theme.py` / `constants.py` | Semantic theme tokens and compatibility aliases | theme → colors/fonts/widgets | Tk/ttk |
| `utils/validator.py` | Interface/protocol/IP/port/path checks | user input → boolean validation | ipaddress, interfaces |
| `utils/logger.py` | File logging | messages → `logs/sniffer.log` | logging, os |
| `training/unsw_flow_schema.py` | Fixed UNSW schema constants | schema definitions | stdlib |
| `training/prepare_unsw.py` | Validate/read official split | CSVs → path-backed iterator | csv, pathlib |
| `training/unsw_model_pipeline.py` | Unfitted UNSW sklearn pipelines | schema/target → pipeline + metadata | NumPy, sklearn |
| `training/train_unsw_flow.py` | Train separate UNSW model | CSV split → pipeline + metadata files | sklearn, NumPy, joblib |
| `training/evaluate_unsw_flow.py` | Held-out evaluation | artifact + CSVs → metrics/report | sklearn, joblib, research helpers |
| `training/audit_unsw_flow.py` | Internal training-set feature audit | explicit training CSV → variant metrics | sklearn, NumPy |
| `training/dataset_adapter.py`, `train.py`, `evaluate.py` | Legacy runtime-schema experiment helpers | 23-column feature CSV → classifier/report | sklearn, CSV, joblib |
| `training/research.py` | Shared research report/hash/importance helpers | arrays/pipeline/report → summaries | sklearn-adjacent, hashlib |
| `benchmarks/benchmark_pipeline.py` | Offline synthetic timing harness | scales → stage timings/allocation peak | Scapy, stdlib, core/AI |

The GUI support modules `gui/toolbar.py`, `menu.py`, `packet_table.py`, `details_panel.py`, `statistics_panel.py`, `statusbar.py`, and `dialogs.py`, plus `core/capture_engine.py`, are present but unused by internal imports in the current app. They are not part of its active architecture.

## Project tree

```text
.
├── main.py                         Tkinter entry point
├── README.md                       Short project entry point
├── requirements.txt                Runtime/research Python packages
├── config.json                     Local UI/capture settings (user data)
├── .github/workflows/tests.yml     Ubuntu/Python 3.11 compile + unittest CI
├── ai/
│   ├── detector.py                 Runtime output semantics
│   ├── feature_extractor.py        Versioned 23-feature vector
│   ├── flow_tracker.py             Bounded directional history
│   ├── model_loader.py             Optional local model compatibility checks
│   └── model/                      Ignored local UNSW binary/metadata; no runtime model
├── benchmarks/benchmark_pipeline.py Synthetic offline stage benchmarks
├── core/
│   ├── sniffer.py, parser.py        Capture and metadata parsing
│   ├── packet_manager.py            Bounded storage and stable IDs
│   ├── pcap.py, worker_queue.py     Streaming I/O and worker backpressure
│   ├── analysis.py, investigation.py Unified records and retained summaries
│   ├── explanations.py              Beginner explanation layer
│   ├── decoder.py                   Public Decoder facade
│   └── decoders/                    DNS, TLS, HTTP, FTP, ICMP plugins/registry
├── gui/
│   ├── main_window.py               Active GUI and worker coordination
│   ├── presentation.py               Pure presentation/grouping models
│   ├── settings_dialog.py            Active preferences dialog
│   └── toolbar.py, menu.py, ...      Present but not actively imported helpers
├── training/
│   ├── unsw_flow_schema.py           Separate 42-predictor contract
│   ├── prepare_unsw.py               CSV validation / iteration
│   ├── unsw_model_pipeline.py         sklearn pipeline builders
│   ├── train/evaluate/audit_unsw_flow.py Offline UNSW operations
│   ├── dataset_adapter.py             Strict 23-feature CSV adapter
│   ├── train.py / evaluate.py         Legacy runtime schema training helpers
│   └── research.py / README.md        Reports, hashes and run notes
├── tests/                            134 stdlib unittest tests
├── docs/                             Architecture, AI, Decoder, workflows, etc.
├── utils/                            Config, validation, logging and themes
├── logs/, exports/, screenshots/     Runtime/user-output directories
└── assests/                          Present in source tree; not used by active GUI imports
```

Python caches, local model artifacts and other generated runtime files may be ignored by Git. The tree above annotates repository components, not every ignored file in a user's working copy.

## Current implementation vs possible future work

### Currently implemented

Passive Scapy live capture; interface selection; protocol capture filter; bounded packet retention; display filtering/search/sorting; packet details and PCAP export; streamed PCAP load with progress/cancel; packet-level DNS/HTTP/TLS/FTP/ICMP decoding; bounded ASCII/hex preview and small heuristic pattern set; optional 23-feature runtime model interface; bounded directional FlowTracker; five Tk workspaces and Decoder/Settings dialogs; retained-window bidirectional conversation and protocol evidence report; separate 42-feature UNSW training/evaluation/audit code; tests and synthetic benchmark.

### Future possibilities (not implemented)

TCP stream/session reconstruction; broader protocol coverage; TLS decryption with lawful key material; IOC extraction; configurable detection rules; alerting/case persistence; large-table virtualization; measured live-capture performance under diverse traffic; a packaged release; validated and calibrated runtime-model dataset/model; additional ML experiments that remain separate from runtime until semantically validated.

## Beginner and analyst workflows

The complete step-by-step live and PCAP workflows are in [user_guide.md](user_guide.md). The usual progression is:

```text
Launch → select interface or open PCAP → observe retained packets
  → select packet → Beginner explanation → Analyst decode
  → Technical fields/raw preview → Flows → Investigation evidence/timeline
```

For an analyst, review traffic/endpoints, group a retained conversation, inspect an evidence packet, compare AI output to Decoder heuristic evidence as separate sources, then follow packet IDs through related evidence and timeline. No workflow step converts a model label or heuristic pattern into confirmed maliciousness.

## Viva / interview notes

### 30-second explanation

“This is a Python/Tkinter desktop tool for passive packet capture and PCAP review. Scapy supplies packet capture and dissection; the app keeps a bounded packet window, provides packet-level protocol decoding, and builds conversation and protocol evidence summaries from retained packets. It can call an optional local model using 23 packet/context features, but no model is bundled and its labels are not confirmed threat verdicts. A separate UNSW-NB15 flow research pipeline is not part of live inference.”

### 2-minute explanation

“The Scapy capture callback puts packets on a bounded queue and drops rather than blocking when it is full. Tk drains packets, parses metadata, stores them under stable packet IDs, and submits them to the AI queue only if the local model is available. A worker updates the bounded directional FlowTracker, creates the ordered runtime feature vector, predicts, and returns a result by packet ID. Decoder work is on demand: a facade traverses Scapy fields and dispatches DNS, TLS, HTTP, FTP, or ICMP plugins; the GUI offers Beginner, Analyst and Technical/Raw views. The investigation worker reads the retained records and uses a unified analysis record to assemble bidirectional conversations, talkers, protocol evidence, findings, and timeline rows. AI and heuristic evidence remain separate. PCAP reading is streamed through bounded batches and a bounded I/O queue. The 42-predictor UNSW model is an offline research path with its own schema and artifact checks, not a source of runtime packet predictions.”

### 5-minute technical explanation

“The main app lives in `gui/main_window.py`. `core.sniffer.PacketSniffer` wraps `AsyncSniffer` with `store=False`. The callback only enqueues; the Tk event loop parses in bounded drain batches. `PacketManager` holds at most the configured 10,000 records by default, up to 20,000, and assigns monotonic IDs used for table identity and evidence navigation. Parser metadata captures timestamp, endpoints, protocol, ports and length; the Decoder is separate and runs when selected or during retained investigation.

“Runtime AI uses schema version 1.0 with exactly 23 floats. The single AI worker first updates `FlowTracker`, keyed by directed source/destination address+port+protocol. Flow and endpoint dictionaries are bounded to 10,000, state expires after 300 seconds on periodic sweeps, endpoint timestamps are capped at 6,000 and pruned by a 60-second window, and unique destinations/ports stop at 1,000. Feature names are ordered by the canonical tuple. `ModelLoader` checks metadata version and exact feature order, then deserializes trusted joblib and checks `predict` plus exposed feature count. Classifier confidence is max `predict_proba`; the risk score is a label-based formula, not a calibrated probability. A missing model means unavailable, not benign.

“The Decoder has a registry with DNS, TLS, HTTP, FTP and ICMP plugins and generic Scapy field traversal. Output is packet-level and bounded: it cannot reassemble TCP streams or decrypt TLS. Investigation runs `core.analysis.analyze_packet` over only retained records. It separates AI results from Decoder heuristic observations and produces navigation IDs. PCAP I/O is streamed in batches of 128 through an eight-item queue; the UI applies those batches and enforces the same retention cap.

“UNSW research is separate: a fixed 42-predictor schema, 39 numeric and 3 categorical, validation of official train/test CSVs, a pipeline that fits scaling and one-hot encoding on training rows, source hashes in metadata, and held-out evaluation that predicts without refitting. The repository does not bundle those CSVs or the model. Tests cover parsing, decoding, worker queues, PCAP, investigation, schema, pipeline safeguards and presentation models; they do not replace a live Npcap or interactive GUI test.”

### 10-minute architecture walkthrough

1. **Identity and scope:** passive desktop packet analysis, no active response functions.
2. **Entry/UI:** `main.py` starts Tk; active view and worker wiring is `PacketSnifferApp`.
3. **Live capture:** `AsyncSniffer` callback → nonblocking bounded queue → Tk parse/retain; drops under capture-queue pressure.
4. **Record identity:** PacketManager FIFO and ID index; retention settings bound the data an analyst can revisit.
5. **Runtime AI:** AI queue → directional FlowTracker → 23 ordered features → optional trusted local classifier → bounded result queue → Tk result mapping. Discuss unavailable semantics and uncalibrated confidence/risk.
6. **Decoder:** generic Scapy fields plus registry plugins; describe packet-level limits, preview/heuristic bounds, and three user modes.
7. **Unified analysis and investigation:** analysis record preserves metadata/Decoder/AI categories, investigation groups bidirectional conversations and evidence from retained packets, and timeline/navigation use IDs.
8. **PCAP/export:** PcapReader worker, 128-item batches, eight-item result queue, cancellation/backpressure/cleanup, PacketManager retention; export uses `wrpcap` worker.
9. **Research boundary:** 42-predictor UNSW flow pipeline is offline, train-only fit, hash-protected held-out evaluation and training-data audit. It cannot be swapped into live 23-feature inference.
10. **Reliability:** bounded state/queues and tests; explain artifact trust, worker overload, absent model, no TCP reassembly/TLS decrypt, retained-only reports, and platform capture dependencies.

### Common viva questions and verified answers

| Question | Answer grounded in source |
|---|---|
| Why Scapy? | It supplies packet capture (`AsyncSniffer`), packet/layer representation, PCAP reading and writing. |
| Why Tkinter? | The product is a local Python desktop UI built with standard-library Tk/ttk; it avoids a separate GUI runtime. |
| How does the AI work? | It updates bounded directional FlowTracker context, extracts 23 ordered numeric features and calls an optional local estimator from a worker. |
| Why FlowTracker? | Some runtime features need recent endpoint/flow context; state is bounded and expires. It does not reconstruct sessions. |
| Why 23 features? | It is the explicit current runtime schema used by feature extraction, loader metadata and the runtime CSV adapter; no code proves it is optimal. |
| Packet vs flow? | A packet is one captured unit. Runtime Tracker flows are directional 5-tuples; Investigation groups packets into canonical bidirectional endpoint conversations. |
| Why is UNSW separate? | It is a distinct 42-predictor flow schema with different semantics and offline evaluation; silently mapping it to packet features would be invalid. |
| Why a Decoder? | Parser metadata is lightweight; Decoder plugins expose protocol/application details and bounded payload inspection on demand. |
| How are malformed packets handled? | Parser operations catch common malformed values; Decoder plugins guard extraction; unified analysis marks malformed or unavailable results instead of requiring a verdict. |
| How is concurrency handled? | Bounded queues, Tk `after()` polling, worker threads for capture/AI/I/O/investigation/export, and shutdown events. Widgets are updated on Tk. |
| How is memory bounded? | Packet retention, queues, FlowTracker maps/history/sets, Decoder payload/field limits, DNS and HTTP limits. Packet object size and transient report size are not a total-RSS guarantee. |
| Is AI reliable? | Source only establishes outputs from a model if installed; this checkout has none, no runtime benchmark/calibration is bundled, and labels are not proof. |
| Why can't it decrypt TLS? | Decoder inspects packet bytes/records and visible ClientHello fields only; no keys, stream reconstruction or TLS decryptor exists. |
| How does PCAP investigation work? | Streamed batches are applied to the same PacketManager; after load, Investigation summarizes only records still retained. |
| What does a high risk score mean? | The implementation applies a formula to label and estimator confidence; it is not a calibrated probability or measured harm score. |

## Project claims audit and remaining concerns

- Documentation must call AI labels predictions/classifications, never guaranteed threat detection or confirmed malware. This wording is used here and in the entry-point README.
- Confidence is a classifier output from `predict_proba`, not documented as calibrated; risk score is a local formula.
- “Flows” are explicitly either directed AI context or bidirectional investigation conversations; neither is TCP stream reconstruction.
- Investigation is bounded by retained PacketManager records, not unlimited PCAP history.
- TLS means visible record/ClientHello inspection, not decryption.
- The ignored local UNSW binary hash matches the recorded manifest, but the source CSVs are absent and the binary was not loaded; metrics remain a recorded local report, not independently rerun evidence.
- `ModelLoader`'s feature-count fallback accepts a model without `n_features_in_`; schema metadata is the primary exact contract.
- Legacy `training/train.py` writes into the runtime artifact location and does not guard against overwriting it. Its input reader is less strict than `dataset_adapter.py`; it should be used only with reviewed local training data and trusted outputs.
- The `evaluate_unsw_flow.py` parser uses `UNSW_NB15_DIR` for its default training path but its default test path is currently hardcoded from `DEFAULT_DATASET_ROOT`; supply both paths when overriding the dataset directory.
- Full-window Investigation and GUI Treeviews may be slow on the maximum retained limit; the table does not virtualize rows.
- `core/capture_engine.py` and several `gui/*` modules are unused placeholders; package tree presence alone is not active feature evidence.

## Documentation map

| File | Purpose |
|---|---|
| [README.md](../README.md) | Concise entry point and links. |
| [architecture.md](architecture.md) | System/module diagrams, lifecycle and queue boundaries. |
| [ai_architecture.md](ai_architecture.md) | Exact AI features, FlowTracker and model behavior. |
| [decoder.md](decoder.md) | Plugins, modes, heuristic scope and limits. |
| [investigation.md](investigation.md) | PCAP and retained-window evidence behavior. |
| [user_guide.md](user_guide.md) | Beginner and analyst workflows/troubleshooting. |
| [performance.md](performance.md) | Benchmark methodology and recorded results. |
| [testing.md](testing.md) | Test environment and CI validation. |
| [training/README.md](../training/README.md) | UNSW/runtime CSV training command details and historical run manifest. |
