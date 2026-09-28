# Verified System Architecture

This document describes the checked-in implementation. It distinguishes packet capture, on-demand analysis, the live runtime classifier, and the separate offline UNSW research pipeline.

## High-level system

```text
                    LIVE / OFFLINE PACKETS
              ┌──────────────┴──────────────┐
              │                             │
    Scapy AsyncSniffer                 Scapy PcapReader
    capture callback                  background reader
              │                             │
       bounded queue              batches of at most 128
              │                             │
              └──── Tk event loop / bounded I/O queue ────┐
                                                          │
                                                  Parser metadata
                                                          │
                                                  PacketManager
                                         bounded retained packet records
                                           │              │
                                    packet table     AI input queue
                                                          │
                                                   AI worker thread
                                        FlowTracker → FeatureExtractor
                                          → ThreatDetector/model
                                                          │
                                                  AI result queue
                                                          │
                                               Tk update by packet ID

       On demand: selected packet → Decoder facade → registry → plugins
                                      │                    │
                                      └→ fields/payload   └→ heuristics
                                                │
                                   Investigation worker (retained records)
                             analysis → conversations / protocol evidence / timeline
                                                │
                                 Overview / Flows / Investigation / Statistics

       Separate offline research: UNSW CSV → schema validation → sklearn pipeline
                  → joblib artifact + metadata → held-out evaluation / audit
                  (not loaded by the live packet detector)
```

The application is a passive desktop analyzer. The GUI is implemented in Tkinter/ttk. Scapy handles packet objects, packet dissection, capture, and PCAP I/O. `psutil` enumerates interface names. The live model is optional and local. UNSW training and evaluation are offline command-line tools.

## Internal module architecture

```text
main.py
└── gui.main_window.PacketSnifferApp
    ├── core.sniffer.PacketSniffer ─────────────── Scapy AsyncSniffer
    ├── core.parser ───────────────────────────── metadata / search / previews
    ├── core.packet_manager.PacketManager ─────── retention / stable IDs
    ├── ai.FlowTracker → ai.feature_extractor → ai.detector → ai.model_loader
    ├── core.decoder ─→ core.decoders.registry ── DNS / TLS / HTTP / FTP / ICMP
    ├── core.analysis ─→ core.investigation ──── retained-window reports
    ├── core.pcap ─────────────────────────────── streamed PCAP batches
    ├── gui.presentation ──────────────────────── pure display/grouping models
    ├── gui.settings_dialog ─→ utils.config
    └── utils.theme / constants / validator / logger

training/* ─→ UNSW schemas + NumPy + scikit-learn + joblib
benchmarks/* ─→ synthetic Scapy packets and runtime stages (offline only)
tests/* ────── unittest; synthetic packets/files and isolated fixtures
```

Responsibilities:

| Boundary | Responsibility |
|---|---|
| Capture (`core/sniffer.py`) | Starts/stops `AsyncSniffer`; passes a callback and BPF expression; does not retain packets. |
| Parser (`core/parser.py`) | Extracts lightweight table metadata, timestamps, ports, search text and a bounded text/hex preview. |
| Retention (`core/packet_manager.py`) | FIFO bounded packet records, monotonic IDs, and ID lookup. It owns packet references used by navigation. |
| Runtime AI (`ai/`) | Maintains bounded directed traffic context, creates the ordered 23-value vector, and calls the optional local classifier. |
| Decoder (`core/decoder.py`, `core/decoders/`) | On-demand packet-level field, application, payload, and heuristic inspection. It does not reassemble streams. |
| Unified analysis (`core/analysis.py`) | Assembles parser metadata, Decoder output, and a supplied AI result into a structured record. It does not run the AI model. |
| Investigation (`core/investigation.py`) | Analyzes the retained record list into conversations, talkers, DNS/HTTP/TLS evidence, findings, and timeline events. |
| GUI (`gui/main_window.py`) | Owns widgets, UI-thread record updates, background workers, result polling, navigation, and export. |
| Presentation (`gui/presentation.py`) | Pure display grouping, empty-state, dashboard and Decoder view models; no Tk widgets or packet parsing. |
| UNSW research (`training/`) | Validates a distinct flow schema, trains/evaluates separate offline artifacts, and audits a training-only internal split. |

## Live packet flow

```text
Scapy capture callback
  → bounded packet queue (1,000)
  → Tk `after()` drain (up to 200 packets per drain)
  → parser metadata
  → PacketManager retention and packet-table row
  → bounded AI input queue (1,000), if a model is available
  → AI worker: FlowTracker → 23 features → ThreatDetector
  → bounded AI result queue (1,000)
  → Tk poll maps result to retained record by packet ID
```

Capture-time callback behavior is intentionally small: it attempts a nonblocking enqueue and counts/logs a drop if the queue is full. It does not parse, decode or wait for the GUI. Parser and PacketManager work happen on the Tk thread in batches. AI feature extraction and prediction happen on a dedicated worker. Model output returns through another bounded queue and is applied on the Tk thread. If the model is missing, the AI worker is not started and records are marked unavailable. If the AI input or result queue fills, an AI result can be skipped; overload can leave a row pending or unavailable rather than blocking capture.

Decoder work is on demand: selecting a packet opens the packet detail view; the Decoder dialog decodes the selected packet independently. Unified analysis is invoked by investigation, not as an obligatory synchronous stage for every capture packet. Investigation runs in its own worker over the retained records. It may observe AI results that are present while it runs; records are shallow-copied as a list, so AI results completing concurrently can make a run's AI evidence timing-dependent. Re-run analysis for a refreshed report.

## PCAP flow

```text
Open PCAP action / Ctrl+O
  → I/O worker: context-managed Scapy PcapReader
  → batches of at most 128 packets (cancellation checked between packets)
  → bounded eight-item I/O result queue (backpressure to reader)
  → Tk event loop consumes each batch
  → parser → PacketManager → AI queue (if available)
  → final packet table refresh
  → automatic retained-window investigation
```

PCAP parsing runs off the UI thread. Batch insertion, metadata parsing, retention, and widget interaction occur on the Tk thread. The open descriptor is also enclosed outside the Scapy reader constructor so an invalid header closes the file on Windows even if Scapy raises before entering its own context manager. Cancellation stops reading at the next packet boundary; already processed packets remain. A read error is reported and prior batches remain in the application. Retention caps records; the total loaded count may exceed records available for investigation/navigation.

## Investigation workflow

```text
PacketManager.records() (bounded retained window)
  → Investigation worker / InvestigationEngine
  → analyze_packet per record
      ├── parser metadata
      ├── Decoder result and Decoder heuristics
      └── AI result already attached to record, or unavailable
  → directed packet pairs canonicalized into bidirectional conversations
  → DNS / HTTP / TLS evidence + talkers + findings + sorted timeline
  → Tk views keyed by stable packet IDs
```

Conversation IDs are assembled from canonical `(address, port)` endpoint pairs plus protocol. Each conversation includes packet IDs for navigation; this is not a TCP stream. Timeline order is timestamp, numeric packet ID where available, event type, and description. Cancellation is checked between input records. The analysis records, evidence, and timeline are temporary in-memory output and are not persisted as cases.

## Decoder pipeline

```text
Selected Scapy packet
  → core.decoder.decode_packet
  → generic Scapy layer/field traversal
  → raw-payload preview (256-byte default)
  → registry matching by plugin priority
      DNS → TLS → HTTP → FTP → ICMP/ICMPv6
  → structured application output + separate heuristic findings
  → Beginner explanation / Analyst application / Technical layer and raw views
```

The generic field renderer limits field text to 200 characters. The Decoder payload preview defaults to 256 bytes. Heuristic inspection is capped at 65,536 bytes. The GUI's application payload display is derived from this structured output. There is no TCP stream reassembly and no TLS decryption.

## Runtime AI data flow

```text
Packet record
  → AI queue
  → FlowTracker.observe(packet, metadata, packet.time)
  → extract_features(packet, metadata, context)
  → 23 floats ordered by FEATURE_NAMES
  → ThreatDetector
      → ModelLoader checks JSON schema metadata
      → trusted joblib model predict / predict_proba
  → {available, label, confidence, risk_score, model_version}
  → AI result queue
  → Tk updates retained record and packet row by packet ID
```

The local runtime classifier is separate from the UNSW research model. Exact feature semantics, state bounds, compatibility checks, and interpretation limits are in [AI architecture](ai_architecture.md).

## Offline UNSW research flow

```text
Local official UNSW-NB15 training/testing CSVs
  → exact header, row, label, type and schema validation
  → preserve official split; exclude id and non-target label columns
  → fit StandardScaler + OneHotEncoder(handle_unknown="ignore") + RandomForest
       on training rows only
  → separate joblib Pipeline + metadata JSON (source SHA-256, counts, versions)
  → evaluation checks metadata, source names/hashes/counts and predicts test rows
       without fitting/refitting
  → JSON/text metrics and feature report

Separate audit: one explicit training CSV → stratified 80/20 internal split
  → four feature-set variants → metrics/importances; no artifact or official test use
```

The UNSW schema has 42 predictors (39 numeric, 3 categorical); it is not semantically or structurally interchangeable with the runtime packet/context 23-feature schema. This local workspace has an ignored, untracked UNSW binary and metadata, but no UNSW artifacts are checked into Git. See [UNSW research](master_project.md#runtime-model-vs-unsw-research-model).

## GUI workspaces

The root window contains a menu, capture toolbar, main notebook, and status label. The notebook pages are **Overview**, **Packets**, **Flows**, **Investigation**, and **Statistics**. Flows displays conversation results from investigation; it does not continuously render `FlowTracker` state. The Decoder and Settings are dialogs. Help offers a Getting Started message and About dialog. Settings persist `config.json` at the repository root.

Theme colors, text, spacing, font and control tokens are centralized in `utils/theme.py`; `utils/constants.py` retains legacy dark-theme aliases. `apply_tk_theme` applies ttk styles and classic Tk widget colors. Status labels distinguish capture/loading/analyzing/completed/error operations. The GUI uses `gui/presentation.py` for testable display models, but the main application class constructs the Tk widgets directly.

## Bounded state and shutdown

| State | Bound/default |
|---|---:|
| Retained packet records | 10,000 default; configuration maximum 20,000 |
| Capture packet queue | 1,000; full queue drops packet |
| AI input queue | 1,000; full queue skips AI input |
| AI result queue | 1,000; full queue drops result |
| I/O result queue | 8; timed producer backpressure |
| PCAP batch | 128 packets |
| Runtime directed flows/endpoints | 10,000 each by default |
| FlowTracker endpoint timestamps | 6,000 per endpoint |
| FlowTracker unique destinations/ports | 1,000 per endpoint |
| Decoder preview / heuristic scan | 256 / 65,536 bytes |
| DNS question/answer rendering | at most 64 records each |
| HTTP header/body inspection | 16,384 / 256 bytes |

Shutdown signals capture/AI/PCAP/investigation work, cancels Tk callbacks, and briefly joins worker threads. Queue producers poll shutdown between timed puts. An in-progress filesystem read or model call is not forcibly interrupted; joins are bounded so the window does not wait indefinitely.

## Repository support files

`core/capture_engine.py` and `gui/details_panel.py`, `dialogs.py`, `menu.py`, `packet_table.py`, `statistics_panel.py`, `statusbar.py`, and `toolbar.py` are present but not imported by the current application. Their presence does not imply that the active GUI uses those abstractions. The active implementation is primarily `gui/main_window.py` plus `gui/settings_dialog.py` and `gui/presentation.py`.
