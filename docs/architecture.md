# Architecture and lifecycle

## Module boundaries

| Area | Owner | Responsibility |
|---|---|---|
| Capture | `core/sniffer.py` | Scapy `AsyncSniffer` start/stop and BPF capture filter. |
| Parser | `core/parser.py` | Lightweight timestamp, address, protocol, port, length, and bounded payload preview. |
| Retention | `core/packet_manager.py` | FIFO records, monotonic packet IDs, O(1) ID lookup, configured count limit. |
| Runtime AI | `ai/flow_tracker.py`, `ai/feature_extractor.py`, `ai/detector.py` | Bounded directional context, the unchanged 23-feature vector, and model prediction. |
| Decoder | `core/decoder.py`, `core/decoders/` | Packet-level layer, protocol, payload, and heuristic inspection through a facade and registry. |
| Unified analysis | `core/analysis.py` | Combines parser metadata, Decoder output, and supplied AI result without generating an AI verdict. |
| Investigation | `core/investigation.py` | Converts packet analysis into conversations, evidence, talkers, findings, and timeline events. |
| PCAP | `core/pcap.py` | Context-managed streaming reader and bounded batches with cancellation checks. |
| GUI | `gui/main_window.py` | User interaction, rendering, navigation, and worker/result coordination. |
| Research | `training/` | Separate UNSW flow schema, training, independent evaluation, and audit. |

The runtime AI `FlowTracker` groups directed tuples `(src, dst, sport, dport, protocol)`. The analyst investigation engine instead groups canonical endpoint pairs and labels them `bidirectional_conversation`. Neither performs TCP stream reconstruction.

The Decoder registry currently contains DNS, TLS, HTTP, FTP, and ICMP plugins (including ICMPv6). The facade remains the public entry point. It does not depend on Tkinter or AI. Decoder fields, payload previews, and security scans have explicit size limits.

## Packet identity and memory bounds

`PacketManager` assigns monotonically increasing IDs. Eviction removes the ID from its lookup index but does not reuse it, including after `clear()`. GUI selections and investigation records carry those IDs; they do not use sorted row positions as identity. The lookup dictionary stores references to the same records already held in the FIFO, not duplicate packet objects.

The default retained-packet count is 10,000 and the configuration hard limit is 20,000. Capture, AI-input, and AI-result queues each hold at most 1,000 entries; the shared PCAP/export/result queue holds at most 8 items. The capture callback never waits for GUI work: if its queue is full it drops and counts a packet. PCAP and result producers use timed bounded puts and stop when shutdown is requested.

Runtime flow state is bounded to 10,000 directed flows and 10,000 endpoints by default. Expiration sweeps run at most once per second; endpoint rolling history holds at most 6,000 packet timestamps. Under bursts beyond that timestamp cap, rate/count context is capped, so a runtime model trained on a different high-rate history policy may not have equivalent feature semantics.

Investigation consumes at most its configured number of records using a bounded deque. Its returned evidence and timeline are temporary result structures held by the GUI until replaced. A result generation token prevents an older investigation worker from updating a newer capture.

## Worker flow and shutdown

```text
Scapy callback -> bounded packet queue -> Tk `after()` drain -> PacketManager
                                      -> bounded AI queue -> AI worker
                                                           -> AI result queue
                                                           -> Tk result polling

PCAP worker -> bounded I/O result queue -> Tk polling -> packet batches
Investigation worker -> bounded I/O result queue -> Tk polling -> views
Export worker -> bounded I/O result queue -> Tk polling -> completion/error
```

Only the Tk thread mutates widgets and packet-manager state. On close, the application stops capture, signals AI/PCAP/investigation shutdown, cancels scheduled callbacks, and briefly joins workers. Queue producers check shutdown between timed puts, so a full result queue cannot trap a daemon worker indefinitely. A filesystem read or Scapy inference already in progress cannot be forcibly interrupted; joins are bounded so closing the window does not wait indefinitely.

## Research boundary

The live detector uses `ai/feature_extractor.py` (23 packet/context features). The UNSW-NB15 research model uses its own 42-predictor flow schema. Research scripts are not imported by the live capture path; evaluation validates sources and metadata and does not refit the saved pipeline.

## Unused placeholders

`core/capture_engine.py` and the empty GUI support modules (`details_panel.py`,
`dialogs.py`, `menu.py`, `packet_table.py`, `statistics_panel.py`, `statusbar.py`,
and `toolbar.py`) have no internal imports in the current application. They were
left in place because their possible use by external callers is unknown; no
functionality is implied by their presence.
