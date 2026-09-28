# Network Packet Sniffer

A Python desktop application for passive packet capture and investigation. It uses Scapy for packet capture and packet-level dissection, Tkinter for the analyst interface, and an optional local model for packet-level predictions.

Use it only on traffic you own or are authorized to inspect. It is an educational and defensive analysis tool, not an IDS/IPS or a production SOC platform.

## Capabilities

- Live capture with interface selection and TCP, UDP, DNS, ARP, ICMP, and ICMPv6 capture filters.
- Packet metadata parsing, display filtering, search, bounded details, and PCAP export.
- Packet-level Decoder plugins for DNS, HTTP, TLS record/ClientHello, FTP, ICMP, and ICMPv6.
- Optional local AI classification using the separate 23-feature runtime schema.
- Streamed PCAP loading with bounded batches, progress, and cancellation.
- Bounded retained-packet investigation: bidirectional conversations, top talkers, DNS/HTTP/TLS evidence, findings, and a timeline.
- Separate UNSW-NB15 42-predictor flow-model training, evaluation, and audit tools.

Heuristic findings are observations, not confirmed malicious activity. AI labels and confidence values are model outputs, not certainty.

## Architecture

```text
Live capture                         Offline research
Scapy AsyncSniffer                   UNSW-NB15 CSV splits
       |                                      |
Bounded capture queue              Schema/source validation
       |                                      |
Parser -> PacketManager             42-predictor flow pipeline
       |                                      |
       +-> FlowTracker -> FeatureExtractor    Train / evaluate / audit
       |                    |                 (never loaded by live AI)
       |               ThreatDetector
       |                    |
Packet -> Decoder facade -> registry/plugins
                 |                    |
                 +-> Unified analysis <-+  (AI result stays distinct from
                              |            Decoder heuristic findings)
                      Investigation engine
                              |
                    Tkinter analyst views
           Overview / Packets / Flows / Investigation / Statistics

PCAP reader -> bounded batches -> same packet manager and analysis path
```

The parser provides lightweight metadata. The Decoder handles packet-level protocol dissection. Runtime AI tracks traffic context and predicts independently. Unified analysis and investigation coordinate those outputs; they do not replace their implementations. Tkinter widgets are updated on the UI thread from worker results.

The primary workspaces are **Overview**, **Packets**, **Flows**, **Investigation**, and **Statistics**. Overview summarizes retained traffic and clearly marks investigation-only measures unavailable until analysis has run. Investigation groups DNS, HTTP, TLS, AI findings, heuristic security findings, and a chronological timeline; double-click an evidence row to return to its packet. Flows are bidirectional conversations, not TCP stream reconstructions. Statistics describe captured counts and, when available, the retained investigation window.

See [architecture](docs/architecture.md) for module responsibilities and worker lifecycles.

## Decoder and AI boundaries

`core/decoder.py` is the stable Decoder facade. It uses a registry and independent protocol plugins in `core/decoders/`. The current plugins handle DNS, HTTP, TLS records and ClientHello/SNI, FTP, ICMP, and ICMPv6. Layer fields and payload previews are bounded.

Decoder behavior is packet-level: **there is no TCP stream reassembly and no TLS decryption**. A TLS application-data record remains encrypted data.

The runtime detector consumes the existing 23-feature schema in `ai/feature_extractor.py`. `FlowTracker` supplies bounded context; `ThreatDetector` keeps its existing label, confidence, and risk-score behavior. If a compatible local model is unavailable, AI is shown as unavailable. The repository does not include a production-trained packet model.

## PCAP and investigation workflow

Open a PCAP from **File → Open PCAP**, the top-bar **Open PCAP** button, or press **Ctrl+O**. A worker reads bounded packet batches; a bounded queue applies backpressure. Loading progress and cancellation are available in the top bar and Investigation view. Packets use the same parser and retention limit as live capture.

After a PCAP load, the retained packets are analyzed in a worker. For live capture, choose **Analyze retained packets** in the Investigation view when you want a current summary. The Flows view groups packets into explicitly bidirectional conversations; it does not reconstruct TCP streams. Double-click flow or evidence rows to navigate to a retained packet. If a display filter hides that packet, navigation clears the filter first.

Investigation reports only packets still retained by `PacketManager`, which is bounded by the **Max Packets** setting (default 10,000; maximum 20,000). Older packets in a larger PCAP are not available for investigation navigation after eviction. Protocol evidence is sourced from the Decoder; AI findings and Decoder heuristics remain labeled separately.

For details, see [investigation](docs/investigation.md).

## Installation and use

Use Python 3.11 or newer and install the packages declared in `requirements.txt`:

```bash
python -m pip install -r requirements.txt
python main.py
```

Tkinter must be available in the Python installation. Live capture may require Npcap on Windows, libpcap on Linux/macOS, and operating-system privileges.

Typical workflow:

1. Select an interface and capture protocol, then click **Start**.
2. Search or filter the retained packets in the Packets view.
3. Select a packet to read details; use **Decode Packet** for protocol fields and heuristic findings.
4. Open Flows or Investigation and double-click evidence to return to its packet.
5. Use Statistics for retained-packet summaries. Export writes the currently visible packet view.

### Getting Started for Beginners

1. Start the application and select a network interface.
2. Click **Start** to capture, or choose **File → Open PCAP** to inspect a saved capture.
3. Select a packet in the Packets view. Source and destination identify endpoints; port numbers commonly identify a service.
4. Open **Decode Packet** and begin with **Beginner**. Read what happened, the protocol stack, and the suggested next inspection.
5. Switch to **Analyst** for decoded application data and heuristic indicators, or **Technical / Raw** for Scapy fields and bounded payload bytes.
6. Use Flows to group related packets into conversations and Investigation to follow evidence back to packets.

The Decoder's explanations summarize observed packet structure. They do not establish that traffic is malicious. Heuristic findings and AI classifications remain identified by their source.

### Decoder modes

The Decoder dialog opens on a concise Beginner summary. Analyst opens decoded application details and payload previews. Technical / Raw opens the complete Scapy layer and field tree; the application details and Payload / Raw tab show bounded ASCII and hex previews. Decoder output limits remain in force.

Dark and light themes use a shared semantic palette across the main workspaces, ttk tables and controls, Tk text areas, and application dialogs. Settings keeps the existing `theme` configuration values (`dark` and `light`).

Shortcuts: **F5** starts capture, **Ctrl+O** opens a PCAP, and **Ctrl+S** exports the current display view.

## UNSW-NB15 research tools

The UNSW flow model is a separate research pipeline with 42 declared predictors (39 numeric and 3 categorical). It does not share the runtime packet schema and is never loaded by the live detector. Training validates the official train/test CSV schemas and source hashes, fits preprocessing on training data only, and writes target-specific artifacts without overwriting existing artifacts. Evaluation checks metadata and source hashes and predicts on the independent test split without refitting. Audit tooling uses only an explicitly supplied training CSV and an internal stratified split.

```bash
python training/prepare_unsw.py --help
python training/train_unsw_flow.py --target label --train path/to/UNSW_NB15_training-set.csv --test path/to/UNSW_NB15_testing-set.csv
python training/evaluate_unsw_flow.py --artifact ai/model/unsw_flow/binary/unsw_flow_pipeline.joblib --train path/to/UNSW_NB15_training-set.csv --test path/to/UNSW_NB15_testing-set.csv
python training/evaluate_unsw_flow.py --help
python training/audit_unsw_flow.py --training-data path/to/UNSW_NB15_training-set.csv
```

Evaluation emits JSON by default; use `--format text` for a concise human-readable report. Serialized `joblib` files can execute code while loading: only evaluate artifacts from trusted sources. The official dataset is not downloaded or included. More detail is in [training/README.md](training/README.md).

## Tests and benchmarks

Run the complete suite and syntax check from the repository root:

```bash
python -m unittest discover -v
python -m compileall .
git diff --check
```

On Windows, Scapy may enumerate Npcap devices during import. The synthetic test suite does not need live interfaces; if local Npcap discovery blocks startup, use the offline Scapy setup described in [testing](docs/testing.md). CI runs the tests on Ubuntu/Python 3.11.

Run reproducible synthetic throughput checks with:

```bash
python -m benchmarks.benchmark_pipeline
```

The default scales are 1,000, 10,000, and 50,000 packets. The benchmark reports elapsed time and packets per second for parsing, decoding, unified analysis, runtime flow tracking, investigation, PCAP batch reading, and packet retention. Packet construction and PCAP writing are excluded from stage timings. See [performance](docs/performance.md) for methodology and recorded results.

## Limitations and safety

- Passive analysis only; no scanning, injection, blocking, or exploitation.
- Packet-level protocol decoding only; no TCP stream reassembly or TLS decryption.
- PCAP investigation covers only the configured retained packet window.
- The local model is optional and no production detection accuracy is claimed.
- Payloads and PCAPs may contain credentials or other sensitive information. Decoder findings are displayed in memory; do not share captures, exports, or screenshots without authorization.
- Only capture traffic in environments where you have permission.
