# Network Packet Sniffer

**Passive Packet Analysis and Investigation Workbench** — a Python desktop application for authorized live packet capture and PCAP review. It combines bounded packet retention, packet-level protocol decoding, optional local AI predictions, and retained-window traffic investigation.

This is an educational and defensive analysis tool, not a production IDS/IPS or SOC platform. AI labels and Decoder heuristics are observations, not confirmed maliciousness. Use only on traffic you own or are authorized to inspect.

## Capabilities

- Live Scapy capture and streamed PCAP loading, with progress and cancellation.
- Searchable packet table, bounded details, PCAP export, and stable packet navigation.
- Tkinter workspaces: Overview, Packets, Flows, Investigation, and Statistics.
- Packet-level Decoder plugins for DNS, HTTP, TLS record/ClientHello, FTP, ICMP, and ICMPv6; Beginner, Analyst, and Technical / Raw views.
- Optional local packet/context classifier using a distinct 23-feature runtime schema; no runtime model is included.
- Bounded retained-window conversations, DNS/HTTP/TLS evidence, separated AI and heuristic findings, talkers, and timeline.
- Separate offline UNSW-NB15 flow training/evaluation tools (42 predictors); they are not used by live inference.

There is no TCP stream reassembly, session reconstruction, or TLS decryption. Investigation covers only retained packets (10,000 by default; maximum 20,000).

## Install and run

Requires Python 3.11+, Tkinter, and packages in `requirements.txt`. Live capture may require Npcap on Windows, libpcap on Linux/macOS, and operating-system capture privileges.

```bash
python -m pip install -r requirements.txt
python main.py
```

Choose an interface and click **Start**, or open a saved capture with **Open PCAP** / Ctrl+O. Select a packet and open **Decode Packet** to start in Beginner mode. F5 starts capture; Ctrl+S exports the current visible packet view.

## Documentation

- [Master project audit](docs/master_project.md) — verified identity, technology, architecture, AI/research separation, test results, limitations, roadmap, and viva notes.
- [System architecture](docs/architecture.md) — module boundaries, packet/PCAP/AI/Decoder/investigation flows, and resource limits.
- [Runtime AI and FlowTracker](docs/ai_architecture.md) — all 23 features, model loading, prediction semantics, and UNSW comparison.
- [Decoder](docs/decoder.md) — plugins, modes, heuristic coverage, and boundaries.
- [User guide](docs/user_guide.md) — beginner, PCAP, and analyst workflows.
- [Investigation](docs/investigation.md) — retained data scope and evidence model.
- [Performance](docs/performance.md) and [testing](docs/testing.md).
- [UNSW training documentation](training/README.md).

## Development checks

```bash
python -m compileall -q .
python -m unittest discover -v
git diff --check
```

CI runs compile and unittest discovery on Ubuntu/Python 3.11. Synthetic benchmark details and recorded results are in [docs/performance.md](docs/performance.md).
