# Network Packet Sniffer

A desktop network packet sniffer built with Python, [Scapy](https://scapy.net/), and Tkinter. It captures live traffic on a chosen network interface, displays packets in a searchable, color-coded table, and shows per-packet details (Ethernet/IP/TCP/UDP/ICMP fields, ASCII payload, and hex dump) alongside live capture statistics.

## Features

- **Live capture** on any interface detected via `psutil`
- **Protocol filtering** — capture everything, or restrict to TCP / UDP / ICMP / ARP / DNS
- **Packet table** with time, source/destination IP, protocol, ports, and length, color-tagged by protocol
- **Packet detail view** — Ethernet, IP, TCP/UDP/ICMP headers, ASCII payload, and full hex dump
- **Search** across captured packets, cycling through matches on repeated use
- **Live statistics** — packet/TCP/UDP/ICMP counts
- **Export** captured packets to a `.pcap` file for later analysis (e.g. in Wireshark)
- **Pluggable AI threat detection** scaffold (`ai/detector.py`) for scoring packets with a trained model

## Project structure

```
Network-Packet-Sniffer/
├── main.py                 # Entry point — launches the Tkinter app
├── requirements.txt
├── core/
│   ├── sniffer.py           # Wraps scapy.AsyncSniffer (start/stop)
│   ├── parser.py            # Packet summary/length/protocol helpers
│   └── interfaces.py        # Lists available network interfaces (psutil)
├── gui/
│   └── main_window.py       # Tkinter UI: menu, toolbar, packet table, details, stats
├── ai/
│   └── detector.py          # ThreatDetector — scores packets with a joblib model
└── utils/
    ├── constants.py          # Window size and color palette
    ├── validator.py          # Interface/IP/port validation helpers
    └── logger.py             # File logging to logs/sniffer.log
```

## Requirements

- Python 3.9+
- Root/administrator privileges (raw packet capture requires elevated permissions)
- A supported packet-capture backend:
  - **Linux:** works out of the box with `scapy` in most cases
  - **Windows:** [Npcap](https://npcap.com/) must be installed
  - **macOS:** works out of the box, but run with `sudo`

## Installation

```bash
git clone https://github.com/Rajavarman-GR/Network-Packet-Sniffer.git
cd Network-Packet-Sniffer
pip install -r requirements.txt
```

## Usage

```bash
# Linux / macOS
sudo python3 main.py

# Windows (run terminal as Administrator)
python main.py
```

1. Select a network **interface** from the dropdown.
2. Optionally choose a **protocol filter** (default: ALL).
3. Click **▶ Start** to begin capturing, **■ Stop** to stop.
4. Click any row in the packet table to see full packet details on the right.
5. Use **Search** to jump to matching rows; click **Find** again to cycle to the next match.
6. Click **Export** (or File → Export) to save the current capture as a `.pcap` file.

## AI threat detection (optional)

`ai/detector.py` defines a `ThreatDetector` class that loads a model from `ai/threat_model.pkl` and scores each packet on `[length, sub-second timestamp]` features. This is a scaffold, not a shipped feature — the app runs and captures normally without a model. To enable it:

1. Train and save a binary classifier to `ai/threat_model.pkl` with `joblib.dump(...)`.
2. Instantiate `ThreatDetector()` in `PacketSnifferApp` and call `.detect(packet)` inside `packet_callback`, updating the "Threats" counter for any packet it flags.

## Known limitations

- The bundled `ThreatDetector` has no trained model and is not currently wired into the capture pipeline — the "Threats" stat stays at 0 until both are done.
- The "Bandwidth" stat is currently static and not computed from live throughput.
- The `Settings` toolbar button has no behavior yet.
- Interface names from `psutil` may not exactly match what Scapy/Npcap expects on Windows; Linux/macOS interface names generally work as-is.

## License

No license file is currently included in this repository.
