# Network Packet Sniffer

A local Python desktop application for capturing, inspecting, filtering, and exporting network packets with Scapy and Tkinter. It is an educational analyzer, not an IDS or a replacement for Wireshark.

## Features

- Live capture through Scapy `AsyncSniffer`.
- Tkinter-safe packet delivery through a queue and the main event loop.
- Protocol filters for `ALL`, TCP, UDP, ICMP, ICMPv6, ARP, and DNS.
- DNS filtering for both UDP/53 and TCP/53.
- Stable packet selection while sorting, searching, and evicting old rows.
- Bounded packet retention with configurable `max_packets`.
- Visible count of packets dropped when the capture queue is full.
- Separate capture and display filters, with searchable source, destination, protocol, port, timestamp, and MAC fields.
- Bounded printable/binary payload previews with hexadecimal output.
- IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6 Echo, and DNS metadata parsing.
- PCAP import and export through Scapy.
- Configurable theme, interface, protocol, timestamp format, and auto-scroll.
- Optional threat-detector integration when a compatible local model exists.
- Optional structured AI inference with deterministic packet and flow features.

## Architecture

Scapy capture callbacks enqueue packets only. Tkinter periodically drains the queue on the GUI thread, parses metadata, updates statistics, and inserts rows into the Treeview. `core/packet_manager.py` owns monotonic IDs and FIFO retention; the GUI uses those IDs as Treeview item identifiers. When a trusted AI model is available, packet records are sent to a separate bounded AI worker queue; results return through Tk's event loop and never block capture or widget updates.

## Installation

Use Python 3.9 or newer, then install the local dependencies:

```bash
python -m pip install -r requirements.txt
```

Tkinter must also be installed. Most Windows Python installations include it; on Debian/Ubuntu install the `python3-tk` package.

## Capture requirements

Capture only traffic on networks you own or are authorized to monitor.

- **Windows:** install Npcap and run PowerShell or Command Prompt with Administrator privileges. Scapy interface names can differ from readable Windows adapter names; the application resolves known mappings where possible.
- **Linux:** install libpcap and run with the required privileges, for example `sudo python3 main.py`.
- **macOS:** install libpcap permissions as required by the system and run with appropriate privileges.

Start the application with:

```bash
python main.py
```

## Filters and PCAP files

The **capture filter** selector supports `ALL`, TCP, UDP, ICMP, ICMPv6, ARP, and DNS. It controls the BPF expression sent to Scapy. The **display filter** selector supports those protocols plus `Other`; the search box filters retained rows by source/destination address, protocol, ports, timestamp, and MAC address without deleting packets. Source IP, destination IP, and port values are validated before they are included in the BPF expression.

Imported PCAP packets use the same parser and retention limit as live packets, but they do not contribute to live bandwidth measurements. Export runs in a background worker and writes the packets currently visible under the display filter. Status text reports loading, export, and displayed counts.

The statistics panel distinguishes cumulative `Captured` packets from currently retained `Displayed` packets and reports TCP, UDP, DNS, ARP, ICMP, ICMPv6, Other, Dropped, and Threats counts.

Packet details preserve full addresses and packet objects while showing bounded payload previews. Printable payloads are shown as text; binary payloads are shown as hexadecimal, with previews limited to 4096 bytes.

## Configuration

Settings are stored in `config.json` in the project directory. The file is ignored by Git. Missing, malformed, or invalid values fall back to safe defaults:

```json
{
  "theme": "dark",
  "max_packets": 10000,
  "default_interface": "",
  "default_protocol": "ALL",
  "auto_scroll": true,
  "timestamp_format": "%H:%M:%S"
}
```

## AI analysis

The runtime uses the deterministic feature schema in `ai/feature_extractor.py` and bounded behavioral context from `ai/flow_tracker.py`. Features include packet/protocol fields, ports, TCP flags, payload size, TTL/hop limit, endpoint rates and counts, unique destinations/ports, connection frequency, and DNS activity.

The application loads only `ai/model/threat_model.joblib` together with matching `ai/model/metadata.json`. Metadata must declare the exact feature schema and version. No model is included in this repository, so the normal status is **AI: unavailable** and predictions are not fabricated. A missing or incompatible artifact leaves the capture application functional.

To train and evaluate a local model, provide a documented CSV with the exact feature columns and a `label` column:

```bash
python training/train.py path/to/dataset.csv
python training/evaluate.py path/to/test.csv
```

The training pipeline does not download data or commit datasets. See [training/README.md](training/README.md). Joblib artifacts are executable serialized objects; use only trusted local models and review their provenance. The application is not an IDS or IPS, and no accuracy claim is made without a documented test set.

## Testing

Run the local test suite with:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python -m compileall .
```

The repository tests cover protocol metadata, packet timestamps, filters, retention IDs, and malformed configuration handling. Live capture and Tkinter interactions require a suitable desktop and capture environment and are not covered by automated GUI tests.

Useful shortcuts include `Enter` to apply the display search, `Escape` to clear search or close Settings, `Ctrl+O` to open a PCAP, `Ctrl+S` to export the current display view, and `F5` to start capture.

## Known limitations and security

- Live capture requires operating-system permissions and a functioning Npcap/libpcap installation.
- PCAP file I/O runs in background workers, but very large captures still require memory and time to decode and render retained rows.
- The application displays packet payloads and should not be used to expose sensitive captures to unauthorized users.
- The optional model has no security or accuracy guarantee and should not be used for automated incident decisions.
- No session reconstruction, packet replay, or protocol dissection beyond the displayed metadata is provided.

This project is for authorized educational and diagnostic use only.
