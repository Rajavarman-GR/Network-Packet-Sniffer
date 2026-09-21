# Network Packet Sniffer

A Python desktop network packet analyzer built with **Scapy** and **Tkinter** for live packet capture, inspection, filtering, PCAP analysis, and optional machine-learning-based traffic analysis.

The project is designed as an **educational and cybersecurity analysis tool**. It is not intended to replace Wireshark, an IDS/IPS, or a production SOC platform.

---

## ✨ Features

### 📡 Live Packet Capture

* Live capture using Scapy `AsyncSniffer`
* Windows/Npcap, Linux/libpcap, and macOS-compatible capture workflow
* Start / Stop / Restart capture
* Network interface selection
* Capture protocol filters:

  * ALL
  * TCP
  * UDP
  * DNS
  * ARP
  * ICMP
  * ICMPv6
* DNS capture filtering supports both:

  * UDP/53
  * TCP/53

### 🧵 Thread-Safe Capture Architecture

The application separates packet capture from Tkinter UI updates:

```text
Scapy AsyncSniffer
        │
        ▼
Capture Callback
        │
        ▼
Bounded Packet Queue
        │
        ▼
Tkinter Main Loop
        │
        ▼
Packet Parser
        │
        ▼
PacketManager
        │
        ▼
GUI / Statistics / AI
```

This prevents Scapy's capture thread from directly modifying Tkinter widgets.

The capture queue is bounded to prevent uncontrolled memory growth, and dropped packets are reported to the user.

---

## 📦 Packet Management

* Stable packet IDs
* FIFO packet retention
* Configurable maximum retained packets
* Safe packet eviction
* Correct packet selection after sorting/filtering
* Incremental Treeview updates
* Captured vs currently retained packet statistics

The application distinguishes between:

```text
Captured  = packets processed during the current capture
Displayed = packets currently retained in PacketManager
```

---

## 🔎 Filtering & Search

The application separates **capture filtering** from **display filtering**.

### Capture Filter

The capture filter determines what Scapy receives from the network.

Supported:

```text
ALL
TCP
UDP
DNS
ARP
ICMP
ICMPv6
```

### Display Filter

The display filter operates only on packets already retained by the application.

Supported:

```text
ALL
TCP
UDP
DNS
ARP
ICMP
ICMPv6
Other
```

Applying a display filter does **not** delete packets from the capture.

### Search

Search can match retained packets using:

* Source IP
* Destination IP
* Protocol
* Source port
* Destination port
* Timestamp
* MAC addresses

Example:

```text
DNS
192.168.1.10
443
TCP
```

The UI reports how many retained packets currently match the active display filter/search.

---

## 📊 Packet Statistics

The statistics panel provides:

```text
Captured
Displayed
TCP
UDP
DNS
ARP
ICMP
ICMPv6
Other
Dropped
Threats
Suspicious
High Risk
```

Statistics are reset for a new capture.

The dropped counter represents packets discarded because the capture queue reached its configured limit.

---

## 🔬 Packet Inspection

Selecting a packet displays structured packet information including:

### Ethernet

* Source MAC
* Destination MAC

### IPv4

* Source IP
* Destination IP
* TTL
* Protocol
* Length

### IPv6

* Source IPv6
* Destination IPv6
* Hop Limit
* Payload Length

### TCP

* Source port
* Destination port
* Flags
* Sequence number
* Acknowledgement number

### UDP

* Source port
* Destination port

### ICMP / ICMPv6

* Protocol information
* Echo message information where applicable

### Payload

Payload inspection uses bounded previews.

Printable payloads are shown as text.

Binary payloads are presented as hexadecimal.

Large payloads are truncated to prevent the UI from being overwhelmed.

---

## 🗂 PCAP Support

### Import

Open an existing PCAP file and inspect it using the same packet parser and retention system used by live capture.

PCAP loading is performed in a background worker to avoid unnecessary GUI blocking.

### Export

Export retained packets to PCAP.

Exports use the **currently visible display-filtered view**.

The UI reports:

* loading state
* export state
* number of displayed/exported packets
* errors

---

## ⚙️ Settings

Configurable settings include:

* Theme
* Default network interface
* Default capture protocol
* Maximum retained packets
* Auto-scroll
* Timestamp format

Configuration is stored in:

```text
config.json
```

The file is ignored by Git.

Invalid settings are validated before being applied.

---

# 🤖 Optional AI Threat Analysis

The application includes an **optional machine-learning pipeline** for network traffic analysis.

AI is intentionally separated from packet capture so that inference does not block the capture/UI path.

### AI Architecture

```text
Captured Packet
      │
      ▼
Packet Parser
      │
      ▼
FlowTracker
      │
      ▼
Feature Extractor
      │
      ▼
AI Worker Queue
      │
      ▼
Validated ML Model
      │
      ▼
Prediction Result
      │
      ▼
Tkinter Result Handler
      │
      ▼
Packet + Statistics + Details
```

When a trusted compatible model is unavailable, the application continues normally and reports:

```text
AI: Unavailable
```

No predictions are fabricated.

---

## 🧠 Runtime Feature Schema

The runtime feature extractor currently uses a deterministic **23-feature schema**.

Features include:

* Packet length
* TCP indicator
* UDP indicator
* DNS indicator
* ARP indicator
* ICMP indicator
* ICMPv6 indicator
* Other-protocol indicator
* Source port
* Destination port
* TCP flags
* Payload length
* IPv4 TTL / IPv6 Hop Limit
* Source packet count
* Destination packet count
* Source byte count
* Destination byte count
* Packet rate
* Byte rate
* Unique destination count
* Unique destination-port count
* Connection frequency
* DNS activity

The same schema is intended to be used during both training and runtime inference.

---

## 🔄 Flow-Based Context

`ai/flow_tracker.py` maintains bounded behavioral context for network flows.

A flow is based on:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

The tracker derives contextual information such as:

* packet counts
* byte counts
* packet rates
* byte rates
* unique destinations
* unique destination ports
* connection frequency

Flow history is bounded and expires over time to avoid uncontrolled memory growth.

---

# 🧠 AI Model Loading

The runtime expects trusted local model artifacts:

```text
ai/
└── model/
    ├── threat_model.joblib
    └── metadata.json
```

Before inference, the application validates:

* model availability
* model prediction interface
* feature schema version
* exact feature names
* feature count
* model metadata

An incompatible or missing model causes AI to remain unavailable while the packet sniffer continues to operate normally.

---

## 🎯 AI Prediction Output

The detector provides structured results:

```text
Label
Confidence
Risk Score
Model Version
Availability
```

Example:

```text
Prediction: SUSPICIOUS
Confidence: 0.91
Risk Score: 73
Model: network-packet-random-forest 1.0
```

The application does not currently claim production-grade threat-detection accuracy.

---

# 🏋️ Offline Model Training

Training is intentionally separate from the desktop application.

```text
training/
├── README.md
├── train.py
├── evaluate.py
└── __init__.py
```

### Training workflow

```text
Dataset
   │
   ▼
Feature-compatible CSV
   │
   ▼
Training pipeline
   │
   ▼
Preprocessing
   │
   ▼
Random Forest Classifier
   │
   ├── threat_model.joblib
   └── metadata.json
```

### Train

```bash
python training/train.py path/to/dataset.csv
```

### Evaluate

```bash
python training/evaluate.py path/to/test.csv
```

The training dataset must contain all runtime feature columns plus:

```text
label
```

Do not train a model using feature definitions that differ from the runtime feature schema.

---

## ⚠️ Current AI Limitation

This repository currently **does not include a production-trained threat model or dataset**.

The AI pipeline has been implemented and tested using temporary/test models, but no real-world detection accuracy is claimed.

Before deploying a model, use a documented dataset and evaluate it using appropriate metrics such as:

* Precision
* Recall
* F1-score
* Confusion matrix
* ROC-AUC where appropriate

A model should only be considered production-ready after evaluation on a suitable held-out test set.

---

# 🛡 Security Considerations

### Packet Capture

Only capture traffic on networks you own or are explicitly authorized to monitor.

### ML Model Security

`joblib` model files are serialized executable artifacts.

Only load trusted model files from known sources.

Do not place untrusted `.pkl` or `.joblib` files into the model directory.

### Sensitive Traffic

Packet payloads may contain sensitive information.

Do not expose captured traffic, PCAP files, logs, or packet details to unauthorized users.

### AI Decisions

AI predictions should be treated as analytical signals, not automatic incident-response decisions.

---

# 🖥 Installation

## Requirements

* Python 3.9+
* Tkinter
* Scapy
* psutil
* NumPy
* joblib
* scikit-learn for the training pipeline

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

---

# 🌐 Platform Requirements

## Windows

Install:

* Python
* Npcap

Packet capture may require Administrator privileges depending on the interface and environment.

Run:

```bash
python main.py
```

## Linux

Install Tkinter and libpcap as needed.

Example:

```bash
sudo apt install python3-tk libpcap-dev
```

Then:

```bash
sudo python3 main.py
```

## macOS

Install the required Python/Tkinter/libpcap components and provide the appropriate system permissions for capture.

---

# 🚀 Running the Application

```bash
python main.py
```

Typical workflow:

```text
1. Select network interface
2. Select capture protocol
3. Start capture
4. Inspect packets
5. Apply display filters/search
6. Select packets for detailed analysis
7. Open/import PCAP when needed
8. Export the current visible packet set
9. Stop capture
```

---

# ⌨️ Keyboard Shortcuts

```text
Enter   → Apply display search
Escape  → Clear search / close Settings
Ctrl+O  → Open PCAP
Ctrl+S  → Export current display view
F5      → Start capture
```

---

# 🧪 Testing

Run the unit tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Run compilation validation:

```bash
python -m compileall .
```

Check repository formatting:

```bash
git diff --check
```

The current test suite covers:

* packet parsing
* IPv4 / IPv6
* DNS
* ICMP / ICMPv6
* timestamps
* BPF filters
* packet-manager IDs
* packet retention
* feature extraction
* flow tracking
* model compatibility
* detector output
* display filtering
* search behavior
* payload preview
* configuration handling

GUI and live packet-capture behavior require a suitable desktop/Npcap environment and are supplemented with manual smoke testing.

---

# 🏗 Project Structure

```text
Network-Packet-Sniffer/
│
├── main.py
│
├── ai/
│   ├── detector.py
│   ├── feature_extractor.py
│   ├── flow_tracker.py
│   ├── model_loader.py
│   └── model/
│       ├── threat_model.joblib      # trusted local model, not included
│       └── metadata.json             # trusted local metadata, not included
│
├── core/
│   ├── interfaces.py
│   ├── parser.py
│   ├── filter_engine.py
│   ├── packet_manager.py
│   └── sniffer.py
│
├── gui/
│   ├── main_window.py
│   ├── settings_dialog.py
│   └── ...
│
├── training/
│   ├── README.md
│   ├── train.py
│   ├── evaluate.py
│   └── __init__.py
│
├── tests/
│   └── test_parser_and_config.py
│
├── utils/
│   ├── config.py
│   ├── constants.py
│   ├── logger.py
│   └── validator.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

# 🔭 Roadmap

Planned areas for future development include:

* Real-world trained threat-detection model
* Dataset adapters for public network-security datasets
* Improved flow-level detection
* More protocol-aware feature extraction
* Explainable AI / prediction reasons
* Threat timeline and event history
* Alert severity management
* Model performance dashboard
* Detection threshold configuration
* Additional PCAP analytics
* Session reconstruction
* Advanced protocol dissection
* Detection-rule + ML hybrid analysis
* SOC/SIEM integration
* Model retraining workflow

---

# ⚠️ Current Limitations

* No production-trained AI model is included.
* AI accuracy is not claimed without documented evaluation.
* Large PCAP files can still require significant memory.
* Live capture depends on operating-system permissions and Npcap/libpcap.
* Protocol dissection is limited compared with full-featured tools such as Wireshark.
* No packet replay or full session reconstruction is currently implemented.
* AI output should not be treated as an autonomous security decision.

---

# 📚 Project Purpose

This project is intended to demonstrate practical concepts in:

* Network packet capture
* Network protocol analysis
* Python security tooling
* GUI-based packet inspection
* Network traffic filtering
* PCAP processing
* Flow-based traffic analysis
* Machine learning for cybersecurity
* Secure ML model integration
* Thread-safe desktop application design

---

# ⚖️ Disclaimer

This project is intended for **authorized educational, research, and diagnostic use only**.

Do not use it to capture or analyze traffic without appropriate authorization.

The authors are not responsible for misuse of the software.

---

## Author

**Rajavarman G.R.**

B.Tech Computer Science & Engineering — Cybersecurity

GitHub:
https://github.com/Rajavarman-GR

LinkedIn:
https://www.linkedin.com/in/rajavarman-g-r
