# Network Packet Sniffer

A Python-based desktop application for capturing, inspecting, and analyzing live network traffic using **Scapy** and **Tkinter**. The application provides a graphical interface for real-time packet capture, protocol filtering, packet inspection, live statistics, and PCAP export, making it a useful educational tool for learning networking and packet analysis.

> **Note:** This project is designed for educational and learning purposes. It is **not** intended to replace professional packet analysis tools such as Wireshark or tcpdump.

---

# Overview

The Network Packet Sniffer captures live packets from a selected network interface and presents them in an interactive graphical dashboard. Users can filter traffic by protocol, inspect detailed packet information, search captured packets, monitor protocol statistics, and export captured traffic for further analysis.

The project demonstrates practical concepts in networking, packet parsing, GUI development, and Python application design while providing an intuitive interface for understanding network communication.

---

# Features

### Live Packet Capture

- Capture live network traffic from available network interfaces
- Detect interfaces automatically using **psutil**
- Start and stop captures with a single click
- Asynchronous packet capture using **Scapy AsyncSniffer**

---

### Protocol Filtering

Capture all traffic or filter by:

- TCP
- UDP
- ICMP
- ARP
- DNS
- ALL Traffic

---

### Packet Table

Display captured packets with:

- Timestamp
- Source IP Address
- Destination IP Address
- Protocol
- Source Port
- Destination Port
- Packet Length

Additional features include:

- Color-coded protocol highlighting
- Scrollable packet list
- Automatic live updates

---

### Packet Inspection

Selecting a packet displays detailed information including:

#### Ethernet Layer

- Source MAC Address
- Destination MAC Address
- EtherType

#### IP Layer

- Source Address
- Destination Address
- TTL
- Identification
- Flags
- Protocol

#### Transport Layer

TCP

- Source Port
- Destination Port
- Sequence Number
- Acknowledgement Number
- TCP Flags

UDP

- Source Port
- Destination Port
- Length

ICMP

- Type
- Code
- Checksum

---

### Payload Analysis

Inspect packet payloads in multiple formats:

- ASCII representation
- Hexadecimal dump
- Raw payload data

---

### Search Functionality

Search captured packets by:

- IP Address
- Protocol
- Port Number

Repeated searches automatically cycle through matching packets.

---

### Live Statistics

Monitor capture statistics in real time:

- Total Packets
- TCP Packets
- UDP Packets
- ICMP Packets

---

### PCAP Export

Export captured traffic as a **.pcap** file for analysis using tools such as:

- Wireshark
- tcpdump
- Tshark

---

### AI Detection Scaffold

The repository includes a placeholder AI module:

```
ai/detector.py
```

This module is intended for future threat detection functionality but is **not currently connected** to the packet capture workflow.

---

# Screenshots

> Add screenshots of your application here.

Example:

```
screenshots/
├── dashboard.png
├── packet-details.png
├── live-capture.png
└── search-feature.png
```

---

# Technology Stack

| Component | Technology |
|------------|------------|
| Programming Language | Python 3.9+ |
| Packet Capture | Scapy |
| GUI Framework | Tkinter |
| Interface Detection | psutil |
| PCAP Support | Scapy |

---

# Project Structure

```
Network-Packet-Sniffer/
│
├── main.py                     # Application entry point
├── requirements.txt
│
├── core/
│   ├── sniffer.py              # Async packet capture
│   ├── parser.py               # Packet parsing utilities
│   └── interfaces.py           # Network interface detection
│
├── gui/
│   └── main_window.py          # Main graphical interface
│
├── ai/
│   └── detector.py             # AI detection scaffold
│
├── utils/
│   ├── constants.py            # UI constants and color palette
│   ├── validator.py            # Validation utilities
│   └── logger.py               # Logging utilities
│
└── README.md
```

---

# Application Workflow

```
User
   │
   ▼
Select Network Interface
   │
   ▼
Choose Protocol Filter
   │
   ▼
Start Packet Capture
   │
   ▼
Scapy AsyncSniffer
   │
   ▼
Packet Parser
   │
   ▼
Update GUI
   │
   ├──────────────► Packet Table
   │
   ├──────────────► Packet Details
   │
   ├──────────────► Live Statistics
   │
   └──────────────► Export PCAP
```

---

# Requirements

### Operating System

- Windows
- Linux
- macOS

### Python

- Python 3.9 or newer

### Packet Capture Permissions

Raw packet capture requires elevated privileges.

#### Linux

Run using:

```bash
sudo python3 main.py
```

#### Windows

- Install **Npcap**
- Run the terminal as Administrator

#### macOS

Run using:

```bash
sudo python3 main.py
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Rajavarman-GR/Network-Packet-Sniffer.git
```

Navigate into the project:

```bash
cd Network-Packet-Sniffer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running the Application

### Linux / macOS

```bash
sudo python3 main.py
```

### Windows

Run Command Prompt or PowerShell as Administrator.

```bash
python main.py
```

---

# How to Use

1. Launch the application.
2. Select a network interface.
3. Choose a protocol filter (or **ALL**).
4. Click **Start** to begin capturing packets.
5. Watch packets appear in real time.
6. Select any packet to inspect its headers and payload.
7. Use the search feature to locate specific packets.
8. Export the captured traffic as a PCAP file when needed.

---

# Supported Protocols

| Protocol | Supported |
|----------|-----------|
| Ethernet | ✅ |
| IPv4 | ✅ |
| TCP | ✅ |
| UDP | ✅ |
| ICMP | ✅ |
| ARP | ✅ |
| DNS | ✅ |

---

# Sample Packet Information

| Field | Example |
|--------|----------|
| Timestamp | 14:42:17 |
| Source IP | 192.168.1.15 |
| Destination IP | 142.250.183.78 |
| Protocol | TCP |
| Source Port | 51542 |
| Destination Port | 443 |
| Length | 66 Bytes |

---

# Current Limitations

This application is intended as an educational packet analyzer rather than a full-featured network analysis suite.

Current limitations include:

- AI threat detection module is present but not integrated into the live capture workflow
- No machine learning model has been trained or deployed
- The "Threats" statistic always remains zero
- The displayed "Bandwidth" statistic is not calculated from real network throughput
- The Settings button is currently a placeholder
- `utils/logger.py` is included but not used
- `utils/validator.py` is included but not used
- Interface names returned by **psutil** may differ from those expected by Scapy/Npcap on Windows
- No packet filtering using Berkeley Packet Filters (BPF)
- No packet replay functionality
- No session reconstruction
- No automated unit or integration tests

---

# Future Enhancements

Potential improvements include:

- Integrate the AI Threat Detector into the packet processing pipeline
- Train a machine learning model for anomaly detection
- Calculate live bandwidth and throughput statistics
- Add protocol-specific packet filters
- Implement Berkeley Packet Filter (BPF) support
- Add packet replay functionality
- Implement flow/session reconstruction
- Add packet capture history
- Support dark mode and customizable themes
- Complete the Settings dialog
- Improve Windows interface detection
- Optimize packet rendering for large captures
- Add multithreading for improved responsiveness
- Write comprehensive unit and integration tests
- Containerize the application using Docker

---

# Learning Outcomes

This project helped reinforce practical knowledge in:

- Computer Networking
- TCP/IP Protocol Suite
- Packet Capture using Scapy
- Network Packet Parsing
- GUI Development with Tkinter
- Asynchronous Programming
- Object-Oriented Python
- PCAP File Generation
- Network Protocol Analysis
- Python Application Architecture

---

# Disclaimer

This project is intended solely for educational purposes.

It captures packets only from network interfaces accessible to the host system and requires appropriate permissions. Users should only capture traffic on networks they own or are explicitly authorized to monitor.

This application is **not** an Intrusion Detection System (IDS), Intrusion Prevention System (IPS), or AI-powered threat detection platform. Although the repository includes an AI module scaffold, no active machine learning or automated threat detection functionality is currently implemented.

---

# Author

**Rajavarman G.R.**

Cybersecurity Undergraduate | Security Engineering | Python | Networking

**GitHub**

https://github.com/Rajavarman-GR

**LinkedIn**

https://www.linkedin.com/in/rajavarman-g-r

---

# License

No license has currently been specified for this repository.

If you plan to make the project open source, adding an MIT License or Apache 2.0 License is recommended.
