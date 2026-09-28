# User Guide

## Before you start

Use the application only on traffic you own or are authorized to inspect. It is a passive educational/defensive packet analyzer. It does not block traffic or provide production IDS/IPS coverage. Live capture requires an appropriate capture driver (Npcap on Windows, libpcap-compatible support on Linux/macOS) and may require elevated operating-system privileges. Tkinter must be present in the Python installation.

Install dependencies and launch from the repository root:

```powershell
python -m pip install -r requirements.txt
python main.py
```

On Windows, a configured Scapy/Npcap environment is required for interface discovery and live capture. The local AI indicator can say **Unavailable** when no compatible runtime model and metadata are installed; packet browsing and Decoder views are separate from AI availability.

## Beginner live-capture workflow

1. Launch the app and choose a network interface from the top toolbar.
2. Choose a capture protocol filter (`ALL`, TCP, UDP, ICMP, ARP, DNS, or ICMPv6) and click **Start**. F5 is the Start shortcut.
3. Open **Overview** to see capture state, retained packet counts, recent packets, and available investigation context. Investigation-only metrics remain unavailable until analysis completes.
4. Open **Packets**. Search/filter the retained list and select a row. Source/destination are endpoint addresses; ports commonly identify transport services. Packet details show bounded facts and do not establish whether traffic is safe.
5. Click **Decode Packet**. Start with **Beginner** to see the observed protocol stack, a short explanation, and a next inspection suggestion.
6. Read the explanation as context for the packet: a protocol's presence is not a security verdict.
7. Open **Flows** after analysis to group retained packets into bidirectional conversations. Double-click a row to navigate to one of its packets.
8. Open **Investigation** to review DNS, HTTP, TLS, AI findings, Decoder heuristic findings, and timeline. Double-click evidence to navigate to its retained packet.
9. Open **Statistics** for capture counters and the latest retained-window analysis report.

## Progress from Beginner to Analyst to Technical

- **Beginner** translates selected observed fields into short, cautious explanations. It can show a protocol stack and suggested next step.
- **Analyst** shows plugin-decoded application data and payload previews. For HTTP/TLS/DNS/FTP/ICMP, the exact output depends on what is visible in that individual packet.
- **Technical / Raw** shows Scapy's layer/field tree. The Payload / Raw tab shows bounded ASCII and hex bytes.

The interface does not reassemble TCP streams, correlate an entire session, or decrypt TLS. Split headers and application data may not be visible in one packet.

## PCAP workflow

1. Choose **Open PCAP** in the toolbar or **File → Open PCAP** (Ctrl+O).
2. The PCAP worker reads packets in batches of at most 128 and sends them through an eight-item bounded queue. The UI shows processed count and offers **Cancel Load**.
3. The Tk event loop parses each delivered batch and adds records to PacketManager. The configured limit defaults to 10,000 and cannot exceed 20,000. A file may contain more packets than remain retained.
4. After the load finishes or is cancelled, the table refreshes and retained-window investigation starts automatically. The AI worker processes packets independently; if its results are still pending when investigation runs, rerun **Analyze retained packets** after AI processing for a refreshed AI finding view.
5. Investigate only the retained window. Evicted packets cannot be opened from the GUI. Already processed batches remain available if the PCAP read later fails.

PCAPs and exports can contain credentials, personal data, or other sensitive payloads. Export writes only the packets visible under the current display filter, to a path selected by the user. Protect capture files and exports accordingly.

## Analyst workflow

```text
Capture or load a PCAP
  → inspect protocol and endpoints in Packets
  → group retained packets in Flows
  → inspect the chosen packet in Decoder
  → review AI label separately from Decoder heuristic findings
  → use evidence packet references to navigate related retained packets
  → review the event timeline and Statistics report
```

Use the AI label as a model output to prioritize inspection, not as a confirmed attack. Confidence is the estimator's maximum `predict_proba` class value when supported; it is not guaranteed calibrated. The risk score is a label-specific arithmetic display transformation, not a calibrated threat probability. Heuristic evidence describes observed patterns and may be false positive or incomplete.

## Workspaces and controls

| Workspace/dialog | Use |
|---|---|
| Overview | Capture state, retained-packet metrics, recent packets, and post-analysis context. |
| Packets | Search/filter/sort retained packet rows, inspect packet details, and open Decoder. |
| Flows | View bidirectional conversations from the last investigation result; double-click to navigate. |
| Investigation | Analyze retained packets and inspect grouped evidence/timeline; supports canceling PCAP load. |
| Statistics | Capture counters plus retained-window analysis report. |
| Decoder dialog | Beginner / Analyst / Technical / Raw tabs and separate heuristic findings. |
| Settings | Dark/light theme, packet retention limit, default interface/protocol, auto-scroll and timestamp format. |
| Help | Getting Started glossary and About dialog. |

Shortcuts: **F5** start capture, **Ctrl+O** open PCAP, **Ctrl+S** export current display view. Capture and operation state appears in the toolbar badge, Overview and status bar.

## Settings and retention

Settings are saved as `config.json` at the repository root. Defaults are dark theme, `ALL` protocol, auto-scroll, `%H:%M:%S`, and 10,000 retained packets; maximum is 20,000. Packet IDs are monotonically assigned and not reused after clearing. Investigation and navigation cannot reach packets already evicted from retention.

## Troubleshooting

- **No interfaces / live capture fails:** verify Scapy can discover interfaces and that Npcap/libpcap is installed and permitted. Choose a valid interface and check operating-system capture permissions.
- **AI unavailable:** the repository does not contain a runtime model artifact. Install only a model and metadata generated for the exact 23-feature schema from a trusted source.
- **PCAP rejected:** verify it is a readable PCAP supported by Scapy. A malformed file reports an error; packets from already completed batches remain available.
- **No application decode:** the protocol may not have a plugin, payload may be encrypted, or fields may be split across packets. Review generic fields and payload preview.
- **No findings:** the limited heuristic scanner only reports its configured patterns; an empty result is not proof of safety.
- **Large captures:** analysis and navigation use the retained limit, not unlimited file history. GUI table rendering is not virtualized.

For implementation detail see [architecture](architecture.md), [Decoder](decoder.md), [AI architecture](ai_architecture.md), and [investigation](investigation.md).
