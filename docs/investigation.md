# PCAP and packet investigation

## Loading and retention

Open a capture through **File → Open PCAP** or **Ctrl+O**. `core.pcap.iter_pcap_batches()` reads with a context-managed Scapy `PcapReader`, yields at most 128 packets per batch by default, and checks cancellation between packets. The GUI posts each batch through an eight-item bounded queue; a full queue pauses the reader until the Tk event loop consumes work. Progress is reported by processed packet count. A malformed file surfaces an error; batches already processed before a read failure remain visible.

Packets pass through the same lightweight parser and `PacketManager` used by live capture. The default retention limit is 10,000, configurable up to 20,000. The displayed captured count can exceed the retained count. Investigation and packet navigation are limited to retained records; loading a larger file does not provide unlimited historical storage.

## Evidence model

- **Flows:** canonical, bidirectional conversations by protocol and endpoint/port pairs. Packet count, byte count, first/last timestamp, duration, and stable packet IDs are included. This is not TCP stream reassembly.
- **Top talkers:** source address, packet count, and bytes.
- **DNS:** query/response state, question name/type when present, response records, and packet ID.
- **HTTP:** request/response kind, method, host, path, endpoints, and packet ID.
- **TLS:** handshake type and SNI when a ClientHello in that packet contains it. No TLS content is decrypted.
- **Findings:** AI suspicious/high-risk results and Decoder heuristic observations are separately labeled.
- **Timeline:** packet, protocol, AI, and heuristic events sorted by timestamp, stable packet ID, type, and description.

Investigation reads protocol data from the existing Decoder facade. It does not implement a second DNS/HTTP/TLS parser. A packet ID can be opened from either a flow or evidence row. If the packet is retained but hidden by the current display filter, the GUI clears that filter before selecting it.

## Investigation workspace

The Investigation workspace reports packet, flow, DNS, HTTP, TLS, AI, and heuristic counts for the completed retained-window analysis. Evidence is separated into DNS, HTTP, TLS, AI Findings, Security Findings, and Timeline tabs. Rows include time, evidence type, a concise detail, endpoints, and a packet reference. Double-click a row to select the retained packet in Packets; this uses the existing packet ID index and does not copy packet data. Empty tabs explain why evidence may be absent.

The Overview dashboard summarizes current retained packet counts and recent packets. Flow, byte, and finding measures display as unavailable until investigation has completed; the dashboard does not present missing analysis as zero. Statistics combines current capture counters with investigation results and marks the analyzed scope as the retained window.

## Missing and partial data

Packets without IP or Raw layers still have records and can appear in conversations when metadata permits. Unavailable AI is represented explicitly. A protocol without a matching Decoder plugin has no application result. Malformed packet objects become a `malformed` analysis record where the parser/Decoder boundary can safely identify the failure. A packet evicted before navigation is unavailable in the GUI.

All payload and decoded field displays are bounded. The Decoder heuristic scanner inspects a maximum of 65,536 payload bytes; payload preview is at most 256 bytes in Decoder results and at most 4,096 bytes in packet details.
