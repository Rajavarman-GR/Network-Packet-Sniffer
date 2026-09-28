# Packet Decoder

## Pipeline and modes

`core/decoder.py` is the stable packet-level facade. It traverses the current Scapy packet layer chain, renders declared fields, extracts a bounded Raw payload preview, selects the highest-priority matching application decoder, and runs a separate heuristic scan. It does not mutate the packet, perform network I/O, or depend on Tkinter or the AI subsystem.

```text
Selected packet
  → generic Scapy layer traversal (200 characters per rendered field)
  → plugin registry matching (priority order)
  → bounded payload preview (256 bytes by default)
  → heuristic scan (up to 65,536 payload bytes)
  → structured result
      ├─ Beginner: explanation built from decoded facts
      ├─ Analyst: application protocol fields and bounded payload preview
      └─ Technical / Raw: Scapy layer tree and raw ASCII/hex preview
```

`core/explanations.py` is the presentation-neutral explanation layer. It maps observed protocol names and available fields to conservative descriptions, indication text, and suggested next inspection. It does not decode packets itself or infer threats. `gui/presentation.py` builds mode-specific view models; `gui/main_window.py` renders them. The Decoder opens in Beginner mode. Choosing Analyst or Technical / Raw changes the selected notebook tab.

## Registered protocol plugins

| Plugin | Detection | Decoded output | Heuristics / limits |
|---|---|---|---|
| DNS | Scapy DNS layer; highest registered priority | Query/response, transaction ID, flags, up to 64 questions and 64 answers, question name/type, response data (512-character cap per answer), NXDOMAIN flag | Does not reconstruct a multi-packet transaction or correlate query and response into a session. Malformed records may be incomplete. |
| TLS | Raw bytes resemble a TLS record: recognized content type, at least 5 bytes, major version byte 3 | Content type, record/version, declared record length/truncation; handshake type and bounded ClientHello SNI parsing when complete | Packet-level record only. No TLS decryption or multi-record/segment reassembly. An SNI value may not be present/visible. |
| HTTP | Raw payload starts with a matching HTTP/1.x request or response line | Request method/URI or response status, headers within 16,384 bytes, Host, content metadata, up to 256-byte body preview (text or hex) and truncation markers | No stream reassembly. Headers split across packets are not assembled. Basic Authorization is a heuristic; displayed credentials may be sensitive. |
| FTP | First CRLF-delimited payload line resembles a recognized command or 3-digit response | Command/argument or reply code/message | Packet-level control-channel recognition; does not reconstruct an FTP session or data channel. USER/PASS triggers heuristic observation. |
| ICMP / ICMPv6 | Scapy ICMP or qualifying ICMPv6 layers | Type/name, code, and echo identifier/sequence when applicable | Type names cover common values; unknown values retain a generic/name fallback. No broader event correlation. |

Plugins are registered by `create_default_registry()` in `core/decoder.py` and sorted by descending priority for detection. `analyze_payload_findings()` also asks all matching plugins for plugin-specific findings. The current registry does not include a generic “decode every application protocol” plugin.

## Generic fields and payload

Layer traversal follows Scapy's payload chain, stops at `NoPayload`, and detects cycles by object identity. Each Scapy declared field is rendered using its representation with fallback for common malformed values. A field string is capped at 200 characters; large byte fields and long lists are shortened. The layer tree is generic Scapy metadata, not a complete protocol semantics report.

`inspect_payload()` returns complete Raw length plus at most 256 bytes of ASCII and hex preview by default, with a truncation flag. The packet details view separately uses parser preview defaults up to 4,096 bytes. These are bounded display paths; neither changes the packet stored in PacketManager.

## Security heuristic findings

The scanner checks at most the first 65,536 bytes of Raw payload for a small set of embedded file signatures (PNG, JPEG, GIF, PDF, ZIP, ELF, PE, GZIP, RAR, PEM), HTTP Basic Authorization, FTP USER/PASS commands, the literal word `password`, and long Base64-like runs. HTTP and FTP plugins can add corresponding observations. Duplicate finding messages are removed. Output is labeled heuristic and can have false positives or miss split/encoded/encrypted data. These checks are not malware confirmation, a full content inspection engine, or an IDS rule set. Some findings can contain credentials or payload snippets; handle reports and screenshots as sensitive.

## Important boundaries

- Packets are decoded independently; no TCP stream reassembly or session reconstruction is implemented.
- TLS ClientHello and SNI can be recognized in a packet, but TLS application data is not decrypted.
- The Decoder does not perform active scanning, packet injection, host lookups, or threat-intelligence checks.
- A generic layer can be shown even when no application plugin matches.
- Decoder heuristics and runtime AI results are separate result categories.

See [user guide](user_guide.md) for how to move from Beginner through Analyst to Technical / Raw.
