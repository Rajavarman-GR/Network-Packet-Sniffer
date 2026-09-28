# Application Security Review

This is a source-based application security review and regression pass, not a
formal penetration test. The application is passive: it captures or reads
traffic and does not inject packets, scan hosts, or block traffic.

## Trust boundaries and inputs

- Live packets and PCAP contents are untrusted input. Parser and Decoder output
  is presented as data; payload bytes are not evaluated as code.
- Packet and investigation retention, capture/AI queues, PCAP batches, payload
  previews, metadata JSON size, and several Decoder outputs have explicit
  bounds. Investigation cancellation reports only records processed before
  cancellation.
- PCAP input is streamed with bounded batches and context-managed readers.
  Export writes selected packet records to a path selected by the user.
- Configuration is normalized to safe known values. Worker results are
  delivered through queues and handled on Tk's event thread.

## Model artifacts

Runtime and UNSW models are joblib/pickle artifacts. Deserialization can execute
code, so artifacts must come from trusted local sources. Runtime ModelLoader
validates metadata before loading, rejects Windows UNC paths and oversized
metadata, then checks schema version, exact ordered features, model name/version,
class agreement, predictor support, and the required 23-feature count. This is
compatibility validation, not cryptographic authenticity. Mapped drives and
other local paths still depend on operator trust.

Runtime training refuses to replace existing artifacts unless `--force` is
supplied and rejects destinations inside the UNSW research model tree. Runtime
packet artifacts and UNSW flow research artifacts remain separate. The UNSW
evaluator checks recorded dataset filenames, hashes, row counts, schema, and
metadata and predicts on the held-out split without fitting.

## Payload display and logging

Packet previews are bounded before display. Decoder heuristic findings may
identify cleartext credentials or other sensitive evidence; users should treat
displayed packets and findings as sensitive. Application logging does not
intentionally log full payloads or credential values. Serialized artifacts
should be trusted before loading.

## Resource and concurrency limits

Packet retention is clamped to 20,000 records. Capture, AI, and worker result
queues are bounded; saturation can drop work and is surfaced as a warning.
PCAP loading and investigations run in workers with cancellation and bounded
shutdown waits. GUI guards prevent duplicate capture and prevent a PCAP load
from overlapping live capture. FlowTracker caps flow/endpoint counts, timestamp
history, and unique-destination sets; these limits affect feature context as
documented in `ai_architecture.md`.

## Known limitations

- No cryptographic signature or model hash authenticates runtime artifacts.
- Python's joblib deserializer is not a sandbox; do not load untrusted artifacts.
- Local filesystem permissions and user-selected input/export paths remain the
  operator's responsibility.
- Full interactive Tk workflows and live capture require a suitable desktop
  and capture environment; headless unit tests do not prove them.
- Packet metadata and payloads may contain private data even when logs do not.
