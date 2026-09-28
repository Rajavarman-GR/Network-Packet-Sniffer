# Performance baseline

Run the offline synthetic benchmark from the repository root:

```powershell
python -m benchmarks.benchmark_pipeline
```

It defaults to 1,000, 10,000, and 50,000 packets. Packet construction and PCAP
writing are setup work and are excluded from the stage timers. Each workload
uses synthetic IPv4/UDP/DNS-shaped packets with a small Raw payload. The
benchmark reports parser metadata, packet decoding, unified analysis, runtime
flow tracking, bounded investigation, streamed PCAP reading (128 packet
batches), and PacketManager retention. `tracemalloc` records Python allocations
during retention only; packet objects are prebuilt, so this is not total process
memory. Results depend on host, Python, Scapy, and filesystem versions.

The audit reran the default workload on Windows 11, Python 3.14.4, and Scapy
2.7.0. These figures are a reproducible starting point, not a before/after
comparison: no comparable pre-change benchmark was available. Values are
elapsed seconds and packets per second (rounded). Unified analysis was supplied
an explicit unavailable AI result; this run did not load or benchmark a model.

| Packets | Parser | Decoder | Unified analysis | Flow tracker | Investigation | PCAP read | Retention |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.0164 s / 60,963 pps | 0.0674 s / 14,844 pps | 0.0732 s / 13,658 pps | 0.2240 s / 4,465 pps | 0.5762 s / 1,735 pps | 0.1674 s / 5,973 pps | 0.0040 s / 251,300 pps |
| 10,000 | 0.1749 s / 57,185 pps | 0.6639 s / 15,062 pps | 0.7190 s / 13,909 pps | 1.8908 s / 5,289 pps | 5.0830 s / 1,967 pps | 1.5855 s / 6,307 pps | 0.0376 s / 266,119 pps |
| 50,000 | 0.9057 s / 55,207 pps | 3.4008 s / 14,703 pps | 3.5893 s / 13,930 pps | 10.2103 s / 4,897 pps | 4.9550 s / 2,018 pps* | 8.1728 s / 6,118 pps | 0.1890 s / 264,498 pps |

At 50,000 input packets, the benchmark retained 10,000 PacketManager records
with a measured Python allocation peak of 6,222,752 bytes. The corresponding
peak was 532,824 bytes at 1,000 packets and 5,328,776 bytes at 10,000 packets.
These measurements do not include the preallocated Scapy packet objects,
decoder/investigation results, native allocations, or total application RSS.
Investigation itself is bounded by its configured record limit; its runtime
scales with the retained input and the evidence produced. The 50,000-packet
investigation row analyzed the last 10,000 records, so its rate is based on
10,000 analyzed packets (the input still contained 50,000 records).

The benchmark is diagnostic and synthetic. Individual timings vary between
runs. It does not model GUI rendering, real capture drivers, packet loss,
payload diversity, or AI inference with a loaded model. Use repeated runs on
the target host before making performance claims or comparing code changes.
