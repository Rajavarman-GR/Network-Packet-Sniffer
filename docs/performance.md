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

The Phase 5.1 run reran the default workload on Windows 11, Python 3.14.4, and
Scapy 2.7.0. These figures are a reproducible starting point, not a before/after
comparison: no comparable pre-change benchmark was available. Values are
elapsed seconds and packets per second (rounded). Unified analysis was supplied
an explicit unavailable AI result; this run did not load or benchmark a model.

| Packets | Parser | Decoder | Unified analysis | Flow tracker | Investigation | PCAP read | Retention |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.0380 s / 26,330 pps | 0.1435 s / 6,971 pps | 0.1282 s / 7,799 pps | 0.3395 s / 2,946 pps | 0.5120 s / 1,953 pps | 0.2864 s / 3,491 pps | 0.0059 s / 168,745 pps |
| 10,000 | 0.3342 s / 29,924 pps | 1.3248 s / 7,548 pps | 1.2884 s / 7,761 pps | 3.4896 s / 2,866 pps | 5.5613 s / 1,798 pps | 3.1484 s / 3,176 pps | 0.0570 s / 175,470 pps |
| 50,000 | 1.6650 s / 30,030 pps | 6.2165 s / 8,043 pps | 6.5613 s / 7,620 pps | 27.6603 s / 1,808 pps | 13.2865 s / 753 pps* | 31.9654 s / 1,564 pps | 0.7356 s / 67,971 pps |

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
