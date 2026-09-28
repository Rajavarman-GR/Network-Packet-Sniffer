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

The measured local run used Windows 11, Python 3.14.4, and Scapy 2.7.0. These
figures are a reproducible starting point, not a before/after comparison: no
comparable pre-change benchmark was available. Values are elapsed seconds and
packets per second (rounded).

| Packets | Parser | Decoder | Unified analysis | Flow tracker | Investigation | PCAP read | Retention |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.0180 s / 55,582 pps | 0.0766 s / 13,047 pps | 0.0771 s / 12,975 pps | 0.2095 s / 4,774 pps | 0.4696 s / 2,129 pps | 0.1804 s / 5,545 pps | 0.0036 s / 274,816 pps |
| 10,000 | 0.1995 s / 50,113 pps | 1.0756 s / 9,297 pps | 0.7681 s / 13,019 pps | 1.8300 s / 5,465 pps | 5.5632 s / 1,798 pps | 1.5545 s / 6,433 pps | 0.0366 s / 273,146 pps |
| 50,000 | 0.8541 s / 58,543 pps | 3.3401 s / 14,969 pps | 3.4907 s / 14,324 pps | 10.3512 s / 4,830 pps | 5.2534 s / 1,904 pps* | 8.3066 s / 6,019 pps | 0.1849 s / 270,415 pps |

At 50,000 input packets, the benchmark retained 10,000 PacketManager records
with a measured Python allocation peak of 6,222,768 bytes. The corresponding
peak was 532,824 bytes at 1,000 packets and 5,328,776 bytes at 10,000 packets.
These measurements do not include the preallocated Scapy packet objects,
decoder/investigation results, native allocations, or total application RSS.
Investigation itself is bounded by its configured record limit; its runtime
scales with the retained input and the evidence produced. The 50,000-packet
investigation row analyzed the last 10,000 records, so its rate is based on
10,000 analyzed packets (the input still contained 50,000 records).

The benchmark is diagnostic and synthetic. Individual timings vary between
runs; the 50,000-packet parser figure was repeated separately after one noisy
run. It does not model GUI rendering,
real capture drivers, packet loss, payload diversity, or AI inference with a
loaded model. Use repeated runs on the target host before making performance
claims or comparing code changes.
