# Testing and Validation

The repository contains **134 tests** in 12 `unittest` modules. The test files use synthetic Scapy packets/PCAPs and temporary fixtures; they do not require live traffic or the UNSW dataset/model artifacts.

| Module | Tests | Coverage |
|---|---:|---|
| `tests/test_dataset_adapter.py` | 6 | Runtime feature CSV columns, numeric conversion, label normalization, missing/extra/duplicate/invalid data. |
| `tests/test_decoder.py` | 35 | Plugin registration/detection, DNS/HTTP/TLS/FTP/ICMP decoding, malformed and truncated payloads, output limits and heuristic findings. |
| `tests/test_investigation.py` | 4 | Bidirectional grouping, protocol evidence, findings separation, IDs/timeline/retention/cancellation. |
| `tests/test_parser_and_config.py` | 19 | Packet metadata, IPv4/IPv6/ARP, filter/search text, malformed packet fields, previews, FlowTracker cap/expiry/self-traffic, model compatibility, config normalization. |
| `tests/test_pcap_stream.py` | 4 | Batch size, cancellation, malformed input, and file descriptor cleanup. |
| `tests/test_product_presentation.py` | 12 | Beginner explanations, Decoder/dashboard/evidence models, empty states, theme token/config compatibility. |
| `tests/test_research.py` | 3 | Dataset metadata/hash summaries, feature importance, report formatting/data. |
| `tests/test_unsw_audit.py` | 8 | Training-only audit restrictions, stratified split, feature variants and internal validation. |
| `tests/test_unsw_flow_schema.py` | 15 | Exact UNSW header/row validation, targets, data typing and path-backed iteration. |
| `tests/test_unsw_model_pipeline.py` | 15 | Pipeline structure, numeric/categorical transforms, schema guard, target metadata and separation. |
| `tests/test_unsw_training.py` | 11 | Training artifacts, output safeguards, source hashes/metadata and no-refit evaluation behavior. |
| `tests/test_worker_queue.py` | 2 | Bounded-queue backpressure and producer exit on shutdown. |

The suite includes malformed packet and PCAP cases, truncated payloads, thread/queue shutdown behavior, Decoder edge cases, AI absence/schema behavior, and UNSW input/artifact validation. It does not assert a real detector's accuracy; no runtime model or dataset is bundled. It does not exercise an actual Npcap capture session or a full interactive GUI launch. GUI automated coverage is limited to pure presentation models and theme/token behavior, not end-to-end widget navigation.

## Local commands

```powershell
.venv\Scripts\python.exe -m compileall -q .
.venv\Scripts\python.exe -m unittest discover -v
git diff --check
```

The system `python` can be used if the project packages are installed there. Do not install or upgrade packages only to satisfy one local run without checking the project's declared `requirements.txt` and environment first.

## CI

`.github/workflows/tests.yml` checks out the repository, installs Python 3.11 and `requirements.txt` on Ubuntu, runs `python -m compileall .`, then `python -m unittest discover -v` on push and pull request.

## Environment limits

On some managed Windows hosts, importing Scapy can enumerate Npcap devices, and default Scapy cache or system temp directories may be inaccessible. Synthetic tests do not need live interfaces. When required, redirect temporary/cache files to a writable scratch location or use a testing-only offline Scapy interface/route shim; keep that workaround outside production code. Do not skip or weaken tests. Report environment initialization failures separately from assertion failures.

The Tkinter app needs an interactive desktop session for end-to-end GUI validation. Compile success and pure presentation tests do not prove that all widgets can be visually exercised on every OS/window manager.

During this audit, `main.py` was attempted once with the project virtual environment and writable local temp/cache paths. It produced no traceback or window title within about 10 seconds and was stopped; therefore this run did not verify reaching `create_body()` or the Investigation tabs. Startup/visual smoke remains an environment-dependent demonstration check, not a passing result.
