# Testing and validation

From the repository root, run:

```bash
python -m unittest discover -v
python -m compileall .
git diff --check
```

Tests use synthetic Scapy packets and PCAPs. They do not need live network traffic. The GitHub Actions workflow installs `requirements.txt` on Ubuntu with Python 3.11, compiles the repository, and runs `python -m unittest discover -v`.

On this Windows development host, ordinary Scapy import can enter Npcap interface discovery, and Python-created temporary directories may be inaccessible under the managed filesystem sandbox. The local full-suite run therefore used an in-process offline Scapy interface/route shim and pre-created workspace scratch slots for tests that use `TemporaryDirectory`. Those shims were not added to application code. On a normal Windows machine with working Npcap and temp-directory permissions, use the commands above directly.

When a test fails, run the specific module while keeping the suite and fixtures intact; do not skip or weaken unrelated tests to get a green run.
