# Testing and validation

From the repository root, use the repository environment when present:

```powershell
.venv\Scripts\python.exe -m unittest discover -v
.venv\Scripts\python.exe -m compileall -q .
git diff --check
```

On a host without `.venv`, use `python` in place of `.venv\Scripts\python.exe`. The declared dependencies are in `requirements.txt`; avoid upgrading packages just to run validation.

Tests use synthetic Scapy packets and PCAPs. They do not need live network traffic. The GitHub Actions workflow installs `requirements.txt` on Ubuntu with Python 3.11, compiles the repository, and runs `python -m unittest discover -v`.

On some managed Windows hosts, Scapy import may attempt Npcap interface discovery and tests using `TemporaryDirectory` may fail because the process cannot access the configured system temp directory or Scapy's user cache. Use a writable scratch/cache directory and an offline Scapy interface/route test shim if the host requires them; keep such setup outside production code and do not skip or weaken tests. A full validation report should distinguish these environment failures from assertion failures. This repository does not ship an offline Scapy shim.

The Tkinter UI is a desktop application and requires an interactive Windows session for visual smoke testing. Syntax and pure presentation-model tests can run without a display; they do not replace a GUI smoke test.

When a test fails, run the specific module while keeping the suite and fixtures intact; do not skip or weaken unrelated tests to get a green run.
