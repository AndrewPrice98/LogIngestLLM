# Log Agent

Reads your logs, throws away the noise, and tells you the handful of things worth your attention, with why they matter and what to do.

Sources: **Windows Event Log**, **Linux syslog / journald**, **your own app logs** (text or JSON lines, stack traces grouped), and **Raspberry Pi / Jetson** boxes over SSH (plus live health checks: under-voltage, throttling, temperature, disk, failed services).

Runs on your own LLM (Ollama, LM Studio, llama.cpp, vLLM...). Works with no LLM at all too, in rules-only mode.

## Quick start (Windows)

Double-click **Start logagent** on the desktop (or `Start logagent.bat` here). It:

1. starts your trained model in the background (if `models\*dapter` exists) and waits until it answers,
2. starts the dashboard at http://127.0.0.1:8765 and opens it,
3. runs an automatic scan every 6 h (`schedule` in `logagent.toml`) while it's open.

Use **Start logagent (admin)** to include the Security log (failed logons, account changes, audit-log cleared). Closing the window stops everything. If the model isn't available the dashboard says so in the top bar and falls back to the built-in rules.

Settings live in `logagent.toml` (copied from `config.example.toml` on first run). Sources with `enabled = false` are listed but not scanned by default.

## How it decides what's valuable

1. **Collect** events from each source into one format (time, host, severity, program, message).
2. **Cluster** identical messages into patterns (IPs, numbers, paths and IDs are masked), so 4,000 cron lines become one row.
3. **Score** each pattern:
   - ~50 built-in rules for things that actually matter (disk/SD card I/O errors, filesystem corruption, OOM killer, kernel panics, WHEA hardware errors, blue screens, unexpected shutdowns, under-voltage, thermal throttling, Jetson GPU faults, SSH brute force, new admin accounts, Defender detections, audit-log cleared, service crash loops, app tracebacks...)
   - severity, burst size, and **"first time ever seen on this host"** (it keeps a baseline across scans)
   - known-benign chatter (DCOM 10016, cron runs...) is suppressed
4. **Review**: only the top ~40 patterns (not your raw logs) go to the LLM, which correlates them (e.g. *under-voltage → SD card errors*), drops false alarms, and writes the summary and findings.

## Your LLM

In `logagent.toml`:

```toml
[llm]
provider = "ollama"                  # or "openai" for any OpenAI-compatible server
base_url = "http://localhost:11434"  # LM Studio: http://localhost:1234/v1, llama.cpp: http://localhost:8080/v1
model = "qwen3:8b"
```

Check it with `python -m logagent check-llm`. `provider = "none"` = rules only.

## Training your own model

The agent can run on a model you train yourself: an open base model (Qwen3 4B Instruct, Apache 2.0) fine-tuned with QLoRA on your GPU to triage *your* logs the way *you* want. The base model's weights are downloaded once, and your trained part (a ~60 MB LoRA adapter in `models/`) never leaves your PC.

1. **Label.** In the dashboard, mark findings 👍 *worth knowing* (with an importance) or 👎 *noise*. Turn on "also show lower-scored patterns" to label anything the rules missed. Labels go to `data/feedback.json`.
2. **Build the dataset.** Your labels count most (weighted x3). The built-in rules label everything else, and synthetic Pi/Jetson/Linux scenarios fill the gaps.
   ```bash
   python -m logagent dataset
   ```
3. **Train** (one-time setup of a Python 3.12 environment, since 3.14 has no CUDA PyTorch builds yet):
   ```bash
   py -3.12 -m venv .venv-train
   .venv-train\Scripts\pip install torch --index-url https://download.pytorch.org/whl/cu128
   .venv-train\Scripts\pip install transformers peft accelerate bitsandbytes
   .venv-train\Scripts\python trainer\train.py
   ```
4. **Evaluate**: compare against the untrained base model on held-out data (including scans you labeled):
   ```bash
   .venv-train\Scripts\python trainer\evaluate.py --adapter none
   .venv-train\Scripts\python trainer\evaluate.py
   ```
5. **Use it**: `.venv-train\Scripts\python trainer\serve.py`, then in `logagent.toml`:
   ```toml
   [llm]
   provider = "openai"
   base_url = "http://127.0.0.1:8081/v1"
   model = "logagent"
   mode = "triage"      # the model reviews each pattern separately; this is what it was trained on
   ```

Repeat 1-4 as you label more. Each run is saved as a new version in `models/` with its eval score.

## Raspberry Pi / Jetson

Set up key login once (`ssh-copy-id pi@raspberrypi.local`), then:

```toml
[[sources]]
name = "pi"
type = "ssh"
host = "pi@raspberrypi.local"
device = "pi"                # or "jetson" / "linux"
logs = ["/home/pi/myapp/*.log"]
```

Nothing is installed on the device; it runs `journalctl` and a few read-only health commands over SSH.

## Command line

```bash
python -m logagent scan                                   # all configured sources
python -m logagent scan --window 7d --source "This PC"
python -m logagent scan --file syslog:/path/syslog --file app:./app.log --no-llm
python -m logagent scan --json > scan.json
```

Scans are saved in `data/scans/`. Add your own rules under `[[rules]]` in the config.

## Tests

```bash
python -m pytest -q
```
