# Log Agent

Reads your logs, throws away the noise, and tells you the handful of things worth your attention, with why they matter and what to do.

Sources: **Windows Event Log**, **Linux syslog / journald**, **your own app logs** (text or JSON lines, stack traces grouped), and **Raspberry Pi / Jetson** boxes over SSH (plus live health checks: under-voltage, throttling, temperature, disk, failed services).

Runs on your own LLM (Ollama, LM Studio, llama.cpp, vLLM...). Works with no LLM at all too, in rules-only mode.

## Quick start (Windows)

```powershell
cd D:\Projects\LogIngestionLLM
copy config.example.toml logagent.toml    # then edit sources and [llm]
python -m logagent ui                       # opens http://127.0.0.1:8765
```

Or double-click `start-dashboard.bat`. Python 3.11+ only, no packages to install.

For the Security log (failed logons, new accounts, audit-log cleared), run from an **admin** terminal.

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
