# Log Agent

Reads your logs, throws away the noise, and tells you the handful of things worth your attention, with why they matter and what to do.

Sources: **Windows Event Log**, **Linux syslog / journald**, **your own app logs** (text or JSON lines, stack traces grouped), and **Raspberry Pi / Jetson** boxes over SSH (plus live health checks: under-voltage, throttling, temperature, disk, failed services).

Runs on your own LLM (Ollama, LM Studio, llama.cpp, vLLM...). Works with no LLM at all too, in rules-only mode.

## Quick start (Windows)

Double-click **Start logagent** on the desktop (or `Start logagent.bat` here). It:

1. starts your trained model in the background (if `models\*\adapter` exists) and waits until it answers,
2. starts the dashboard at http://127.0.0.1:8765 and opens it,
3. runs an automatic scan every 6 h (`schedule` in `logagent.toml`) while it's open.

Use **Start logagent (admin)** to include the Security log (failed logons, account changes, audit-log cleared). Closing the window stops everything. If the model isn't available the dashboard says so in the top bar and falls back to the built-in rules.

Settings live in `logagent.toml` (copied from `config.example.toml` on first run). Sources with `enabled = false` are listed but not scanned by default.

## Quick start (Linux / macOS)

```bash
./start-logagent.sh               # --no-browser, --port 8765, --model-port 8081
```

Same steps as the Windows launcher. Ctrl+C stops the dashboard and the model it started. On Linux the local systemd journal is a `journald` source, and no admin step is needed if your user can read the system journal (`wheel`/`adm`/`systemd-journal` group).

## Log locations and picking a log

Open **LOG LOCATIONS** (top of the sidebar) to manage where logagent looks, without editing the config by hand:

- **Configured**: every source, with *browse / pick*, *test* (resolves the location and reads a sample), *edit*, *remove*, and an on/off switch for RUN SCAN and scheduled scans. Changes are written to `logagent.toml` (the previous version is kept as `logagent.toml.bak`; comments and the rest of the file stay as they were).
- **Discover**: finds log locations for the OS you're on: the systemd journal, `/var/log`, app log folders under your home directory (Linux); `/var/log`, `~/Library/Logs` (macOS); Event Log channels, `ProgramData`/`AppData` log folders (Windows); and SSH hosts from `~/.ssh/config`. It shows how many files you can actually read.
- **+ Add / open file**: add a location (a folder, glob or file; `type = "files"` detects syslog, journald JSON, app/JSON-lines and .evtx per file), or open one file by path without saving it.

*Browse / pick* lists a location's files (format, size, modified time, whether you can read them), a journal's systemd units, or Windows channels. Pick one or more and press **ANALYZE**: the logs are parsed, every pattern is ranked (rules, then your model), and with *summarize* on, the model writes a whole-log summary: what produced the log, health, key events with UTC times, what the noise is, and next steps.

The summary is OS-aware: logagent works out which OS produced the log (from the source type and the messages themselves: Windows paths and providers, systemd units, `com.apple.*`, Raspberry Pi under-voltage, Jetson `nvgpu`...) and which OS you're viewing it on, and commands are written for the right one (e.g. "ssh into the Pi first" when you're reading a Pi's log on your laptop). Files over 100 MB are read from their newest 100 MB.

## Learning to read logs, and analyst tools

- **Explain this event** (open any finding): the line with its parts highlighted (IPs and whether they're public, users, ports, PIDs, status codes, paths), an anatomy table (when, host, source, program, event ID, severity, every Windows/journal field with what it means: logon types, NTSTATUS failure codes, Kerberos encryption types), what normally causes it and when it deserves a closer look, and **check it yourself**: the native command that shows the same events (`journalctl`, `grep`, `Get-WinEvent`, Event Viewer, `log show`), for the OS that produced the log. **Ask model** adds a plain-language walkthrough for someone learning, or a terse brief for an analyst.
- **REFERENCE** (top bar): searchable, offline notes on Windows event IDs, Sysmon IDs, logon types, failure codes, common Linux messages, severities and programs.
- **ATT&CK** tab: findings mapped to MITRE ATT&CK techniques, laid out by tactic; click a technique to see its patterns. Only evidence is mapped (rule hits and events that are notable in themselves, such as log clearing or account creation); routine events like a normal logon only show related techniques as context.
- **Indicators** tab: every IP (public/private), domain, URL, email, file hash and user name, extracted from every event with exact counts. Click *patterns* to filter findings to it, *pivot* to find it in every saved scan, or export CSV.

## Tools, jumping to the event, and asking your model

- **Tools** tab: which tools show up in the logs: attacker tools (Mimikatz, LinPEAS, reverse shells, C2), Windows/Linux built-ins being abused (certutil downloads, encoded PowerShell, comsvcs.dll LSASS dumps, `curl | sh`, shadow-copy deletion), scanners (Nmap, sqlmap, Nikto, gobuster, by command or web user agent), remote-access software, tunnels and miners. A built-in signature catalog checks every event; your model then names the remaining programs and binaries. A model-named tool is only kept if its evidence string really occurs in the log, and it's folded into the catalog entry when it is the same lines. Patterns that contain a tool are scored up so they reach the findings and the model review.
- **Jump to the event**: every event remembers where it is (file + line + byte offset, journal cursor, or Windows record ID). Click **↗ log** on a tool use, a sample line, an indicator, a first/latest occurrence or a citation to open the original log at that line with the lines around it; page earlier/later, highlight text, `Esc` to go back. Works for text and `.gz` files, the local journal, a Pi/Jetson's journal over SSH, exported `.evtx`/`.xml` and (on Windows) live channels.
- **Citations**: the whole-log summary and **Query model** answers cite real events as `[E3]`; click one to open that line. Query model offers questions generated from the scan (what happened step by step, how a tool was used, what an IP did, likely false alarms).
- Samples to try: `samples/intrusion-auth.log` (Linux break-in), `samples/web-access.log` (web scanners), `samples/windows-security.xml` (Windows intrusion).

## Label queue

**LABEL QUEUE** (top bar) shows every pattern you haven't labeled, across all scans, once, ordered by what your label teaches the model most: where the model and the rules disagree, alarms to confirm, errors no rule covers, new and recurring patterns. Keys: `j`/`k` move, `u` relevant (suggested importance), `1`-`4` relevant as critical/high/medium/low, `n` noise, `s` skip, `z` undo, `e` explain, `o` open in its scan, `?` help. The same keys work in a scan's findings table. After 25 new labels it shows the retrain commands.

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
   summary_model = "logagent-base"   # whole-log summaries: same weights with your adapter switched off
   ```
   `serve.py` answers to two model ids: `logagent` (your adapter) and `logagent-base` (adapter off for that request). The adapter is trained for per-pattern triage JSON, so free-form summaries come out better from the base model.

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
python -m logagent scan --file files:/var/log --window all  # folder, format detected per file
python -m logagent scan --json > scan.json
```

Scans are saved in `data/scans/`. Add your own rules under `[[rules]]` in the config.

## Tests

```bash
python -m pytest -q
```
