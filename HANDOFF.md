# HANDOFF: read this first (for the next agent)

Last updated 2026-11-06 by the agent that built this. The owner (Author) is moving the project from his
desktop (Windows 11, RTX 3070 Ti 8 GB) to his **laptop**. Start by doing "Laptop setup" below, then pick
up "Next steps". `README.md` is the user-facing doc; this file is the engineering state.

## What this is

`logagent`: ingests Windows Event Log, Linux syslog/journald, the owner's own app logs, and Raspberry Pi /
Jetson logs over SSH, then surfaces ("nitpicks") the few events worth the owner's attention, with why and
what to do. It has a local web dashboard and runs on **a model the owner trained himself**.

## Owner's decisions (do not re-ask)

- **Stay local.** No log data goes to Anthropic or any cloud LLM, including for drafting training labels.
- **His own LLM.** He wants a model he creates, trains and develops, not a hosted one. Current approach:
  QLoRA fine-tune of `Qwen/Qwen3-4B-Instruct-2507` (Apache 2.0) on log-triage data. Training from scratch
  was ruled out (compute), and he accepted fine-tuning.
- **UI style:** dense, technical, precise (ops console look, exact UTC timestamps, IDs, counts, rates).
  Avoid friendly or marketing-style UI.
- He wants it "good to go": one-click start, robust fallbacks, no manual steps.

## Architecture (package `logagent/`, Python 3.11+, stdlib only)

| file | role |
|---|---|
| `collectors/windows.py` | `wevtutil qe ... /f:RenderedXml` → Events. Security channel needs admin. |
| `collectors/textlogs.py` | syslog (RFC3164/5424/ISO), journald JSON, app logs (text or JSON lines, tracebacks folded) |
| `collectors/sources.py` | source specs from config → events; `ssh` type runs journalctl + a read-only health probe (disk, mem, temps, `vcgencmd get_throttled`, failed units) on Pi/Jetson |
| `signals.py` | ~50 rules (id, score, why, action) + `NOISE_RULES` (negative score = suppress). Rules support `event_ids`, `providers`, `pattern`, `exclude`, `max_severity`, `min_count` |
| `analysis.py` | template masking → clusters → score (rule + severity + burst + novelty vs `data/baseline.json`) |
| `llm.py` | providers `openai` (any OpenAI-compatible), `ollama`, `anthropic` (unused per owner), `none`. Two modes: whole-report JSON, or `mode="triage"` (one call per pattern, which is what the owner's model is trained on). `TRIAGE_PROMPT` + `triage_input()` are shared by training and inference, so **change them only together with a retrain** |
| `engine.py` | scan pipeline; saves `data/scans/<id>.json` (findings + up to 300 lower-scored "others" for training negatives) |
| `feedback.py` | owner's 👍/👎 + importance labels → `data/feedback.json` (training gold) |
| `server.py` + `static/index.html` | dashboard on 127.0.0.1:8765; `/api/status` (model health, admin, schedule), scheduled scans (`schedule = "6h"`) |
| `train/synth.py`, `train/dataset.py` | synthetic Pi/Jetson/Linux/app scenarios + scans + feedback → `train_data/{train,eval}.jsonl` (`python -m logagent dataset`) |
| `trainer/` | **separate venv** `.venv-train` (Python 3.12, torch cu128, transformers 5.x, peft, bitsandbytes). `train.py` (QLoRA, custom loop, fits 8 GB at `--batch-tokens 1024`), `evaluate.py`, `serve.py` (OpenAI-compatible on :8081, CUDA + 4-bit) |
| `start-logagent.ps1` + `Start logagent*.bat` | launcher: starts serve.py if an adapter exists, waits for it, starts dashboard; `-Admin` self-elevates |

Config: `logagent.toml` (gitignored; template `config.example.toml`). Tests: `python -m pytest -q` (14 passing).

## Current state

- Working end to end on the desktop: launcher → model online → scan → model triage → dashboard.
- Trained model v1: `models/logagent-20261106-1138/adapter` (~130 MB LoRA). Trained only on **rule labels
  and synthetic scenarios**, with zero owner labels yet. Eval on 100 held-out examples: exact importance
  0.87 (base model 0.33), within-one-level 0.96, flag precision 0.986 (base 0.76), recall 0.96. Results
  in `models/eval-*.json`. It mostly imitates the rules so far, and its value grows with owner labels.
- Inference ~8 s per pattern on the 3070 Ti (`triage_limit = 20` caps a scan at ~3 min).
- Real PC findings so far: shadow copies deleted on C: (volsnap 25/36), Claude service crashes,
  new services installed. DCOM 10016 and NTFS "volume healthy" were tuned out as noise.

## Laptop setup

Gitignored, so it must be **copied from the desktop** (not in git): `models/` (trained adapter + evals),
`data/` (scan history, baseline, owner feedback), `logagent.toml`. `.venv-train/` should be recreated, not copied.
There is no git remote yet. Ask the owner how he moved the folder; if only the git repo came over, the
adapter is missing and must be copied or retrained.

1. Python 3.11+ for the app: `python -m pytest -q`, then `python -m logagent ui`. Works anywhere, rules-only if no model.
2. **Check the laptop GPU first** (`nvidia-smi`). `trainer/serve.py` and `train.py` need an NVIDIA GPU
   (bitsandbytes 4-bit). Then pick one:
   - NVIDIA with ≥6 GB: recreate `.venv-train` (README "Training your own model"; PyTorch needs Python 3.12,
     not 3.14). The first run downloads ~8 GB of base weights to `~/.cache/huggingface`.
   - No NVIDIA GPU / small GPU: **next step 1 below** (merge + GGUF → Ollama/llama.cpp, which runs on CPU or Apple/AMD).
     Until then set `[llm] provider = "none"` and the dashboard runs on rules alone.
3. Update `logagent.toml` sources for the laptop (Windows channels, Pi/Jetson SSH hosts). The launcher and
   desktop shortcuts are Windows-only. On macOS/Linux run `python -m logagent ui` directly.

## Next steps (priority order)

1. **Portable model export:** merge adapter into base (fp16, on a CUDA box or CPU with enough RAM), convert
   to GGUF Q4_K_M with llama.cpp `convert_hf_to_gguf.py`, create an Ollama model (`Modelfile` with the
   Qwen chat template). Point config at `provider="ollama"`, `model="logagent"`, `mode="triage"`. Add a
   `trainer/export.py` + doc. This removes the CUDA requirement for *using* the model.
2. **Get owner labels.** The model only gets better than the rules with them. Make labeling faster
   (keyboard shortcuts j/k/u/n in the findings table, a "label queue" view of unreviewed patterns).
3. **Retrain loop:** `python -m logagent dataset` → `trainer/train.py` → `trainer/evaluate.py` against the
   previous version; only switch `serve.py` to the new adapter if eval on owner-labeled (`src=you`) rows
   improves. Consider a dashboard "Models" tab showing versions + eval scores.
4. **Connect real devices:** owner hasn't given Pi/Jetson SSH addresses yet (`type="ssh"`, `device="pi"|"jetson"`,
   key auth via `ssh-copy-id`). The `ssh` collector and health probe are unit-tested but not yet run against real hardware.
5. **Precision in model text:** facts in "why" are generic ("Seen N times on host"). Training targets could
   include exact first/last UTC, rate, event ID, and the specific value (IP, unit, stop code) from samples,
   which needs dataset changes + retrain. The dashboard already shows these fields precisely.
6. Nice-to-haves: run as a Windows service / startup task, notifications for critical findings,
   correlation across findings in triage mode (currently only the whole-report mode correlates).

## Gotchas

- Default `python` on the desktop was 3.14 (no CUDA torch wheels), hence the separate 3.12 `.venv-train`.
- Other apps using VRAM (Zoom, Wallpaper Engine) push training into shared memory and make it ~4x slower.
- PowerShell 5.1 `Get-Content -Raw` round-trips garble UTF-8, so edit files with proper tools.
- Never add Claude/AI attribution lines to the owner's commits.
- The dashboard binds 127.0.0.1 only and checks the Host header (DNS-rebinding guard). Keep it that way
  unless you add auth.
