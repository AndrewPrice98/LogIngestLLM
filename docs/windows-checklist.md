# Windows checklist

Things only a Windows machine can exercise. CI runs the unit tests on Windows, but not these (they need a real
Event Log, `wevtutil`, an admin token and a desktop). About 20 minutes. Note anything that differs from "expect".

| # | do | expect |
|---|---|---|
| 1 | `git pull`, then `python -m pytest -q` in a normal terminal | all pass |
| 2 | double-click **Start logagent** | model starts (if `.venv-train` exists), dashboard opens; top bar shows `privilege user (Security log skipped)` |
| 3 | double-click it **again** while it's running | the browser opens the running dashboard; no second copy, no error |
| 4 | close the window, then start **Start logagent (admin)** | UAC prompt; top bar shows `privilege admin` |
| 5 | LOG LOCATIONS → Discover | Windows System + Application, Security, Defender, plus log folders under ProgramData / AppData |
| 6 | RUN SCAN on "This PC" with model review on | findings appear; the model column says `logagent (triage)` |
| 7 | open a finding from the System or Security log → **↗ first occurrence in log** | the log viewer shows the event with neighbouring records (this uses `wevtutil` with an EventRecordID range) |
| 8 | in the viewer, press **▲ earlier 100** and **Esc** | earlier records load, the event stays highlighted; Esc returns to the finding |
| 9 | LOG LOCATIONS → + Add / open file → a `.evtx` export (Event Viewer → Save All Events As) | the picker lists it with format `evtx`; ANALYZE works; ↗ log opens records |
| 10 | Explain this event on a Security finding (e.g. 4624/4625) | logon type and status codes decoded; "check it yourself" shows a `Get-WinEvent` command that runs in PowerShell |
| 11 | copy that `Get-WinEvent` command into PowerShell (admin for Security) | it returns the same events |
| 12 | report → printable / PDF | opens a printable page; Ctrl+P → Save as PDF works |
| 13 | `python -m logagent demo --port 8766` | five example investigations; the Windows one shows the LSASS dump, certutil, PsExec and the cleared log |
| 14 | edit a source in LOG LOCATIONS and save | `logagent.toml` keeps its comments; `logagent.toml.bak` holds the previous version |

If something fails, the dashboard's console line (left sidebar) and the launcher window usually say why; a
screenshot of either is enough to fix it.
