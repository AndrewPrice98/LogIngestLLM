"""Where things live, from a source checkout and from the packaged app (PyInstaller).

- resource(): files that ship with the app (samples, Sigma examples, scenarios, config template)
- app_dir(): the folder the user unpacked; the bundled AI engine and model sit next to the executable there
- user_dir(): writable per-user folder for config, scans and labels when packaged (the app folder may be read-only)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
REPO = Path(__file__).resolve().parents[1]


def app_dir() -> Path:
    if not FROZEN:
        return REPO
    exe = Path(sys.executable).resolve().parent
    # macOS .app bundle: LogIngestLLM.app/Contents/MacOS/LogIngestLLM -> the folder holding the .app
    if exe.name == "MacOS" and exe.parent.name == "Contents":
        return exe.parent.parent.parent
    return exe


def resource(rel: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", REPO)) if FROZEN else REPO
    return base / rel


def user_dir() -> Path:
    if not FROZEN:
        return REPO
    if sys.platform == "win32":
        d = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "LogIngestLLM"
    elif sys.platform == "darwin":
        d = Path.home() / "Library" / "Application Support" / "LogIngestLLM"
    else:
        d = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "LogIngestLLM"
    d.mkdir(parents=True, exist_ok=True)
    return d


def models_dir() -> Path:
    """Trained adapters and evaluation reports (development checkout only)."""
    return REPO / "models"
