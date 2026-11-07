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


def host_env() -> dict:
    """The environment for launching the user's own programs (browser, file manager). The packaged Linux app
    points LD_LIBRARY_PATH at its bundled libraries, which breaks system tools: kde-open dies on the bundled
    OpenSSL and the browser never opens. PyInstaller keeps the original value in LD_LIBRARY_PATH_ORIG."""
    env = dict(os.environ)
    if FROZEN and sys.platform.startswith("linux"):
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return env


def open_browser(url: str) -> bool:
    """Open url in the user's browser, with host_env() so a packaged app can launch it."""
    import shutil
    import subprocess
    import webbrowser
    if FROZEN and sys.platform.startswith("linux") and not os.environ.get("BROWSER") and shutil.which("xdg-open"):
        try:
            subprocess.Popen(["xdg-open", url], env=host_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return True
        except OSError:
            pass
    return webbrowser.open(url)
