"""Double-click entry point of the packaged app: start (or reopen) the dashboard and the built-in model."""
import socket
import sys
import urllib.request
import webbrowser
from pathlib import Path

if not getattr(sys, "frozen", False):  # run from a checkout: python packaging/launcher.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logagent.cli import main  # noqa: E402

PORT = 8765


def running(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):  # LogIngestLLM scan|eval|demo|... : the CLI
        sys.exit(main(sys.argv[1:]))
    if running(PORT):  # already open: just show it
        webbrowser.open(f"http://127.0.0.1:{PORT}/")
        sys.exit(0)
    port = PORT if free(PORT) else 0
    if not port:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
    print("LogIngestLLM: local-only log analyzer. Close this window or press QUIT in the dashboard to stop.")
    sys.exit(main(["ui", "--port", str(port)] + sys.argv[1:]))
