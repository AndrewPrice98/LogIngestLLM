"""Build the downloadable app for the current OS: dist/LogIngestLLM-<version>-<os>-<arch>.(zip|tar.gz)

    pip install pyinstaller
    python packaging/build.py                         # app + llama.cpp engine; model files added separately
    python packaging/build.py --model-dir model       # also copy model files (for a local, complete build)

Layout of the result:
    LogIngestLLM/
      LogIngestLLM(.exe)        the app: double-click (Windows/Linux) or "Start LogIngestLLM.command" (macOS)
      engine/gpu, engine/cpu    llama.cpp server builds (MIT)
      model/                    put the model files here (the release's .gguf.part files + SHA256SUMS)
      README-FIRST.txt, LICENSE, NOTICE
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packaging"))

from fetch_llama import fetch, this_os  # noqa: E402
from logagent import __version__  # noqa: E402

README = """LogIngestLLM {version}: local-only log analyzer and analyst co-pilot
=====================================================================

Everything runs on this computer. Nothing is sent anywhere; it works with the network unplugged.

1. Put the model files in the "model" folder next to this file:
     logingestllm-base-Q4_K_M.gguf.part1, .part2 (...), logingestllm-triage.lora.gguf, SHA256SUMS
   (from the same GitHub release). The parts are joined on first start. Without them, LogIngestLLM still runs on
   its detection rules, without the AI.
2. Start it:
{start}
3. Your browser opens the dashboard at http://127.0.0.1:8765. Try an example investigation, or open your own logs.
   Stop it with QUIT (top right) or by closing the window.

Your settings, scans and labels are kept in {data}.
The first AI review after starting takes a little longer while the model loads (a few seconds on a GPU, up to a
minute on a CPU).

Source, docs and issues: the GitHub page you downloaded this from.
"""
START = {
    "windows": "     Double-click LogIngestLLM.exe. Windows SmartScreen may warn about an unrecognised app (it isn't\n"
               "     code-signed): click \"More info\" -> \"Run anyway\".",
    "macos": "     Double-click \"Start LogIngestLLM.command\". The first time, macOS blocks unsigned apps: right-click it ->\n"
             "     Open -> Open. If it still refuses, run in Terminal:  xattr -dr com.apple.quarantine <this folder>",
    "linux": "     Run ./LogIngestLLM (or double-click it in your file manager). To read the system journal your user\n"
             "     needs to be in the systemd-journal (or adm/wheel) group.",
}
DATA = {"windows": r"%LOCALAPPDATA%\LogIngestLLM", "macos": "~/Library/Application Support/LogIngestLLM",
        "linux": "~/.local/share/LogIngestLLM"}


def pyinstaller(work: Path, dist: Path) -> Path:
    import PyInstaller.__main__
    sep = os.pathsep
    data = [(ROOT / "logagent" / "static", "logagent/static"), (ROOT / "samples", "samples"), (ROOT / "rules", "rules"),
            (ROOT / "evals" / "scenarios.json", "evals"), (ROOT / "config.example.toml", "."),
            (ROOT / "LICENSE", "."), (ROOT / "NOTICE", ".")]
    args = [str(ROOT / "packaging" / "launcher.py"), "--name", "LogIngestLLM", "--onedir", "--console", "--noconfirm",
            "--clean", "--distpath", str(dist), "--workpath", str(work / "build"), "--specpath", str(work),
            "--collect-submodules", "logagent", "--paths", str(ROOT)]
    for src, dst in data:
        args += ["--add-data", f"{src}{sep}{dst}"]
    PyInstaller.__main__.run(args)
    return dist / "LogIngestLLM"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llama-tag", default="latest")
    ap.add_argument("--model-dir", help="folder with model .gguf / .part files to include")
    ap.add_argument("--out", default=str(ROOT / "dist"))
    a = ap.parse_args()
    osn, arch = this_os()
    out = Path(a.out)
    work = out / "work"
    app = pyinstaller(work, out / "app")

    tag = fetch(a.llama_tag, osn, arch, app / "engine")  # keeps llama.cpp's LICENSE files next to each build

    model = app / "model"
    model.mkdir(exist_ok=True)
    if a.model_dir:
        for f in Path(a.model_dir).iterdir():
            if f.suffix in (".gguf",) or ".gguf.part" in f.name or f.name == "SHA256SUMS":
                shutil.copy(f, model / f.name)
    (model / "PUT-MODEL-FILES-HERE.txt").write_text("Copy the model files from the GitHub release into this folder.\n")
    for f in ("LICENSE", "NOTICE"):
        shutil.copy(ROOT / f, app / f)
    (app / "README-FIRST.txt").write_text(README.format(version=__version__, start=START[osn], data=DATA[osn]),
                                          encoding="utf-8")
    if osn == "macos":
        cmd = app / "Start LogIngestLLM.command"
        cmd.write_text('#!/bin/bash\ncd "$(dirname "$0")" && ./LogIngestLLM\n')
        cmd.chmod(0o755)

    name = f"LogIngestLLM-{__version__}-{osn}-{arch}"
    final = out / "LogIngestLLM"
    if final.exists():
        shutil.rmtree(final)
    app.rename(final)
    if osn == "linux":
        archive = out / f"{name}.tar.gz"
        with tarfile.open(archive, "w:gz") as t:
            t.add(final, arcname="LogIngestLLM")
    else:
        archive = Path(shutil.make_archive(str(out / name), "zip", out, "LogIngestLLM"))
    print(f"built {archive} ({archive.stat().st_size / 2**20:.0f} MB) with llama.cpp {tag}")


if __name__ == "__main__":
    main()
