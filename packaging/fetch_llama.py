"""Download llama.cpp's prebuilt server for this OS into engine/ (the AI engine bundled with LogIngestLLM).

    python packaging/fetch_llama.py                    # latest llama.cpp release, this OS, into ./engine
    python packaging/fetch_llama.py --tag b6050 --os windows --dest dist/LogIngestLLM/engine

Puts a GPU build (Vulkan on Windows/Linux, Metal on macOS) in engine/gpu and a plain CPU build in engine/cpu, and keeps
only llama-server, llama-quantize and the shared libraries they need. llama.cpp is MIT-licensed; its license is copied
alongside. Standard library only.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import platform
import posixpath
import re
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

API = "https://api.github.com/repos/ggml-org/llama.cpp/releases"
# (os, arch) -> {build: asset name pattern}
ARC = r"\.(zip|tar\.gz)$"
ASSETS = {
    ("windows", "x64"): {"gpu": r"-bin-win-vulkan-x64" + ARC, "cpu": r"-bin-win-cpu-x64" + ARC},
    ("linux", "x64"): {"gpu": r"-bin-ubuntu-vulkan-x64" + ARC, "cpu": r"-bin-ubuntu-x64" + ARC},
    ("macos", "arm64"): {"gpu": r"-bin-macos-arm64" + ARC},
    ("macos", "x64"): {"gpu": r"-bin-macos-x64" + ARC},
}
KEEP = re.compile(r"^(llama-server|llama-quantize)(\.exe)?$|\.(dll|so(\.\d+)*|dylib|metal)$|^LICENSE", re.I)


def this_os() -> tuple[str, str]:
    osn = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
    m = platform.machine().lower()
    return osn, "arm64" if m in ("arm64", "aarch64") else "x64"


def _get(url: str):
    headers = {"accept": "application/vnd.github+json", "user-agent": "LogIngestLLM-build"}
    if os.environ.get("GITHUB_TOKEN"):  # CI: avoid the anonymous API rate limit
        headers["authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def release(tag: str, wanted: dict) -> dict:
    """A tagged build, or for "latest" the newest release that has every build we need (llama.cpp publishes its
    binaries as bNNNNN pre-releases; GitHub's "latest" can be a stub without them)."""
    if tag != "latest":
        return _get(f"{API}/tags/{tag}")
    for rel in _get(f"{API}?per_page=40"):
        names = [a["name"] for a in rel.get("assets", [])]
        if all(any(re.search(p, n) for n in names) for p in wanted.values()):
            return rel
    raise SystemExit("no recent llama.cpp release has the builds this OS needs; pass --tag explicitly")


def _members(blob: bytes, name: str):
    """(file name, bytes) for every file in a .zip or .tar.gz; symlinked libraries come out under their link name."""
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for info in z.infolist():
                if not info.is_dir():
                    yield Path(info.filename).name, z.read(info)
        return
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        files = {m.name: m for m in t.getmembers()}
        for m in t.getmembers():
            target = m
            for _ in range(8):  # follow symlinks inside the archive
                if not target.issym():
                    break
                link = posixpath.normpath(posixpath.join(posixpath.dirname(target.name), target.linkname))
                target = files.get(link)
                if target is None:
                    break
            if target is not None and target.isfile():
                yield Path(m.name).name, t.extractfile(target).read()


def fetch(tag: str, osn: str, arch: str, dest: Path) -> str:
    wanted = ASSETS.get((osn, arch))
    if not wanted:
        raise SystemExit(f"no prebuilt llama.cpp for {osn}/{arch}")
    rel = release(tag, wanted)
    names = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    for build, pat in wanted.items():
        name = next((n for n in names if re.search(pat, n)), None)
        if not name:
            raise SystemExit(f"release {rel.get('tag_name')}: no asset matching {pat}. Assets: {sorted(names)}")
        print(f"downloading {name} ...", flush=True)
        with urllib.request.urlopen(names[name], timeout=600) as r:
            data = r.read()
        out = dest / build
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        for base, blob in _members(data, name):
            if not KEEP.search(base):
                continue
            target = out / base
            target.write_bytes(blob)
            if not base.lower().endswith((".dll", ".metal")) and "LICENSE" not in base:
                target.chmod(0o755)
        if not any(out.glob("llama-server*")):
            raise SystemExit(f"{name} contained no llama-server")
        print(f"  -> {out}: {', '.join(sorted(p.name for p in out.iterdir()))}")
    (dest / "VERSION").write_text(f"llama.cpp {rel.get('tag_name')} ({osn}/{arch})\n")
    return rel.get("tag_name", tag)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="latest", help="llama.cpp release tag, e.g. b6050 (default: latest)")
    ap.add_argument("--os", choices=["windows", "linux", "macos"], default=this_os()[0])
    ap.add_argument("--arch", choices=["x64", "arm64"], default=this_os()[1])
    ap.add_argument("--dest", default="engine")
    a = ap.parse_args()
    tag = fetch(a.tag, a.os, a.arch, Path(a.dest))
    print(f"llama.cpp {tag} ready in {a.dest}/")


if __name__ == "__main__":
    main()
