"""Log locations on this machine: what this OS offers, finding logs, browsing a location, testing it, saving sources.

Everything here backs the dashboard's "Log locations" view. Sources are saved to the [[sources]] tables of
logagent.toml; the rest of the file (comments, [llm], [[rules]]) is left as it was.
"""
from __future__ import annotations

import itertools
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import tomllib
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .collectors import windows
from .collectors.sources import (SourceError, _files, collect, detect_format, is_log_file, parse_window)

TYPES = ("files", "journald", "syslog", "app", "windows", "evtx")
FORMATS = ("auto", "syslog", "journal", "app", "evtx")
_SAFE_UNIT = re.compile(r"^[\w@.:\\-]{1,200}$")
_SAFE_CHANNEL = re.compile(r"^[\w ./-]{1,200}$")


# ---------------------------------------------------------------- this machine
def _os_pretty() -> str:
    sysname = platform.system()
    if sysname == "Linux":
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return "Linux " + platform.release()
    if sysname == "Darwin":
        return "macOS " + platform.mac_ver()[0]
    if sysname == "Windows":
        return f"Windows {platform.release()} ({platform.version()})"
    return f"{sysname} {platform.release()}"


def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


_sys_cache: dict = {}


def system_info() -> dict:
    """OS of the machine the dashboard runs on, and which source types work here."""
    if _sys_cache.get("t", 0) > time.time() - 60:
        return _sys_cache["v"]
    sysname = platform.system()
    os_name = {"Darwin": "macOS"}.get(sysname, sysname)
    journal = bool(shutil.which("journalctl"))
    journal_system = False
    if journal:
        p = _run(["journalctl", "-q", "-n", "1", "--no-pager", "_TRANSPORT=kernel"])
        journal_system = bool(p and p.returncode == 0 and p.stdout.strip())
    types = ["files", "syslog", "app"]
    if journal:
        types.append("journald")
    if sysname == "Windows":
        types += ["windows", "evtx"]
    notes = []
    if journal and not journal_system:
        notes.append("journalctl only shows your user journal; add yourself to the systemd-journal group "
                      "(sudo usermod -aG systemd-journal $USER, then log in again) to read system logs")
    if sysname == "Darwin":
        notes.append("macOS keeps most logs in the unified log; export one first: "
                     "log show --last 1d --style syslog > ~/Desktop/system-1d.log, then add that file")
    if sysname == "Windows":
        notes.append("the Security channel needs the dashboard started as admin")
    v = {"os": os_name, "pretty": _os_pretty(), "release": platform.release(), "machine": platform.machine(),
         "hostname": socket.gethostname(), "home": str(Path.home()), "sep": os.sep, "types": types,
         "journal_system": journal_system, "notes": notes}
    _sys_cache.update(t=time.time(), v=v)
    return v


# ---------------------------------------------------------------- validation
def _str(v, field: str, max_len: int = 500) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{field} is required")
    v = v.strip()
    if len(v) > max_len or any(c in v for c in "\x00\r\n"):
        raise ValueError(f"{field} is not valid")
    return v


def _list(v, field: str, pattern: re.Pattern) -> list[str]:
    if isinstance(v, str):
        v = [x for x in re.split(r"[,\n]", v)]
    if not isinstance(v, list):
        raise ValueError(f"{field} must be a list")
    out = [str(x).strip() for x in v if str(x).strip()]
    bad = [x for x in out if not pattern.match(x)]
    if bad:
        raise ValueError(f"{field}: not allowed: {bad[0]!r}")
    return out


def validate_source(spec: dict) -> dict:
    """Clean one source spec from the UI. Raises ValueError with a message meant for the user."""
    if not isinstance(spec, dict):
        raise ValueError("source must be an object")
    kind = str(spec.get("type", "")).lower()
    if kind not in TYPES:
        raise ValueError(f"type must be one of {', '.join(TYPES)}")
    out: dict = {"name": _str(spec.get("name") or "", "name", 60), "type": kind}
    if kind in ("files", "syslog", "app", "evtx"):
        out["path"] = _str(spec.get("path"), "path")
    if kind == "files":
        fmt = str(spec.get("format") or "auto").lower()
        if fmt not in FORMATS:
            raise ValueError(f"format must be one of {', '.join(FORMATS)}")
        if fmt != "auto":
            out["format"] = fmt
    if kind == "app" and spec.get("app"):
        out["app"] = _str(spec["app"], "app", 60)
    if kind == "windows":
        out["channels"] = _list(spec.get("channels") or ["System", "Application"], "channels", _SAFE_CHANNEL)
    if kind == "journald" and spec.get("units"):
        out["units"] = _list(spec["units"], "units", _SAFE_UNIT)
    if spec.get("since"):
        out["since"] = _str(spec["since"], "since", 10)
    if spec.get("enabled") is False:
        out["enabled"] = False
    return out


def validate_sources(sources: list) -> list[dict]:
    if not isinstance(sources, list):
        raise ValueError("sources must be a list")
    out, seen = [], set()
    for i, s in enumerate(sources):
        try:
            c = validate_source(s)
        except ValueError as exc:
            raise ValueError(f"source {i + 1}: {exc}") from None
        if c["name"].lower() in seen:
            raise ValueError(f"two sources are named {c['name']!r}")
        seen.add(c["name"].lower())
        out.append(c)
    return out


# ---------------------------------------------------------------- saving to logagent.toml
def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    raise TypeError(f"cannot write {type(v).__name__} to TOML")


def _toml_table(header: str, d: dict) -> str:
    return "\n".join([header] + [f"{k} = {_toml_value(v)}" for k, v in d.items()]) + "\n"


def _toml_dump(data: dict) -> str:
    """Whole-file writer, used only if the in-place edit can't be verified."""
    out = [f"{k} = {_toml_value(v)}" for k, v in data.items() if not isinstance(v, (dict, list)) or
           (isinstance(v, list) and not (v and isinstance(v[0], dict)))]
    out.append("")
    for k, v in data.items():
        if isinstance(v, dict):
            out.append(_toml_table(f"[{k}]", v))
    for k, v in data.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            out += [_toml_table(f"[[{k}]]", t) for t in v]
    return "\n".join(out)


def _replace_sources(text: str, sources: list[dict]) -> str:
    """Swap the live [[sources]] tables for new ones. Comments, commented examples and other tables stay."""
    lines = text.splitlines(keepends=True)
    out, skipping, insert_at = [], False, None
    for line in lines:
        s = line.strip()
        if s == "[[sources]]":
            skipping = True
            if insert_at is None:
                insert_at = len(out)
            continue
        if skipping:
            if s.startswith("[") or s.startswith("#"):
                skipping = False
            else:
                continue
        out.append(line)
    block = "\n".join(_toml_table("[[sources]]", s) for s in sources)
    if insert_at is None:
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        return "".join(out) + ("\n" + block if sources else "")
    return "".join(out[:insert_at]) + block + ("\n" if sources else "") + "".join(out[insert_at:])


def save_sources(cfg: dict, sources: list) -> list[dict]:
    """Validate, write to logagent.toml (keeping a .bak), and update the running config in place."""
    clean = validate_sources(sources)
    path = Path(cfg.get("_path") or "logagent.toml")
    if path.exists():
        text = path.read_text(encoding="utf-8")
    else:
        example = Path(__file__).resolve().parents[1] / "config.example.toml"
        text = example.read_text(encoding="utf-8") if example.exists() else ""
    old = tomllib.loads(text) if text.strip() else {}
    new_text = _replace_sources(text, clean)
    try:
        parsed = tomllib.loads(new_text)
        ok = (parsed.get("sources", []) == clean and
              {k: v for k, v in parsed.items() if k != "sources"} == {k: v for k, v in old.items() if k != "sources"})
    except tomllib.TOMLDecodeError:
        ok = False
    if not ok:  # unusual hand-edited layout: rewrite the whole file from its data rather than risk a broken edit
        new_text = "# Rewritten by the logagent dashboard; your previous file is logagent.toml.bak\n" + \
                   _toml_dump({**{k: v for k, v in old.items() if k != "sources"}, "sources": clean})
    if path.exists():
        path.with_name(path.name + ".bak").write_text(text, encoding="utf-8")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(new_text, encoding="utf-8")
    os.replace(tmp, path)
    cfg["sources"] = clean
    cfg["_path"] = str(path)
    return clean


# ---------------------------------------------------------------- discovery
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", "site-packages", "venv", ".venv", ".venv-train", "proc", "sys",
              "dev", "Cache", "cache", "GPUCache", "Code Cache", "CacheStorage", "IndexedDB", "blob_storage"}
_DISCOVER_FILE = re.compile(r"(\.log|\.log[.-]\d+|\.log\.\d+\.gz|\.log\.gz|\.evtx)$", re.I)


def _looks_like_log(dirpath: str, name: str) -> bool:
    if _DISCOVER_FILE.search(name) or (is_log_file(name) and not re.search(r"\.(txt|json|jsonl|out|err)$", name, re.I)):
        return True
    # .txt/.out/.json only count inside a folder that says it holds logs
    return is_log_file(name) and "log" in os.path.basename(dirpath).lower()


def _walk_logs(roots: list[str], max_depth: int, budget_s: float, found: dict[str, list[str]]) -> None:
    deadline = time.time() + budget_s
    for root in roots:
        root = os.path.expandvars(os.path.expanduser(root))
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirs, names in os.walk(root, onerror=lambda e: None):
            if time.time() > deadline:
                return
            depth = dirpath.count(os.sep) - base_depth
            dirs[:] = [] if depth >= max_depth else [d for d in dirs if d not in _SKIP_DIRS and
                                                     not (d.startswith(".") and depth > 0)]
            hits = [os.path.join(dirpath, n) for n in names if _looks_like_log(dirpath, n)]
            if hits:
                found.setdefault(dirpath, []).extend(hits)


def _collapse(found: dict[str, list[str]]) -> dict[str, list[str]]:
    """One suggestion per log area: 3+ sibling log folders become their parent, and a folder within two
    levels of another suggestion is folded into it (a folder source already reads two levels down)."""
    found = {k: list(v) for k, v in found.items()}
    by_parent: dict[str, list[str]] = {}
    for d in found:
        by_parent.setdefault(os.path.dirname(d), []).append(d)
    for parent, kids in by_parent.items():
        if len(kids) >= 3 and parent not in (os.sep, str(Path.home())):
            merged = found.pop(parent, [])
            for k in kids:
                merged += found.pop(k, [])
            found[parent] = merged
    out: dict[str, list[str]] = {}
    for d in sorted(found, key=len):
        anc = next((a for a in out if d.startswith(a.rstrip(os.sep) + os.sep) and
                    d[len(a):].strip(os.sep).count(os.sep) < 2), None)
        if anc:
            out[anc] += found[d]
        else:
            out[d] = found[d]
    return out


def _dir_name(d: str) -> str:
    p = Path(d)
    home = str(Path.home())
    if p.name.lower() in ("logs", "log") and p.parent.name:
        return f"{p.parent.name} {p.name}"
    if str(p) == "/var/log":
        return "var/log"
    return p.name or str(p).replace(home, "~")


def _same(spec: dict, configured: list[dict]) -> bool:
    keys = ("type", "path", "host", "channels", "units")
    norm = lambda s: {k: (os.path.normpath(os.path.expanduser(s[k])) if k == "path" else s[k]) for k in keys if s.get(k)}
    return any(norm(spec) == norm(c) for c in configured)


def discover(cfg: dict) -> dict:
    """Suggest log locations for this OS. Read-only and bounded in time."""
    info = system_info()
    cands: list[dict] = []
    home = Path.home()

    def add(spec: dict, note: str = "", files: list[str] | None = None, readable: bool | None = None):
        c = {"spec": spec, "note": note, "configured": _same(spec, cfg.get("sources", []))}
        if files is not None:
            st = []
            for f in files:
                try:
                    st.append((f, os.stat(f)))
                except OSError:
                    continue
            c["files"] = len(st)
            c["readable"] = sum(1 for f, _ in st if os.access(f, os.R_OK))
            c["bytes"] = sum(s.st_size for _, s in st)
            c["newest"] = (datetime.fromtimestamp(max(s.st_mtime for _, s in st), timezone.utc).isoformat()
                           if st else None)
        if readable is not None:
            c["readable_ok"] = readable
        cands.append(c)

    found: dict[str, list[str]] = {}
    if info["os"] == "Linux":
        if shutil.which("journalctl"):
            add({"name": "System journal", "type": "journald"},
                "systemd journal: kernel, services, logins" if info["journal_system"] else
                "only your user journal is readable (see note above)", readable=info["journal_system"])
        _walk_logs(["/var/log"], 2, 2.0, found)
        _walk_logs([str(home / ".local/share"), str(home / ".local/state"), str(home / ".config"),
                    str(home / ".cache")], 3, 3.0, found)
        _walk_logs([str(home / d) for d in ("Desktop", "Documents", "projects", "Projects", "src", "code", "dev")],
                   3, 3.0, found)
    elif info["os"] == "macOS":
        _walk_logs(["/var/log", "/Library/Logs", str(home / "Library/Logs")], 2, 3.0, found)
        _walk_logs([str(home / d) for d in ("Desktop", "Documents", "Projects", "src", "code")], 3, 3.0, found)
    elif info["os"] == "Windows":
        add({"name": "Windows System + Application", "type": "windows", "channels": ["System", "Application"]},
            "Windows Event Log")
        add({"name": "Windows Security", "type": "windows", "channels": ["Security"]},
            "failed logons, account changes; needs admin")
        add({"name": "Defender", "type": "windows", "channels": ["Microsoft-Windows-Windows Defender/Operational"]},
            "malware detections")
        env = os.environ
        _walk_logs([env.get("ProgramData", r"C:\ProgramData"), env.get("LOCALAPPDATA", ""), env.get("APPDATA", ""),
                    os.path.join(env.get("SystemRoot", r"C:\Windows"), "Logs")], 3, 4.0, found)
        _walk_logs([str(home / d) for d in ("Desktop", "Documents", "source", "Projects")], 3, 2.0, found)

    for d, files in sorted(_collapse(found).items(), key=lambda kv: (-len(kv[1]), kv[0])):
        files = sorted(set(files))
        add({"name": _dir_name(d), "type": "files", "path": d}, "", files)
    return {"system": info, "candidates": cands[:80]}


# ---------------------------------------------------------------- browsing one location
def browse(spec: dict) -> dict:
    """What's inside a location, so the user can pick specific logs to analyze."""
    kind = spec["type"]
    if kind in ("files", "syslog", "app", "evtx"):
        root = os.path.expandvars(os.path.expanduser(spec["path"]))
        base = root if os.path.isdir(root) else os.path.dirname(root)
        items = []
        for f in _files(spec["path"]):
            try:
                st = os.stat(f)
            except OSError:
                continue
            readable = os.access(f, os.R_OK)
            fmt = spec.get("format") or ({"syslog": "syslog", "app": "app", "evtx": "evtx"}.get(kind))
            if not fmt or fmt == "auto":
                fmt = detect_format(f) if readable and st.st_size else ("empty" if readable else "?")
            items.append({"path": f, "name": os.path.relpath(f, base) if base else f, "bytes": st.st_size,
                          "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                          "readable": readable, "format": fmt})
        items.sort(key=lambda x: x["mtime"], reverse=True)
        hint = None
        if items and not all(i["readable"] for i in items):
            hint = ("some files are root-only; run the dashboard with sudo, or add your user to the group that "
                    "owns them (e.g. adm on Debian/Ubuntu)" if os.name != "nt" else
                    "some files need admin; start the dashboard as administrator")
        return {"kind": "files", "items": items, "hint": hint}
    if kind == "journald":
        p = _run(["journalctl", "-F", "_SYSTEMD_UNIT", "--no-pager"], timeout=20)
        units = sorted(set((p.stdout.decode(errors="replace") if p else "").split()))
        return {"kind": "units", "items": [{"unit": u} for u in units if _SAFE_UNIT.match(u)][:400],
                "hint": None if p and p.returncode == 0 else "journalctl did not answer"}
    if kind == "windows":
        chans = list(dict.fromkeys((spec.get("channels") or []) + windows.DEFAULT_CHANNELS))
        return {"kind": "channels", "items": [{"channel": c} for c in chans], "hint": None}
    return {"kind": "whole", "items": [], "hint": "this source is analyzed as a whole"}


def test_source(cfg: dict, spec: dict, max_events: int = 3000) -> dict:
    """Try a location: does it resolve, can we read it, what does an event look like."""
    out: dict = {"ok": False, "warnings": []}
    if spec["type"] in ("files", "syslog", "app", "evtx"):
        files = _files(spec["path"])
        out["files"] = len(files)
        out["unreadable"] = sum(1 for f in files if not os.access(f, os.R_OK))
        if not files:
            out["error"] = f"no log files at {spec['path']}"
            return out
    try:
        evs = list(itertools.islice(collect(spec, parse_window(cfg.get("window")),
                                            warn=out["warnings"].append, max_events=max_events), max_events))
    except (SourceError, windows.CollectorError, OSError, KeyError) as exc:
        out["error"] = str(exc)
        return out
    out["events"] = len(evs)
    out["window"] = cfg.get("window") or "24h"
    if evs:
        ts = sorted(e.ts for e in evs)
        out.update(first=ts[0].isoformat(), last=ts[-1].isoformat(), sample=evs[-1].message[:300])
    out["ok"] = True
    return out
