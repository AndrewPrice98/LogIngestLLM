"""Turn a source spec (from config or the UI) into a stream of Events.

Source spec dict keys:
  type:    files | windows | evtx | journald | syslog | app
  name:    label shown in the UI (optional)
  since:   e.g. "24h", "7d", "all" (optional; falls back to the scan window)
  files:   path = "/var/log" | "~/app/logs/*.log" | "C:/logs/app.log" (folder, glob or file),
           format = "auto" | "syslog" | "journal" | "app" | "evtx" | "prefetch" (auto = detect per file)
  windows: channels = ["System", "Application", "Security"]
  evtx:    path = "C:/exports/System.evtx"  (or .xml)
  journald:units = ["nginx.service"] (optional)
  syslog:  path = "/var/log/syslog" (globs ok)
  app:     path = "D:/myapp/logs/*.log", app = "myapp"

Everything is read on this machine: logagent is a local-only analyzer. Logs from other machines are analyzed by
copying them here (or exporting them) and adding them as files.
"""
from __future__ import annotations

import glob
import gzip
import os
import re
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from ..model import Event, WARNING, ERR, CRIT, INFO
from . import prefetch, windows
from .textlogs import Line, parse_syslog, parse_journal_json, parse_app_log, is_syslog_line


class SourceError(RuntimeError):
    pass


ALL_TIME = timedelta(days=36500)
MAX_FILE_BYTES = 100 * 1024 * 1024   # larger files are read from the end (newest data)

# Names that are logs even without a .log suffix (/var/log/messages, rotated messages-20261101, ...)
_LOG_NAME = re.compile(r"^(messages|syslog|secure|auth|kern|daemon|maillog|mail|cron|dmesg|boot|user|debug|"
                       r"system|install|dpkg|alternatives|faillog)(\.log)?([.-]\d+)?(\.gz)?$", re.I)
_LOG_SUFFIX = re.compile(r"(\.log([.-]\d+)?|\.log\.\d+\.gz|\.log\.gz|\.out|\.err|\.txt|\.jsonl?|\.evtx|\.pf)$", re.I)


def parse_window(s: str | None, default: timedelta = timedelta(hours=24)) -> timedelta:
    if not s:
        return default
    s = str(s).strip().lower()
    if s in ("all", "any", "0"):
        return ALL_TIME
    unit = s[-1]
    try:
        n = float(s[:-1])
    except ValueError:
        return default
    return {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n), "w": timedelta(weeks=n)}.get(unit, default)


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _read_lines(path: str, warn=print, max_bytes: int = MAX_FILE_BYTES) -> Iterator[str]:
    """Lines of a text log, each a Line carrying its line number and byte offset (gzip: line number only).
    A file over max_bytes is read from its last max_bytes (the newest data); line numbers are then unknown."""
    if path.endswith(".gz"):
        with _open_text(path) as fh:
            for n, raw in enumerate(fh, 1):
                ln = Line(raw)
                ln.ln = n
                yield ln
        return
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        n: int | None = 1
        if size > max_bytes:
            warn(f"{path} is {size / 2**20:.0f} MB; reading the newest {max_bytes / 2**20:.0f} MB only")
            fh.seek(size - max_bytes)
            fh.readline()  # drop the partial first line
            n = None
        while True:
            pos = fh.tell()
            raw = fh.readline()
            if not raw:
                break
            ln = Line(raw.decode("utf-8", errors="replace"))
            ln.ln, ln.pos = n, pos
            if n is not None:
                n += 1
            yield ln


def _drop_cursor(events: Iterator[Event]) -> Iterator[Event]:
    for e in events:
        e.loc.pop("cursor", None)
        yield e


def _in_file(events: Iterator[Event], path: str) -> Iterator[Event]:
    for e in events:
        e.loc["file"] = path
        yield e


def is_log_file(path: str) -> bool:
    name = os.path.basename(path)
    return bool(_LOG_SUFFIX.search(name) or _LOG_NAME.match(name))


def _files(pattern: str, max_files: int = 1500) -> list[str]:  # a Prefetch folder holds up to 1024 files
    """A file, a glob, or a folder (log-looking files up to two levels down)."""
    pattern = os.path.expandvars(os.path.expanduser(pattern))
    if os.path.isdir(pattern):
        out = []
        for root, dirs, names in os.walk(pattern):
            if root[len(pattern):].count(os.sep) >= 2:
                dirs[:] = []
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            out += [os.path.join(root, n) for n in sorted(names) if is_log_file(n)]
            if len(out) >= max_files:
                break
        return [f for f in out[:max_files] if os.path.isfile(f)]
    files = sorted(glob.glob(pattern)) if any(c in pattern for c in "*?[") else [pattern]
    return [f for f in files if os.path.isfile(f)][:max_files]


def detect_format(path: str) -> str:
    """Best guess at a file's format: evtx | prefetch | journal | syslog | app | binary."""
    low = path.lower()
    if low.endswith(".evtx"):
        return "evtx"
    if low.endswith(".pf") and prefetch.is_prefetch(path):
        return "prefetch"
    try:
        if low.endswith(".gz"):
            with gzip.open(path, "rb") as fh:
                head = fh.read(65536)
        else:
            with open(path, "rb") as fh:
                head = fh.read(65536)
    except (OSError, EOFError):
        return "app"
    if b"\x00" in head[:4096]:
        return "binary"
    text = head.decode("utf-8", errors="replace")
    if low.endswith(".xml") and "<Event" in text:
        return "evtx"
    lines = [l for l in text.splitlines()[:-1] or text.splitlines() if l.strip()][:40]
    if not lines:
        return "app"
    journal = sum(1 for l in lines if l.lstrip().startswith("{") and ('"__REALTIME_TIMESTAMP"' in l or '"_HOSTNAME"' in l))
    if journal >= len(lines) / 2:
        return "journal"
    if sum(1 for l in lines if is_syslog_line(l)) >= len(lines) / 2:
        return "syslog"
    return "app"


def _collect_file(path: str, fmt: str, host: str, cutoff: datetime, warn, max_events: int) -> Iterator[Event]:
    if fmt == "auto":
        fmt = detect_format(path)
    if fmt == "binary":
        warn(f"skipped {path}: binary file, not a text log")
        return
    if fmt == "evtx":
        yield from _in_file(windows.collect(path=path, max_events=max_events, warn=warn), path)
        return
    if fmt == "prefetch":  # like .evtx: a record of what happened, so not cut to the scan window
        try:
            yield from prefetch.read_prefetch(path, host, warn)
        except prefetch.PrefetchError as exc:
            warn(f"skipped {path}: {exc}")
        return
    lines = _read_lines(path, warn)
    if fmt == "journal":
        evs = _drop_cursor(parse_journal_json(lines, host))  # an exported file: point at its lines, not the live journal
    elif fmt == "syslog":
        evs = parse_syslog(lines, host)
    else:
        evs = parse_app_log(lines, Path(path).name.split(".")[0] or "app", host)
    yield from _since_filter(_in_file(evs, path), cutoff)


def _since_filter(events: Iterator[Event], cutoff: datetime) -> Iterator[Event]:
    for e in events:
        if e.ts >= cutoff:
            yield e


def collect(spec: dict, window: timedelta, warn=print, max_events: int = 20000) -> Iterator[Event]:
    kind = spec.get("type", "").lower()
    window = parse_window(spec.get("since"), window)
    cutoff = datetime.now(timezone.utc) - window
    host = spec.get("host") or socket.gethostname()  # set host for logs copied from another machine

    if kind == "files":
        files = _files(spec["path"])
        if not files:
            raise SourceError(f"no log files at {spec['path']}")
        for f in files:
            try:
                yield from _collect_file(f, spec.get("format", "auto"), host, cutoff, warn, max_events)
            except (OSError, windows.CollectorError) as exc:
                warn(f"skipped {f}: {exc}")
    elif kind == "windows":
        yield from windows.collect(spec.get("channels"), since=window, max_events=max_events, warn=warn)
    elif kind == "evtx":
        yield from _in_file(windows.collect(path=spec["path"], max_events=max_events, warn=warn), spec["path"])
    elif kind == "journald":
        cmd = ["journalctl", "-o", "json", "--no-pager", "-n", str(max_events)]
        if window < ALL_TIME:
            cmd += ["--since", f"-{int(window.total_seconds())}s"]
        for u in spec.get("units", []):
            cmd += ["-u", u]
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=300).stdout.decode("utf-8", errors="replace")
        except FileNotFoundError as exc:
            raise SourceError("journalctl not available on this machine") from exc
        yield from parse_journal_json(out.splitlines(), host)
    elif kind == "syslog":
        files = _files(spec["path"])
        if not files:
            raise SourceError(f"no files match {spec['path']}")
        for f in files:
            yield from _since_filter(_in_file(parse_syslog(_read_lines(f, warn), host), f), cutoff)
    elif kind == "app":
        files = _files(spec["path"])
        if not files:
            raise SourceError(f"no files match {spec['path']}")
        name = spec.get("app") or spec.get("name") or Path(files[0]).stem
        for f in files:
            yield from _since_filter(_in_file(parse_app_log(_read_lines(f, warn), name, host), f), cutoff)
    elif kind == "ssh":
        raise SourceError("SSH sources were removed: logagent reads logs on this machine. Copy the logs here "
                          "(for example with scp) and add them as files.")
    else:
        raise SourceError(f"unknown source type {kind!r}")
