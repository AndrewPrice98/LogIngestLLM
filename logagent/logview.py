"""Jump to an event in its original log: the lines (or journal entries / Windows records) around it.

The browser never names a file. It sends a reference into a saved scan ("c/<key>/<i>" = sample i of a pattern,
"t/<n>/<j>" = use j of tool n, "i/<n>" = first sighting of indicator n), and the location comes from the scan
JSON that logagent itself wrote. Paging moves within that same file / journal / channel only.
"""
from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
from collections import deque
from datetime import datetime, timezone

from .collectors import windows

MAX_LINE = 2000
CHUNK = 64 * 1024


class ViewError(ValueError):
    pass


def resolve(scan: dict, ref: str) -> dict:
    parts = ref.split("/")
    try:
        if parts[0] == "c":
            c = next(c for c in scan.get("findings", []) + scan.get("others", []) if c["key"] == parts[1])
            i = int(parts[2])
            loc = c.get("first_loc") if i == -1 else c.get("last_loc") if i == -2 else (c.get("sample_locs") or [])[i]
        elif parts[0] == "t":
            loc = scan["tools"][int(parts[1])]["uses"][int(parts[2])]["loc"]
        elif parts[0] == "i":
            loc = scan["iocs"][int(parts[1])].get("loc")
        else:
            raise ViewError("bad reference")
    except (StopIteration, IndexError, KeyError, ValueError) as exc:
        raise ViewError("that event isn't in this scan") from exc
    if not loc:
        raise ViewError("no position was recorded for this event (scans from before this feature)")
    return loc


def _clip(t: str) -> str:
    t = t.rstrip("\r\n")
    return t if len(t) <= MAX_LINE else t[:MAX_LINE] + " …"


# ---------------------------------------------------------------- text files
def _file_lines(path: str, pos: int, line: int | None, before: int, after: int) -> dict:
    size = os.path.getsize(path)
    pos = max(0, min(pos, size))
    with open(path, "rb") as fh:
        start, prev = pos, []
        while len(prev) <= before and start > 0:  # read backwards in chunks until we have enough lines
            start = max(0, start - CHUNK)
            fh.seek(start)
            data = fh.read(pos - start)
            prev = data.split(b"\n")
            if start > 0:
                prev = prev[1:]  # partial line at the chunk edge
            if prev and prev[-1] == b"":
                prev = prev[:-1]
        prev = prev[-before:] if before else []
        out, p = [], pos - sum(len(x) + 1 for x in prev)
        for k, raw in enumerate(prev):
            out.append({"n": line - len(prev) + k if line else None, "pos": p, "text": _clip(raw.decode("utf-8", "replace"))})
            p += len(raw) + 1
        fh.seek(pos)
        at_end = False
        for k in range(after + 1):
            here = fh.tell()
            raw = fh.readline()
            if not raw:
                at_end = True
                break
            out.append({"n": line + k if line else None, "pos": here, "text": _clip(raw.decode("utf-8", "replace"))})
        at_end = at_end or fh.tell() >= size
    return {"lines": out, "at_start": not out or out[0]["pos"] == 0, "at_end": at_end, "size": size}


def _gz_lines(path: str, line: int, before: int, after: int) -> dict:
    prev: deque = deque(maxlen=before)
    out = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            if n < line:
                prev.append((n, raw))
                continue
            if n > line + after:
                break
            out.append({"n": n, "text": _clip(raw)})
    return {"lines": [{"n": n, "text": _clip(r)} for n, r in prev] + out, "at_start": not prev or prev[0][0] == 1}


# ---------------------------------------------------------------- journal (this machine)
def _journal(cursor: str, before: int, after: int) -> dict:
    def run(extra: list[str], n: int) -> list[dict]:
        cmd = ["journalctl", f"--cursor={cursor}", "-o", "json", "--no-pager", "-n", str(n), *extra]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ViewError(f"journalctl failed: {exc}") from exc
        if p.returncode != 0 and not p.stdout:
            raise ViewError("journalctl: " + p.stderr.decode(errors="replace").strip()[:300])
        rows = []
        for l in p.stdout.decode("utf-8", "replace").splitlines():
            try:
                rows.append(json.loads(l))
            except json.JSONDecodeError:
                pass
        return rows

    def fmt(j: dict) -> dict:
        try:
            t = datetime.fromtimestamp(int(j.get("__REALTIME_TIMESTAMP", 0)) / 1e6, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%fZ")[:-4] + "Z"
        except (TypeError, ValueError):
            t = "?"
        msg = j.get("MESSAGE", "")
        if isinstance(msg, list):
            msg = bytes(msg).decode("utf-8", "replace")
        prog = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or ""
        pid = j.get("_PID", "")
        return {"cursor": j.get("__CURSOR"), "text": _clip(f"{t} {j.get('_HOSTNAME', '')} {prog}{'[' + pid + ']' if pid else ''}: {msg}")}

    back = run(["-r"], before + 1)[1:] if before else []
    fwd = run([], after + 1)
    out = [fmt(j) for j in reversed(back)] + [fmt(j) for j in fwd]
    return {"lines": out, "at_start": len(back) < before, "at_end": len(fwd) < after + 1}


# ---------------------------------------------------------------- Windows records
_SHOW = ("CommandLine", "NewProcessName", "ParentProcessName", "TargetUserName", "SubjectUserName", "IpAddress",
         "LogonType", "Status", "SubStatus", "ServiceName", "ImagePath", "MemberName", "TaskName")


def _key_fields(e) -> str:
    """Fields worth seeing inline, unless the rendered message already contains them."""
    extra = [f"{k}={v}" for k, v in (e.fields or {}).items() if k in _SHOW and v not in ("", "-") and str(v) not in e.message]
    return ("  | " + "  ".join(extra)) if extra else ""


def _win(loc: dict, record: int, before: int, after: int) -> dict:
    lo, hi = max(1, record - before), record + after
    q = f"*[System[(EventRecordID>={lo}) and (EventRecordID<={hi})]]"
    path = loc.get("file")
    if path and path.lower().endswith(".xml"):
        with open(path, encoding="utf-8", errors="replace") as fh:
            evs = list(windows.parse_events_xml(fh.read()))
    else:
        try:
            if path and not shutil.which("wevtutil"):
                evs = list(windows.read_evtx(path, None, lambda m: None))
            else:
                args = ["qe", path, "/lf:true"] if path else ["qe", loc.get("channel") or "System"]
                evs = list(windows.parse_events_xml(windows._run_wevtutil(args + [f"/q:{q}", "/f:RenderedXml"])))
        except windows.CollectorError as exc:
            raise ViewError(str(exc)) from exc
    rows = []
    for e in evs:
        try:
            rid = int(e.loc.get("record", 0))
        except ValueError:
            continue
        if lo <= rid <= hi:
            rows.append((rid, e))
    rows.sort(key=lambda x: x[0])
    return {"lines": [{"record": rid, "n": rid,
                       "text": _clip(f"{e.ts.astimezone(timezone.utc):%Y-%m-%d %H:%M:%SZ} {e.program} [{e.event_id}] {e.message}"
                                     + _key_fields(e))}
                      for rid, e in rows], "at_start": lo == 1}


def view(scan: dict, ref: str, before: int = 25, after: int = 25, at: str | None = None) -> dict:
    """Context around a referenced event. `at` re-centres on another line of the same log (for paging)."""
    loc = resolve(scan, ref)
    before, after = max(0, min(int(before), 500)), max(0, min(int(after), 500))
    try:
        if loc.get("cursor"):
            if loc.get("ssh"):
                raise ViewError("this event came from a remote SSH source; logagent now reads logs on this machine only")
            res = _journal(at or loc["cursor"], before, after)
            res.update(kind="journal", title="systemd journal (this machine)", target=loc["cursor"])
        elif loc.get("record"):
            res = _win(loc, int(at or loc["record"]), before, after)
            res.update(kind="windows", title=loc.get("file") or f"Windows Event Log: {loc.get('channel', '?')}",
                       target=int(loc["record"]))
        elif loc.get("file"):
            path = loc["file"]
            if not os.path.isfile(path):
                raise ViewError(f"{path} no longer exists (moved, rotated or deleted)")
            if path.endswith(".gz"):
                res = _gz_lines(path, int(at or loc.get("line") or 1), before, after)
            else:
                if at is not None:
                    pos, line = int(at.split(":")[0]), (int(at.split(":")[1]) if ":" in at and at.split(":")[1] else None)
                else:
                    pos, line = loc.get("pos"), loc.get("line")
                if pos is None:
                    raise ViewError("no byte position recorded for this line")
                res = _file_lines(path, int(pos), line, before, after)
            res.update(kind="file", title=path, target=loc.get("pos") if not path.endswith(".gz") else loc.get("line"),
                       target_line=loc.get("line"))
        else:
            raise ViewError("unknown location type")
    except OSError as exc:
        raise ViewError(f"{type(exc).__name__}: {exc}") from exc
    # the original event stays highlighted while paging
    for l in res["lines"]:
        l["hit"] = (l.get("cursor") == loc["cursor"] if loc.get("cursor") else
                    l.get("record") == int(loc["record"]) if loc.get("record") else
                    l.get("n") == loc.get("line") if loc["file"].endswith(".gz") else l.get("pos") == loc.get("pos"))
        # paging handle for the client: where to re-centre
        l["at"] = (l.get("cursor") if loc.get("cursor") else str(l.get("record")) if loc.get("record") else
                   str(l.get("n")) if loc["file"].endswith(".gz") else f"{l['pos']}:{l['n'] or ''}")
    return res
