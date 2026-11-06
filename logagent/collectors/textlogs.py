"""Text-based log parsers: syslog (RFC3164/RFC5424), journald JSON, and app logs.

All parsers take an iterable of lines so the same code works for local files,
stdin, and output streamed over SSH from a Pi/Jetson.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone, timedelta
from typing import Iterable, Iterator

from ..model import Event, INFO, ERR, WARNING, severity_from_word, ensure_aware

class Line(str):
    """A text line that remembers where it came from (1-based line number and byte offset; either may be None)."""
    ln: int | None = None
    pos: int | None = None


def _loc(raw) -> dict:
    out = {}
    if getattr(raw, "ln", None) is not None:
        out["line"] = raw.ln
    if getattr(raw, "pos", None) is not None:
        out["pos"] = raw.pos
    return out


# ---------------------------------------------------------------- syslog
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[.*?\])+) ?(?P<msg>.*)$"
)
_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
# Modern rsyslog default on Debian/RPi OS 12+: ISO timestamp, no PRI
_ISO_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) (?P<host>\S+) "
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_MSG_LEVEL = re.compile(r"\b(emerg|panic|fatal|critical|crit|error|err|failed|failure|warn(?:ing)?)\b", re.I)


def _guess_severity(msg: str, default: int = INFO) -> int:
    m = _MSG_LEVEL.search(msg)
    if not m:
        return default
    w = m.group(1).lower()
    if w in ("failed", "failure"):
        return min(default, WARNING)
    return min(default, severity_from_word(w, default))


def _parse_iso(ts: str) -> datetime | None:
    try:
        return ensure_aware(datetime.fromisoformat(ts.replace("Z", "+00:00")))
    except ValueError:
        return None


def is_syslog_line(line: str) -> bool:
    return bool(_RFC5424.match(line) or _ISO_SYSLOG.match(line) or _RFC3164.match(line))


def parse_syslog(lines: Iterable[str], default_host: str = "", year: int | None = None) -> Iterator[Event]:
    now = datetime.now().astimezone()
    year = year or now.year
    last: Event | None = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        m = _RFC5424.match(line)
        if m:
            pri = int(m["pri"])
            ts = _parse_iso(m["ts"]) or now
            ev = Event(ts=ts, host=m["host"] if m["host"] != "-" else default_host, source="syslog",
                       severity=pri & 7, message=m["msg"], program="" if m["app"] == "-" else m["app"],
                       event_id="" if m["msgid"] == "-" else m["msgid"], loc=_loc(raw))
        else:
            m = _ISO_SYSLOG.match(line) or _RFC3164.match(line)
            if not m:
                # Continuation line (stack traces, multi-line kernel dumps): fold into previous.
                if last is not None and len(last.message) < 4000:
                    last.message += " | " + line.strip()
                continue
            gd = m.groupdict()
            if gd.get("pri"):
                sev = int(gd["pri"]) & 7
            else:
                sev = _guess_severity(gd["msg"])
            ts = _parse_iso(gd["ts"])
            if ts is None:
                try:
                    ts = datetime.strptime(f"{year} {gd['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=now.tzinfo)
                    if ts > now + timedelta(days=1):  # log from last December read in January
                        ts = ts.replace(year=year - 1)
                except ValueError:
                    ts = now
            ev = Event(ts=ts, host=gd["host"] or default_host, source="syslog", severity=sev,
                       message=gd["msg"], program=gd["prog"], fields={"pid": gd.get("pid")} if gd.get("pid") else {}, loc=_loc(raw))
        last = ev
        yield ev


# ---------------------------------------------------------------- journald
def parse_journal_json(lines: Iterable[str], default_host: str = "") -> Iterator[Event]:
    """Parse `journalctl -o json` output (one JSON object per line)."""
    for raw in lines:
        loc = _loc(raw)
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            j = json.loads(raw)
        except json.JSONDecodeError:
            continue
        msg = j.get("MESSAGE", "")
        if isinstance(msg, list):  # binary messages come back as byte arrays
            try:
                msg = bytes(msg).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                msg = str(msg)
        try:
            ts = datetime.fromtimestamp(int(j.get("__REALTIME_TIMESTAMP", 0)) / 1e6, tz=timezone.utc)
        except (TypeError, ValueError):
            ts = datetime.now(timezone.utc)
        try:
            sev = int(j.get("PRIORITY", 6))
        except (TypeError, ValueError):
            sev = INFO
        prog = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or ("kernel" if j.get("_TRANSPORT") == "kernel" else "")
        fields = {k: j[k] for k in ("_SYSTEMD_UNIT", "_PID", "_EXE", "UNIT", "JOB_RESULT", "_BOOT_ID", "CODE_FILE") if k in j}
        if j.get("__CURSOR"):
            loc["cursor"] = j["__CURSOR"]
        yield Event(ts=ts, host=j.get("_HOSTNAME", default_host), source="journald", severity=sev,
                    message=str(msg), program=str(prog), event_id=j.get("MESSAGE_ID", ""), fields=fields, loc=loc)


# ---------------------------------------------------------------- app logs
_APP_TS = re.compile(
    r"^\[?(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\]?"
)
_CLF = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4})\] "[^"]*" (?P<status>\d{3}|-) ')
_APP_LEVEL = re.compile(r"\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|SEVERE|CRITICAL|CRIT|FATAL|PANIC)\b")
_CONTINUATION = re.compile(r"^(\s+|Traceback|Caused by|\tat |During handling|[A-Za-z_.]+(Error|Exception):)")


def parse_app_log(lines: Iterable[str], app_name: str = "app", default_host: str = "") -> Iterator[Event]:
    """Generic app log parser: JSON-lines or text with a leading timestamp + level word.

    Multi-line records (Python tracebacks, Java stack traces) are folded into one event.
    """
    pending: Event | None = None
    now = datetime.now(timezone.utc)
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        if line.lstrip().startswith("{"):
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                j = None
            if isinstance(j, dict):
                if pending:
                    yield pending
                    pending = None
                ts_raw = j.get("timestamp") or j.get("time") or j.get("ts") or j.get("@timestamp") or j.get("asctime")
                ts = (_parse_iso(str(ts_raw).replace(",", ".")) if ts_raw and not isinstance(ts_raw, (int, float))
                      else datetime.fromtimestamp(float(ts_raw), tz=timezone.utc) if isinstance(ts_raw, (int, float))
                      else None) or now
                lvl = j.get("level") or j.get("severity") or j.get("levelname") or j.get("lvl")
                msg = j.get("message") or j.get("msg") or j.get("event") or line
                extra = {k: v for k, v in j.items() if k not in ("timestamp", "time", "ts", "@timestamp", "level",
                                                                    "severity", "levelname", "message", "msg")}
                exc = extra.pop("exc_info", None) or extra.pop("exception", None) or extra.pop("stack", None)
                text = str(msg) + (f" | {exc}" if exc else "")
                yield Event(ts=ts, host=default_host, source=f"app:{app_name}",
                            severity=severity_from_word(str(lvl), _guess_severity(text)),
                            message=text, program=str(j.get("logger") or j.get("name") or app_name),
                            fields={k: v for k, v in extra.items() if isinstance(v, (str, int, float, bool))}, loc=_loc(raw))
                continue

        w = _CLF.match(line)
        if w:  # web server access log (Apache/nginx combined format): one request per line
            if pending:
                yield pending
                pending = None
            try:
                ts = datetime.strptime(w["ts"], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                ts = now
            st = int(w["status"]) if w["status"].isdigit() else 0
            yield Event(ts=ts, host=default_host, source=f"app:{app_name}", severity=ERR if st >= 500 else NOTICE if st in (401, 403) else INFO,
                        message=line.strip(), program=app_name, fields={"client": w["ip"], "status": w["status"]}, loc=_loc(raw))
            continue

        m = _APP_TS.match(line)
        if m:
            if pending:
                yield pending
            ts = _parse_iso(m["ts"].replace(",", ".").replace(" ", "T", 1)) or now
            rest = line[m.end():].strip(" -|:")
            lm = _APP_LEVEL.search(rest[:60])
            sev = severity_from_word(lm.group(1)) if lm else _guess_severity(rest)
            pending = Event(ts=ts, host=default_host, source=f"app:{app_name}", severity=sev,
                            message=rest, program=app_name, loc=_loc(raw))
        elif pending is not None and (_CONTINUATION.match(line) or len(pending.message) < 200):
            if len(pending.message) < 6000:
                pending.message += " | " + line.strip()
            if line.startswith("Traceback") or "Exception" in line or "Error" in line:
                pending.severity = min(pending.severity, ERR)
        else:
            if pending:
                yield pending
            pending = Event(ts=now, host=default_host, source=f"app:{app_name}",
                            severity=_guess_severity(line), message=line.strip(), program=app_name, loc=_loc(raw))
    if pending:
        yield pending
