"""Normalized event model shared by every collector."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

# Syslog-style severities (lower = worse). Every collector maps into these.
EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG = range(8)
SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

_LEVEL_WORDS = {
    "emerg": EMERG, "emergency": EMERG, "panic": EMERG,
    "alert": ALERT,
    "crit": CRIT, "critical": CRIT, "fatal": CRIT,
    "err": ERR, "error": ERR, "severe": ERR,
    "warn": WARNING, "warning": WARNING,
    "notice": NOTICE,
    "info": INFO, "information": INFO, "informational": INFO,
    "debug": DEBUG, "trace": DEBUG, "verbose": DEBUG,
}


def severity_from_word(word: str | None, default: int = INFO) -> int:
    if not word:
        return default
    return _LEVEL_WORDS.get(str(word).strip().lower(), default)


@dataclass
class Event:
    ts: datetime
    host: str
    source: str            # e.g. "windows:System", "journald", "syslog", "app:myservice"
    severity: int
    message: str
    program: str = ""      # provider / unit / process name
    event_id: str = ""     # Windows EventID, MESSAGE_ID, etc.
    fields: dict[str, Any] = field(default_factory=dict)
    loc: dict[str, Any] = field(default_factory=dict)  # where it is: file+line+pos, journal cursor, or Windows record

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES[max(0, min(7, self.severity))]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        d["severity"] = self.severity_name
        return d


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
