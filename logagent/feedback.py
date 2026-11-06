"""Your verdicts on findings. This is the training signal for your own model.

Stored in data/feedback.json as {"<scan_id>/<cluster_key>": {...}}.
verdict: "useful" | "noise"; importance: critical | high | medium | low.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

IMPORTANCE = ("critical", "high", "medium", "low")
_lock = threading.Lock()


def _path(cfg: dict) -> Path:
    return Path(cfg["data_dir"]) / "feedback.json"


def load_all(cfg: dict) -> dict:
    try:
        return json.loads(_path(cfg).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def for_scan(cfg: dict, scan_id: str) -> dict:
    prefix = scan_id + "/"
    return {k[len(prefix):]: v for k, v in load_all(cfg).items() if k.startswith(prefix)}


def save(cfg: dict, scan_id: str, key: str, verdict: str | None, importance: str | None = None,
         note: str | None = None) -> dict:
    if verdict not in (None, "useful", "noise"):
        raise ValueError("verdict must be useful, noise or null")
    if importance not in (None, *IMPORTANCE):
        raise ValueError("bad importance")
    with _lock:
        data = load_all(cfg)
        k = f"{scan_id}/{key}"
        if verdict is None and importance is None and not note:
            data.pop(k, None)
            entry = {}
        else:
            entry = data.get(k, {})
            entry.update({"verdict": verdict, "importance": importance if verdict != "noise" else None,
                          "ts": datetime.now(timezone.utc).isoformat()})
            if note is not None:
                entry["note"] = note[:1000]
            data[k] = entry
        p = _path(cfg)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        tmp.replace(p)
    return entry
