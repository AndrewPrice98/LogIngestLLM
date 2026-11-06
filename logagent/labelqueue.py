"""The label queue: every pattern you haven't labeled yet, across all scans, ordered by how much your label
would teach the model. Labels are saved with feedback.save() against the newest scan containing the pattern,
so the dataset builder picks them up unchanged."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import feedback, knowledge
from .train.dataset import weak_label

LEVELS = ["critical", "high", "medium", "low", "noise"]
ROOT = Path(__file__).resolve().parents[1]


def _gap(a: str | None, b: str | None) -> int:
    if a not in LEVELS or b not in LEVELS:
        return 0
    return abs(LEVELS.index(a) - LEVELS.index(b))


def _priority(c: dict, model: dict | None, rules_imp: str, scans: int) -> tuple[float, list[str]]:
    p, why = 0.0, []
    model_imp = model["importance"] if model else None
    gap = _gap(model_imp, rules_imp)
    if gap >= 2:
        p += 45
        why.append(f"model and rules disagree: model says {model_imp}, rules say {rules_imp}")
    elif gap == 1:
        p += 15
        why.append(f"model ({model_imp}) and rules ({rules_imp}) differ by one level")
    top = model_imp if model_imp else rules_imp
    if top in ("critical", "high"):
        p += 25
        why.append(f"flagged {top}: confirm it's a real alarm")
    if c["severity"] in ("emerg", "alert", "crit", "err") and not c.get("rule"):
        p += 20
        why.append("error with no rule covering it: only your label can teach this one")
    if c.get("novel"):
        p += 10
        why.append("new on this host")
    if scans >= 3:
        p += min(15, scans * 2)
        why.append(f"recurs in {scans} scans: one label covers all of them")
    if not why and top == "noise":
        p -= 10  # routine chatter: labelling it helps a little (negatives), but last
    p += min(10, c["score"] / 15)
    return p, why


def _newest_model_time() -> float:
    """When the newest adapter was trained: from its folder name (logagent-YYYYMMDD-HHMM, local time); the file
    mtime is useless after a git checkout."""
    best = 0.0
    for r in (ROOT / "models").glob("logagent-*/adapter"):
        try:
            t = datetime.strptime(r.parent.name[len("logagent-"):], "%Y%m%d-%H%M").astimezone().timestamp()
        except ValueError:
            t = r.stat().st_mtime
        best = max(best, t)
    return best


def build(cfg: dict, max_scans: int = 200, limit: int = 400) -> dict:
    fb = feedback.load_all(cfg)
    labeled_keys = {k.split("/", 1)[1] for k in fb}
    seen: dict[str, dict] = {}
    for p in sorted((Path(cfg["data_dir"]) / "scans").glob("*.json"), reverse=True)[:max_scans]:
        try:
            scan = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        model = {}
        for f in scan.get("analysis", {}).get("findings", []):
            for k in f.get("keys", []):
                model[k] = {"importance": (f.get("importance") or "low").lower(), "title": f.get("title"),
                            "why": f.get("why"), "action": f.get("action")}
        for d in scan.get("analysis", {}).get("dismissed", []):
            for k in d.get("keys", []):
                model.setdefault(k, {"importance": "noise", "title": None, "why": d.get("reason"), "action": None})
        reviewed = scan.get("analysis", {}).get("_meta", {}).get("provider") not in (None, "none")
        for c in scan.get("findings", []) + scan.get("others", []):
            k = c["key"]
            if k in labeled_keys:
                continue
            if k in seen:  # an older scan of the same pattern: just count it
                seen[k]["scans"] += 1
                seen[k]["total"] += c["count"]
                seen[k]["first"] = min(seen[k]["first"], c["first"])
                continue
            seen[k] = {"key": k, "scan_id": scan["id"], "created": scan["created"], "label": scan.get("label"),
                       "cluster": c, "model": model.get(k) if reviewed else None, "scans": 1, "total": c["count"],
                       "first": c["first"], "last": c["last"]}
    items = []
    for k, s in seen.items():
        c = s["cluster"]
        rules = weak_label(c)
        pri, reasons = _priority(c, s["model"], rules["importance"], s["scans"])
        suggested = (s["model"] or {}).get("importance") or rules["importance"]
        items.append({
            "key": k, "scan_id": s["scan_id"], "created": s["created"], "scan_label": s["label"],
            "host": c["host"], "source": c["source"], "program": c["program"], "event_id": c["event_id"],
            "severity": c["severity"], "count": c["count"], "total": s["total"], "scans": s["scans"],
            "first": s["first"], "last": s["last"], "template": c["template"], "samples": c["samples"][:3],
            "score": c["score"], "novel": c.get("novel", False), "rule": c.get("rule"),
            "attack": c.get("attack") if "attack" in c else knowledge.attack_for(c),
            "title": (s["model"] or {}).get("title") or (c.get("rule") or {}).get("title") or c["template"][:90],
            "model": s["model"], "rules": {"importance": rules["importance"], "why": rules["why"]},
            "suggested": suggested, "priority": round(pri, 1), "reasons": reasons,
        })
    items.sort(key=lambda x: (-x["priority"], x["key"]))
    since = _newest_model_time()
    new_labels = sum(1 for v in fb.values() if v.get("ts") and
                     datetime.fromisoformat(v["ts"]).timestamp() > since)
    return {"items": items[:limit], "unlabeled": len(items), "labeled": len(fb),
            "by_verdict": {v: sum(1 for x in fb.values() if x.get("verdict") == v) for v in ("useful", "noise")},
            "since_model": new_labels,
            "model_trained": datetime.fromtimestamp(since, timezone.utc).isoformat() if since else None}
