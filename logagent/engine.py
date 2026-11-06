"""Scan pipeline: collect -> cluster -> score -> LLM -> store."""
from __future__ import annotations

import json
import time
import tomllib
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

from . import llm, summary as summ
from .analysis import Baseline, cluster_events, score_clusters, select_findings
from .collectors.sources import collect, parse_window, SourceError
from .collectors.windows import CollectorError
from .signals import load_rules

DEFAULT_CONFIG = {
    "data_dir": "data",
    "window": "24h",
    "max_findings": 40,
    "min_score": 30,
    "llm": {"provider": "none"},
    "sources": [],
    "rules": [],
}


def load_config(path: str | Path | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path and Path(path).exists():
        with open(path, "rb") as fh:
            user = tomllib.load(fh)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    cfg["_path"] = str(path) if path else None
    return cfg


def _heuristic_report(findings: list[dict]) -> dict:
    """Readable result when no LLM is configured (or the LLM call failed)."""
    imp = lambda s: "critical" if s >= 100 else "high" if s >= 75 else "medium" if s >= 50 else "low"
    out = []
    for f in findings[:15]:
        r = f["rule"] or {}
        out.append({
            "keys": [f["key"]], "title": r.get("title") or f["template"][:80], "importance": imp(f["score"]),
            "host": f["host"], "what": f"{f['count']}x {f['program'] or f['source']}: {f['samples'][0][:300]}",
            "why": r.get("why") or "High-severity event not covered by a known rule.",
            "action": r.get("action") or "Read the sample message and check the program named.",
        })
    top = out[0]["title"] + f" on {out[0]['host']}" if out else "Nothing needs your attention"
    return {"headline": top, "summary": "", "findings": out, "dismissed": []}


def run_scan(cfg: dict, sources: list[dict] | None = None, window: str | None = None,
             use_llm: bool = True, progress=print, summarize: bool = False, label: str | None = None) -> dict:
    t0 = time.time()
    data_dir = Path(cfg["data_dir"])
    win = parse_window(window or cfg.get("window"))
    rules = load_rules(cfg.get("rules"))
    sources = sources if sources is not None else cfg.get("sources", [])
    warnings: list[str] = []

    def warn(msg):
        warnings.append(msg)
        progress(msg)

    events, per_source = [], {}
    for spec in sources:
        src_label = spec.get("name") or spec.get("type")
        progress(f"collecting {src_label} ...")
        n0 = len(events)
        try:
            events.extend(collect(spec, win, warn=warn))
        except (SourceError, CollectorError, OSError, KeyError) as exc:
            warn(f"[{src_label}] {exc}")
        per_source[src_label] = len(events) - n0

    progress(f"{len(events)} events; clustering ...")
    clusters = cluster_events(events, rules)
    baseline = Baseline(data_dir / "baseline.json")
    score_clusters(clusters, baseline)
    selected = select_findings(clusters, int(cfg.get("max_findings", 40)), float(cfg.get("min_score", 30)))
    findings = [c.to_dict() for c in selected]
    chosen = {c.key for c in selected}
    # Lower-scored patterns are kept too: they are the "not important" examples for training.
    others = [c.to_dict() for c in sorted((c for c in clusters if c.key not in chosen),
                                          key=lambda c: (c.score, c.count), reverse=True)[:300]]

    sev = Counter(e.severity_name for e in events)
    stats = {
        "window": window or cfg.get("window") or "24h", "events": len(events), "clusters": len(clusters), "flagged": len(findings),
        "hosts": sorted({e.host for e in events}), "per_source": per_source,
        "by_severity": dict(sev), "rule_hits": dict(Counter(c.rule.id for c in clusters if c.rule).most_common(20)),
    }
    from .locations import system_info
    viewer = system_info()
    origin = summ.guess_origin(sources, events)
    stats["os"] = {"viewer": viewer["pretty"], "origin": origin["os"], "origin_detail": origin["detail"]}

    analysis, llm_error = {}, None
    if use_llm and cfg["llm"].get("provider", "none") != "none" and findings:
        progress(f"asking {cfg['llm']['provider']} to review {len(findings)} findings ...")
        try:
            if cfg["llm"].get("mode") == "triage":
                analysis = llm.analyze_triage(findings, stats, cfg["llm"], progress)
            else:
                analysis = llm.analyze(findings, stats, cfg["llm"])
        except (llm.LLMError, KeyError, ValueError, TimeoutError) as exc:
            llm_error = str(exc)
            warn(f"[llm] {exc}")
    if not analysis:
        analysis = _heuristic_report(findings)
        analysis["_meta"] = {"provider": "none"}

    file_summary = None
    if summarize:
        digest = summ.build_digest(sources, events, [c.to_dict() for c in clusters], analysis, viewer, origin)
        file_summary = {"origin": origin, "viewer": viewer["pretty"], "by": "rules", "error": None}
        if use_llm and cfg["llm"].get("provider", "none") != "none" and events:
            progress("model summarizing the whole log ...")
            try:
                file_summary["text"], meta = llm.summarize(digest, cfg["llm"])
                file_summary["by"] = meta.get("model") or meta.get("provider")
            except (llm.LLMError, KeyError, ValueError, TimeoutError, OSError) as exc:
                file_summary["error"] = str(exc)
                warn(f"[summary] {exc}")
        if not file_summary.get("text"):
            file_summary["text"] = summ.heuristic_summary(digest)

    baseline.update(clusters)
    scan = {
        "id": datetime.now().strftime("%Y%m%d-%H%M%S"),
        "created": datetime.now(timezone.utc).isoformat(),
        "duration_s": round(time.time() - t0, 1),
        "sources": [{k: v for k, v in s.items() if k not in ("identity",)} for s in sources],
        "label": label, "summary": file_summary,
        "stats": stats, "analysis": analysis, "findings": findings, "others": others,
        "warnings": warnings, "llm_error": llm_error,
    }
    scans = data_dir / "scans"
    scans.mkdir(parents=True, exist_ok=True)
    (scans / f"{scan['id']}.json").write_text(json.dumps(scan, indent=1, default=str), encoding="utf-8")
    progress(f"done in {scan['duration_s']}s: {len(findings)} findings")
    return scan


def list_scans(cfg: dict, limit: int = 50) -> list[dict]:
    d = Path(cfg["data_dir"]) / "scans"
    out = []
    for p in sorted(d.glob("*.json"), reverse=True)[:limit]:
        try:
            s = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({"id": s["id"], "created": s["created"], "headline": s["analysis"].get("headline", ""),
                    "label": s.get("label"), "summarized": bool(s.get("summary")),
                    "flagged": s["stats"]["flagged"], "events": s["stats"]["events"],
                    "hosts": s["stats"]["hosts"], "provider": s["analysis"].get("_meta", {}).get("provider")})
    return out


def load_scan(cfg: dict, scan_id: str) -> dict | None:
    if not scan_id.replace("-", "").isdigit():
        return None
    p = Path(cfg["data_dir"]) / "scans" / f"{scan_id}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
